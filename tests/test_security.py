"""门控、凭据与审计链。

覆盖：匿名与越权拒绝并留痕、角色与站台分区、跨分区只读放开、危险动作的一次性
确认凭据（过期 / 复用 / 张冠李戴都不认）、会话随有效期失效、并发消费、重启后
凭据状态回放、审计历史只追加。
"""

from __future__ import annotations

import json
import urllib.error
import urllib.request
from concurrent.futures import ThreadPoolExecutor

from psdline.app import build_platform
from psdline.config import default_config
from psdline.console.api import Api
from psdline.console.server import ConsoleServer


def _creds(platform, name="admin"):
    key = next(spec.key for spec in platform.config.security.principals if spec.name == name)
    return {"token": key, "confirm": ""}


def _confirm(api, creds, action, target):
    status, payload = api.handle("POST", "/api/confirm", {}, {"action": action, "target": target}, creds)
    assert status == 200, payload
    return payload["ticket"]


def _kinds(platform):
    return [entry.kind for entry in platform.audit.list()]


def _denials(platform):
    return [
        entry
        for entry in platform.audit.list()
        if entry.kind in ("access_denied", "confirm_rejected")
    ]


# ---- 认证 -------------------------------------------------------------


def test_anonymous_request_is_denied_and_audited(platform):
    api = Api(platform)
    status, payload = api.handle("GET", "/api/status", {}, {})
    assert status == 401
    assert payload["error"] == "unauthenticated"
    assert payload["reason"] == "missing"
    denials = _denials(platform)
    assert denials and denials[-1].kind == "access_denied"
    assert denials[-1].detail["reason"] == "missing"
    assert denials[-1].detail["action"] == "/api/status"


def test_unknown_key_is_denied_and_audited(platform):
    api = Api(platform)
    status, payload = api.handle("GET", "/api/status", {}, {}, {"token": "nope"})
    assert status == 401
    assert payload["reason"] == "unknown"
    assert _denials(platform)[-1].detail["reason"] == "unknown"


def test_static_key_works_on_every_request(platform):
    api = Api(platform)
    for _ in range(3):
        status, payload = api.handle("GET", "/api/status", {}, {}, _creds(platform))
        assert status == 200
        assert payload["platform"] == platform.config.name


def test_login_failure_is_audited(platform):
    api = Api(platform)
    status, payload = api.handle("POST", "/api/session", {}, {"key": "wrong"})
    assert status == 401
    assert _denials(platform)[-1].detail["reason"] == "unknown_key"


def test_session_lifecycle(platform, clock):
    api = Api(platform)
    status, payload = api.handle("POST", "/api/session", {}, {"key": _creds(platform)["token"]})
    assert status == 200
    session = payload["session"]
    assert payload["principal"]["name"] == "admin"

    status, _ = api.handle("GET", "/api/status", {}, {}, {"token": session})
    assert status == 200

    status, closed = api.handle("POST", "/api/session/close", {}, {}, {"token": session})
    assert status == 200 and closed["ok"] is True
    status, payload = api.handle("GET", "/api/status", {}, {}, {"token": session})
    assert status == 401
    assert "session_issued" in _kinds(platform)
    assert "session_closed" in _kinds(platform)


def test_session_expires_with_ttl(platform, clock):
    api = Api(platform)
    ttl = platform.config.security.session_ttl_s
    _, payload = api.handle("POST", "/api/session", {}, {"key": _creds(platform)["token"]})
    session = payload["session"]
    clock.advance(ttl + 1)
    status, payload = api.handle("GET", "/api/status", {}, {}, {"token": session})
    assert status == 401
    assert payload["reason"] == "session_expired"
    assert "session_expired" in _kinds(platform)


# ---- 角色与分区 -------------------------------------------------------


def test_viewer_is_read_only(platform):
    api = Api(platform)
    viewer = _creds(platform, "viewer")
    status, _ = api.handle("GET", "/api/status", {}, {}, viewer)
    assert status == 200
    status, payload = api.handle(
        "POST", "/api/arrive", {}, {"train_id": "T01", "station_id": "ST1"}, viewer
    )
    assert status == 403
    assert payload["reason"] == "capability"
    denial = _denials(platform)[-1]
    assert denial.detail["principal"] == "viewer"
    assert denial.detail["reason"] == "capability"


def test_operator_partition_scopes_writes(platform):
    api = Api(platform)
    operator = _creds(platform, "operator")
    status, _ = api.handle(
        "POST", "/api/arrive", {}, {"train_id": "T01", "station_id": "ST1", "position_m": 0}, operator
    )
    assert status == 200
    status, payload = api.handle(
        "POST", "/api/arrive", {}, {"train_id": "T02", "station_id": "ST2", "position_m": 0}, operator
    )
    assert status == 403
    assert payload["reason"] == "partition"
    assert payload["station"] == "ST2"
    denial = _denials(platform)[-1]
    assert denial.detail["principal"] == "operator"
    assert denial.station_id == "ST2"


def test_cross_partition_read_is_open(platform):
    api = Api(platform)
    operator = _creds(platform, "operator")
    status, view = api.handle("GET", "/api/stations/ST2", {}, {}, operator)
    assert status == 200
    assert view["station"]["id"] == "ST2"


def test_unresolvable_scope_fails_closed(platform):
    api = Api(platform)
    operator = _creds(platform, "operator")
    status, payload = api.handle("POST", "/api/position", {}, {"train_id": "T99", "position_m": 3}, operator)
    assert status == 403
    assert payload["reason"] == "partition"
    status, _ = api.handle("POST", "/api/position", {}, {"train_id": "T99", "position_m": 3}, _creds(platform))
    assert status != 403


def test_reset_state_requires_admin_and_confirm(platform):
    api = Api(platform)
    operator = _creds(platform, "operator")
    status, payload = api.handle("POST", "/api/reset-state", {}, {}, operator)
    assert status == 403
    assert payload["reason"] == "capability"
    admin = _creds(platform)
    status, payload = api.handle("POST", "/api/reset-state", {}, {}, admin)
    assert status == 428
    ticket = _confirm(api, admin, "/api/reset-state", "")
    status, payload = api.handle("POST", "/api/reset-state", {}, {"confirm_ticket": ticket}, admin)
    assert status == 200


# ---- 一次性确认凭据 ---------------------------------------------------


def test_dangerous_action_needs_confirm_ticket(platform):
    api = Api(platform)
    admin = _creds(platform)
    status, payload = api.handle("POST", "/api/batch-open", {}, {"station_id": "ST1"}, admin)
    assert status == 428
    assert payload["error"] == "confirmation_required"
    assert payload["action"] == "/api/batch-open"

    ticket = _confirm(api, admin, "/api/batch-open", "ST1")
    status, payload = api.handle(
        "POST", "/api/batch-open", {}, {"station_id": "ST1", "confirm_ticket": ticket}, admin
    )
    assert status == 200
    kinds = _kinds(platform)
    assert "confirm_issued" in kinds
    assert "confirm_consumed" in kinds
    assert "console_action" in kinds


def test_ticket_reuse_is_rejected_and_audited(platform):
    api = Api(platform)
    admin = _creds(platform)
    ticket = _confirm(api, admin, "/api/batch-open", "ST1")
    status, _ = api.handle(
        "POST", "/api/batch-open", {}, {"station_id": "ST1", "confirm_ticket": ticket}, admin
    )
    assert status == 200
    status, payload = api.handle(
        "POST", "/api/batch-open", {}, {"station_id": "ST1", "confirm_ticket": ticket}, admin
    )
    assert status == 403
    assert payload["reason"] == "reused"
    denial = _denials(platform)[-1]
    assert denial.kind == "confirm_rejected"
    assert denial.detail["reason"] == "reused"


def test_expired_ticket_is_rejected(platform, clock):
    api = Api(platform)
    admin = _creds(platform)
    ticket = _confirm(api, admin, "/api/batch-open", "ST1")
    clock.advance(platform.config.security.confirm_ttl_s + 1)
    status, payload = api.handle(
        "POST", "/api/batch-open", {}, {"station_id": "ST1", "confirm_ticket": ticket}, admin
    )
    assert status == 403
    assert payload["reason"] == "expired"


def test_ticket_bound_to_target_and_principal(platform):
    api = Api(platform)
    admin = _creds(platform)
    ticket = _confirm(api, admin, "/api/batch-open", "ST1")
    status, payload = api.handle(
        "POST", "/api/batch-open", {}, {"station_id": "ST2", "confirm_ticket": ticket}, admin
    )
    assert status == 403
    assert payload["reason"] == "mismatch"

    operator_ticket = _confirm(api, _creds(platform, "operator"), "/api/batch-open", "ST1")
    status, payload = api.handle(
        "POST", "/api/batch-open", {}, {"station_id": "ST1", "confirm_ticket": operator_ticket}, admin
    )
    assert status == 403
    assert payload["reason"] == "mismatch"


def test_operator_cannot_mint_ticket_outside_partition(platform):
    api = Api(platform)
    operator = _creds(platform, "operator")
    status, payload = api.handle(
        "POST", "/api/confirm", {}, {"action": "/api/batch-open", "target": "ST2"}, operator
    )
    assert status == 403
    assert payload["reason"] == "partition"


def test_confirm_rejects_unknown_action(platform):
    api = Api(platform)
    status, payload = api.handle(
        "POST", "/api/confirm", {}, {"action": "/api/arrive", "target": "ST1"}, _creds(platform)
    )
    assert status == 400


def test_fault_confirm_uses_gate_scope(platform):
    api = Api(platform)
    admin = _creds(platform)
    ticket = _confirm(api, admin, "/api/fault", "ST1-G01-01")
    status, payload = api.handle(
        "POST", "/api/fault", {}, {"psd_id": "ST1-G01-01", "confirm_ticket": ticket}, admin
    )
    assert status == 200
    assert payload["locked"] is True


def test_concurrent_ticket_consume_allows_exactly_one(platform):
    api = Api(platform)
    admin = _creds(platform)
    ticket = _confirm(api, admin, "/api/batch-open", "ST1")

    def attempt(_):
        return api.handle(
            "POST", "/api/batch-open", {}, {"station_id": "ST1", "confirm_ticket": ticket}, admin
        )[0]

    with ThreadPoolExecutor(max_workers=8) as pool:
        statuses = list(pool.map(attempt, range(8)))
    assert statuses.count(200) == 1
    assert statuses.count(403) == 7


def test_concurrent_session_requests_are_safe(platform):
    api = Api(platform)
    _, payload = api.handle("POST", "/api/session", {}, {"key": _creds(platform)["token"]})
    session = payload["session"]

    def fetch(index):
        return api.handle("GET", "/api/status", {}, {}, {"token": session})[0]

    with ThreadPoolExecutor(max_workers=8) as pool:
        statuses = list(pool.map(fetch, range(32)))
    assert statuses == [200] * 32


# ---- 重启回放与历史不可变 ---------------------------------------------


def test_restart_keeps_consumed_tickets_and_sessions(tmp_path, clock):
    storage = str(tmp_path / "state")
    first = build_platform(default_config(), clock=clock, storage_root=storage)
    api = Api(first)
    admin = _creds(first)
    _, payload = api.handle("POST", "/api/session", {}, {"key": admin["token"]})
    session = payload["session"]
    ticket = _confirm(api, admin, "/api/batch-open", "ST1")
    status, _ = api.handle(
        "POST", "/api/batch-open", {}, {"station_id": "ST1", "confirm_ticket": ticket}, admin
    )
    assert status == 200

    second = build_platform(default_config(), clock=clock, storage_root=storage)
    api2 = Api(second)
    status, payload = api2.handle(
        "POST", "/api/batch-open", {}, {"station_id": "ST1", "confirm_ticket": ticket}, admin
    )
    assert status == 403
    assert payload["reason"] == "reused"
    status, _ = api2.handle("GET", "/api/status", {}, {}, {"token": session})
    assert status == 200


def test_audit_history_is_append_only(platform):
    api = Api(platform)
    before = [entry.id for entry in platform.audit.replay()]
    api.handle("GET", "/api/status", {}, {})
    api.handle("POST", "/api/session", {}, {"key": "wrong"})
    after = [entry.id for entry in platform.audit.replay()]
    assert after[: len(before)] == before
    assert len(after) > len(before)
    kinds = _kinds(platform)
    assert kinds.count("access_denied") >= 2


def test_audit_never_contains_raw_credentials(platform):
    api = Api(platform)
    admin = _creds(platform)
    _, payload = api.handle("POST", "/api/session", {}, {"key": admin["token"]})
    session = payload["session"]
    ticket = _confirm(api, admin, "/api/batch-open", "ST1")
    api.handle(
        "POST", "/api/batch-open", {}, {"station_id": "ST1", "confirm_ticket": ticket}, admin
    )
    blob = json.dumps([entry.as_dict() for entry in platform.audit.list()], ensure_ascii=False)
    assert session not in blob
    assert ticket not in blob
    assert admin["token"] not in blob


def test_security_journal_is_persisted(platform):
    import os

    api = Api(platform)
    api.handle("POST", "/api/session", {}, {"key": _creds(platform)["token"]})
    segments = [name for name in os.listdir(platform.store.root) if name.startswith("security-")]
    assert segments


def test_security_overview_endpoint(platform):
    api = Api(platform)
    status, payload = api.handle("GET", "/api/security", {}, {}, _creds(platform, "viewer"))
    assert status == 200
    assert payload["principal"]["name"] == "viewer"
    assert "/api/batch-open" in payload["confirm_required"]
    assert payload["cross_partition_read"] is True


# ---- HTTP 层：页面门控与 Cookie ---------------------------------------


def _request(method, url, payload=None, headers=None):
    data = json.dumps(payload).encode("utf-8") if payload is not None else None
    request = urllib.request.Request(url, data=data, method=method)
    request.add_header("Content-Type", "application/json")
    for name, value in (headers or {}).items():
        request.add_header(name, value)
    try:
        with urllib.request.urlopen(request, timeout=5) as response:
            return response.status, response.read().decode("utf-8"), dict(response.headers)
    except urllib.error.HTTPError as error:
        return error.code, error.read().decode("utf-8"), dict(error.headers)


def test_pages_require_login_and_session_cookie(platform):
    server = ConsoleServer(platform, host="127.0.0.1", port=0)
    base_url = server.start()
    try:
        status, body, _ = _request("GET", f"{base_url}/")
        assert status == 401
        assert "控制台登录" in body

        key = platform.config.security.first_admin_key()
        status, body, headers = _request("POST", f"{base_url}/api/session", {"key": key})
        assert status == 200
        cookie = headers["Set-Cookie"].split(";")[0]
        assert cookie.startswith("psdline_session=")

        status, body, _ = _request("GET", f"{base_url}/", headers={"Cookie": cookie})
        assert status == 200
        assert "站台控制台" in body

        status, _, _ = _request("POST", f"{base_url}/api/session/close", {}, {"Cookie": cookie})
        assert status == 200
        status, _, _ = _request("GET", f"{base_url}/", headers={"Cookie": cookie})
        assert status == 401
    finally:
        server.stop()


def test_http_confirm_flow_with_header(platform):
    server = ConsoleServer(platform, host="127.0.0.1", port=0)
    base_url = server.start()
    try:
        key = platform.config.security.first_admin_key()
        auth = {"Authorization": f"Bearer {key}"}
        status, body, _ = _request("POST", f"{base_url}/api/batch-open", {"station_id": "ST1"}, auth)
        assert status == 428
        status, body, _ = _request(
            "POST", f"{base_url}/api/confirm", {"action": "/api/batch-open", "target": "ST1"}, auth
        )
        assert status == 200
        ticket = json.loads(body)["ticket"]
        status, body, _ = _request(
            "POST",
            f"{base_url}/api/batch-open",
            {"station_id": "ST1"},
            {**auth, "X-PSDLine-Confirm": ticket},
        )
        assert status == 200
        assert json.loads(body)["opened"]
    finally:
        server.stop()
