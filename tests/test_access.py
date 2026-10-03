"""访问控制链：认证、角色、分区、一次性凭据、去重与门控集成。"""

from __future__ import annotations

import json
import threading
import urllib.request

import pytest

from psdline.access import (
    KeyRegistry,
    NonceLedger,
    POLICY,
    SessionStore,
    TicketStore,
)
from psdline.access.tickets import body_fingerprint
from psdline.config import default_config
from psdline.console.api import Api, RequestContext
from psdline.console.server import ConsoleServer, probe_endpoints

VIEWER = "demo-view-st1"
OP1 = "demo-op-st1"
OP2 = "demo-op-st2"
DISP = "demo-dispatcher"
SUP = "demo-supervisor"


@pytest.fixture()
def api(platform) -> Api:
    platform.start()
    return Api(platform)


def _ctx(key: str = "", cookie: str = "", body: dict | None = None) -> RequestContext:
    body = body or {}
    return RequestContext(
        api_key=key,
        session_token=cookie,
        ticket_id=str(body.get("ticket_id", "")),
        request_id=str(body.get("request_id", "")),
    )


def _call(api: Api, method: str, path: str, body: dict | None = None, key: str = ""):
    body = body or {}
    return api.handle_request(method, path, {}, body, _ctx(key, body=body))[:2]


# ---- Key 注册表 -------------------------------------------------------

def test_key_registry_constant_time_lookup():
    registry = KeyRegistry(default_config().auth)
    principal = registry.authenticate(OP1)
    assert principal is not None and principal.role == "operator"
    assert principal.stations == ("ST1",)
    assert registry.authenticate("nope") is None
    assert registry.authenticate("") is None
    assert sorted(p.id for p in [principal])  # sanity


def test_key_registry_env_override(monkeypatch):
    monkeypatch.setenv("PSDLINE_KEY_OP_ST1", "rotated-secret")
    registry = KeyRegistry(default_config().auth)
    assert registry.authenticate(OP1) is None
    assert registry.authenticate("rotated-secret").id == "op-st1"


# ---- 会话 -------------------------------------------------------------

def test_session_idle_and_absolute_expiry(clock):
    sessions = SessionStore(clock, idle_s=100, absolute_s=300)
    principal = KeyRegistry(default_config().auth).authenticate(OP1)
    token = sessions.issue(principal).token
    assert sessions.resolve(token).id == "op-st1"
    clock.advance(90)
    assert sessions.resolve(token) is not None  # 活跃顺延
    clock.advance(100)
    assert sessions.resolve(token) is None  # 空闲超 100s
    other = sessions.issue(principal).token
    clock.advance(301)
    assert sessions.resolve(other) is None  # 绝对有效期硬截止


def test_session_revoke(clock):
    sessions = SessionStore(clock)
    principal = KeyRegistry(default_config().auth).authenticate(OP1)
    token = sessions.issue(principal).token
    assert sessions.revoke(token) is True
    assert sessions.resolve(token) is None
    assert sessions.revoke(token) is False


# ---- 一次性凭据 -------------------------------------------------------

def test_ticket_consume_once(clock):
    store = TicketStore(clock, ttl_s=60)
    registry = KeyRegistry(default_config().auth)
    principal = registry.authenticate(OP1)
    other = registry.authenticate(OP2)
    body = {"station_id": "ST1"}
    ticket = store.issue(principal, "/api/sweep", body)
    assert store.consume(principal, "/api/sweep", body, ticket.id).id == ticket.id
    with pytest.raises(Exception) as replay:
        store.consume(principal, "/api/sweep", body, ticket.id)
    assert replay.value.reason == "ticket_replayed"
    # 别人的票据
    theirs = store.issue(principal, "/api/sweep", body)
    with pytest.raises(Exception) as stolen:
        store.consume(other, "/api/sweep", body, theirs.id)
    assert stolen.value.reason == "ticket_principal_mismatch"
    # 原主人不受盗用影响
    assert store.consume(principal, "/api/sweep", body, theirs.id).id == theirs.id


def test_ticket_expiry_and_fingerprint(clock):
    store = TicketStore(clock, ttl_s=60)
    registry = KeyRegistry(default_config().auth)
    principal = registry.authenticate(OP1)
    ticket = store.issue(principal, "/api/sweep", {"station_id": "ST1"})
    clock.advance(61)
    with pytest.raises(Exception) as expired:
        store.consume(principal, "/api/sweep", {"station_id": "ST1"}, ticket.id)
    assert expired.value.reason in ("ticket_expired", "ticket_unknown")
    fresh = store.issue(principal, "/api/sweep", {"station_id": "ST1"})
    with pytest.raises(Exception) as mismatch:
        store.consume(principal, "/api/sweep", {"station_id": "ST2"}, fresh.id)
    assert mismatch.value.reason == "ticket_fingerprint_mismatch"
    # 指纹只看业务体，键顺序无关
    assert body_fingerprint({"a": 1, "b": 2}) == body_fingerprint({"b": 2, "a": 1})


def test_ticket_concurrent_only_one_wins(clock):
    store = TicketStore(clock, ttl_s=60)
    principal = KeyRegistry(default_config().auth).authenticate(OP1)
    body = {"station_id": "ST1"}
    ticket = store.issue(principal, "/api/batch-open", body)
    wins = []
    lock = threading.Lock()

    def consume() -> None:
        try:
            store.consume(principal, "/api/batch-open", body, ticket.id)
            with lock:
                wins.append(True)
        except Exception:  # noqa: BLE001 - 其余必须全部失败
            pass

    threads = [threading.Thread(target=consume) for _ in range(24)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()
    assert wins == [True]


# ---- 幂等账本 ---------------------------------------------------------

def test_nonce_ledger_replay_and_mutation(clock):
    from psdline.access.nonces import NonceError

    ledger = NonceLedger(ttl_s=300)
    fp = body_fingerprint({"station_id": "ST1"})
    ledger.check("op-st1", "r1", "/api/sweep", fp, clock.now())
    ledger.remember("op-st1", "r1", "/api/sweep", fp, clock.now(), (200, {"ok": True}))
    with pytest.raises(NonceError) as same:
        ledger.check("op-st1", "r1", "/api/sweep", fp, clock.now())
    assert same.value.reason == "replayed"
    assert same.value.cached == (200, {"ok": True})
    other_fp = body_fingerprint({"station_id": "ST2"})
    with pytest.raises(NonceError) as changed:
        ledger.check("op-st1", "r1", "/api/sweep", other_fp, clock.now())
    assert changed.value.reason == "replay_mutated"


# ---- 门控主链（Api 集成） --------------------------------------------

def test_missing_and_bad_credentials_rejected(api):
    status, payload = _call(api, "GET", "/api/status")
    assert status == 401 and payload["error"] == "unauthorized"
    status, payload = _call(api, "GET", "/api/status", key="garbage")
    assert status == 401


def test_role_denials_are_audited(api, platform):
    status, _ = _call(api, "POST", "/api/arrive",
                      {"train_id": "T1", "station_id": "ST1"}, key=VIEWER)
    assert status == 403
    status, _ = _call(api, "GET", "/api/audit", key=VIEWER)
    assert status == 403
    kinds = [e.kind for e in platform.audit.list() if e.kind.startswith("security")]
    assert "security_authz_denied" in kinds


def test_scope_partition_write_and_cross_read(api, platform):
    # 跨分区只读放开
    status, view = _call(api, "GET", "/api/stations/ST2", key=OP1)
    assert status == 200 and view["station"]["id"] == "ST2"
    # 跨分区写拒绝
    status, payload = _call(api, "POST", "/api/enqueue",
                            {"train_id": "T2", "id": "c", "station_id": "ST2"}, key=OP1)
    assert status == 403 and payload["error"] == "forbidden"
    denied = [e for e in platform.audit.list() if e.kind == "security_scope_denied"]
    assert denied and denied[0].detail["target"] == "ST2"
    # 本站写放行
    status, payload = _call(api, "POST", "/api/arrive",
                            {"train_id": "T1", "station_id": "ST1", "position_m": 0}, key=OP1)
    assert status == 200 and payload["ok"] is True
    # 列车标识解析到所属站台：ST1 值班员碰 ST2 的列车被拒
    platform.arrive("T2", "ST2", 0)
    status, _ = _call(api, "POST", "/api/process", {"train_id": "T2"}, key=OP1)
    assert status == 403
    status, _ = _call(api, "POST", "/api/gap", {"train_id": "T2"}, key=OP1)
    assert status == 403
    # 门标识同理
    status, _ = _call(api, "POST", "/api/fault", {"psd_id": "ST2-G01-01"}, key=OP1)
    assert status == 403


def test_dangerous_action_requires_ticket(api, platform):
    status, payload = _call(api, "POST", "/api/batch-open", {"station_id": "ST1"}, key=OP1)
    assert status == 409 and payload["error"] == "confirmation_required"
    status, ticket = _call(
        api, "POST", "/api/auth/prepare",
        {"path": "/api/batch-open", "body": {"station_id": "ST1"}}, key=OP1,
    )
    assert status == 200 and ticket["expires_at"] > ticket["issued_at"]
    status, done = _call(
        api, "POST", "/api/batch-open",
        {"station_id": "ST1", "ticket_id": ticket["ticket_id"]}, key=OP1,
    )
    assert status == 200 and done["ok"] is True
    # 复用拒绝并审计
    status, replay = _call(
        api, "POST", "/api/batch-open",
        {"station_id": "ST1", "ticket_id": ticket["ticket_id"]}, key=OP1,
    )
    assert status == 409 and replay["error"] == "ticket_rejected"
    kinds = {e.kind for e in platform.audit.list()}
    assert "security_ticket_issued" in kinds
    assert "security_ticket_replay_denied" in kinds


def test_prepare_checks_role_scope_and_fingerprint(api, clock):
    # 角色不足连票据都拿不到
    status, _ = _call(
        api, "POST", "/api/auth/prepare",
        {"path": "/api/arm", "body": {"train_id": "T1"}}, key=OP1,
    )
    assert status == 403
    # 越分区在票据校验之前就拒绝（票据不被消费）
    status, _ = _call(
        api, "POST", "/api/auth/prepare",
        {"path": "/api/sweep", "body": {"station_id": "ST2"}}, key=OP1,
    )
    assert status == 403
    ticket_ok = _call(
        api, "POST", "/api/auth/prepare",
        {"path": "/api/sweep", "body": {"station_id": "ST1"}}, key=OP1,
    )[1]
    status, rejected = _call(
        api, "POST", "/api/sweep",
        {"station_id": "ST2", "ticket_id": ticket_ok["ticket_id"]}, key=OP1,
    )
    assert status == 403 and rejected["error"] == "forbidden"
    # 原票对 ST1 仍有效（越权尝试不消耗票据）
    status, done = _call(
        api, "POST", "/api/sweep",
        {"station_id": "ST1", "ticket_id": ticket_ok["ticket_id"]}, key=OP1,
    )
    assert status == 200
    # 全线主管：分区不拦，改门标识直接撞指纹校验
    status, sup_ticket = _call(
        api, "POST", "/api/auth/prepare",
        {"path": "/api/fault", "body": {"psd_id": "ST1-G01-01"}}, key=SUP,
    )
    status, rejected = _call(
        api, "POST", "/api/fault",
        {"psd_id": "ST1-G01-02", "ticket_id": sup_ticket["ticket_id"]}, key=SUP,
    )
    assert status == 409 and rejected["error"] == "ticket_rejected"


def test_request_id_idempotency(api):
    body = {"train_id": "T9", "station_id": "ST1", "position_m": 0, "request_id": "x1"}
    status, first = _call(api, "POST", "/api/arrive", body, key=OP1)
    assert status == 200
    status, second = _call(api, "POST", "/api/arrive", dict(body), key=OP1)
    assert status == 200 and second["op_id"] == first["op_id"]
    # 改单重放拒绝
    mutated = dict(body, train_id="T8")
    status, payload = _call(api, "POST", "/api/arrive", mutated, key=OP1)
    assert status == 409 and payload["error"] == "replay_rejected"


def test_login_logout_session_flow(api):
    status, login = _call(api, "POST", "/api/auth/login", {"api_key": OP1})
    assert status == 200 and login["principal"]["role"] == "operator"
    token = login["token"]
    status, who = api.handle_request(
        "GET", "/api/auth/whoami", {}, {}, _ctx(cookie=token)
    )[:2]
    assert status == 200 and who["principal"]["id"] == "op-st1"
    status, out = api.handle_request(
        "POST", "/api/auth/logout", {}, {}, _ctx(cookie=token)
    )[:2]
    assert status == 200 and out["revoked"] is True
    status, _ = api.handle_request(
        "GET", "/api/status", {}, {}, _ctx(cookie=token)
    )[:2]
    assert status == 401


def test_policy_covers_every_route(api):
    """策略表必须覆盖全部已注册路由，防止新接口悄悄漏网（fail-closed 自检）。"""

    for route in api.routes():
        # 路径参数用一个样例值代替
        sample = (
            route["path"]
            .replace("{stationID}", "ST1")
            .replace("{trainID}", "T1")
            .replace("{psdID}", "ST1-G01-01")
        )
        found = POLICY.lookup(route["method"], sample)
        assert found is not None, f"{route['method']} {route['path']} 缺少访问策略"


def test_dangerous_routes_are_all_classified(api):
    for path in (
        "/api/batch-open",
        "/api/sweep",
        "/api/fault",
        "/api/clear-fault",
        "/api/arm",
        "/api/renumber",
        "/api/sequence",
        "/api/reset-state",
    ):
        policy = POLICY.lookup("POST", path)[1]
        assert policy.dangerous is True


def test_in_process_handle_still_works_as_system(platform):
    """不带上下文的进程内调用保持旧行为：现有 CLI/演示/夹具不受影响。"""

    platform.start()
    api = Api(platform)
    status, payload = api.handle("GET", "/api/status", {}, {})
    assert status == 200 and payload["platform"] == platform.config.name
    status, arrival = api.handle(
        "POST", "/api/arrive", {},
        {"train_id": "T01", "station_id": "ST1", "position_m": 0},
    )
    assert status == 200 and arrival["ok"] is True


# ---- 真实 HTTP：Cookie 登录 ------------------------------------------

def test_http_login_cookie_and_auth_header(platform):
    platform.start()
    server = ConsoleServer(platform, host="127.0.0.1", port=0)
    base = server.start()
    try:
        assert probe_endpoints(base, ["/api/status"])["/api/status"]["status"] == 401
        request = urllib.request.Request(
            base + "/api/auth/login",
            data=json.dumps({"api_key": OP1}).encode("utf-8"),
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        with urllib.request.urlopen(request, timeout=5) as response:
            cookie = response.headers["Set-Cookie"]
            assert "HttpOnly" in cookie and "SameSite=Strict" in cookie
            pair = cookie.split(";", 1)[0]
        ok = probe_endpoints(base, ["/api/status"], headers={"Cookie": pair})
        assert ok["/api/status"]["ok"] is True
        # 登出后 Cookie 立刻失效
        urllib.request.urlopen(
            urllib.request.Request(
                base + "/api/auth/logout",
                data=b"{}",
                headers={"Content-Type": "application/json", "Cookie": pair},
                method="POST",
            ),
            timeout=5,
        ).read()
        gone = probe_endpoints(base, ["/api/status"], headers={"Cookie": pair})
        assert gone["/api/status"]["status"] == 401
    finally:
        server.stop()


def test_unauthenticated_page_is_login(platform):
    server = ConsoleServer(platform, host="127.0.0.1", port=0)
    base = server.start()
    try:
        import urllib.error

        with pytest.raises(urllib.error.HTTPError) as error:
            urllib.request.urlopen(base + "/doors", timeout=5)
        assert error.value.code == 401
        assert "控制台登录" in error.value.read().decode("utf-8")
    finally:
        server.stop()


def test_alarms_page_hides_audit_from_low_roles(platform):
    """审计明细在页面上也要按角色隐藏，与 /api/audit 一致。"""

    from psdline.access.identity import Principal
    from psdline.console.pages import render_page

    platform.arrive("T01", "ST1", 0)
    viewer = Principal(id="view-st1", name="v", role="viewer", stations=("ST1",))
    sup = Principal(id="sup", name="s", role="supervisor")
    viewer_html = render_page("/alarms", platform, viewer)
    sup_html = render_page("/alarms", platform, sup)
    assert "审计明细仅对调度及以上角色开放" in viewer_html
    assert "最近审计" in sup_html
