"""控制台接口处理器。

每个接口都是对平台公开方法的一次调用；动作类接口把请求体里的参数透传给平台，
缺少必填字段或取值非法时返回 ``400``，联锁异常统一转成 ``409`` 并在响应里带上
组件名与原因。页面不走这里，见 :mod:`psdline.console.pages`。

远程请求（HTTP）在进入业务处理器之前必须先过
:class:`~psdline.access.guard.Guard`：认证 → 角色 → 分区 → 去重 → 一次性凭据。
进程内直接调用（命令行、演示、测试夹具）不带 :class:`RequestContext`，按内部
主体处理，行为与旧版一致，保证现有调用方兼容。
"""

from __future__ import annotations

from dataclasses import dataclass

from ..access import (
    Guard,
    KeyRegistry,
    NonceLedger,
    SessionStore,
    TicketStore,
)
from ..access.errors import AccessError
from ..access.guard import ReplayAccepted
from ..access.identity import Principal, system_principal
from ..app import Platform
from ..audit import build_timeline
from ..errors import RailError
from .router import Router

LOGIN_PATH = "/api/auth/login"
LOGOUT_PATH = "/api/auth/logout"
WHOAMI_PATH = "/api/auth/whoami"
PREPARE_PATH = "/api/auth/prepare"

# 请求信封字段：不参与动作，也不进入一次性票据的请求体指纹。
_ENVELOPE_KEYS = ("ticket_id", "request_id")

SESSION_COOKIE = "psd_session"


@dataclass(frozen=True)
class RequestContext:
    """一次远程请求携带的凭据与信封信息。"""

    api_key: str = ""
    session_token: str = ""
    ticket_id: str = ""
    request_id: str = ""
    remote: str = ""


def _require(body: dict, key: str) -> str:
    """取出必填的字符串字段。"""

    value = body.get(key)
    if value is None or str(value) == "":
        raise RailError(f"缺少必填字段 {key!r}", component="console")
    return str(value)


def _as_int(body: dict, key: str, default: int) -> int:
    """取出整数字段。"""

    try:
        return int(body.get(key, default))
    except (TypeError, ValueError) as error:
        raise RailError(f"参数 {key!r} 必须是整数", component="console") from error


def _as_float(body: dict, key: str, default: float) -> float:
    """取出浮点字段。"""

    try:
        return float(body.get(key, default))
    except (TypeError, ValueError) as error:
        raise RailError(f"参数 {key!r} 必须是数值", component="console") from error


class Api:
    """把 HTTP 请求翻译成平台调用。"""

    def __init__(self, platform: Platform) -> None:
        self._platform = platform
        self._router = Router()
        auth = platform.config.auth
        self.auth_enabled = auth.enabled
        self._registry = KeyRegistry(auth)
        self._sessions = SessionStore(
            platform.clock,
            idle_s=auth.session_idle_s,
            absolute_s=auth.session_absolute_s,
        )
        self._tickets = TicketStore(platform.clock, ttl_s=auth.ticket_ttl_s)
        self._nonces = NonceLedger(ttl_s=auth.request_ttl_s)
        self._guard = Guard(
            platform.clock,
            self._registry,
            self._sessions,
            self._tickets,
            self._nonces,
            audit=self._audit_security,
            resolve_scope=self._resolve_scope,
            enabled=auth.enabled,
        )
        self._register()

    @property
    def platform(self) -> Platform:
        return self._platform

    @property
    def guard(self) -> Guard:
        return self._guard

    @property
    def sessions(self) -> SessionStore:
        return self._sessions

    def _audit_security(self, kind: str, train_id: str, station_id: str, **detail: object) -> None:
        """安全事件统一落不可变审计流水。"""

        self._platform.audit.record(kind, train_id, station_id, **detail)

    def _resolve_scope(self, kind: str, ident: str) -> str:
        """把列车/门标识解析成所属站台，用于分区判定。"""

        if kind == "train":
            train = self._platform.trains.get(ident)
            return str(train.station) if train is not None and train.station else ""
        if kind == "gate":
            gate = self._platform.gates.get(ident)
            return gate.station if gate is not None else ""
        return ""

    def _register(self) -> None:
        add = self._router.add
        add("GET", "/api/status", lambda params, body: self._platform.status())
        add("GET", "/api/snapshot", lambda params, body: self._platform.snapshot())
        add("GET", "/api/namespace", lambda params, body: self._platform.namespace.as_dict())
        add("GET", "/api/namespaces", lambda params, body: self._platform.namespaces.describe())
        add("GET", "/api/stations", lambda params, body: {"stations": self._platform.status()["stations"]})
        add("GET", "/api/stations/{stationID}", self._station)
        add("GET", "/api/trains", lambda params, body: {"trains": self._platform.status()["trains"]})
        add("GET", "/api/trains/{trainID}", self._train)
        add("GET", "/api/doors", lambda params, body: {"doors": self._platform.status()["doors"]})
        add("GET", "/api/doors/{psdID}", self._gate)
        add("GET", "/api/interlock", lambda params, body: self._platform.status()["interlock"])
        add("GET", "/api/gaps", lambda params, body: self._platform.status()["gaps"])
        add("GET", "/api/quota", lambda params, body: self._platform.status()["quota"])
        add("GET", "/api/audit", self._audit)
        add("GET", "/api/timeline", self._timeline)
        add("GET", "/api/trend", self._trend)
        add("GET", "/api/store", self._store)
        add("GET", "/api/mapping/{stationID}", self._mapping)
        add("GET", "/api/resolve", self._resolve)
        add("GET", "/api/readiness", self._readiness)
        add("POST", "/api/arrive", self._arrive)
        add("POST", "/api/depart", self._depart)
        add("POST", "/api/gap", self._gap)
        add("POST", "/api/enqueue", self._enqueue)
        add("POST", "/api/process", self._process)
        add("POST", "/api/renumber", self._renumber)
        add("POST", "/api/batch-open", self._batch_open)
        add("POST", "/api/fault", self._fault)
        add("POST", "/api/clear-fault", self._clear_fault)
        add("POST", "/api/arm", self._arm)
        add("POST", "/api/position", self._position)
        add("POST", "/api/sequence", self._sequence)
        add("POST", "/api/cycle", self._cycle)
        add("POST", "/api/sweep", self._sweep)
        add("POST", "/api/dwell", self._dwell)
        add("POST", "/api/route", self._route)
        add("POST", "/api/reset-state", self._reset_state)
        add("POST", LOGIN_PATH, self._login)
        add("POST", LOGOUT_PATH, self._logout)
        add("GET", WHOAMI_PATH, self._whoami)
        add("POST", PREPARE_PATH, self._prepare)

    def routes(self) -> list[dict]:
        """返回接口清单，供自检与文档核对。"""

        return [route.as_dict() for route in self._router.routes()]

    # ---- 入口 ---------------------------------------------------------

    def handle(self, method: str, path: str, query: dict, body: dict) -> tuple[int, dict]:
        """进程内入口：按内部主体直接处理，保持旧调用方式兼容。"""

        status, payload, _headers = self.handle_request(method, path, query, body, None)
        return status, payload

    def handle_request(
        self,
        method: str,
        path: str,
        query: dict,
        body: dict,
        context: RequestContext | None,
    ) -> tuple[int, dict, dict[str, str]]:
        """远程入口：完整过一遍门控链，返回状态码、响应体与响应头。"""

        headers: dict[str, str] = {}

        # 登录在认证之前可达；登出认不认得到会话都给成功，避免接口枚举。
        if path == LOGIN_PATH and method == "POST":
            return self._do_login(body)
        if path == LOGOUT_PATH and method == "POST":
            token = (context.session_token if context else "") or str(body.get("session_token", ""))
            revoked = self._sessions.revoke(token) if token else False
            headers["Set-Cookie"] = f"{SESSION_COOKIE}=; Max-Age=0; Path=/; HttpOnly; SameSite=Strict"
            return 200, {"ok": True, "revoked": revoked}, headers

        if context is None:
            principal: Principal = system_principal()
        else:
            try:
                principal = self._guard.authenticate(context.api_key, context.session_token)
            except AccessError as error:
                return error.status, error.as_payload(), headers

        if path == WHOAMI_PATH and method == "GET":
            return 200, {"principal": principal.as_dict()}, headers
        if path == PREPARE_PATH and method == "POST":
            try:
                return self._do_prepare(principal, body)
            except RailError as error:
                self._platform.note_error(error)
                return 400, {"error": type(error).__name__, **error.as_record()}, headers

        matched = self._router.match(method, path)
        if matched is None:
            return 404, {"error": "not_found", "path": path}, headers
        handler, params, _pattern = matched
        merged = {**query, **params}

        # 信封字段只用于门控，动作体里剥掉，保证票据指纹两次一致。
        action_body = {key: value for key, value in body.items() if key not in _ENVELOPE_KEYS}
        if context is not None and not principal.is_system:
            try:
                self._guard.admit(
                    principal,
                    method,
                    path,
                    merged,
                    action_body,
                    ticket_id=context.ticket_id,
                    request_id=context.request_id,
                )
            except ReplayAccepted as accepted:
                # 同样的 request_id/路径/请求体重放：不重复执行，原样回首次结果。
                status, payload = accepted.cached
                return status, payload, headers
            except AccessError as error:
                return error.status, error.as_payload(), headers

        try:
            payload = handler(merged, action_body)
        except RailError as error:
            self._platform.note_error(error)
            status = 409 if error.component != "console" else 400
            return status, {"error": type(error).__name__, **error.as_record()}, headers
        except (TypeError, ValueError) as error:
            return 400, {"error": "bad_request", "message": str(error)}, headers

        if context is not None and not principal.is_system and context.request_id:
            self._guard.remember(principal, path, action_body, context.request_id, (200, payload))
        return 200, payload, headers

    # ---- 鉴权动作 -----------------------------------------------------

    def _do_login(self, body: dict) -> tuple[int, dict, dict[str, str]]:
        api_key = str(body.get("api_key", ""))
        principal = self._registry.authenticate(api_key) if self.auth_enabled else system_principal()
        if principal is None:
            self._audit_security(
                "security_auth_denied", "", "", reason="login_bad_key", path=LOGIN_PATH
            )
            return 401, {"error": "unauthorized", "reason": "凭据无效"}, {}
        session = self._sessions.issue(principal)
        self._audit_security(
            "security_login",
            "",
            "",
            principal=principal.id,
            role=principal.role,
            session=session.token[:10] + "…",
        )
        cookie = (
            f"{SESSION_COOKIE}={session.token}; Path=/; HttpOnly; SameSite=Strict"
        )
        return (
            200,
            {
                "ok": True,
                "token": session.token,
                "expires_at": session.absolute_expiry,
                "principal": principal.as_dict(),
            },
            {"Set-Cookie": cookie},
        )

    def _do_prepare(self, principal: Principal, body: dict) -> tuple[int, dict, dict[str, str]]:
        target_path = str(body.get("path", ""))
        target_body = body.get("body", {})
        if not target_path:
            raise RailError("缺少必填字段 'path'", component="console")
        if not isinstance(target_body, dict):
            raise RailError("'body' 必须是对象", component="console")
        target_body = {key: value for key, value in target_body.items() if key not in _ENVELOPE_KEYS}
        try:
            ticket = self._guard.prepare_ticket(principal, target_path, {}, target_body)
        except AccessError as error:
            return error.status, error.as_payload(), {}
        return 200, {"ok": True, **ticket}, {}

    # ---- 查询 ---------------------------------------------------------

    def _station(self, params: dict, body: dict) -> dict:
        return self._platform.station_view(str(params.get("stationID", "")))

    def _train(self, params: dict, body: dict) -> dict:
        train_id = str(params.get("trainID", ""))
        view = self._platform.train_view(train_id)
        if view["train"] is None:
            raise RailError(f"列车不存在: {train_id}", component="console")
        return view

    def _gate(self, params: dict, body: dict) -> dict:
        psd_id = str(params.get("psdID", ""))
        gate = self._platform.gates.get(psd_id)
        if gate is None:
            raise RailError(f"站台门不存在: {psd_id}", component="console")
        return {"gate": gate.as_dict(), "pressure": self._platform.doors.batch_limit()}

    def _audit(self, params: dict, body: dict) -> dict:
        entries = self._platform.audit.list()
        return {
            "entries": [entry.as_dict() for entry in entries[-int(params.get("limit", 50)) :]],
            "summary": self._platform.audit.summary(),
        }

    def _timeline(self, params: dict, body: dict) -> dict:
        train_id = str(params.get("train_id", ""))
        return {"timeline": build_timeline(self._platform.audit.list(), train_id)}

    def _trend(self, params: dict, body: dict) -> dict:
        signal = str(params.get("signal", "locked_count"))
        samples = self._platform.trend.series(signal, int(params.get("limit", 60)))
        filled = self._platform.trend.fill_gaps(signal, samples)
        return {
            "signal": signal,
            "period_s": self._platform.trend.period_s,
            "signals": self._platform.trend.signals(),
            "samples": [sample.as_dict() for sample in samples],
            "filled": [sample.as_dict() for sample in filled],
        }

    def _store(self, params: dict, body: dict) -> dict:
        return {
            "summary": self._platform.metrics.summary(),
            "documents": self._platform.store.list_ids(),
        }

    def _mapping(self, params: dict, body: dict) -> dict:
        station_id = str(params.get("stationID", ""))
        mapping = self._platform.mappings.current(station_id)
        if mapping is None:
            raise RailError(f"站台 {station_id} 没有门区映射", component="console")
        return mapping.as_dict()

    def _resolve(self, params: dict, body: dict) -> dict:
        return self._platform.resolve_group(
            str(params.get("station_id", "")), str(params.get("group_key", ""))
        )

    def _readiness(self, params: dict, body: dict) -> dict:
        checks = {
            "stations": bool(self._platform.stations.list()),
            "gates": bool(self._platform.gates.list()),
            "quota_arrival": self._platform.quotas.status("arrival")["configured"],
            "quota_depart": self._platform.quotas.status("depart")["configured"],
            "audit_log": self._platform.audit.journal.count() >= 0,
        }
        return {"ready": all(checks.values()), "checks": checks}

    # ---- 动作 ---------------------------------------------------------

    def _arrive(self, params: dict, body: dict) -> dict:
        return self._platform.arrive(
            _require(body, "train_id"),
            _require(body, "station_id"),
            _as_int(body, "position_m", 0),
        )

    def _depart(self, params: dict, body: dict) -> dict:
        return self._platform.depart(_require(body, "train_id"), _require(body, "station_id"))

    def _gap(self, params: dict, body: dict) -> dict:
        return self._platform.check_gap(_require(body, "train_id"), bool(body.get("clear", True)))

    def _enqueue(self, params: dict, body: dict) -> dict:
        return self._platform.enqueue(
            _require(body, "train_id"),
            _require(body, "id"),
            str(body.get("kind", "open")),
            str(body.get("station_id", "")),
        )

    def _process(self, params: dict, body: dict) -> dict:
        return self._platform.process_queue(_require(body, "train_id"))

    def _renumber(self, params: dict, body: dict) -> dict:
        groups = body.get("groups")
        if not isinstance(groups, dict) or not groups:
            raise RailError("映射必须是非空对象", component="console")
        return self._platform.renumber(
            _require(body, "station_id"), {str(k): str(v) for k, v in groups.items()}
        )

    def _batch_open(self, params: dict, body: dict) -> dict:
        return self._platform.batch_open(_require(body, "station_id"))

    def _fault(self, params: dict, body: dict) -> dict:
        return self._platform.set_fault(_require(body, "psd_id"))

    def _clear_fault(self, params: dict, body: dict) -> dict:
        return self._platform.clear_fault(_require(body, "psd_id"))

    def _arm(self, params: dict, body: dict) -> dict:
        return self._platform.arm(_require(body, "train_id"), bool(body.get("armed", True)))

    def _position(self, params: dict, body: dict) -> dict:
        return self._platform.refresh_position(
            _require(body, "train_id"), _as_int(body, "position_m", 0)
        )

    def _sequence(self, params: dict, body: dict) -> dict:
        return self._platform.sequence_verdict(
            _as_int(body, "previous", 0), _as_int(body, "step", 1)
        )

    def _cycle(self, params: dict, body: dict) -> dict:
        return self._platform.cycle(_as_float(body, "dt", 1.0))

    def _sweep(self, params: dict, body: dict) -> dict:
        return self._platform.sweep(_require(body, "station_id"))

    def _dwell(self, params: dict, body: dict) -> dict:
        return self._platform.register_dwell(
            _require(body, "train_id"),
            _as_float(body, "seconds", 0.0),
            str(body.get("station_id", "")),
        )

    def _route(self, params: dict, body: dict) -> dict:
        return self._platform.assign_route(
            _require(body, "train_id"),
            _require(body, "origin"),
            _require(body, "destination"),
            _as_int(body, "distance_m", 0),
        )

    def _reset_state(self, params: dict, body: dict) -> dict:
        return {"removed": self._platform.reset_state()}

    # ---- 鉴权占位处理器（实际在入口处分流，注册仅为路由自洽） ---------

    def _login(self, params: dict, body: dict) -> dict:
        return {"ok": True}

    def _logout(self, params: dict, body: dict) -> dict:
        return {"ok": True}

    def _whoami(self, params: dict, body: dict) -> dict:
        return {"ok": True}

    def _prepare(self, params: dict, body: dict) -> dict:
        return {"ok": True}
