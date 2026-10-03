"""控制台接口处理器。

每个接口都是对平台公开方法的一次调用；动作类接口把请求体里的参数透传给平台，
缺少必填字段或取值非法时返回 ``400``，联锁异常统一转成 ``409`` 并在响应里带上
组件名与原因。页面不走这里，见 :mod:`psdline.console.pages`。

所有请求先过门控（见 :mod:`psdline.security`）：认证（会话或静态密钥）、授权
（角色能力 + 站台分区）、危险动作的一次性确认凭据，任何一步拒绝都会留下审计。
路由、参数与响应结构保持原样，客户端只需补上凭据。
"""

from __future__ import annotations

from ..app import Platform
from ..audit import build_timeline
from ..errors import RailError
from ..security import AccessContext, Credentials, Gate, RoutePolicy
from .router import Router


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
    """把 HTTP 请求翻译成平台调用，并在调用前过门控。"""

    def __init__(self, platform: Platform) -> None:
        self._platform = platform
        self._gate = Gate(
            platform.config.security,
            platform.store,
            platform.clock,
            platform.audit,
            segment_limit=platform.config.audit.journal_segment,
        )
        self._router = Router()
        self._register()
        self._endpoints = {
            ("POST", "/api/session"): self._endpoint_login,
            ("POST", "/api/session/close"): self._endpoint_logout,
            ("POST", "/api/confirm"): self._endpoint_confirm,
            ("GET", "/api/security"): self._endpoint_security,
        }

    @property
    def platform(self) -> Platform:
        return self._platform

    @property
    def gate(self) -> Gate:
        return self._gate

    def _register(self) -> None:
        add = self._router.add
        add("GET", "/api/status", lambda params, body: self._platform.status(), RoutePolicy("read"))
        add("GET", "/api/snapshot", lambda params, body: self._platform.snapshot(), RoutePolicy("read"))
        add("GET", "/api/namespace", lambda params, body: self._platform.namespace.as_dict(), RoutePolicy("read"))
        add("GET", "/api/namespaces", lambda params, body: self._platform.namespaces.describe(), RoutePolicy("read"))
        add("GET", "/api/stations", lambda params, body: {"stations": self._platform.status()["stations"]}, RoutePolicy("read"))
        add("GET", "/api/stations/{stationID}", self._station, RoutePolicy("read", "station"))
        add("GET", "/api/trains", lambda params, body: {"trains": self._platform.status()["trains"]}, RoutePolicy("read"))
        add("GET", "/api/trains/{trainID}", self._train, RoutePolicy("read", "train"))
        add("GET", "/api/doors", lambda params, body: {"doors": self._platform.status()["doors"]}, RoutePolicy("read"))
        add("GET", "/api/doors/{psdID}", self._gate_view, RoutePolicy("read", "gate"))
        add("GET", "/api/interlock", lambda params, body: self._platform.status()["interlock"], RoutePolicy("read"))
        add("GET", "/api/gaps", lambda params, body: self._platform.status()["gaps"], RoutePolicy("read"))
        add("GET", "/api/quota", lambda params, body: self._platform.status()["quota"], RoutePolicy("read"))
        add("GET", "/api/audit", self._audit, RoutePolicy("read"))
        add("GET", "/api/timeline", self._timeline, RoutePolicy("read"))
        add("GET", "/api/trend", self._trend, RoutePolicy("read"))
        add("GET", "/api/store", self._store, RoutePolicy("read"))
        add("GET", "/api/mapping/{stationID}", self._mapping, RoutePolicy("read", "station"))
        add("GET", "/api/resolve", self._resolve, RoutePolicy("read", "station"))
        add("GET", "/api/readiness", self._readiness, RoutePolicy("read"))
        add("GET", "/api/security", self._reserved, RoutePolicy("read"))
        add("POST", "/api/arrive", self._arrive, RoutePolicy("write", "station"))
        add("POST", "/api/depart", self._depart, RoutePolicy("write", "station"))
        add("POST", "/api/gap", self._gap, RoutePolicy("write", "train"))
        add("POST", "/api/enqueue", self._enqueue, RoutePolicy("write", "station_or_train"))
        add("POST", "/api/process", self._process, RoutePolicy("write", "train"))
        add("POST", "/api/renumber", self._renumber, RoutePolicy("write", "station", confirm=True))
        add("POST", "/api/batch-open", self._batch_open, RoutePolicy("write", "station", confirm=True))
        add("POST", "/api/fault", self._fault, RoutePolicy("write", "gate", confirm=True))
        add("POST", "/api/clear-fault", self._clear_fault, RoutePolicy("write", "gate", confirm=True))
        add("POST", "/api/arm", self._arm, RoutePolicy("write", "train", confirm=True))
        add("POST", "/api/position", self._position, RoutePolicy("write", "train"))
        add("POST", "/api/sequence", self._sequence, RoutePolicy("write"))
        add("POST", "/api/cycle", self._cycle, RoutePolicy("write"))
        add("POST", "/api/sweep", self._sweep, RoutePolicy("write", "station", confirm=True))
        add("POST", "/api/dwell", self._dwell, RoutePolicy("write", "station_or_train"))
        add("POST", "/api/route", self._route, RoutePolicy("write", "train"))
        add("POST", "/api/reset-state", self._reset_state, RoutePolicy("admin", confirm=True))
        add("POST", "/api/session", self._reserved, RoutePolicy("open"))
        add("POST", "/api/session/close", self._reserved, RoutePolicy("read"))
        add("POST", "/api/confirm", self._reserved, RoutePolicy("write"))

    def routes(self) -> list[dict]:
        """返回接口清单，供自检与文档核对。"""

        return [route.as_dict() for route in self._router.routes()]

    def handle(
        self, method: str, path: str, query: dict, body: dict, credentials: object = None
    ) -> tuple[int, dict]:
        """处理一次请求，返回状态码与响应体。

        先过门控（认证 → 授权 → 二次确认），再放行到处理器；安全端点（会话、
        确认凭据、门控自检）由门控协议处理器直接接管。
        """

        matched = self._router.match_route(method, path)
        if matched is None:
            return 404, {"error": "not_found", "path": path}
        route, params = matched
        policy = route.policy if isinstance(route.policy, RoutePolicy) else RoutePolicy()
        merged = {**query, **params}
        creds = Credentials.normalize(credentials, body)
        context = self._context(route.method, route.pattern, policy, merged, body)
        decision = self._gate.authorize(policy, context, creds)
        if not decision.allowed:
            return decision.status, decision.payload
        try:
            endpoint = self._endpoints.get((route.method, route.pattern))
            if endpoint is not None:
                return endpoint(decision.principal, body, creds)
            payload = route.handler(merged, body)
            status = 200
        except RailError as error:
            self._platform.note_error(error)
            status = 409 if error.component != "console" else 400
            payload = {"error": type(error).__name__, **error.as_record()}
        except (TypeError, ValueError) as error:
            status = 400
            payload = {"error": "bad_request", "message": str(error)}
        if route.method == "POST" and policy.capability in ("write", "admin"):
            self._gate.note_action(decision.principal, context, status, payload)
        return status, payload

    # ---- 门控 ---------------------------------------------------------

    def _reserved(self, params: dict, body: dict) -> dict:
        """安全端点的占位处理器；正常请求在端点分发处就被接管，不会走到这里。"""

        raise RailError("安全端点应由门控协议处理器接管", component="console")

    def _context(
        self, method: str, pattern: str, policy: RoutePolicy, merged: dict, body: dict
    ) -> AccessContext:
        """按路由策略从请求里解析站台分区与确认目标。"""

        scope = policy.scope
        target = ""
        station = ""
        if scope == "station":
            target = str(
                merged.get("stationID") or merged.get("station_id") or body.get("station_id") or ""
            )
            station = target
        elif scope == "gate":
            target = str(merged.get("psdID") or merged.get("psd_id") or body.get("psd_id") or "")
            station = self._station_for("gate", target)
        elif scope == "train":
            target = str(merged.get("trainID") or merged.get("train_id") or body.get("train_id") or "")
            station = self._station_for("train", target)
        elif scope == "station_or_train":
            station = str(merged.get("station_id") or body.get("station_id") or "")
            if station:
                target = station
            else:
                target = str(merged.get("train_id") or body.get("train_id") or "")
                station = self._station_for("train", target)
        return AccessContext(
            method=method,
            action=pattern,
            station=station,
            target=target,
            scoped=scope != "none",
        )

    def _station_for(self, scope: str, target: str) -> str:
        """把门 id／列车 id 解析成所属站台；解析不到返回空串。"""

        if scope == "gate":
            gate = self._platform.gates.get(target)
            return gate.station if gate is not None else ""
        if scope == "train":
            train = self._platform.trains.get(target)
            return train.station if train is not None else ""
        return ""

    def _confirm_routes(self) -> list[str]:
        """返回需要一次性确认凭据的动作清单。"""

        return [
            route.pattern
            for route in self._router.routes()
            if isinstance(route.policy, RoutePolicy) and route.policy.confirm
        ]

    # ---- 门控协议端点 -------------------------------------------------

    def _endpoint_login(self, principal: object, body: dict, creds: Credentials) -> tuple[int, dict]:
        return self._gate.login(str(body.get("key", "")))

    def _endpoint_logout(self, principal: object, body: dict, creds: Credentials) -> tuple[int, dict]:
        return 200, self._gate.logout(creds.token)

    def _endpoint_security(self, principal: object, body: dict, creds: Credentials) -> tuple[int, dict]:
        return 200, self._gate.describe(principal, self._confirm_routes())

    def _endpoint_confirm(self, principal: object, body: dict, creds: Credentials) -> tuple[int, dict]:
        action = str(body.get("action", ""))
        target = str(body.get("target", ""))
        route = self._find_confirm_route(action)
        if route is None:
            raise RailError(f"动作 {action!r} 不存在或不需要二次确认", component="console")
        policy = route.policy
        station = target if policy.scope == "station" else self._station_for(policy.scope, target)
        context = AccessContext(
            method="POST",
            action=action,
            station=station,
            target=target,
            scoped=policy.scope != "none",
        )
        return self._gate.request_ticket(principal, policy, context)

    def _find_confirm_route(self, action: str):
        """按路径找到需要二次确认的动作路由；找不到或不需确认返回 ``None``。"""

        for route in self._router.routes():
            if (
                route.method == "POST"
                and route.pattern == action
                and isinstance(route.policy, RoutePolicy)
                and route.policy.confirm
            ):
                return route
        return None

    # ---- 查询 ---------------------------------------------------------

    def _station(self, params: dict, body: dict) -> dict:
        return self._platform.station_view(str(params.get("stationID", "")))

    def _train(self, params: dict, body: dict) -> dict:
        train_id = str(params.get("trainID", ""))
        view = self._platform.train_view(train_id)
        if view["train"] is None:
            raise RailError(f"列车不存在: {train_id}", component="console")
        return view

    def _gate_view(self, params: dict, body: dict) -> dict:
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
