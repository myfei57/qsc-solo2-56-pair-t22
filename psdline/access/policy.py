"""路由授权策略：按角色授权、按站台分区、标注危险动作。

每条路由一条 :class:`RoutePolicy`：

action      动作标识（审计与自检用）；
min_role    最低角色；
scoped      是否按站台分区做写范围检查（``True`` 时从参数/请求体解析 station）；
scope_from  分区标识从哪里取：``body`` 的哪个字段，或路径参数名；
dangerous   是否危险动作——危险动作必须带一次性票据二次确认；
read        是否只读（只读对全部已认证角色放开跨分区查看）。

取舍说明：跨分区**只读**放开（viewer/operator 都能看全线态势，只读开不了门）；
跨分区**写**严格拒绝。审计明细只放给 dispatcher 及以上——它包含故障、越权尝试
等敏感信息，普通值班员不需要。
"""

from __future__ import annotations

from dataclasses import dataclass

from .identity import Principal, role_rank

# 角色名常量，便于策略表阅读。
VIEWER = "viewer"
OPERATOR = "operator"
DISPATCHER = "dispatcher"
SUPERVISOR = "supervisor"


@dataclass(frozen=True)
class RoutePolicy:
    """一条路由的访问策略。"""

    action: str
    min_role: str = VIEWER
    scoped: bool = False
    scope_from: str = "station_id"
    scope_kind: str = "station"
    dangerous: bool = False
    read: bool = False

    def role_ok(self, principal: Principal) -> bool:
        return role_rank(principal.role) >= role_rank(self.min_role)


def can_read_everywhere(principal: Principal) -> bool:
    """所有已认证角色都可以跨分区只读；内部主体当然可以。"""

    return principal.is_system or role_rank(principal.role) >= role_rank(VIEWER)


@dataclass(frozen=True)
class _PolicyEntry:
    method: str
    pattern: str
    policy: RoutePolicy


def _e(method: str, pattern: str, **kwargs: object) -> _PolicyEntry:
    return _PolicyEntry(method, pattern, RoutePolicy(**kwargs))  # type: ignore[arg-type]


# 顺序与 Api._register 保持一致；未列出的路由默认拒绝（fail-closed）。
_POLICIES: tuple[_PolicyEntry, ...] = (
    # ---- 只读：全员可跨分区查看 ----
    _e("GET", "/api/status", action="read_status", read=True),
    _e("GET", "/api/snapshot", action="read_snapshot", read=True),
    _e("GET", "/api/namespace", action="read_namespace", read=True),
    _e("GET", "/api/namespaces", action="read_namespaces", read=True),
    _e("GET", "/api/stations", action="read_stations", read=True),
    _e("GET", "/api/stations/{stationID}", action="read_station", read=True),
    _e("GET", "/api/trains", action="read_trains", read=True),
    _e("GET", "/api/trains/{trainID}", action="read_train", read=True),
    _e("GET", "/api/doors", action="read_doors", read=True),
    _e("GET", "/api/doors/{psdID}", action="read_door", read=True),
    _e("GET", "/api/interlock", action="read_interlock", read=True),
    _e("GET", "/api/gaps", action="read_gaps", read=True),
    _e("GET", "/api/quota", action="read_quota", read=True),
    _e("GET", "/api/trend", action="read_trend", read=True),
    _e("GET", "/api/store", action="read_store", min_role=DISPATCHER, read=True),
    _e("GET", "/api/mapping/{stationID}", action="read_mapping", read=True),
    _e("GET", "/api/resolve", action="read_resolve", read=True),
    _e("GET", "/api/readiness", action="read_readiness", read=True),
    # 审计明细：调度及以上
    _e("GET", "/api/audit", action="read_audit", min_role=DISPATCHER, read=True),
    _e("GET", "/api/timeline", action="read_timeline", min_role=DISPATCHER, read=True),
    # ---- 行车运行：调度全线；值班员限本站台 ----
    _e(
        "POST",
        "/api/arrive",
        action="arrive",
        min_role=OPERATOR,
        scoped=True,
        scope_from="station_id",
    ),
    _e(
        "POST",
        "/api/depart",
        action="depart",
        min_role=OPERATOR,
        scoped=True,
        scope_from="station_id",
    ),
    _e(
        "POST",
        "/api/gap",
        action="gap_check",
        min_role=OPERATOR,
        scoped=True,
        scope_from="train_id",
        scope_kind="train",
    ),
    _e(
        "POST",
        "/api/enqueue",
        action="enqueue",
        min_role=OPERATOR,
        scoped=True,
        scope_from="station_id",
    ),
    _e(
        "POST",
        "/api/process",
        action="process_queue",
        min_role=OPERATOR,
        scoped=True,
        scope_from="train_id",
        scope_kind="train",
    ),
    _e(
        "POST",
        "/api/position",
        action="position",
        min_role=DISPATCHER,
        scoped=True,
        scope_from="train_id",
        scope_kind="train",
    ),
    _e(
        "POST",
        "/api/dwell",
        action="dwell",
        min_role=OPERATOR,
        scoped=True,
        scope_from="station_id",
    ),
    _e(
        "POST",
        "/api/route",
        action="route",
        min_role=DISPATCHER,
        scoped=True,
        scope_from="origin",
    ),
    _e("POST", "/api/cycle", action="cycle", min_role=DISPATCHER),
    # ---- 危险动作：值班员/调度可发起，但必须二次确认 + 一次性票据 ----
    _e(
        "POST",
        "/api/batch-open",
        action="batch_open",
        min_role=OPERATOR,
        scoped=True,
        scope_from="station_id",
        dangerous=True,
    ),
    _e(
        "POST",
        "/api/sweep",
        action="sweep",
        min_role=OPERATOR,
        scoped=True,
        scope_from="station_id",
        dangerous=True,
    ),
    _e(
        "POST",
        "/api/fault",
        action="set_fault",
        min_role=SUPERVISOR,
        scoped=True,
        scope_from="psd_id",
        scope_kind="gate",
        dangerous=True,
    ),
    _e(
        "POST",
        "/api/clear-fault",
        action="clear_fault",
        min_role=SUPERVISOR,
        scoped=True,
        scope_from="psd_id",
        scope_kind="gate",
        dangerous=True,
    ),
    _e(
        "POST",
        "/api/arm",
        action="arm",
        min_role=SUPERVISOR,
        scoped=True,
        scope_from="train_id",
        scope_kind="train",
        dangerous=True,
    ),
    _e(
        "POST",
        "/api/renumber",
        action="renumber",
        min_role=SUPERVISOR,
        scoped=True,
        scope_from="station_id",
        dangerous=True,
    ),
    _e(
        "POST",
        "/api/sequence",
        action="sequence",
        min_role=DISPATCHER,
        dangerous=True,
    ),
    _e(
        "POST",
        "/api/reset-state",
        action="reset_state",
        min_role=SUPERVISOR,
        dangerous=True,
    ),
    # ---- 鉴权自身 ----
    _e("POST", "/api/auth/login", action="auth_login", min_role=VIEWER),
    _e("POST", "/api/auth/logout", action="auth_logout", min_role=VIEWER),
    _e("GET", "/api/auth/whoami", action="auth_whoami", read=True),
    _e("POST", "/api/auth/prepare", action="auth_prepare", min_role=OPERATOR),
)


class PolicyTable:
    """按 (方法, 路径模式) 查策略。"""

    def __init__(self, entries: tuple[_PolicyEntry, ...] = _POLICIES) -> None:
        self._entries = entries

    def lookup(self, method: str, path: str) -> tuple[str, RoutePolicy] | None:
        """按实际路径匹配，返回 (命中的模式, 策略)；匹配规则与路由表一致。"""

        method = method.upper()
        segments = [part for part in path.strip("/").split("/") if part]
        for entry in self._entries:
            if entry.method != method:
                continue
            pattern_segments = [part for part in entry.pattern.strip("/").split("/") if part]
            if len(pattern_segments) != len(segments):
                continue
            if all(expected == actual or (expected.startswith("{") and expected.endswith("}"))
                   for expected, actual in zip(pattern_segments, segments)):
                return entry.pattern, entry.policy
        return None


POLICY = PolicyTable()
