"""请求门控：把认证、授权、分区、二次确认与去重串成一条链。

一次远程请求的完整顺序：

1. 认证：``Authorization: Bearer <key>``（每请求凭据）或
   ``Cookie: psd_session=<token>``（会话凭据），二选一；都没有/失效 → 401 并留
   ``security_auth_denied`` 审计。
2. 路由策略：路由必须在策略表里（未知路由在更外层就是 404，不放行）。
3. 角色：等级不足 → 403 并留 ``security_authz_denied``。
4. 分区（仅写操作）：值班员只能对绑定站台下手；列车/门标识会解析成所属站台。
   越分区 → 403 并留 ``security_scope_denied``。
5. 去重：带 ``request_id`` 时查重，改单重放 → 409 并留
   ``security_replay_denied``。
6. 危险动作：必须消费一次性票据，过期/复用/伪造/指纹不符 → 409 并留
   ``security_ticket_*`` 审计。

全程任何一步拒绝，这次尝试都会原样（主体、来源、动作、路径、原因、目标资产）
进不可变审计流水。内部主体（进程内直接调用）跳过整条链。
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Callable

from ..clock import Clock
from .errors import (
    AuthenticationError,
    AuthorizationError,
    ConfirmationError,
    ReplayRejected,
    TicketRejected,
)
from .identity import Principal, system_principal
from .nonces import NonceLedger
from .policy import POLICY, PolicyTable, RoutePolicy
from .registry import KeyRegistry
from .sessions import SessionStore
from .tickets import TicketError, TicketStore, body_fingerprint

# (标识类型, 标识值) → 所属站台；由 Platform 提供，避免 access 包反向依赖平台。
ScopeResolver = Callable[[str, str], str]


@dataclass(frozen=True)
class GuardResult:
    """门控放行结果。"""

    principal: Principal
    policy: RoutePolicy
    pattern: str


class Guard:
    """控制台远程请求的统一门控。"""

    def __init__(
        self,
        clock: Clock,
        registry: KeyRegistry,
        sessions: SessionStore,
        tickets: TicketStore,
        nonces: NonceLedger,
        *,
        audit: Callable[..., None],
        resolve_scope: ScopeResolver | None = None,
        policy_table: PolicyTable | None = None,
        enabled: bool = True,
    ) -> None:
        self._clock = clock
        self._registry = registry
        self._sessions = sessions
        self._tickets = tickets
        self._nonces = nonces
        self._audit = audit
        self._resolve_scope = resolve_scope or (lambda _kind, _ident: "")
        self._policy = policy_table or POLICY
        self._enabled = enabled

    # ---- 认证 ---------------------------------------------------------

    def authenticate(self, api_key: str = "", session_token: str = "") -> Principal:
        """按每请求 Key → 会话的顺序认证，失败抛 401。"""

        if not self._enabled:
            return system_principal()
        if api_key:
            principal = self._registry.authenticate(api_key)
            if principal is not None:
                return principal
            self._deny("auth", "bad_api_key", "")
            raise AuthenticationError("凭据无效")
        if session_token:
            principal = self._sessions.resolve(session_token)
            if principal is not None:
                return principal
            self._deny("auth", "session_invalid", "")
            raise AuthenticationError("会话不存在或已过期")
        self._deny("auth", "no_credential", "")
        raise AuthenticationError("需要认证")

    # ---- 门控主链 -----------------------------------------------------

    def admit(
        self,
        principal: Principal,
        method: str,
        path: str,
        params: dict,
        body: dict,
        *,
        ticket_id: str = "",
        request_id: str = "",
    ) -> GuardResult:
        """认证之后的授权链；内部主体直接放行。"""

        if principal.is_system:
            match = self._policy.lookup(method, path)
            if match is None:
                raise AuthorizationError("路由无策略")
            return GuardResult(principal, match[1], match[0])

        match = self._policy.lookup(method, path)
        if match is None:
            # 没有策略的写/读路径一律拒绝；404 由外层路由决定，这里不放行。
            self._deny("authz", "route_unprotected", path, principal=principal)
            raise AuthorizationError("该路径未登记访问策略", audit=False)
        pattern, route_policy = match

        if not route_policy.role_ok(principal):
            self._deny(
                "authz",
                "role_insufficient",
                path,
                principal=principal,
                action=route_policy.action,
                required_role=route_policy.min_role,
            )
            raise AuthorizationError("角色权限不足")

        if route_policy.scoped and not route_policy.read:
            self._check_scope(principal, route_policy, path, params, body)

        if method.upper() == "POST":
            self._check_nonce(principal, path, body, request_id)

        if route_policy.dangerous:
            self._consume_ticket(principal, path, body, ticket_id)

        return GuardResult(principal, route_policy, pattern)

    # ---- 分区 ---------------------------------------------------------

    def _check_scope(
        self, principal: Principal, policy: RoutePolicy, path: str, params: dict, body: dict
    ) -> None:
        if principal.line_wide:
            return
        target = str(body.get(policy.scope_from) or params.get(policy.scope_from) or "")
        if not target:
            self._deny(
                "scope",
                "target_missing",
                path,
                principal=principal,
                action=policy.action,
                field=policy.scope_from,
            )
            raise AuthorizationError("请求缺少分区目标")
        if policy.scope_kind == "station":
            station_id = target
        else:
            station_id = self._resolve_scope(policy.scope_kind, target)
        if not station_id or not principal.covers(station_id):
            self._deny(
                "scope",
                "station_outside_partition",
                path,
                principal=principal,
                action=policy.action,
                target_kind=policy.scope_kind,
                target=target,
                resolved_station=station_id,
            )
            raise AuthorizationError("目标站台不在你的负责分区内")

    # ---- 去重 ---------------------------------------------------------

    def _check_nonce(
        self, principal: Principal, path: str, body: dict, request_id: str
    ) -> None:
        if not request_id:
            return
        from .nonces import NonceError

        try:
            self._nonces.check(
                principal.id, request_id, path, body_fingerprint(body), self._clock.now()
            )
        except NonceError as error:
            if error.reason == "replayed":
                # 无害重放：编号、路径、请求体都一致，外层直接返回缓存结果。
                raise ReplayAccepted(error.cached) from error
            self._deny(
                "replay",
                "request_id_mutated",
                path,
                principal=principal,
                request_id=request_id,
            )
            raise ReplayRejected("请求编号已用于不同动作") from error

    def remember(
        self, principal: Principal, path: str, body: dict, request_id: str, response: tuple
    ) -> None:
        """动作成功后留底，供同样 request_id 的重试直接命中。"""

        self._nonces.remember(
            principal.id,
            request_id,
            path,
            body_fingerprint(body),
            self._clock.now(),
            response,
        )

    # ---- 一次性凭据 ---------------------------------------------------

    def _consume_ticket(
        self, principal: Principal, path: str, body: dict, ticket_id: str
    ) -> None:
        if not ticket_id:
            self._deny("ticket", "missing", path, principal=principal)
            raise ConfirmationError("危险动作需要二次确认凭据")
        try:
            self._tickets.consume(principal, path, body, ticket_id)
        except TicketError as error:
            kind = "replay" if error.reason == "ticket_replayed" else "invalid"
            self._deny(
                f"ticket_{kind}",
                error.reason,
                path,
                principal=principal,
                ticket_id=ticket_id,
            )
            if error.reason == "ticket_replayed":
                raise TicketRejected("一次性凭据已被使用，不能复用") from error
            raise TicketRejected("一次性凭据无效或已过期") from error

    def prepare_ticket(
        self, principal: Principal, target_path: str, params: dict, body: dict
    ) -> dict:
        """二次确认第一步：核对目标动作的角色与分区后签发票据。"""

        match = self._policy.lookup("POST", target_path)
        if match is None:
            self._deny("authz", "route_unprotected", target_path, principal=principal)
            raise AuthorizationError("目标路径未登记访问策略")
        _pattern, policy = match
        if not policy.dangerous:
            raise AuthorizationError("该动作不是危险动作，无需确认")
        if not policy.role_ok(principal):
            self._deny(
                "authz",
                "role_insufficient",
                target_path,
                principal=principal,
                action=policy.action,
                required_role=policy.min_role,
            )
            raise AuthorizationError("角色权限不足")
        if policy.scoped:
            self._check_scope(principal, policy, target_path, params, body)
        ticket = self._tickets.issue(principal, target_path, body)
        self._audit(
            "security_ticket_issued",
            "",
            "",
            principal=principal.id,
            role=principal.role,
            path=target_path,
            action=policy.action,
            ticket_id=ticket.id,
            expires_at=ticket.expires_at,
        )
        return {
            "ticket_id": ticket.id,
            "path": target_path,
            "fingerprint": ticket.fingerprint,
            "issued_at": ticket.issued_at,
            "expires_at": ticket.expires_at,
            "ttl_s": int(ticket.expires_at - ticket.issued_at),
        }

    # ---- 审计留痕 -----------------------------------------------------

    def _deny(self, kind: str, reason: str, path: str, **detail: object) -> None:
        principal = detail.pop("principal", None)
        principal_id = principal.id if isinstance(principal, Principal) else ""
        role = principal.role if isinstance(principal, Principal) else ""
        self._audit(
            f"security_{kind}_denied",
            "",
            "",
            principal=principal_id,
            role=role,
            reason=reason,
            path=path,
            **detail,
        )


class ReplayAccepted(Exception):
    """同一 request_id 的无害重放，携带首次响应。"""

    def __init__(self, cached: tuple[int, dict] | None) -> None:
        super().__init__("replayed")
        self.cached = cached or (200, {"ok": True, "replayed": True})
