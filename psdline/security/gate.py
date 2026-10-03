"""门控：认证、授权、二次确认与审计的一条链。

每个接口请求在这里依次过三道：认证（会话或静态密钥 → 主体）、授权（角色能力 +
站台分区）、危险动作的一次性确认凭据。任何一步拒绝都会写一条审计流水（不记凭
据本身），放行的写动作由 :meth:`Gate.note_action` 补一条带主体与结果的记录，
审计里能完整重建「谁、在哪、做了什么、结果如何」。
"""

from __future__ import annotations

import hashlib

from ..audit import AuditLog
from ..clock import Clock
from ..config import SecuritySection
from ..store import JsonStore
from .credentials import CredentialStore
from .policy import ROLE_CAPABILITIES, AccessContext, Credentials, Decision, RoutePolicy
from .principals import Principal, PrincipalDirectory


def _fingerprint(credential: str) -> str:
    """凭据指纹：审计里只留它，能对照同一次签发，又不能拿去重放。"""

    return hashlib.sha256(credential.encode("utf-8")).hexdigest()[:12]


class Gate:
    """控制台门控。"""

    def __init__(
        self,
        security: SecuritySection,
        store: JsonStore,
        clock: Clock,
        audit: AuditLog,
        segment_limit: int = 512,
    ) -> None:
        self._security = security
        self._directory = PrincipalDirectory(security.principals)
        self._credentials = CredentialStore(store.root, clock, segment_limit=segment_limit)
        self._audit = audit

    # ---- 认证 ---------------------------------------------------------

    def authenticate(self, token: str) -> Principal | None:
        """把令牌解析成主体；解析失败返回 ``None``（不记审计，供页面与日志用）。"""

        principal, _reason = self._resolve(token)
        return principal

    def _resolve(self, token: str) -> tuple[Principal | None, str]:
        """解析令牌，返回 ``(主体, 失败原因)``；会话过期在这里落一条审计。"""

        if not token:
            return None, "missing"
        session, expired = self._credentials.resolve_session(token)
        if session is not None:
            principal = self._directory.by_name(session.principal)
            if principal is not None:
                return principal, ""
            return None, "unknown"
        if expired:
            self._record(
                "session_expired", "", AccessContext("POST", ""), session=_fingerprint(token)
            )
            return None, "session_expired"
        principal = self._directory.find_by_key(token)
        if principal is not None:
            return principal, ""
        return None, "unknown"

    def login(self, key: str) -> tuple[int, dict]:
        """用静态密钥换一个会话；密钥无效时拒绝并留审计。"""

        context = AccessContext("POST", "/api/session")
        principal = self._directory.find_by_key(key)
        if principal is None:
            self._record("access_denied", "", context, reason="unknown_key")
            return 401, {"error": "unauthenticated", "reason": "unknown_key"}
        session = self._credentials.issue_session(
            principal.name, self._security.session_ttl_s
        )
        self._record(
            "session_issued",
            principal.name,
            context,
            session=_fingerprint(session.id),
            expires_at=session.expires_at,
        )
        return 200, {
            "session": session.id,
            "expires_at": session.expires_at,
            "principal": principal.as_dict(),
        }

    def logout(self, token: str) -> dict:
        """注销当前会话；静态密钥不是会话，注销返回 ``ok=False``。"""

        closed, principal = self._credentials.close_session(token)
        if closed:
            self._record(
                "session_closed",
                principal,
                AccessContext("POST", "/api/session/close"),
                session=_fingerprint(token),
            )
        return {"ok": closed}

    # ---- 授权 ---------------------------------------------------------

    def authorize(
        self, policy: RoutePolicy, context: AccessContext, credentials: Credentials
    ) -> Decision:
        """对一次请求做认证、授权与二次确认。"""

        if policy.capability == "open":
            return Decision(True, 200, {})
        principal, reason = self._resolve(credentials.token)
        if principal is None:
            self._record("access_denied", "", context, reason=reason)
            return Decision(False, 401, {"error": "unauthenticated", "reason": reason})
        if policy.capability not in ROLE_CAPABILITIES.get(principal.role, frozenset()):
            self._record(
                "access_denied",
                principal.name,
                context,
                reason="capability",
                required=policy.capability,
                role=principal.role,
            )
            return Decision(
                False,
                403,
                {
                    "error": "forbidden",
                    "reason": "capability",
                    "required": policy.capability,
                    "role": principal.role,
                },
            )
        if not self._partition_ok(principal, policy, context):
            self._record(
                "access_denied",
                principal.name,
                context,
                reason="partition",
                station=context.station,
                partitions=list(principal.partitions),
            )
            return Decision(
                False,
                403,
                {
                    "error": "forbidden",
                    "reason": "partition",
                    "station": context.station,
                    "partitions": list(principal.partitions),
                },
            )
        if policy.confirm:
            outcome = self._credentials.consume_ticket(
                credentials.confirm, principal.name, context.action, context.target
            )
            if outcome == "missing":
                # 两步流程的第一步：提示客户端先取一次性凭据，不算越权，不记审计。
                return Decision(
                    False,
                    428,
                    {
                        "error": "confirmation_required",
                        "action": context.action,
                        "target": context.target,
                        "hint": "POST /api/confirm 取一次性凭据，随 confirm_ticket 或 X-PSDLine-Confirm 提交",
                    },
                )
            if outcome != "ok":
                self._record(
                    "confirm_rejected",
                    principal.name,
                    context,
                    reason=outcome,
                    ticket=_fingerprint(credentials.confirm),
                )
                return Decision(
                    False,
                    403,
                    {"error": "confirmation_rejected", "reason": outcome},
                )
            self._record(
                "confirm_consumed",
                principal.name,
                context,
                ticket=_fingerprint(credentials.confirm),
            )
        return Decision(True, 200, {}, principal)

    def _partition_ok(
        self, principal: Principal, policy: RoutePolicy, context: AccessContext
    ) -> bool:
        """核对站台分区：只读按配置放开，写动作定位不到站台时拒绝。"""

        if policy.capability == "read" and self._security.cross_partition_read:
            return True
        if principal.allows_all:
            return True
        if not context.scoped:
            return True
        if not context.station:
            return False
        return context.station in principal.partitions

    # ---- 二次确认 -----------------------------------------------------

    def request_ticket(
        self, principal: Principal, policy: RoutePolicy, context: AccessContext
    ) -> tuple[int, dict]:
        """为一个危险动作签发一次性确认凭据；签发前按目标动作再核一遍权限。"""

        if policy.capability not in ROLE_CAPABILITIES.get(principal.role, frozenset()):
            self._record(
                "access_denied",
                principal.name,
                context,
                reason="capability",
                required=policy.capability,
                role=principal.role,
            )
            return 403, {"error": "forbidden", "reason": "capability"}
        if not self._partition_ok(principal, policy, context):
            self._record(
                "access_denied",
                principal.name,
                context,
                reason="partition",
                station=context.station,
                partitions=list(principal.partitions),
            )
            return 403, {"error": "forbidden", "reason": "partition"}
        ticket = self._credentials.issue_ticket(
            principal.name, context.action, context.target, self._security.confirm_ttl_s
        )
        self._record(
            "confirm_issued",
            principal.name,
            context,
            ticket=_fingerprint(ticket.id),
            expires_at=ticket.expires_at,
        )
        return 200, {
            "ticket": ticket.id,
            "action": context.action,
            "target": context.target,
            "expires_at": ticket.expires_at,
        }

    # ---- 审计与自检 ---------------------------------------------------

    def note_action(
        self, principal: Principal | None, context: AccessContext, status: int, payload: dict
    ) -> None:
        """给一次已放行的写动作补一条带主体与结果的审计。"""

        ok = status == 200 and bool(payload.get("ok", True))
        self._record(
            "console_action",
            principal.name if principal is not None else "",
            context,
            http_status=status,
            ok=ok,
        )

    def describe(self, principal: Principal, confirm_routes: list[str]) -> dict:
        """返回当前主体看到的门控策略与凭据用量。"""

        return {
            "principal": principal.as_dict(),
            "session_ttl_s": self._security.session_ttl_s,
            "confirm_ttl_s": self._security.confirm_ttl_s,
            "cross_partition_read": self._security.cross_partition_read,
            "confirm_required": list(confirm_routes),
            "sessions_active": self._credentials.active_sessions(),
            "tickets_pending": self._credentials.pending_tickets(),
        }

    def _record(self, kind: str, principal: str, context: AccessContext, **detail: object) -> None:
        """写一条门控审计；凭据内容永不落盘，只记标识与结论。"""

        self._audit.record(
            kind,
            "",
            context.station,
            component="console",
            principal=principal,
            action=context.action,
            target=context.target,
            **detail,
        )
