"""访问控制异常：全部在 API 边界转成 HTTP 状态码，不泄漏内部细节。"""

from __future__ import annotations


class AccessError(Exception):
    """访问被拒绝的基类，带 HTTP 状态码与机器可读原因。"""

    status = 403
    error = "forbidden"

    def __init__(self, reason: str, *, audit: bool = True) -> None:
        super().__init__(reason)
        self.reason = reason
        self.audit = audit

    def as_payload(self) -> dict:
        return {"error": self.error, "reason": self.reason}


class AuthenticationError(AccessError):
    """没有有效凭据（未登录、Key 错误、会话过期）。"""

    status = 401
    error = "unauthorized"


class AuthorizationError(AccessError):
    """已认证但角色不足或越出绑定分区。"""

    status = 403
    error = "forbidden"


class ConfirmationError(AccessError):
    """危险动作缺少一次性凭据，需要先走二次确认。"""

    status = 409
    error = "confirmation_required"


class TicketRejected(AccessError):
    """一次性凭据过期、复用、伪造或指纹不符。"""

    status = 409
    error = "ticket_rejected"


class ReplayRejected(AccessError):
    """request_id 复用且改了动作/请求体。"""

    status = 409
    error = "replay_rejected"
