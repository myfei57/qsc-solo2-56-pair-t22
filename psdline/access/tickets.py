"""危险动作二次确认用的一次性凭据（ticket）。

流程分两步，杜绝"页面上一个请求就把整站门开了"：

1. 客户端先 POST 准备接口（``/api/auth/prepare``），声明要执行的动作路径与请求
   体，服务端核对角色与分区后签发一次性票据，返回票据标识、到期时间和请求指纹；
2. 真正的动作请求带上票据标识。服务端在一把全局锁内完成"取出→校验→作废"，
   票据必须同时满足：未过期、未使用、主体一致、动作路径一致、请求体指纹一致。

任何一条不满足都拒绝，并且：

* 复用（已使用）会留下 ``security_ticket_replay`` 审计；
* 过期/伪造/指纹不符留下 ``security_ticket_invalid`` 审计；
* 校验通过的瞬间票据立即作废，并发重放里最多一个请求能拿到它。

票据只存内存，进程重启即失效——一次性凭据本就不该活得比进程久。
"""

from __future__ import annotations

import hashlib
import hmac
import json
import secrets
import threading
from dataclasses import dataclass

from ..clock import Clock
from .identity import Principal


@dataclass(frozen=True)
class Ticket:
    """一张待使用的一次性凭据。"""

    id: str
    principal_id: str
    path: str
    fingerprint: str
    issued_at: float
    expires_at: float


def body_fingerprint(body: dict) -> str:
    """计算请求体指纹：键排序后序列化再 SHA-256。

    票据只对"完全相同的请求体"有效，防止先申请开门一扇、实际请求改成批量开门。
    """

    canonical = json.dumps(body, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


class TicketError(Exception):
    """票据校验失败，``reason`` 供审计区分过期、复用与伪造。"""

    def __init__(self, reason: str, ticket_id: str = "") -> None:
        super().__init__(reason)
        self.reason = reason
        self.ticket_id = ticket_id


class TicketStore:
    """内存一次性票据表，所有操作在同一把锁内完成。"""

    def __init__(self, clock: Clock, ttl_s: int = 60) -> None:
        self._clock = clock
        self._ttl_s = ttl_s
        self._pending: dict[str, Ticket] = {}
        self._used: dict[str, Ticket] = {}
        self._lock = threading.RLock()

    def issue(self, principal: Principal, path: str, body: dict) -> Ticket:
        """为主体的一次具体动作请求签发票据。"""

        now = self._clock.now()
        ticket = Ticket(
            id="tk-" + secrets.token_urlsafe(24),
            principal_id=principal.id,
            path=path,
            fingerprint=body_fingerprint(body),
            issued_at=now,
            expires_at=now + self._ttl_s,
        )
        with self._lock:
            self._pending[ticket.id] = ticket
        return ticket

    def consume(self, principal: Principal, path: str, body: dict, ticket_id: str) -> Ticket:
        """原子地取出、校验并作废票据；任何不满足都抛 :class:`TicketError`。

        成功路径先作废后放行，保证并发请求里票据只可能被消费一次；失败路径票据
        状态不变（过期票据会被清理），由调用方把尝试写进审计。
        """

        with self._lock:
            now = self._clock.now()
            self._sweep(now)
            used = self._used.get(ticket_id)
            if used is not None:
                raise TicketError("ticket_replayed", ticket_id)
            ticket = self._pending.pop(ticket_id, None)
            if ticket is None:
                # 未知票据：可能是伪造，也可能是过期被清扫。按伪造处理最安全。
                raise TicketError("ticket_unknown", ticket_id)
            if ticket.expires_at <= now:
                raise TicketError("ticket_expired", ticket_id)
            if ticket.principal_id != principal.id:
                # 别人的票据不能拿来用；票据留在表里不动，由真正的主人决定。
                self._pending[ticket.id] = ticket
                raise TicketError("ticket_principal_mismatch", ticket_id)
            if ticket.path != path or not hmac.compare_digest(
                ticket.fingerprint, body_fingerprint(body)
            ):
                # 动作或请求体与申请时不一致：票据作废，不许改单后重提。
                self._used[ticket.id] = ticket
                raise TicketError("ticket_fingerprint_mismatch", ticket_id)
            self._used[ticket.id] = ticket
            return ticket

    def _sweep(self, now: float) -> None:
        """清理过期待使用票据（调用方须持锁）。"""

        expired = [tid for tid, item in self._pending.items() if item.expires_at <= now]
        for tid in expired:
            self._pending.pop(tid, None)
