"""会话与一次性确认凭据。

会话凭据挂在会话上、随有效期失效，可以主动注销；确认凭据绑定「主体 + 动作 +
目标」，一次性、有有效期。两类状态变更都先追加到 ``security`` 流水（只追加不
重写）再更新内存索引：进程重启后按流水回放，已消费的确认凭据不会复活，未过期
的会话继续有效。所有方法共用一把可重入锁，并发请求下「检查并消费」是原子的。
"""

from __future__ import annotations

import secrets
import threading
from dataclasses import dataclass

from ..clock import Clock
from ..store import JsonlJournal


@dataclass(frozen=True)
class Session:
    """一个会话：权限挂在上面，随有效期失效。"""

    id: str
    principal: str
    expires_at: float


@dataclass
class Ticket:
    """一张一次性确认凭据，绑定主体、动作与目标。"""

    id: str
    principal: str
    action: str
    target: str
    expires_at: float
    consumed: bool = False


class CredentialStore:
    """会话与确认凭据的持久化存储。"""

    def __init__(self, root: str, clock: Clock, segment_limit: int = 512) -> None:
        self._clock = clock
        self._journal = JsonlJournal(root, "security", segment_limit=segment_limit)
        self._lock = threading.RLock()
        self._sessions: dict[str, Session] = {}
        self._tickets: dict[str, Ticket] = {}
        self._restore()

    def _restore(self) -> None:
        """按流水回放会话与凭据状态；已过期的会话直接丢弃。"""

        now = self._clock.now()
        for record in self._journal.read_all():
            kind = record.get("type")
            if kind == "session_issued":
                session = Session(
                    id=str(record.get("session", "")),
                    principal=str(record.get("principal", "")),
                    expires_at=float(record.get("expires_at", 0.0)),
                )
                if session.id and session.expires_at > now:
                    self._sessions[session.id] = session
            elif kind in ("session_closed", "session_expired"):
                self._sessions.pop(str(record.get("session", "")), None)
            elif kind == "ticket_issued":
                ticket = Ticket(
                    id=str(record.get("ticket", "")),
                    principal=str(record.get("principal", "")),
                    action=str(record.get("action", "")),
                    target=str(record.get("target", "")),
                    expires_at=float(record.get("expires_at", 0.0)),
                )
                if ticket.id:
                    self._tickets[ticket.id] = ticket
            elif kind == "ticket_consumed":
                ticket = self._tickets.get(str(record.get("ticket", "")))
                if ticket is not None:
                    ticket.consumed = True

    # ---- 会话 ---------------------------------------------------------

    def issue_session(self, principal: str, ttl_s: float) -> Session:
        """签发一个会话。"""

        session = Session(
            id=f"sess_{secrets.token_urlsafe(24)}",
            principal=principal,
            expires_at=self._clock.now() + ttl_s,
        )
        with self._lock:
            self._journal.append(
                {
                    "type": "session_issued",
                    "session": session.id,
                    "principal": session.principal,
                    "expires_at": session.expires_at,
                }
            )
            self._sessions[session.id] = session
        return session

    def resolve_session(self, session_id: str) -> tuple[Session | None, bool]:
        """解析会话；过期时顺手注销并落流水，返回 ``(会话, 是否刚过期)``。"""

        with self._lock:
            session = self._sessions.get(session_id)
            if session is None:
                return None, False
            if session.expires_at <= self._clock.now():
                del self._sessions[session_id]
                self._journal.append(
                    {
                        "type": "session_expired",
                        "session": session_id,
                        "principal": session.principal,
                    }
                )
                return None, True
            return session, False

    def close_session(self, session_id: str) -> tuple[bool, str]:
        """注销会话，返回 ``(是否真的注销了, 主体名)``。"""

        with self._lock:
            session = self._sessions.pop(session_id, None)
            if session is None:
                return False, ""
            self._journal.append(
                {
                    "type": "session_closed",
                    "session": session_id,
                    "principal": session.principal,
                }
            )
            return True, session.principal

    def active_sessions(self) -> int:
        """当前未过期的会话数。"""

        now = self._clock.now()
        with self._lock:
            return sum(1 for session in self._sessions.values() if session.expires_at > now)

    # ---- 确认凭据 -----------------------------------------------------

    def issue_ticket(self, principal: str, action: str, target: str, ttl_s: float) -> Ticket:
        """签发一张一次性确认凭据。"""

        ticket = Ticket(
            id=f"cfm_{secrets.token_urlsafe(18)}",
            principal=principal,
            action=action,
            target=target,
            expires_at=self._clock.now() + ttl_s,
        )
        with self._lock:
            self._journal.append(
                {
                    "type": "ticket_issued",
                    "ticket": ticket.id,
                    "principal": ticket.principal,
                    "action": ticket.action,
                    "target": ticket.target,
                    "expires_at": ticket.expires_at,
                }
            )
            self._tickets[ticket.id] = ticket
        return ticket

    def consume_ticket(self, ticket_id: str, principal: str, action: str, target: str) -> str:
        """原子地检查并消费一张凭据，返回 ``ok`` 或拒绝原因。

        拒绝原因：``missing``（未携带）、``unknown``（不存在）、``reused``
        （已消费）、``expired``（已过期）、``mismatch``（人、动作或目标对不上）。
        """

        if not ticket_id:
            return "missing"
        with self._lock:
            ticket = self._tickets.get(ticket_id)
            if ticket is None:
                return "unknown"
            if ticket.consumed:
                return "reused"
            if ticket.expires_at <= self._clock.now():
                return "expired"
            if (
                ticket.principal != principal
                or ticket.action != action
                or ticket.target != target
            ):
                return "mismatch"
            ticket.consumed = True
            self._journal.append(
                {"type": "ticket_consumed", "ticket": ticket_id, "principal": principal}
            )
            return "ok"

    def pending_tickets(self) -> int:
        """当前未消费且未过期的凭据数。"""

        now = self._clock.now()
        with self._lock:
            return sum(
                1
                for ticket in self._tickets.values()
                if not ticket.consumed and ticket.expires_at > now
            )
