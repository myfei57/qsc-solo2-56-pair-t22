"""会话凭据：登录后权限挂在会话上，随会话失效。

会话令牌是 256bit 随机串（不携带任何权限信息，服务端保存令牌→主体映射），有两
道有效期：

* 空闲有效期：每次访问顺延，闲置超时即失效；
* 绝对有效期：从签发起硬性截止，再活跃也不能续命。

会话可显式注销（登出）。会话只存在内存里，进程重启全部需要重新登录——这正是
"权限挂在会话上随会话失效"的语义；需要跨重启的自动化调用方应使用每请求
API Key。
"""

from __future__ import annotations

import secrets
import threading
from dataclasses import dataclass

from ..clock import Clock
from .identity import Principal


@dataclass(frozen=True)
class Session:
    """一条已签发会话。"""

    token: str
    principal: Principal
    issued_at: float
    last_seen: float
    absolute_expiry: float

    def expired(self, now: float, idle_s: int) -> bool:
        return now >= self.absolute_expiry or now - self.last_seen >= idle_s

    def as_dict(self) -> dict:
        return {
            "principal": self.principal.as_dict(),
            "issued_at": self.issued_at,
            "last_seen": self.last_seen,
            "absolute_expiry": self.absolute_expiry,
        }


class SessionStore:
    """内存会话表，线程安全。"""

    def __init__(
        self,
        clock: Clock,
        idle_s: int = 900,
        absolute_s: int = 43_200,
    ) -> None:
        self._clock = clock
        self._idle_s = idle_s
        self._absolute_s = absolute_s
        self._sessions: dict[str, Session] = {}
        self._lock = threading.RLock()

    def issue(self, principal: Principal) -> Session:
        """为主体签发一条新会话。"""

        now = self._clock.now()
        session = Session(
            token=secrets.token_urlsafe(32),
            principal=principal,
            issued_at=now,
            last_seen=now,
            absolute_expiry=now + self._absolute_s,
        )
        with self._lock:
            self._sessions[session.token] = session
        return session

    def resolve(self, token: str) -> Principal | None:
        """校验令牌并顺延空闲窗口；过期/未知/已注销返回 ``None``。"""

        if not token:
            return None
        with self._lock:
            session = self._sessions.get(token)
            if session is None:
                return None
            now = self._clock.now()
            if session.expired(now, self._idle_s):
                # 过期会话顺手清掉，不留复活窗口。
                self._sessions.pop(token, None)
                return None
            renewed = Session(
                token=session.token,
                principal=session.principal,
                issued_at=session.issued_at,
                last_seen=now,
                absolute_expiry=session.absolute_expiry,
            )
            self._sessions[token] = renewed
            return session.principal

    def revoke(self, token: str) -> bool:
        """注销一条会话，返回是否真的存在。"""

        with self._lock:
            return self._sessions.pop(token, None) is not None
