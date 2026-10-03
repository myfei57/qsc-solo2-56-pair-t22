"""请求去重账本：并发请求与重放的第二道防线。

危险动作的一次性票据已经是强绑定的重放防护；普通动作没有票据，客户端可以在
POST 里带 ``request_id``（由调用方生成，例如 UUID）。同一个主体在有效期内对
同一 ``request_id`` 的重复提交：

* 与首次请求路径/请求体一致 → 直接返回首次的响应，不重复执行动作（幂等）；
* 路径或请求体不一致 → 拒绝并审计，这是拿同一编号套不同动作的重放攻击特征。

账本只存内存，按到期时间惰性清理。账本不参与票据流程：票据解决"动作确认"，
账本解决"网络重试不重复开门"。
"""

from __future__ import annotations

import threading
from dataclasses import dataclass


@dataclass(frozen=True)
class NonceRecord:
    """一次已接受请求的留底。"""

    principal_id: str
    path: str
    fingerprint: str
    response: tuple[int, dict]
    at: float


class NonceError(Exception):
    """request_id 冲突，``reason`` 区分无害重放与改单重放。"""

    def __init__(self, reason: str, cached: tuple[int, dict] | None = None) -> None:
        super().__init__(reason)
        self.reason = reason
        self.cached = cached


class NonceLedger:
    """(主体, request_id) → 首次结果 的内存账本。"""

    def __init__(self, ttl_s: int = 300) -> None:
        self._ttl_s = ttl_s
        self._records: dict[tuple[str, str], NonceRecord] = {}
        self._lock = threading.RLock()

    def check(
        self,
        principal_id: str,
        request_id: str,
        path: str,
        fingerprint: str,
        now: float,
    ) -> None:
        """提交前校验；新编号直接通过，重放命中则抛 :class:`NonceError`。"""

        if not request_id:
            return
        with self._lock:
            self._sweep(now)
            record = self._records.get((principal_id, request_id))
            if record is None:
                return
            if record.path == path and record.fingerprint == fingerprint:
                raise NonceError("replayed", cached=record.response)
            raise NonceError("replay_mutated")

    def remember(
        self,
        principal_id: str,
        request_id: str,
        path: str,
        fingerprint: str,
        now: float,
        response: tuple[int, dict],
    ) -> None:
        """留底一次成功受理的请求（仅 2xx 才留底，失败编号允许改正后重试）。"""

        if not request_id:
            return
        status, _payload = response
        if status >= 400:
            return
        with self._lock:
            self._records[(principal_id, request_id)] = NonceRecord(
                principal_id=principal_id,
                path=path,
                fingerprint=fingerprint,
                response=response,
                at=now,
            )

    def _sweep(self, now: float) -> None:
        stale = [key for key, item in self._records.items() if now - item.at >= self._ttl_s]
        for key in stale:
            self._records.pop(key, None)
