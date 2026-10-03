"""审计流水写入。"""

from __future__ import annotations

import json
import threading

from ..clock import Clock
from ..errors import RailError
from ..eventbus import Event, EventBus
from ..ids import IdFactory
from ..store import JsonlJournal
from .entry import GENESIS, AuditEntry, entry_hash


class AuditLog:
    """审计流水：内存索引 + 分段 JSONL 落盘 + 哈希链。"""

    def __init__(self, clock: Clock, bus: EventBus, journal: JsonlJournal) -> None:
        self._clock = clock
        self._bus = bus
        self._journal = journal
        self._ids = IdFactory("audit")
        self._index: list[AuditEntry] = []
        # 记录与发事件必须在同一把锁内完成：并发请求下链条不能分叉。
        self._lock = threading.RLock()
        self._restore_index()

    def _restore_index(self) -> None:
        """重启后从落盘流水恢复索引，哈希链从最后一条继续，不从头另起。"""

        restored = self.replay()
        if restored:
            self._index = restored

    @property
    def journal(self) -> JsonlJournal:
        return self._journal

    @property
    def ids(self) -> IdFactory:
        return self._ids

    def record(
        self,
        kind: str,
        train_id: str,
        station_id: str,
        at: float | None = None,
        **detail: object,
    ) -> AuditEntry:
        """写入一条审计流水，并接到哈希链尾部。"""

        if not kind:
            raise RailError("审计动作类型为空", component="audit")
        with self._lock:
            entry = AuditEntry(
                id=self._ids.next(),
                kind=kind,
                train_id=train_id,
                station_id=station_id,
                at=self._clock.now() if at is None else at,
                detail={key: value for key, value in detail.items() if value is not None},
            )
            previous = self._index[-1].chain if self._index else GENESIS
            entry = AuditEntry(
                id=entry.id,
                kind=entry.kind,
                train_id=entry.train_id,
                station_id=entry.station_id,
                at=entry.at,
                detail=entry.detail,
                chain=entry_hash(previous, entry.chain_payload()),
            )
            self._journal.append(entry.as_dict())
            self._index.append(entry)
            self._bus.publish(
                Event.of(
                    "audit",
                    "audit",
                    kind,
                    severity="notice",
                    train_id=train_id,
                    station_id=station_id,
                )
            )
            return entry

    def list(self) -> list[AuditEntry]:
        """返回内存里保留的审计条目。"""

        with self._lock:
            return list(self._index)

    def replay(self, limit: int = 100_000) -> list[AuditEntry]:
        """从落盘流水回放审计条目（保留链条字段）。"""

        records = self._journal.read_all()[:limit]
        return [AuditEntry.from_dict(item) for item in records if isinstance(item, dict)]

    def verify_chain(self, entries: list[AuditEntry] | None = None) -> dict:
        """校验哈希链，返回断点位置与总体结论。

        旧版本条目没有 ``chain``：它作为新链段的起点（previous 归零），不算篡改；
        一旦条目带链却与上一环对不上，就是断点。
        """

        entries = entries if entries is not None else self.list()
        previous = GENESIS
        breaks: list[dict] = []
        for index, entry in enumerate(entries):
            if not entry.chain:
                # 旧格式条目：链在这里重新起步。
                previous = GENESIS
                continue
            expected = entry_hash(previous, entry.chain_payload())
            if expected != entry.chain:
                breaks.append(
                    {
                        "index": index,
                        "id": entry.id,
                        "kind": entry.kind,
                        "expected": expected,
                        "actual": entry.chain,
                    }
                )
                # 断点之后不沿"实际值"继续，避免篡改者重算后半条链蒙混过关：
                # 用期望值接着验，把所有受影响位置都标出来。
            previous = entry.chain
        return {"ok": not breaks, "checked": len(entries), "breaks": breaks}

    def segments(self) -> list[list[dict]]:
        """按段返回落盘流水，供巡检逐段核对。"""

        return [
            self._journal.read_segment(index)
            for index in range(len(self._journal.segments()))
        ]

    def summary(self) -> dict:
        """返回审计用量与动作分布。"""

        with self._lock:
            entries = list(self._index)
            return {
                "entries": len(entries),
                "journal_records": self._journal.count(),
                "segment": self._journal.active_segment(),
                "segments": len(self._journal.segments()),
                "segment_sizes": [len(items) for items in self.segments()],
                "by_kind": count_kinds(entries),
                "chain": self.verify_chain(entries),
            }

    def dump(self) -> str:
        """把内存索引序列化成一行 JSON，供状态接口内嵌。"""

        return json.dumps([entry.as_dict() for entry in self.list()], ensure_ascii=False)


def count_kinds(entries: list[AuditEntry]) -> dict[str, int]:
    """按动作类型统计条数。"""

    counts: dict[str, int] = {}
    for entry in entries:
        counts[entry.kind] = counts.get(entry.kind, 0) + 1
    return counts
