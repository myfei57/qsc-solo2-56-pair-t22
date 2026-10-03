"""审计条目。

每条审计带 ``chain`` 哈希：``SHA256(上一条 chain || 本条规范序列化)``。链从创世
记录（固定空串）开始，任何一条被删改，其后所有 chain 都对不上，回放时用
:func:`~psdline.audit.log.AuditLog.verify_chain` 一验便知。旧版本落盘的条目没有
chain 字段，回放时按链断点处理，不影响新条目继续接链。
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field

GENESIS = ""


def entry_hash(previous: str, payload: dict) -> str:
    """计算链条下一环：上一环串接本条规范 JSON 后 SHA-256。"""

    canonical = json.dumps(payload, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256((previous + canonical).encode("utf-8")).hexdigest()


@dataclass(frozen=True)
class AuditEntry:
    """一条审计流水。"""

    id: str
    kind: str
    train_id: str
    station_id: str
    at: float
    detail: dict = field(default_factory=dict)
    chain: str = ""

    def chain_payload(self) -> dict:
        """参与哈希的本条内容（chain 字段本身不参与）。"""

        return {
            "id": self.id,
            "kind": self.kind,
            "train_id": self.train_id,
            "station_id": self.station_id,
            "at": self.at,
            "detail": dict(self.detail),
        }

    def as_dict(self) -> dict:
        return {
            "id": self.id,
            "kind": self.kind,
            "train_id": self.train_id,
            "station_id": self.station_id,
            "at": self.at,
            "detail": dict(self.detail),
            "chain": self.chain,
        }

    @classmethod
    def from_dict(cls, payload: dict) -> "AuditEntry":
        detail = payload.get("detail", {})
        return cls(
            id=str(payload.get("id", "")),
            kind=str(payload.get("kind", "")),
            train_id=str(payload.get("train_id", "")),
            station_id=str(payload.get("station_id", "")),
            at=float(payload.get("at", 0.0)),
            detail=dict(detail) if isinstance(detail, dict) else {},
            chain=str(payload.get("chain", "")),
        )
