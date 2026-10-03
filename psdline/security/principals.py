"""访问主体与名录。

主体来自配置里的 ``security.principals``：名称、角色、静态密钥与站台分区。
静态密钥用 ``hmac.compare_digest`` 逐条比对，避免按字节短路泄露前缀。
"""

from __future__ import annotations

import hmac
from dataclasses import dataclass

from ..config import PrincipalSpec


@dataclass(frozen=True)
class Principal:
    """一个已通过认证的访问主体。"""

    name: str
    role: str
    partitions: tuple[str, ...] = ()

    @property
    def allows_all(self) -> bool:
        """是否拥有全域分区（``"*"``）。"""

        return "*" in self.partitions

    def as_dict(self) -> dict:
        return {"name": self.name, "role": self.role, "partitions": list(self.partitions)}


class PrincipalDirectory:
    """主体名录：按名称或静态密钥查找主体。"""

    def __init__(self, specs: tuple[PrincipalSpec, ...]) -> None:
        self._by_name = {
            spec.name: Principal(spec.name, spec.role, tuple(spec.partitions)) for spec in specs
        }
        self._by_key = {spec.key: spec.name for spec in specs}

    def by_name(self, name: str) -> Principal | None:
        """按名称取主体。"""

        return self._by_name.get(name)

    def find_by_key(self, key: str) -> Principal | None:
        """按静态密钥取主体；比对全程不短路。"""

        if not key:
            return None
        found = None
        for candidate, name in self._by_key.items():
            if hmac.compare_digest(candidate, key):
                found = name
        return self._by_name.get(found) if found is not None else None
