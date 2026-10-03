"""主体（值班员身份）与角色分级。

四个角色权限从低到高：

viewer      只读；只读接口对全部已认证角色放开跨分区（态势查看），但 viewer
            拿不到任何写权限，也看不到审计明细。
operator    本站台的日常作业（到发、门控、间隙确认等）；只读可跨分区看全线，
            写操作严格限定绑定站台。
dispatcher  全线列车运行动作（到发、交路、位置等），可看审计。
supervisor  全部动作（故障置位/解除、联锁投退、重排映射、批量开门、重置），
            可看审计。

内部直接调用（命令行、演示、测试夹具）使用 :data:`SYSTEM_ID` 主体，不经过
HTTP 门控；远程入口必须由 :class:`~psdline.access.guard.Guard` 认证。
"""

from __future__ import annotations

from dataclasses import dataclass

ROLES = ("viewer", "operator", "dispatcher", "supervisor")

SYSTEM_ID = "__system__"

# 角色等级，数字越大权限越高；授权时比较等级而非写死角色名。
_ROLE_RANK = {"viewer": 1, "operator": 2, "dispatcher": 3, "supervisor": 4}


def role_rank(role: str) -> int:
    """返回角色等级，未知角色为 0。"""

    return _ROLE_RANK.get(role, 0)


@dataclass(frozen=True)
class Principal:
    """一个已认证主体。

    ``stations`` 为绑定站台：空元组表示全线（调度/主管/内部主体）。
    """

    id: str
    name: str
    role: str
    stations: tuple[str, ...] = ()
    api_key_id: str = ""

    @property
    def is_system(self) -> bool:
        return self.id == SYSTEM_ID

    @property
    def line_wide(self) -> bool:
        """是否拥有全线范围（调度、主管或内部主体）。"""

        return not self.stations or self.is_system

    def covers(self, scope: str) -> bool:
        """分区范围检查；空范围（不针对具体站台）一律允许。"""

        return not scope or self.line_wide or scope in self.stations

    def as_dict(self) -> dict:
        return {
            "id": self.id,
            "name": self.name,
            "role": self.role,
            "stations": list(self.stations),
            "line_wide": self.line_wide,
        }


def system_principal() -> Principal:
    """内部主体：命令行/演示/测试等可信进程内调用使用。"""

    return Principal(id=SYSTEM_ID, name="内部调用", role="supervisor")
