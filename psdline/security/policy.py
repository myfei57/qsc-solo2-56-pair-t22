"""门控策略。

每条路由挂一个 :class:`RoutePolicy`：要求的能力（``open`` 不需要凭据、
``read``/``write``/``admin``）、站台分区的作用域（从哪个字段解析站台）、以及
是否需要一次性确认凭据。门控对每个请求产出一个 :class:`Decision`，允许或
拒绝都在这一处定形，审计由门控统一落盘。
"""

from __future__ import annotations

from dataclasses import dataclass

#: 角色能覆盖的能力集合。
ROLE_CAPABILITIES: dict[str, frozenset] = {
    "viewer": frozenset({"read"}),
    "operator": frozenset({"read", "write"}),
    "admin": frozenset({"read", "write", "admin"}),
}


@dataclass(frozen=True)
class RoutePolicy:
    """一条路由的门控策略。

    ``capability``：``open`` 不查凭据，其余按角色能力表核对；
    ``scope``：站台分区从哪个目标解析（站台、站台门、列车，或先站台后列车）；
    ``confirm``：是否需要随请求提交一次性确认凭据。
    """

    capability: str = "admin"
    scope: str = "none"
    confirm: bool = False


@dataclass(frozen=True)
class AccessContext:
    """一次请求的访问上下文：动作、解析出的站台与目标。"""

    method: str
    action: str
    station: str = ""
    target: str = ""
    scoped: bool = False


@dataclass(frozen=True)
class Credentials:
    """一次请求携带的凭据：访问令牌（会话或静态密钥）与确认凭据。"""

    token: str = ""
    confirm: str = ""

    @classmethod
    def normalize(cls, raw: object, body: dict) -> "Credentials":
        """合并请求头里的凭据与请求体里的 ``confirm_ticket``。"""

        token = ""
        confirm = ""
        if isinstance(raw, dict):
            token = str(raw.get("token") or "")
            confirm = str(raw.get("confirm") or "")
        if not confirm and isinstance(body, dict):
            confirm = str(body.get("confirm_ticket") or "")
        return cls(token=token, confirm=confirm)


@dataclass(frozen=True)
class Decision:
    """门控结论：放行（带主体）或拒绝（带状态码与响应体）。"""

    allowed: bool
    status: int
    payload: dict
    principal: object | None = None
