"""控制台访问控制：身份、会话、一次性凭据、授权与请求门控。

整条安全链在这里闭合：

* :mod:`identity`  主体、角色与分区（站台）绑定；
* :mod:`registry`  API Key 注册表，支持环境变量覆盖配置里的口令；
* :mod:`sessions`  随会话失效的会话凭据（空闲 + 绝对双有效期，可注销）；
* :mod:`tickets`   危险动作二次确认用的一次性凭据（绑定动作与请求指纹，
                    过期或复用一律不认）；
* :mod:`nonces`    并发/重放去重账本，``request_id`` 在有效期内只认第一次；
* :mod:`policy`    路由策略：按角色授权、按站台分区、区分只读与危险动作；
* :mod:`guard`     把以上部件串成一次请求的门控，并把每次越权留在审计里。
"""

from __future__ import annotations

from .guard import Guard, GuardResult
from .identity import Principal, SYSTEM_ID
from .nonces import NonceLedger
from .policy import POLICY, RoutePolicy, can_read_everywhere, role_rank
from .registry import KeyRegistry
from .sessions import SessionStore
from .tickets import TicketStore

__all__ = [
    "Guard",
    "GuardResult",
    "KeyRegistry",
    "NonceLedger",
    "POLICY",
    "Principal",
    "RoutePolicy",
    "SessionStore",
    "SYSTEM_ID",
    "TicketStore",
    "can_read_everywhere",
    "role_rank",
]
