"""控制台门控与凭据。

``Gate`` 在接口处理器之前完成认证、授权与危险动作的二次确认，并把结论写进审
计流水；``CredentialStore`` 负责会话与一次性确认凭据的签发、消费与重启回放；
``PrincipalDirectory`` 是配置主体的运行时名录。
"""

from __future__ import annotations

from .credentials import CredentialStore, Session, Ticket
from .gate import Gate
from .policy import (
    ROLE_CAPABILITIES,
    AccessContext,
    Credentials,
    Decision,
    RoutePolicy,
)
from .principals import Principal, PrincipalDirectory

__all__ = [
    "AccessContext",
    "CredentialStore",
    "Credentials",
    "Decision",
    "Gate",
    "Principal",
    "PrincipalDirectory",
    "ROLE_CAPABILITIES",
    "RoutePolicy",
    "Session",
    "Ticket",
]
