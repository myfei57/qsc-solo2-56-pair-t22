"""API Key 注册表：每请求凭据的认证源。

Key 不参与任何哈希链，只做恒定时间比对。配置文件里的 ``api_key`` 可被环境变量
``PSDLINE_KEY_<主体ID 大写、连字符转下划线>`` 覆盖，这样真实部署不必把口令写进
版本库里的配置。主体本身仍以配置文件为准，环境变量只换密钥。
"""

from __future__ import annotations

import hmac
import os

from ..config import AuthSection
from .identity import Principal


class KeyRegistry:
    """主体标识 → API Key 的注册表。"""

    def __init__(self, auth: AuthSection) -> None:
        self._keys: dict[str, str] = {}
        self._principals: dict[str, Principal] = {}
        for item in auth.principals:
            env_name = "PSDLINE_KEY_" + item.id.upper().replace("-", "_")
            secret = os.environ.get(env_name) or item.api_key
            if not secret:
                continue
            principal = Principal(
                id=item.id,
                name=item.name or item.id,
                role=item.role,
                stations=tuple(item.stations),
                api_key_id=item.id,
            )
            self._principals[item.id] = principal
            self._keys[item.id] = secret

    def authenticate(self, api_key: str) -> Principal | None:
        """用 API Key 认证；恒定时间比较，命中返回主体，否则 ``None``。"""

        if not api_key:
            return None
        for principal_id, secret in self._keys.items():
            if hmac.compare_digest(secret, api_key):
                return self._principals[principal_id]
        return None

    def get(self, principal_id: str) -> Principal | None:
        return self._principals.get(principal_id)
