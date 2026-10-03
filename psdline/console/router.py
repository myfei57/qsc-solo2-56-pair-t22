"""接口路由。

路由支持 ``{name}`` 形式的路径参数（例如 ``/api/trains/{trainID}``）。匹配按
注册顺序进行，先精确路径后参数路径，保证 ``/api/trains/summary`` 不会被
``/api/trains/{trainID}`` 抢走。
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Callable

Handler = Callable[[dict, dict], dict]


@dataclass(frozen=True)
class Route:
    """一条已注册的路由；``policy`` 是门控策略（由接口层解释，路由表只负责携带）。"""

    method: str
    pattern: str
    handler: Handler
    policy: object | None = None

    def as_dict(self) -> dict:
        return {"method": self.method, "path": self.pattern}


def _split(pattern: str) -> list[str]:
    return [part for part in pattern.strip("/").split("/") if part]


class Router:
    """极简路由表。"""

    def __init__(self) -> None:
        self._routes: list[Route] = []

    def add(
        self, method: str, pattern: str, handler: Handler, policy: object | None = None
    ) -> Route:
        """注册一条路由。"""

        route = Route(method=method.upper(), pattern=pattern, handler=handler, policy=policy)
        self._routes.append(route)
        return route

    def routes(self) -> list[Route]:
        """返回全部已注册路由。"""

        return list(self._routes)

    def match_route(self, method: str, path: str) -> tuple[Route, dict] | None:
        """匹配一条路由，返回路由对象与路径参数。"""

        method = method.upper()
        segments = _split(path)
        wildcard: tuple[Route, dict] | None = None
        for route in self._routes:
            if route.method != method:
                continue
            pattern = _split(route.pattern)
            if len(pattern) != len(segments):
                continue
            params: dict[str, str] = {}
            matched = True
            for expected, actual in zip(pattern, segments):
                if expected.startswith("{") and expected.endswith("}"):
                    params[expected[1:-1]] = actual
                    continue
                if expected != actual:
                    matched = False
                    break
            if matched:
                wildcard = (route, params)
                if "{" not in route.pattern:
                    return wildcard
        return wildcard

    def match(self, method: str, path: str) -> tuple[Handler, dict] | None:
        """匹配一条路由，返回处理器与路径参数。"""

        matched = self.match_route(method, path)
        if matched is None:
            return None
        route, params = matched
        return route.handler, params
