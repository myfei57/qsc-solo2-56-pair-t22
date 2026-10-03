"""控制台 HTTP 服务。

使用标准库 ``ThreadingHTTPServer``：``/api/...`` 交给 :class:`Api` 处理并编码成
JSON，四个页面路径交给 :func:`~psdline.console.pages.render_page` 渲染成 HTML。

每个请求在进入业务前先解析凭据并构造 :class:`RequestContext`：

* ``Authorization: Bearer <api-key>``     每请求凭据（自动化客户端）；
* ``Cookie: psd_session=<token>``         会话凭据（浏览器登录后获得）；
* 请求体里的 ``ticket_id`` / ``request_id`` 二次确认票据与幂等编号。

页面同样需要认证：未认证时返回带登录表单的 401 页面，表单 POST 到
``/api/auth/login``，登录成功后靠 ``HttpOnly`` Cookie 保持会话。访问路径会写进
审计（只记路径不记正文），控制台动作与自动循环动作在审计里能一眼区分。
"""

from __future__ import annotations

import json
import threading
import urllib.error
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlsplit

from ..app import Platform
from ..eventbus import Event
from .api import SESSION_COOKIE, Api, RequestContext
from .pages import PAGE_PATHS, render_login_page, render_page

_SESSION_PREFIX = SESSION_COOKIE + "="


class _Handler(BaseHTTPRequestHandler):
    server_version = "psdline-console/1.0"

    def log_message(self, format: str, *args: object) -> None:  # noqa: A002 - 覆盖基类签名
        # 不往 stderr 刷访问日志；访问路径交给服务器记进审计。
        self.server.record_access(self.path)  # type: ignore[attr-defined]

    def do_GET(self) -> None:  # noqa: N802 - 基类约定
        self._dispatch("GET")

    def do_POST(self) -> None:  # noqa: N802 - 基类约定
        self._dispatch("POST")

    def _bearer(self) -> str:
        header = self.headers.get("Authorization", "")
        if header.startswith("Bearer "):
            return header[len("Bearer ") :].strip()
        return ""

    def _session_cookie(self) -> str:
        for part in self.headers.get("Cookie", "").split(";"):
            item = part.strip()
            if item.startswith(_SESSION_PREFIX):
                return item[len(_SESSION_PREFIX) :]
        return ""

    def _dispatch(self, method: str) -> None:
        parsed = urlsplit(self.path)
        length = int(self.headers.get("Content-Length") or 0)
        raw = self.rfile.read(length) if length else b""
        try:
            body = json.loads(raw.decode("utf-8")) if raw else {}
        except json.JSONDecodeError:
            body = {}
        if not isinstance(body, dict):
            body = {}
        query = {key: values[-1] for key, values in parse_qs(parsed.query).items()}

        context = RequestContext(
            api_key=self._bearer(),
            session_token=self._session_cookie(),
            ticket_id=str(body.get("ticket_id", "")),
            request_id=str(body.get("request_id", "")),
            remote=self.client_address[0] if self.client_address else "",
        )

        if method == "GET" and parsed.path in PAGE_PATHS:
            principal = None
            api = self.server.api  # type: ignore[attr-defined]
            if api.auth_enabled:
                try:
                    principal = api.guard.authenticate(
                        context.api_key, context.session_token
                    )
                except Exception:  # noqa: BLE001 - 未认证退到登录页
                    principal = None
                if principal is None:
                    login = render_login_page(parsed.path)
                    self._respond(
                        401,
                        login.encode("utf-8"),
                        "text/html; charset=utf-8",
                        extra={"WWW-Authenticate": "Bearer"},
                    )
                    return
            page = render_page(parsed.path, self.server.platform, principal)  # type: ignore[attr-defined]
            self._respond(200, page.encode("utf-8"), "text/html; charset=utf-8")
            return

        status, payload, extra_headers = self.server.api.handle_request(  # type: ignore[attr-defined]
            method, parsed.path, query, body, context
        )
        self._respond(
            status,
            json.dumps(payload, ensure_ascii=False, default=str).encode("utf-8"),
            "application/json; charset=utf-8",
            extra=extra_headers,
        )

    def _respond(
        self,
        status: int,
        data: bytes,
        content_type: str,
        extra: dict[str, str] | None = None,
    ) -> None:
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(data)))
        self.send_header("X-Content-Type-Options", "nosniff")
        for key, value in (extra or {}).items():
            self.send_header(key, value)
        self.end_headers()
        self.wfile.write(data)


class _ConsoleHTTPServer(ThreadingHTTPServer):
    daemon_threads = True
    allow_reuse_address = True

    def __init__(self, address: tuple[str, int], api: Api, platform: Platform) -> None:
        super().__init__(address, _Handler)
        self.api = api
        self.platform = platform

    def record_access(self, path: str) -> None:
        self.platform.bus.publish(
            Event.of("console", "console", "http_access", severity="notice", path=path)
        )


class ConsoleServer:
    """控制台服务封装，负责在后台线程里起停 ``ThreadingHTTPServer``。"""

    def __init__(self, platform: Platform, host: str = "127.0.0.1", port: int = 8080) -> None:
        self._platform = platform
        self._host = host
        self._port = port
        self._server: _ConsoleHTTPServer | None = None
        self._thread: threading.Thread | None = None
        self._api = Api(platform)

    @property
    def api(self) -> Api:
        return self._api

    @property
    def port(self) -> int:
        if self._server is None:
            return self._port
        return int(self._server.server_address[1])

    def start(self) -> str:
        """启动服务，返回基础 URL。"""

        if self._server is not None:
            return self.base_url()
        self._server = _ConsoleHTTPServer((self._host, self._port), self._api, self._platform)
        self._thread = threading.Thread(
            target=self._server.serve_forever, name="psdline-console", daemon=True
        )
        self._thread.start()
        return self.base_url()

    def base_url(self) -> str:
        """返回基础 URL（端口为实际监听端口）。"""

        host = self._host if self._host not in ("0.0.0.0", "") else "127.0.0.1"
        return f"http://{host}:{self.port}"

    def stop(self) -> None:
        """停止服务。"""

        if self._server is None:
            return
        self._server.shutdown()
        self._server.server_close()
        if self._thread is not None:
            self._thread.join(timeout=5)
        self._server = None
        self._thread = None


def probe_endpoints(
    base_url: str, paths: list[str], headers: dict[str, str] | None = None
) -> dict:
    """对控制台各接口发真实 HTTP 请求，返回每个路径的健康结果。"""

    results: dict[str, dict] = {}
    request_headers = dict(headers or {})
    for path in paths:
        url = f"{base_url}{path}"
        request = urllib.request.Request(url, headers=request_headers)
        try:
            with urllib.request.urlopen(request, timeout=5) as response:
                raw = response.read().decode("utf-8")
                if path.startswith("/api") or "json" in response.headers.get("Content-Type", ""):
                    payload = json.loads(raw)
                    keys = sorted(payload)[:6]
                else:
                    keys = ["<html>"] if raw.lstrip().startswith("<!doctype html") else ["<text>"]
                results[path] = {"ok": response.status == 200, "status": response.status, "keys": keys}
        except urllib.error.HTTPError as error:
            results[path] = {"ok": False, "status": error.code, "error": error.reason}
        except (urllib.error.URLError, OSError, json.JSONDecodeError) as error:
            results[path] = {"ok": False, "error": str(error)}
    return results
