"""控制台页面。

四个页面各自只读一份状态：站台页看门区与布局、列车页看到发与对位、门控页看开闭
与锁定、告警页看故障与审计。页面不做任何写操作，动作一律走 ``/api/...`` 接口，
避免浏览器刷新就把现场设备带动一次。

未认证访问任何页面都会退到 :func:`render_login_page`：页面本身只有一段 JS，用
API Key 换会话 Cookie（``HttpOnly`` 由登录响应的 ``Set-Cookie`` 下发），之后
浏览器靠会话访问，凭据不落 JS 可读存储。
"""

from __future__ import annotations

from html import escape

from ..access.identity import Principal
from ..app import Platform

PAGE_PATHS: tuple[str, ...] = ("/", "/trains", "/doors", "/alarms")

# 审计明细只对调度及以上可见，与 /api/audit 的策略保持一致。
_AUDIT_ROLES = ("dispatcher", "supervisor")

_STYLE = """
body { font-family: ui-sans-serif, system-ui, sans-serif; margin: 0; background: #101820; color: #e8eef5; }
header { padding: 14px 20px; background: #18222e; border-bottom: 1px solid #243447; }
nav a { color: #8ecdf7; margin-right: 14px; text-decoration: none; }
main { padding: 18px 20px 40px; }
table { border-collapse: collapse; width: 100%; margin-bottom: 18px; }
th, td { border: 1px solid #243447; padding: 6px 10px; text-align: left; font-size: 14px; }
th { background: #18232f; }
.alarm { color: #ff8d8d; font-weight: 600; }
.ok { color: #7ee787; }
.warn { color: #f0c674; }
"""

_NAV: tuple[tuple[str, str], ...] = (
    ("/", "站台"),
    ("/trains", "列车"),
    ("/doors", "门控"),
    ("/alarms", "告警"),
)


def _table(title: str, rows: list[tuple[str, object]]) -> str:
    """渲染一张两列数据表。"""

    body = "".join(
        f"<tr><th>{escape(str(key))}</th><td>{escape(str(value))}</td></tr>" for key, value in rows
    )
    return f"<h2>{escape(title)}</h2><table>{body}</table>"


def _shell(title: str, body: str) -> str:
    """套上页头与导航。"""

    nav = "".join(f'<a href="{path}">{label}</a>' for path, label in _NAV)
    return (
        '<!doctype html><html lang="zh"><head><meta charset="utf-8">'
        f"<title>{escape(title)}</title><style>{_STYLE}</style></head>"
        f'<body><header><strong>{escape(title)}</strong><nav style="margin-top:8px">{nav}</nav>'
        f"</header><main>{body}</main></body></html>"
    )


def _station_page(platform: Platform) -> str:
    """站台页：门区、布局与映射修订。"""

    status = platform.status()
    rows: list[tuple[str, object]] = [
        ("线路", status["line"]),
        ("站台数", len(status["stations"])),
        ("门区总数", sum(len(item["door_groups"]) for item in status["stations"])),
        ("映射重排次数", platform.mappings.rewrites),
    ]
    body = _table("线路概览", rows)
    body += _table(
        "站台与门区",
        [
            (item["id"], f"{item['name']} 门区 {len(item['door_groups'])} 个")
            for item in status["stations"]
        ]
        or [("暂无", "-")],
    )
    views = [platform.station_view(item["id"]) for item in status["stations"]]
    body += _table(
        "布局与映射",
        [(item["station"]["id"], f"修订 {item['revision']} 跨度 {item['span_m']} m") for item in views]
        or [("暂无", "-")],
    )
    return _shell("站台控制台", body)


def _train_page(platform: Platform) -> str:
    """列车页：到发、对位与灯位。"""

    status = platform.status()
    views = [platform.train_view(train_id) for train_id in status["trains"]]
    body = _table(
        "在线列车",
        [
            (
                item["train"]["id"],
                f"{item['train']['station']} 位置 {item['state']['position_m']} m 灯位 {item['aspect']}",
            )
            for item in views
            if item["train"]
        ]
        or [("暂无", "-")],
    )
    body += _table(
        "对位与车门",
        [
            (
                item["state"]["train_id"],
                f"对位 {'已落盘' if item['state']['aligned'] else '未落盘'} 车门 {'开' if item['state']['doors_open'] else '关'}",
            )
            for item in views
        ]
        or [("暂无", "-")],
    )
    body += _table(
        "门控队列",
        [
            (
                item["state"]["train_id"],
                f"排队 {item['doors']['queued']} 条 发车 {'是' if item['doors']['departed'] else '否'}",
            )
            for item in views
        ]
        or [("暂无", "-")],
    )
    return _shell("列车控制台", body)


def _door_page(platform: Platform) -> str:
    """门控页：开闭、锁定与批量上限。"""

    status = platform.status()
    report = status["door_report"]
    body = _table(
        "门控总览",
        [
            ("累计开门", report["opens"]),
            ("累计关门", report["closes"]),
            ("批量上限", report["batch_limit"]),
            ("排队指令", report["queued"]),
            ("锁定门数", report["locked"]),
        ],
    )
    body += _table(
        "门区状态",
        [
            (
                item["id"],
                f"{item['station']} {item['group']} {'开' if item['open'] else '关'}{' 已锁' if item['locked'] else ''}",
            )
            for item in status["doors"][:24]
        ]
        or [("暂无", "-")],
    )
    body += _table(
        "站台开门压力",
        [
            (item["station_id"], f"开 {item['open_count']} / 上限 {item['limit']}")
            for item in report["stations"]
        ]
        or [("暂无", "-")],
    )
    return _shell("门控控制台", body)


def _alarm_page(platform: Platform, principal: Principal | None = None) -> str:
    """告警页：故障、锁定比例与审计时间线。"""

    can_see_audit = principal is not None and principal.role in _AUDIT_ROLES
    status = platform.status()
    interlock = status["interlock"]
    audit = status["audit"]
    body = _table(
        "联锁与故障",
        [
            ("活动故障", ", ".join(interlock["faults_active"]) or "-"),
            ("锁定门数", interlock["locked_count"]),
            ("锁定比例", interlock["locked_ratio"]),
            ("可发车", "是" if interlock["can_release_depart"] else "否"),
            ("审计条数", audit["entries"] if can_see_audit else "需调度及以上权限"),
            ("审计分段", audit["segments"] if can_see_audit else "—"),
        ],
    )
    body += _table(
        "间隙探测",
        [
            (item["train_id"], f"{item['state'] or '未探测'} {'已确认' if item['clear'] else ''}")
            for item in status["gaps"]["trains"]
        ]
        or [("暂无", "-")],
    )
    if can_see_audit:
        timeline = platform.snapshot()["timeline"]
        body += _table(
            "最近审计",
            [(f"{item['step']}. {item['kind']}", f"{item['train_id']} {item['station_id']}") for item in timeline]
            or [("暂无", "-")],
        )
    else:
        body += "<h2>最近审计</h2><p class='warn'>审计明细仅对调度及以上角色开放。</p>"
    return _shell("告警控制台", body)


_RENDERERS = {
    "/": _station_page,
    "/trains": _train_page,
    "/doors": _door_page,
    "/alarms": _alarm_page,
}


def render_page(path: str, platform: Platform, principal: Principal | None = None) -> str | None:
    """渲染一个页面；路径不是页面时返回 ``None``。

    传入已认证主体时按角色过滤敏感区块（审计明细）；不传时按旧行为渲染，供
    进程内自检使用。
    """

    renderer = _RENDERERS.get(path)
    if renderer is None:
        return None
    if renderer is _alarm_page:
        return renderer(platform, principal)
    return renderer(platform)


def render_login_page(next_path: str = "/") -> str:
    """渲染登录页：输入 API Key，换取会话 Cookie 后跳回原页面。"""

    target = escape(next_path if next_path.startswith("/") else "/")
    script = """
async function login(event) {
  event.preventDefault();
  const key = document.getElementById('key').value;
  const box = document.getElementById('msg');
  try {
    const resp = await fetch('/api/auth/login', {
      method: 'POST',
      headers: {'Content-Type': 'application/json'},
      body: JSON.stringify({api_key: key}),
      credentials: 'same-origin'
    });
    if (!resp.ok) {
      box.textContent = '登录失败：凭据无效';
      box.className = 'alarm';
      return;
    }
    window.location = TARGET;
  } catch (err) {
    box.textContent = '登录失败：' + err;
    box.className = 'alarm';
  }
}
""".replace("TARGET", repr(target))
    body = (
        '<h2>控制台登录</h2>'
        '<form onsubmit="return login(event)">'
        '<p><label>API Key <input id="key" type="password" required autocomplete="off" '
        'style="width:320px"></label></p>'
        '<p><button type="submit">登录</button></p>'
        '<p id="msg" class="warn"></p>'
        "</form>"
    )
    html = _shell("控制台登录", body)
    return html.replace("</body>", f"<script>{script}</script></body>")
