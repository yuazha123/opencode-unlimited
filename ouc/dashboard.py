"""Small standard-library dashboard served over loopback HTTP with a JSON API.

No service, autostart, or remote access is configured.
"""

from __future__ import annotations

import json
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Callable
from urllib.parse import urlsplit

from . import auto_resume, common, desktop_brand, proxy_chain, workers, zen_proxy

PAGE = """<!doctype html>
<html lang="en"><head><meta charset="utf-8"><title>Opencode Unlimited</title>
<style>body{font:14px system-ui;background:#11151c;color:#e6edf3;margin:0;padding:24px}
button{background:#238636;color:#fff;border:0;border-radius:6px;padding:8px 12px;cursor:pointer}
pre{background:#0b0f14;padding:12px;border-radius:6px;overflow:auto}label{margin-right:16px}</style></head>
<body><h1>Opencode Unlimited</h1>
<p id="status">Loading…</p>
<label>Egress mode <select id="mode"><option>warp</option><option>tor</option>
<option>custom</option><option>clean</option></select></label>
<button id="apply_mode">Apply mode</button>
<button id="hop">Rotate now</button>
<button id="deep_reset">Clear lockouts</button>
<button id="brand_status">Desktop copy status</button>
<pre id="log"></pre>
<script>
async function get(p){return (await fetch(p)).json()}
async function post(p,b){return (await fetch(p,{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(b||{})})).json()}
async function refresh(){const s=await get('/api/state');document.getElementById('status').textContent=
 'mode='+s.mode+' · tunnels='+s.proxy.tunnels+' · last event='+(s.proxy.last_event?s.proxy.last_event.kind:'none');
 document.getElementById('mode').value=s.mode;
 document.getElementById('log').textContent=(s.proxy.recent||[]).map(e=>e.kind+': '+e.detail).join('\\n')}
document.getElementById('apply_mode').onclick=async()=>{await post('/api/mode',{mode:document.getElementById('mode').value});refresh()};
document.getElementById('hop').onclick=async()=>{await post('/api/rotate',{});refresh()};
document.getElementById('deep_reset').onclick=async()=>{await post('/api/lockouts',{});refresh()};
document.getElementById('brand_status').onclick=async()=>{alert(JSON.stringify(await post('/api/desktop-brand',{})))};
refresh();setInterval(refresh,5000);
</script></body></html>"""


class DashboardApi:
    """Backend controller exposed to the pages served by :mod:`dashboard`."""

    def __init__(self, rotator: Callable[[], tuple[bool, str]] | None = None) -> None:
        self.rotator = rotator or (lambda: (False, "no rotator configured"))

    def get_state(self) -> dict:
        return {
            "mode": str(proxy_chain.get_egress_config().get("mode", "warp")),
            "proxy": zen_proxy.proxy_status(),
            "guard": workers.load_state(),
            "auto_resume": auto_resume.is_auto_resume_enabled(),
        }

    def health(self) -> list[dict]:
        issues = []
        age = common.heartbeat_age(workers.GUARD_HEARTBEAT)
        if age is None or age > 300:
            issues.append({"id": "guard-down", "text": "Guard heartbeat is missing", "fix": "worker-restart"})
        age = common.heartbeat_age(workers.KEEPER_HEARTBEAT)
        if age is None or age > 300:
            issues.append({"id": "keeper-down", "text": "Keeper heartbeat is missing", "fix": "worker-restart"})
        status = zen_proxy.read_status()
        if status.get("fallback_ts"):
            issues.append({"id": "fallback", "text": "Using a direct connection", "fix": "repair-route"})
        return issues

    def fix_issue(self, issue_id: str) -> dict:
        if issue_id == "repair-route":
            zen_proxy.record_event("repair", "route repair requested")
            return {"ok": True}
        if issue_id == "worker-restart":
            return {"ok": False, "message": "automatic service install is disabled"}
        return {"ok": False, "message": "unknown issue"}

    def set_egress_mode(self, mode: str) -> dict:
        if mode not in ("warp", "tor", "custom", "clean"):
            return {"ok": False, "message": "bad mode"}
        return {"ok": True, "config": proxy_chain.set_egress_config(mode)}  # type: ignore[arg-type]

    def hop_now(self) -> dict:
        ok, detail = self.rotator()
        zen_proxy.record_event("hold" if not ok else "repair", f"hop: {detail}")
        return {"ok": ok, "detail": detail}

    def clear_lockouts(self) -> dict:
        return {"ok": True, "deleted": auto_resume.clear_lockouts()}

    def desktop_brand(self) -> dict:
        archive = common.LOCAL_APPDATA / "Programs" / "ai.opencode.desktop" / "resources" / "app.asar"
        return desktop_brand.status(archive)


class Handler(BaseHTTPRequestHandler):
    api: DashboardApi

    def log_message(self, fmt: str, *args) -> None:  # quiet by default
        pass

    def _send(self, payload: bytes, content_type: str, code: int = 200) -> None:
        self.send_response(code)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    def _json(self, value: dict, code: int = 200) -> None:
        self._send(json.dumps(value).encode("utf-8"), "application/json", code)

    def do_GET(self) -> None:
        path = urlsplit(self.path).path
        if path in ("/", "/index.html"):
            self._send(PAGE.encode("utf-8"), "text/html; charset=utf-8")
        elif path == "/api/state":
            self._json(self.api.get_state())
        elif path == "/api/health":
            self._json({"issues": self.api.health()})
        else:
            self._json({"ok": False, "error": "not found"}, 404)

    def do_POST(self) -> None:
        path = urlsplit(self.path).path
        try:
            length = int(self.headers.get("Content-Length", "0"))
            body = json.loads(self.rfile.read(length) or b"{}")
        except (ValueError, OSError):
            body = {}
        routes = {
            "/api/mode": lambda: self.api.set_egress_mode(str(body.get("mode", ""))),
            "/api/rotate": lambda: self.api.hop_now(),
            "/api/lockouts": lambda: self.api.clear_lockouts(),
            "/api/desktop-brand": lambda: self.api.desktop_brand(),
            "/api/fix": lambda: self.api.fix_issue(str(body.get("id", ""))),
        }
        handler = routes.get(path)
        self._json(handler() if handler else {"ok": False, "error": "not found"}, 200 if handler else 404)


def serve(host: str = "127.0.0.1", port: int = 0, *, rotator=None) -> tuple[ThreadingHTTPServer, int]:
    handler = type("BoundHandler", (Handler,), {"api": DashboardApi(rotator)})
    server = ThreadingHTTPServer((host, port), handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True, name="ouc-dashboard")
    thread.start()
    return server, int(server.server_address[1])
