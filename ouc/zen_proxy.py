"""Local HTTP CONNECT proxy with a bounded health-event trail.

The relay is unbuffered, uses TCP_NODELAY/keepalive, counts live tunnels, and
distinguishes a failed route from a reset after response bytes started
(``stream_reset``).
"""

from __future__ import annotations

import select
import socket
import socketserver
import threading
import time
from contextlib import contextmanager
from typing import Callable

from . import common, proxy_chain

PINNED_HOSTS = frozenset({
    "opencode.ai", "www.opencode.ai", "api.opencode.ai",
    "opencode.com", "www.opencode.com", "api.opencode.com",
    "inference.opencode.ai",
})
PROXY_STATUS_FILE = common.LANE_DIR / "proxy_status.json"
PROXY_LOG_FILE = common.LANE_DIR / "proxy.log"
FALLBACK_FLAG = common.LANE_DIR / "fallback.flag"

ERROR_KINDS = frozenset({
    "error", "reset", "stream_reset", "connect_fail",
    "edge_fail", "fallback", "bind_fail",
})
LOG_KINDS = ERROR_KINDS | {"repair", "start", "hold"}

STATUS_LOCK = threading.Lock()
_TUNNEL_LOCK = threading.Lock()
_ACTIVE_TUNNELS = 0


def read_status() -> dict:
    data = common.read_json(PROXY_STATUS_FILE, {})
    return data if isinstance(data, dict) else {}


def write_status(data: dict) -> None:
    common.write_json(PROXY_STATUS_FILE, data)


def record_event(kind: str, detail: str, host: str = "", edge: str = "") -> dict:
    now = int(time.time())
    entry = {
        "ts": now,
        "kind": kind,
        "detail": str(detail)[:400],
        "host": str(host)[:120],
        "edge": str(edge)[:120],
    }
    with STATUS_LOCK:
        data = read_status()
        recent = [e for e in data.get("recent", []) if now - int(e.get("ts", 0)) <= 900]
        recent.append(entry)
        data["recent"] = recent[-30:]
        data["last_event"] = entry
        if kind in ERROR_KINDS:
            data["last_error"] = entry["detail"]
            data["last_error_ts"] = now
        if edge:
            data["edge"] = edge
        if kind == "fallback":
            data["fallback_ts"] = now
        if kind == "edge_fail" and edge:
            data["last_bad_edge"] = edge
        write_status(data)
    if kind in LOG_KINDS:
        common.append_log(PROXY_LOG_FILE, f"{kind} {detail} host={host} edge={edge}")
    return entry


@contextmanager
def tunnel():
    global _ACTIVE_TUNNELS
    with _TUNNEL_LOCK:
        _ACTIVE_TUNNELS += 1
        count = _ACTIVE_TUNNELS
    data = read_status()
    data["tunnels"] = count
    write_status(data)
    try:
        yield
    finally:
        with _TUNNEL_LOCK:
            _ACTIVE_TUNNELS = max(0, _ACTIVE_TUNNELS - 1)
            count = _ACTIVE_TUNNELS
        data = read_status()
        data["tunnels"] = count
        write_status(data)


def active_tunnels() -> int:
    with _TUNNEL_LOCK:
        return _ACTIVE_TUNNELS


def proxy_status() -> dict:
    data = read_status()
    data.setdefault("tunnels", active_tunnels())
    data.setdefault("recent", [])
    return data


def _configure(sock: socket.socket) -> None:
    try:
        sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_KEEPALIVE, 1)
    except OSError:
        pass


def relay_bytes(client: socket.socket, upstream: socket.socket, *, chunk: int = 65536) -> str:
    """Bidirectional copy. Returns '' or 'stream_reset' for health reporting."""
    sockets = [client, upstream]
    started = False
    outcome = ""
    try:
        while True:
            readable, _, _ = select.select(sockets, [], [], 1.0)
            if not readable:
                continue
            for src in readable:
                dst = upstream if src is client else client
                try:
                    data = src.recv(chunk)
                except (ConnectionResetError, OSError):
                    outcome = "stream_reset" if started else "reset"
                    return outcome
                if not data:
                    return outcome
                if src is upstream:
                    started = True
                try:
                    dst.sendall(data)
                except (BrokenPipeError, ConnectionResetError, OSError):
                    return "stream_reset" if started else "reset"
    finally:
        for sock in sockets:
            try:
                sock.close()
            except OSError:
                pass


def default_open_upstream(host: str, port: int, **kwargs) -> socket.socket:
    cfg = proxy_chain.get_egress_config()
    return proxy_chain.open_multi_egress_upstream(host, port, mode=str(cfg.get("mode", "warp")))


class ProxyHandler(socketserver.BaseRequestHandler):
    open_upstream: Callable = staticmethod(default_open_upstream)

    def handle(self) -> None:
        client: socket.socket = self.request
        _configure(client)
        client.settimeout(30.0)
        try:
            request = b""
            while b"\r\n\r\n" not in request and len(request) < 65536:
                piece = client.recv(4096)
                if not piece:
                    return
                request += piece
            line = request.split(b"\r\n", 1)[0].decode("latin-1", "replace")
            parts = line.split()
            if len(parts) < 3 or parts[0].upper() != "CONNECT":
                client.sendall(b"HTTP/1.1 405 Method Not Allowed\r\n\r\n")
                return
            target = parts[1]
            if ":" not in target:
                client.sendall(b"HTTP/1.1 400 Bad Request\r\n\r\n")
                return
            host, _, port_text = target.rpartition(":")
            port = int(port_text)
            host = host.lower()
            if host in PINNED_HOSTS:
                record_event("hold", "pinned host routed", host=host)
            upstream = self.open_upstream(host, port)
            _configure(upstream)
            client.sendall(b"HTTP/1.1 200 Connection Established\r\n\r\n")
            with tunnel():
                outcome = relay_bytes(client, upstream)
            if outcome:
                record_event(outcome, "client stream ended", host=host)
        except Exception as exc:
            record_event("connect_fail", str(exc)[:300])
            try:
                client.sendall(b"HTTP/1.1 502 Bad Gateway\r\n\r\n")
            except OSError:
                pass
        finally:
            try:
                client.close()
            except OSError:
                pass


class ThreadedProxy(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True


def start_proxy_server(
    host: str = "127.0.0.1",
    port: int = 0,
    *,
    open_upstream: Callable | None = None,
) -> tuple[ThreadedProxy, int]:
    handler = ProxyHandler
    if open_upstream is not None:
        handler = type("InjectedProxyHandler", (ProxyHandler,), {"open_upstream": staticmethod(open_upstream)})
    server = ThreadedProxy((host, port), handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True, name="ouc-proxy")
    thread.start()
    record_event("start", f"proxy listening on {host}:{server.server_address[1]}")
    return server, int(server.server_address[1])


def stop_proxy(server: ThreadedProxy) -> None:
    server.shutdown()
    server.server_close()
