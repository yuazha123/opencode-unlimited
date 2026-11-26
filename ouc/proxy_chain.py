"""Multi-egress proxy router: WARP, Tor, custom SOCKS5/HTTP, and block relays.

A ``relay://`` entry points at an authenticated CONNECT tunnel that hides TLS;
only the source address changes.  Outbound sockets are created through
injectable factories in tests.
"""

from __future__ import annotations

import base64
import http.client
import json
import os
import socket
import ssl
import sys
import urllib.parse
from typing import Callable, Literal

from . import common

EgressType = Literal["warp", "tor", "custom", "clean"]
EGRESS_CONFIG_FILE = common.LANE_DIR / "egress_mode.json"
RELAY_INSECURE_FLAG = common.LANE_DIR / "relay_insecure.flag"
PROXY_INDEX_FILE = common.LANE_DIR / "custom_proxy_index.txt"

SCHEMES = {"socks5", "socks5h", "http", "https", "relay", "relayplain"}


def relay_tls_insecure() -> bool:
    return os.environ.get("OUC_RELAY_INSECURE") == "1" or RELAY_INSECURE_FLAG.is_file()


def relay_ssl_context() -> ssl.SSLContext:
    if relay_tls_insecure():
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        return ctx
    return ssl.create_default_context()


def get_default_warp_scope() -> str:
    return "tun" if sys.platform == "win32" else "isolated"


def get_egress_config() -> dict:
    default_scope = get_default_warp_scope()
    cfg = common.read_json(EGRESS_CONFIG_FILE, {})
    if not isinstance(cfg, dict):
        cfg = {}
    cfg.setdefault("warp_scope", default_scope)
    cfg.setdefault("mode", "warp")
    cfg.setdefault("custom_proxy", "127.0.0.1:10808")
    cfg.setdefault("custom_type", "socks5")
    return cfg


def set_egress_config(
    mode: EgressType,
    custom_proxy: str = "127.0.0.1:10808",
    custom_type: str = "socks5",
    warp_scope: str | None = None,
) -> dict:
    common.ensure_dirs()
    scope = get_default_warp_scope() if not warp_scope or not warp_scope.strip() else (
        "tun" if warp_scope.strip().lower() == "tun" else "isolated"
    )
    cfg = {
        "mode": mode,
        "warp_scope": scope,
        "custom_proxy": custom_proxy.strip(),
        "custom_type": custom_type.lower().strip(),
    }
    common.write_json(EGRESS_CONFIG_FILE, cfg, indent=2)
    try:
        PROXY_INDEX_FILE.write_text("0", encoding="utf-8")
    except OSError:
        pass
    return cfg


def parse_proxy_entry(raw: str, default_type: str = "socks5") -> dict | None:
    """Parse ``[scheme://][user:pass@]host:port`` including relay URLs."""
    text = (raw or "").strip()
    if not text:
        return None
    scheme = ""
    if "://" in text:
        scheme, text = text.split("://", 1)
        scheme = scheme.lower().strip()
    text = text.strip().rstrip("/")
    username = ""
    password = ""
    if "@" in text:
        userinfo, text = text.rsplit("@", 1)
        username, _, password = userinfo.partition(":")
        username = urllib.parse.unquote(username)
        password = urllib.parse.unquote(password)
    if ":" not in text:
        return None
    host, _, port_raw = text.rpartition(":")
    try:
        port = int(port_raw)
    except ValueError:
        return None
    if not 1 <= port <= 65535:
        return None
    kind = scheme or default_type.lower().strip()
    if kind not in SCHEMES:
        return None
    return {"type": kind, "host": host, "port": port, "username": username, "password": password, "raw": raw}


def parse_proxy_specs(value: str, default_type: str = "socks5") -> list[dict]:
    """Split on newlines, commas, semicolons, or whitespace."""
    import re

    chunks = [part.strip() for part in re.split(r"[\s,;]+", value or "") if part.strip()]
    specs = []
    for chunk in chunks:
        spec = parse_proxy_entry(chunk, default_type)
        if spec is not None:
            specs.append(spec)
    return specs


def parse_proxy_list(value: str) -> list[tuple[str, int]]:
    return [(s["host"], s["port"]) for s in parse_proxy_specs(value)]


def _proxy_index() -> int:
    try:
        return max(0, int(PROXY_INDEX_FILE.read_text(encoding="utf-8").strip()))
    except (OSError, ValueError):
        return 0


def _set_index(index: int) -> None:
    try:
        PROXY_INDEX_FILE.parent.mkdir(parents=True, exist_ok=True)
        PROXY_INDEX_FILE.write_text(str(index), encoding="utf-8")
    except OSError:
        pass


def current_spec() -> dict | None:
    cfg = get_egress_config()
    specs = parse_proxy_specs(str(cfg.get("custom_proxy", "")), str(cfg.get("custom_type", "socks5")))
    if not specs:
        return None
    return specs[_proxy_index() % len(specs)]


def is_relay_mode() -> bool:
    spec = current_spec()
    return bool(spec and spec["type"] in ("relay", "relayplain"))


def get_current_custom_proxy() -> tuple[str, int, int, int]:
    cfg = get_egress_config()
    specs = parse_proxy_specs(str(cfg.get("custom_proxy", "")), str(cfg.get("custom_type", "socks5")))
    if not specs:
        return "", 0, 0, 0
    index = _proxy_index() % len(specs)
    return specs[index]["host"], specs[index]["port"], index, len(specs)


def advance_custom_proxy() -> int:
    cfg = get_egress_config()
    specs = parse_proxy_specs(str(cfg.get("custom_proxy", "")), str(cfg.get("custom_type", "socks5")))
    if not specs:
        return 0
    index = (_proxy_index() + 1) % len(specs)
    _set_index(index)
    return index


def basic_auth_header(username: str, password: str) -> str:
    token = base64.b64encode(f"{username}:{password}".encode("utf-8")).decode("ascii")
    return f"Proxy-Authorization: Basic {token}\r\n"


def open_http_proxy_tunnel(
    host: str,
    port: int,
    proxy_host: str,
    proxy_port: int,
    *,
    username: str = "",
    password: str = "",
    timeout: float = 10.0,
    connect: Callable | None = None,
) -> socket.socket:
    connect = connect or socket.create_connection
    sock = connect((proxy_host, proxy_port), timeout=timeout)
    try:
        auth = basic_auth_header(username, password) if username else ""
        request = (
            f"CONNECT {host}:{port} HTTP/1.1\r\n"
            f"Host: {host}:{port}\r\n{auth}Proxy-Connection: Keep-Alive\r\n\r\n"
        )
        sock.sendall(request.encode("utf-8"))
        response = bytearray()
        while b"\r\n\r\n" not in response and len(response) < 65536:
            chunk = sock.recv(4096)
            if not chunk:
                break
            response.extend(chunk)
        head = bytes(response).split(b"\r\n\r\n", 1)[0].decode("latin-1", "replace")
        status = head.split("\r\n", 1)[0]
        if " 200 " not in status:
            raise ConnectionError(f"HTTP proxy refused CONNECT: {status}")
        return sock
    except Exception:
        sock.close()
        raise


def relay_api_request(
    spec: dict,
    path: str,
    *,
    opener: Callable | None = None,
    timeout: float = 10.0,
) -> dict:
    """Call the relay control API (``/api/state`` or ``/api/rotate``)."""
    scheme = "https" if spec["type"] == "relay" else "http"
    url = f"{scheme}://{spec['host']}:{spec['port']}{path}"
    request = urllib.request.Request(url)
    token = spec.get("password", "")
    if token:
        request.add_header("Authorization", f"Bearer {token}")
    context = None if scheme == "http" else relay_ssl_context()
    open_url = opener or urllib.request.urlopen
    try:
        with (open_url(request, timeout=timeout, context=context) if context else open_url(request, timeout=timeout)) as response:  # type: ignore[misc]
            payload = response.read(65536).decode("utf-8", "replace")
        data = json.loads(payload)
        return data if isinstance(data, dict) else {}
    except Exception as exc:
        return {"ok": False, "error": str(exc)}


def relay_state(spec: dict, **kwargs) -> dict:
    return relay_api_request(spec, "/api/state", **kwargs)


def rotate_relay(spec: dict, **kwargs) -> dict:
    return relay_api_request(spec, "/api/rotate", **kwargs)


def relay_spec_url(spec: dict) -> str:
    """The client string the relay prints, e.g. ``relay://block:TOKEN@host:4443``."""
    token = urllib.parse.quote(spec.get("password", ""), safe="")
    return f"{spec['type']}://block:{token}@{spec['host']}:{spec['port']}"


def open_multi_egress_upstream(
    host: str,
    port: int,
    *,
    mode: str | None = None,
    connect: Callable | None = None,
    socks_opener: Callable | None = None,
    timeout: float = 15.0,
) -> socket.socket:
    """Open an outbound connection using the active egress mode."""
    cfg = get_egress_config()
    mode = mode or str(cfg.get("mode", "warp"))
    connect = connect or socket.create_connection
    if mode == "custom":
        spec = current_spec()
        if spec is None:
            raise ConnectionError("no custom proxy configured")
        if spec["type"] in ("relay", "relayplain"):
            state = relay_state(spec)
            if not state.get("ok", True):
                raise ConnectionError(str(state.get("error", "relay unavailable")))
        if spec["type"] in ("http", "https"):
            return open_http_proxy_tunnel(
                host, port, spec["host"], spec["port"],
                username=spec["username"], password=spec["password"],
                timeout=timeout, connect=connect,
            )
        if socks_opener is not None:
            return socks_opener(host, port, spec["host"], spec["port"], spec["username"], spec["password"])
        raise ConnectionError("SOCKS5 opener not supplied")
    if mode == "warp":
        return connect((host, port), timeout=timeout)
    raise ConnectionError(f"unsupported egress mode for direct dial: {mode}")
