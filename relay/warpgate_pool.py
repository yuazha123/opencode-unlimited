"""WarpGate control-plane client and SOCKS5 dialer (clean rewrite).

Behavioral target: ``relay/warpgate_pool.py``.  Every control call and socket
creation is injectable, so no test talks to a real WarpGate or WARP exit.
"""

from __future__ import annotations

import ipaddress
import json
import socket
import urllib.parse
from dataclasses import dataclass, field
from typing import Any, Callable

OK_CODE = "00000"
CODE_UNAUTHORIZED = "A0001"
CODE_RATE_LIMITED = "A0002"
TRACE_HOST = "www.cloudflare.com"
TRACE_REQUEST = (
    b"GET /cdn-cgi/trace HTTP/1.1\r\n"
    b"Host: www.cloudflare.com\r\n"
    b"User-Agent: blockrelay\r\n"
    b"Connection: close\r\n\r\n"
)


class WarpGateError(RuntimeError):
    def __init__(self, message: str, code: str = "", status: int = 0) -> None:
        super().__init__(message)
        self.code = code
        self.status = status

    @property
    def rate_limited(self) -> bool:
        return self.code == CODE_RATE_LIMITED or self.status == 429

    @property
    def unauthorized(self) -> bool:
        return self.code == CODE_UNAUTHORIZED or self.status == 401


@dataclass(frozen=True)
class Instance:
    name: str
    host: str
    port: int
    username: str = ""
    password: str = ""
    advertised_ip: str = ""
    session_id: str = ""

    @property
    def endpoint(self) -> str:
        return f"{self.host}:{self.port}"

    @property
    def proxy_url(self) -> str:
        auth = ""
        if self.username:
            auth = (
                urllib.parse.quote(self.username, safe="")
                + ":"
                + urllib.parse.quote(self.password, safe="")
                + "@"
            )
        return f"socks5h://{auth}{self.host}:{self.port}"


@dataclass
class PoolStats:
    instances: int = 0
    available: int = 0
    in_use: int = 0
    reachable: bool = False
    detail: str = ""
    raw: dict[str, Any] = field(default_factory=dict)


def split_credentials(value: str) -> tuple[str, str, str]:
    parsed = urllib.parse.urlsplit(value if "://" in value else f"http://{value}")
    user = urllib.parse.unquote(parsed.username or "")
    password = urllib.parse.unquote(parsed.password or "")
    clean = urllib.parse.urlunsplit((parsed.scheme, parsed.netloc.rsplit("@", 1)[-1], parsed.path, parsed.query, parsed.fragment))
    return user, password, clean


def index_from_name(name: str) -> int | None:
    if not name.startswith("warp-") or not name[5:].isdigit():
        return None
    return int(name[5:])


def block_of(address: str) -> str:
    """The egress block the upstream limiter meters: /64 for IPv6, /32 for IPv4."""
    try:
        addr = ipaddress.ip_address(address.strip())
    except ValueError:
        return ""
    width = 64 if addr.version == 6 else 32
    return str(ipaddress.ip_network(f"{addr}/{width}", strict=False).network_address)


class WarpGatePool:
    """Client for one WarpGate control plane.

    ``request`` is called as ``request(method, path, payload)`` and returns a
    decoded JSON object.  Tests inject it; production uses http.client.
    """

    def __init__(
        self,
        url: str,
        username: str = "",
        password: str = "",
        *,
        api_key: str = "",
        sticky_minutes: int = 1440,
        timeout: float = 10.0,
        verify_tls: bool = True,
        request: Callable | None = None,
    ) -> None:
        user, pw, clean = split_credentials(url)
        self.url = clean.rstrip("/")
        self.username = username or user
        self.password = password or pw
        self.api_key = api_key
        self.sticky_minutes = sticky_minutes
        self.timeout = timeout
        self.verify_tls = verify_tls
        self._request = request or self._http_request

    def _http_request(self, method: str, path: str, payload: dict | None = None) -> dict:
        import http.client

        parsed = urllib.parse.urlsplit(self.url)
        host = parsed.hostname or "127.0.0.1"
        port = parsed.port or (443 if parsed.scheme == "https" else 80)
        body = json.dumps(payload or {}).encode("utf-8")
        headers = {"Content-Type": "application/json", "Content-Length": str(len(body))}
        if self.username:
            import base64
            token = base64.b64encode(f"{self.username}:{self.password}".encode()).decode()
            headers["Authorization"] = f"Basic {token}"
        if self.api_key:
            headers["X-API-Key"] = self.api_key
        conn = (
            http.client.HTTPSConnection(host, port, timeout=self.timeout)
            if parsed.scheme == "https"
            else http.client.HTTPConnection(host, port, timeout=self.timeout)
        )
        try:
            conn.request(method, path, body=body, headers=headers)
            response = conn.getresponse()
            raw = response.read(65536).decode("utf-8", "replace")
            data = json.loads(raw) if raw else {}
            if response.status >= 400 or str(data.get("code", OK_CODE)) != OK_CODE:
                raise WarpGateError(str(data.get("msg", "control plane failure")), str(data.get("code", "")), response.status)
            return data
        finally:
            conn.close()

    def stats(self) -> PoolStats:
        data = self._request("GET", "/api/instances")
        payload = data.get("data") if isinstance(data.get("data"), dict) else data
        instances = payload.get("instances", []) if isinstance(payload, dict) else []
        return PoolStats(
            instances=len(instances),
            available=sum(1 for i in instances if str(i.get("status", "")).lower() in ("idle", "available")),
            in_use=sum(1 for i in instances if str(i.get("status", "")).lower() in ("busy", "in_use")),
            reachable=True,
            raw=payload if isinstance(payload, dict) else {},
        )

    def instances(self) -> list[Instance]:
        data = self._request("GET", "/api/instances")
        payload = data.get("data") if isinstance(data.get("data"), dict) else data
        items = payload.get("instances", []) if isinstance(payload, dict) else []
        result = []
        for item in items:
            if not isinstance(item, dict):
                continue
            host = str(item.get("host") or item.get("proxy_host") or "")
            port = int(item.get("port") or item.get("socks_port") or 0)
            if not host or not port:
                continue
            result.append(Instance(
                name=str(item.get("name", "")), host=host, port=port,
                username=str(item.get("username", "")), password=str(item.get("password", "")),
                advertised_ip=str(item.get("ip", "")), session_id=str(item.get("session_id", "")),
            ))
        return result

    def acquire(self, label: str = "") -> Instance | None:
        data = self._request("POST", "/api/acquire", {"label": label, "sticky_minutes": self.sticky_minutes})
        payload = data.get("data") if isinstance(data.get("data"), dict) else data
        if not isinstance(payload, dict):
            return None
        host = str(payload.get("host") or payload.get("proxy_host") or "")
        port = int(payload.get("port") or payload.get("socks_port") or 0)
        if not host or not port:
            return None
        return Instance(
            name=str(payload.get("name", "")), host=host, port=port,
            username=str(payload.get("username", "")), password=str(payload.get("password", "")),
            advertised_ip=str(payload.get("ip", "")), session_id=str(payload.get("session_id", "")),
        )

    def release(self, name: str) -> None:
        self._request("POST", "/api/release", {"name": name})


def socks5_connect(
    host: str,
    port: int,
    proxy_host: str,
    proxy_port: int,
    username: str = "",
    password: str = "",
    *,
    connect: Callable | None = None,
    timeout: float = 10.0,
) -> socket.socket:
    """Establish a SOCKS5 CONNECT tunnel with optional username/password auth."""
    connect = connect or socket.create_connection
    sock = connect((proxy_host, proxy_port), timeout=timeout)
    try:
        methods = [0x02] if username else [0x00]
        sock.sendall(bytes([0x05, len(methods), *methods]))
        chosen = sock.recv(2)
        if len(chosen) < 2 or chosen[0] != 0x05:
            raise ConnectionError("bad SOCKS5 greeting")
        if chosen[1] == 0xFF:
            raise ConnectionError("no acceptable SOCKS5 method")
        if chosen[1] == 0x02:
            user_b = username.encode("utf-8")[:255]
            pass_b = password.encode("utf-8")[:255]
            auth = bytes([0x01, len(user_b)]) + user_b + bytes([len(pass_b)]) + pass_b
            sock.sendall(auth)
            reply = sock.recv(2)
            if len(reply) < 2 or reply[1] != 0:
                raise ConnectionError("SOCKS5 authentication rejected")
        try:
            addr = socket.inet_aton(host)
            atyp = 0x01
        except OSError:
            addr = host.encode("idna")
            atyp = 0x03
        request = bytes([0x05, 0x01, 0x00, atyp])
        if atyp == 0x03:
            request += bytes([len(addr)]) + addr
        else:
            request += addr
        request += port.to_bytes(2, "big")
        sock.sendall(request)
        head = sock.recv(4)
        if len(head) < 4 or head[1] != 0:
            raise ConnectionError("SOCKS5 CONNECT refused")
        if head[3] == 0x01:
            sock.recv(4)
        elif head[3] == 0x03:
            length = sock.recv(1)[0]
            sock.recv(length)
        elif head[3] == 0x04:
            sock.recv(16)
        sock.recv(2)
        return sock
    except Exception:
        sock.close()
        raise


def probe_egress(sock: socket.socket) -> str:
    sock.sendall(TRACE_REQUEST)
    body = bytearray()
    while len(body) < 65536:
        chunk = sock.recv(4096)
        if not chunk:
            break
        body.extend(chunk)
        if b"\r\n\r\n" in body and b"ip=" in body:
            break
    text = body.decode("utf-8", "replace")
    for line in text.splitlines():
        if line.startswith("ip="):
            return line.partition("=")[2].strip()
    return ""
