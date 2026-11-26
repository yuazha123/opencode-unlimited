"""Authenticated CONNECT relay with sticky IPv6 /64 blocks (clean rewrite).

Behavioral target: ``relay/blockrelay.py``.  The relay is blind: it never
terminates TLS and never edits a request.  Clients authenticate with a token;
blocks are sticky per client and rotated on demand.  All outbound dialing and
clock reads are injectable, so tests never open a live connection.
"""

from __future__ import annotations

import argparse
import asyncio
import base64
import hashlib
import ipaddress
import json
import secrets
import socket
import sqlite3
import ssl
import sys
import time
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Callable

try:
    from . import warpgate_pool
    from .warpgate_pool import Instance, WarpGatePool
except ImportError:  # direct script execution
    import warpgate_pool  # type: ignore[no-redef]
    from warpgate_pool import Instance, WarpGatePool  # type: ignore[no-redef]

IPV6_FREEBIND = 78
BLOCK_PREFIX = 64
DEFAULT_ALLOWED_HOSTS = ["*"]


def log(message: str) -> None:
    stamp = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    print(f"{stamp} {message}", flush=True)


def utc_midnight(now: int | None = None) -> int:
    stamp = datetime.fromtimestamp(int(now or time.time()), timezone.utc)
    nxt = (stamp + timedelta(days=1)).replace(hour=0, minute=0, second=0, microsecond=0)
    return int(nxt.timestamp())


def hash_token(token: str) -> str:
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def parse_basic(value: str) -> str:
    text = (value or "").strip()
    if " " in text:
        scheme, text = text.split(" ", 1)
        if scheme.lower() not in ("basic", "bearer"):
            return ""
        text = text.strip()
    try:
        decoded = base64.b64decode(text, validate=True).decode("utf-8")
    except Exception:
        return ""
    return decoded.split(":", 1)[1] if ":" in decoded else ""


def parse_bearer(value: str) -> str:
    text = (value or "").strip()
    if text.lower().startswith("bearer "):
        return text[7:].strip()
    return text if " " not in text else ""


def host_allowed(host: str, allowed: list[str]) -> bool:
    host = (host or "").lower().rstrip(".")
    for rule in allowed:
        rule = rule.strip().lower().lstrip("*").lstrip(".")
        if rule in ("", "*"):
            return True
        if host == rule or host.endswith("." + rule):
            return True
    return False


def block_of(address: str) -> str:
    return warpgate_pool.block_of(address)


@dataclass
class Config:
    listen: str = "127.0.0.1"
    port: int = 4443
    database: str = "relay.db"
    prefixes: list[str] = field(default_factory=list)
    bind_suffix: str = "::1"
    allowed_hosts: list[str] = field(default_factory=lambda: list(DEFAULT_ALLOWED_HOSTS))
    admin_token: str = ""
    enroll_secret: str = ""
    tls_cert: str = ""
    tls_key: str = ""
    max_tunnels_per_client: int = 8
    idle_timeout: float = 300.0
    connect_timeout: float = 15.0
    public_url: str = ""
    upstream_mode: str = "prefix"
    warpgate_url: str = ""
    warpgate_username: str = ""
    warpgate_password: str = ""
    warpgate_proxy_host: str = ""
    warpgate_api_key: str = ""
    warpgate_sticky_minutes: int = 1440
    warpgate_verify_tls: bool = True
    warpgate_timeout: float = 10.0

    @property
    def blocks(self) -> list[ipaddress.IPv6Network]:
        nets = []
        for raw in self.prefixes:
            net = ipaddress.IPv6Network(str(raw).strip(), strict=False)
            if net.prefixlen > BLOCK_PREFIX:
                net = ipaddress.IPv6Network(f"{net.network_address}/{BLOCK_PREFIX}", strict=False)
            nets.append(net)
        return nets

    @property
    def uses_prefix(self) -> bool:
        return self.upstream_mode in ("prefix", "hybrid") and bool(self.prefixes)

    @property
    def uses_warpgate(self) -> bool:
        return self.upstream_mode in ("warpgate", "hybrid")

    @property
    def capacity(self) -> int:
        return sum(1 << (BLOCK_PREFIX - net.prefixlen) for net in self.blocks)

    def pool(self) -> WarpGatePool | None:
        if not self.uses_warpgate or not self.warpgate_url:
            return None
        return WarpGatePool(
            self.warpgate_url, self.warpgate_username, self.warpgate_password,
            api_key=self.warpgate_api_key, sticky_minutes=self.warpgate_sticky_minutes,
            timeout=self.warpgate_timeout, verify_tls=self.warpgate_verify_tls,
        )

    @classmethod
    def load(cls, path: Path) -> "Config":
        data = json.loads(path.read_text(encoding="utf-8"))
        tls = data.get("tls") if isinstance(data.get("tls"), dict) else {}
        upstream = data.get("upstream") if isinstance(data.get("upstream"), dict) else {}
        gate = upstream.get("warpgate") if isinstance(upstream.get("warpgate"), dict) else {}
        mode = str(upstream.get("mode", data.get("upstream_mode", "prefix"))).lower().strip()
        cfg = cls(
            listen=str(data.get("listen", "127.0.0.1")),
            port=int(data.get("port", 4443)),
            database=str(data.get("database", "relay.db")),
            prefixes=[str(x) for x in data.get("prefixes", [])],
            bind_suffix=str(data.get("bind_suffix", "::1")),
            allowed_hosts=[str(x) for x in data.get("allowed_hosts", DEFAULT_ALLOWED_HOSTS)],
            admin_token=str(data.get("admin_token", "")),
            enroll_secret=str(data.get("enroll_secret", "")),
            tls_cert=str(tls.get("cert", "")), tls_key=str(tls.get("key", "")),
            max_tunnels_per_client=int(data.get("max_tunnels_per_client", 8)),
            idle_timeout=float(data.get("idle_timeout", 300)),
            connect_timeout=float(data.get("connect_timeout", 15)),
            public_url=str(data.get("public_url", "")),
            upstream_mode=mode,
            warpgate_url=str(gate.get("url", "")),
            warpgate_username=str(gate.get("username", "")),
            warpgate_password=str(gate.get("password", "")),
            warpgate_proxy_host=str(gate.get("proxy_host", "")),
            warpgate_api_key=str(gate.get("api_key", "")),
            warpgate_sticky_minutes=int(gate.get("sticky_minutes", 1440)),
            warpgate_verify_tls=bool(gate.get("verify_tls", True)),
            warpgate_timeout=float(gate.get("timeout", 10)),
        )
        if mode not in ("prefix", "warpgate", "hybrid"):
            raise ValueError("upstream.mode must be prefix, warpgate, or hybrid")
        if cfg.uses_prefix and not cfg.prefixes:
            raise ValueError("config needs at least one IPv6 prefix")
        if not cfg.uses_prefix and not cfg.uses_warpgate:
            raise ValueError("config has no usable egress lane")
        if cfg.uses_warpgate and not cfg.warpgate_url:
            raise ValueError("upstream.warpgate.url is required")
        if cfg.listen not in ("127.0.0.1", "::1") and not (cfg.tls_cert and cfg.tls_key):
            raise ValueError("non-loopback listen requires tls.cert and tls.key")
        if not cfg.admin_token:
            raise ValueError("config needs an admin_token")
        _ = cfg.blocks
        return cfg


class NoCapacity(RuntimeError):
    """Every lane is out of unspent blocks."""


class Store:
    """Small SQLite ledger of clients, blocks, exits and settings."""

    def __init__(self, path: str | Path) -> None:
        path = str(path)
        if path != ":memory:":
            Path(path).parent.mkdir(parents=True, exist_ok=True)
        self.conn = sqlite3.connect(path, timeout=10.0, check_same_thread=False)
        self.conn.row_factory = sqlite3.Row
        self.conn.execute("PRAGMA journal_mode=WAL")
        self.conn.executescript(
            """
            CREATE TABLE IF NOT EXISTS clients(
              id TEXT PRIMARY KEY, token_hash TEXT UNIQUE NOT NULL, label TEXT,
              block TEXT, lane TEXT, enabled INTEGER NOT NULL DEFAULT 1,
              created_at INTEGER NOT NULL, last_seen INTEGER, requests INTEGER NOT NULL DEFAULT 0
            );
            CREATE TABLE IF NOT EXISTS blocks(
              block TEXT PRIMARY KEY, client_id TEXT, burnt_until INTEGER NOT NULL DEFAULT 0,
              last_used INTEGER, requests INTEGER NOT NULL DEFAULT 0
            );
            CREATE TABLE IF NOT EXISTS exits(
              name TEXT PRIMARY KEY, endpoint TEXT, block TEXT, seen INTEGER
            );
            CREATE TABLE IF NOT EXISTS settings(key TEXT PRIMARY KEY, value TEXT);
            """
        )
        self.conn.commit()

    def set_setting(self, key: str, value: str) -> None:
        self.conn.execute(
            "INSERT INTO settings(key,value) VALUES(?,?) ON CONFLICT(key) DO UPDATE SET value=excluded.value",
            (key, value),
        )
        self.conn.commit()

    def get_setting(self, key: str, default: str = "") -> str:
        row = self.conn.execute("SELECT value FROM settings WHERE key=?", (key,)).fetchone()
        return str(row["value"]) if row else default

    def create_client(self, admin_token: str, label: str, block: str = "", lane: str = "") -> tuple[str, str, str]:
        token = secrets.token_urlsafe(32)
        client_id = "cl_" + secrets.token_hex(8)
        self.conn.execute(
            "INSERT INTO clients(id,token_hash,label,block,lane,created_at) VALUES(?,?,?,?,?,?)",
            (client_id, hash_token(token), str(label)[:120], block, lane, int(time.time())),
        )
        self.conn.commit()
        return client_id, token, block

    def client_by_token(self, token: str):
        return self.conn.execute(
            "SELECT * FROM clients WHERE token_hash=? AND enabled=1", (hash_token(token),)
        ).fetchone()

    def client_by_id(self, client_id: str):
        return self.conn.execute("SELECT * FROM clients WHERE id=?", (client_id,)).fetchone()

    def list_clients(self) -> list[dict]:
        return [dict(row) for row in self.conn.execute("SELECT * FROM clients ORDER BY created_at DESC")]

    def assign(self, client_id: str, block: str, lane: str) -> None:
        old = self.client_by_id(client_id)
        if old and old["block"] and old["block"] != block:
            self.conn.execute("UPDATE blocks SET client_id=NULL WHERE block=?", (old["block"],))
        self.conn.execute(
            "INSERT INTO blocks(block,client_id) VALUES(?,?) "
            "ON CONFLICT(block) DO UPDATE SET client_id=excluded.client_id, burnt_until=0",
            (block, client_id),
        )
        self.conn.execute("UPDATE clients SET block=?, lane=? WHERE id=?", (block, lane, client_id))
        self.conn.commit()

    def mark_burnt(self, block: str) -> None:
        self.conn.execute(
            "UPDATE blocks SET client_id=NULL, burnt_until=?, last_used=? WHERE block=?",
            (int(time.time()), int(time.time()), block),
        )
        self.conn.commit()

    def touch(self, client_id: str, block: str, count: int = 1) -> None:
        now = int(time.time())
        self.conn.execute("UPDATE clients SET last_seen=?, requests=requests+? WHERE id=?", (now, count, client_id))
        self.conn.execute("UPDATE blocks SET last_used=?, requests=requests+? WHERE block=?", (now, count, block))
        self.conn.commit()

    def revoke(self, client_id: str) -> bool:
        row = self.client_by_id(client_id)
        if not row:
            return False
        self.conn.execute("UPDATE clients SET enabled=0 WHERE id=?", (client_id,))
        if row["block"]:
            self.conn.execute("UPDATE blocks SET client_id=NULL WHERE block=?", (row["block"],))
        self.conn.commit()
        return True

    def used_blocks(self) -> set[str]:
        return {str(row["block"]) for row in self.conn.execute("SELECT block FROM blocks WHERE burnt_until>0")}

    def assigned_blocks(self) -> set[str]:
        return {str(row["block"]) for row in self.conn.execute("SELECT block FROM blocks WHERE client_id IS NOT NULL")}


class Route:
    def __init__(self, block: str, lane: str, *, instance: Instance | None = None, exit_ip: str = "") -> None:
        self.block = block
        self.lane = lane
        self.instance = instance
        self.exit_ip = exit_ip


class Router:
    """Chooses and drives the egress lane for each client."""

    def __init__(
        self,
        cfg: Config,
        store: Store,
        *,
        dial: Callable | None = None,
        pool: WarpGatePool | None = None,
        clock: Callable[[], int] | None = None,
    ) -> None:
        self.cfg = cfg
        self.store = store
        self.dial = dial
        self.pool = pool if pool is not None else (cfg.pool() if cfg.uses_warpgate else None)
        self.clock = clock or (lambda: int(time.time()))

    def _free_prefix_block(self) -> str:
        used = self.store.used_blocks() | self.store.assigned_blocks()
        for net in self.cfg.blocks:
            for addr in net.iter_hosts():
                block = str(ipaddress.IPv6Network(f"{addr}/{BLOCK_PREFIX}", strict=False).network_address)
                if block not in used:
                    return block
        raise NoCapacity("no unspent /64 in the routed prefix")

    def ensure(self, client) -> Route:
        lane = self.cfg.upstream_mode
        if lane == "warpgate":
            route = self._warpgate_route(client)
        elif self.cfg.uses_prefix:
            route = Route(self._free_prefix_block(), "prefix")
        elif self.pool is not None:
            route = self._warpgate_route(client)
        else:
            raise NoCapacity("no egress lane configured")
        self.store.assign(str(client["id"]), route.block, route.lane)
        return route

    def _warpgate_route(self, client) -> Route:
        if self.pool is None:
            raise NoCapacity("WarpGate lane has no pool")
        instance = self.pool.acquire(str(client["id"]))
        if instance is None:
            raise NoCapacity("WarpGate has no free instance")
        exit_ip = ""
        try:
            sock = warpgate_pool.socks5_connect("www.cloudflare.com", 80, instance.host, instance.port,
                                               instance.username, instance.password)
            exit_ip = warpgate_pool.probe_egress(sock)
        except Exception:
            pass
        block = block_of(exit_ip) or block_of(instance.advertised_ip)
        if not block:
            raise NoCapacity("could not determine the WarpGate egress block")
        return Route(block, "warpgate", instance=instance, exit_ip=exit_ip)

    def rotate(self, client) -> Route:
        old = str(client["block"] or "")
        if old:
            self.store.mark_burnt(old)
        return self.ensure(client)

    async def open_connection(self, host: str, port: int, route: Route):
        """Return (reader, writer) from the client's assigned block."""
        if route.lane == "prefix" and self.dial is None:
            raise ConnectionError("prefix lane requires a bound IPv6 dialer")
        if self.dial is not None:
            sock = self.dial(host, port, route)
            return await asyncio.open_connection(sock=sock)
        if self.dial is None and self.pool is not None and route.instance is not None:
            sock = warpgate_pool.socks5_connect(host, port, route.instance.host, route.instance.port,
                                               route.instance.username, route.instance.password)
            return await asyncio.open_connection(sock=sock)
        raise ConnectionError("no outbound dialer configured")


async def pipe(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
    try:
        while True:
            data = await reader.read(65536)
            if not data:
                break
            writer.write(data)
            await writer.drain()
    except (ConnectionError, OSError):
        pass
    finally:
        try:
            writer.close()
        except OSError:
            pass


class Relay:
    """Token-authenticated CONNECT server with a small control API."""

    def __init__(self, cfg: Config, store: Store, router: Router | None = None) -> None:
        self.cfg = cfg
        self.store = store
        self.router = router or Router(cfg, store)
        self.server: asyncio.AbstractServer | None = None

    @staticmethod
    def _parse_request(head: str) -> tuple[str, str, dict[str, str]]:
        lines = head.split("\r\n")
        parts = lines[0].split() if lines else []
        method = parts[0].upper() if parts else ""
        target = parts[1] if len(parts) > 1 else ""
        headers = {}
        for line in lines[1:]:
            key, sep, value = line.partition(":")
            if sep:
                headers[key.strip().lower()] = value.strip()
        return method, target, headers

    def _client_for(self, headers: dict[str, str]):
        token = parse_basic(headers.get("proxy-authorization", "")) or parse_bearer(headers.get("authorization", "")) or headers.get("x-client-token", "")
        return self.store.client_by_token(token) if token else None

    def _json_reply(self, writer: asyncio.StreamWriter, payload: dict, status: int = 200) -> None:
        body = json.dumps(payload).encode("utf-8")
        reason = "OK" if status == 200 else "Forbidden"
        writer.write(
            f"HTTP/1.1 {status} {reason}\r\nContent-Type: application/json\r\n"
            f"Content-Length: {len(body)}\r\nConnection: close\r\n\r\n".encode("ascii") + body
        )

    async def _control(self, method: str, target: str, headers: dict[str, str], writer: asyncio.StreamWriter) -> None:
        token = parse_bearer(headers.get("authorization", "")) or headers.get("x-client-token", "")
        is_admin = bool(token) and secrets.compare_digest(token, self.cfg.admin_token)
        client = self.store.client_by_token(token)
        if target.startswith("/api/enroll"):
            supplied = headers.get("x-enroll-secret", "")
            if not self.cfg.enroll_secret or not secrets.compare_digest(supplied, self.cfg.enroll_secret):
                self._json_reply(writer, {"ok": False, "error": "bad enrollment secret"}, 403)
                return
            cid, new_token, block = self.store.create_client(self.cfg.admin_token, "enrolled")
            self._json_reply(writer, {"ok": True, "id": cid, "token": new_token, "block": block,
                                      "proxy": f"relay://block:{new_token}@{self.cfg.public_url or f'{self.cfg.listen}:{self.cfg.port}'}"})
            return
        if client is None and not is_admin:
            self._json_reply(writer, {"ok": False, "error": "bad client token"}, 403)
            return
        if target.startswith("/api/state"):
            row = self.store.client_by_id(str(client["id"])) if client else None
            self._json_reply(writer, {"ok": True, "block": str(row["block"] or "") if row else "",
                                      "lane": str(row["lane"] or "") if row else "",
                                      "capacity": self.cfg.capacity,
                                      "mode": self.cfg.upstream_mode})
            return
        if target.startswith("/api/rotate") and method == "POST":
            if client is None:
                self._json_reply(writer, {"ok": False, "error": "client token required"}, 403)
                return
            route = self.router.rotate(client)
            self._json_reply(writer, {"ok": True, "block": route.block, "lane": route.lane,
                                      "exit": route.exit_ip, "until": utc_midnight()})
            return
        self._json_reply(writer, {"ok": False, "error": "not found"}, 404)

    async def handle(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        try:
            head = (await asyncio.wait_for(reader.readuntil(b"\r\n\r\n"), timeout=self.cfg.idle_timeout)).decode("latin-1", "replace")
        except (asyncio.IncompleteReadError, asyncio.TimeoutError, OSError):
            writer.close()
            return
        method, target, headers = self._parse_request(head)
        if method == "CONNECT":
            client = self._client_for(headers)
            if client is None:
                writer.write(b"HTTP/1.1 403 Forbidden\r\n\r\n")
                writer.close()
                return
            host, _, port_text = target.rpartition(":")
            try:
                port = int(port_text)
            except ValueError:
                writer.write(b"HTTP/1.1 400 Bad Request\r\n\r\n")
                writer.close()
                return
            if not host_allowed(host, self.cfg.allowed_hosts):
                writer.write(b"HTTP/1.1 403 Forbidden\r\n\r\n")
                writer.close()
                return
            try:
                row = self.store.client_by_id(str(client["id"]))
                route = self.router.ensure(row) if not row or not row["block"] else Route(str(row["block"]), str(row["lane"] or "prefix"))
                up_reader, up_writer = await self.router.open_connection(host, port, route)
                self.store.touch(str(client["id"]), route.block)
                writer.write(b"HTTP/1.1 200 Connection Established\r\n\r\n")
                await asyncio.gather(pipe(reader, up_writer), pipe(up_reader, writer))
            except Exception as exc:
                log(f"tunnel failed: {exc}")
                writer.close()
            return
        await self._control(method, target, headers, writer)
        try:
            await writer.drain()
        finally:
            writer.close()

    async def serve(self) -> None:
        ssl_ctx = None
        if self.cfg.tls_cert and self.cfg.tls_key:
            ssl_ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            ssl_ctx.load_cert_chain(self.cfg.tls_cert, self.cfg.tls_key)
        self.server = await asyncio.start_server(self.handle, self.cfg.listen, self.cfg.port, ssl=ssl_ctx)
        log(f"relay listening on {self.cfg.listen}:{self.cfg.port} lane={self.cfg.upstream_mode}")
        async with self.server:
            await self.server.serve_forever()

    def stop(self) -> None:
        if self.server is not None:
            self.server.close()


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="blockrelay", description="Authenticated IPv6 block relay")
    sub = parser.add_subparsers(dest="command", required=True)
    serve = sub.add_parser("serve")
    serve.add_argument("-c", "--config", required=True)
    sub.add_parser("client-list").add_argument("-c", "--config", required=True)
    new = sub.add_parser("client-new")
    new.add_argument("-c", "--config", required=True)
    new.add_argument("--label", default="")
    rot = sub.add_parser("client-rotate")
    rot.add_argument("-c", "--config", required=True)
    rot.add_argument("--id", required=True)
    rev = sub.add_parser("client-revoke")
    rev.add_argument("-c", "--config", required=True)
    rev.add_argument("--id", required=True)
    doc = sub.add_parser("doctor")
    doc.add_argument("-c", "--config", required=True)
    return parser


def store_for(args) -> tuple[Config, Store]:
    cfg = Config.load(Path(args.config))
    return cfg, Store(cfg.database)


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    cfg, store = store_for(args)
    if args.command == "serve":
        asyncio.run(Relay(cfg, store).serve())
        return 0
    if args.command == "client-list":
        for row in store.list_clients():
            print(f"{row['id']}\t{row['label']}\t{row['block'] or '-'}\tenabled={row['enabled']}")
        return 0
    if args.command == "client-new":
        cid, token, block = store.create_client(cfg.admin_token, args.label)
        print(f"id:       {cid}\nblock:    {block or 'unassigned'}\nproxy:    relay://block:{token}@{cfg.public_url or f'{cfg.listen}:{cfg.port}'}")
        return 0
    if args.command == "client-rotate":
        row = store.client_by_id(args.id)
        if not row:
            print("unknown client", file=sys.stderr)
            return 1
        route = Router(cfg, store).rotate(row)
        print(f"block: {route.block}\nlane: {route.lane}")
        return 0
    if args.command == "client-revoke":
        print(f"revoked={store.revoke(args.id)}")
        return 0
    if args.command == "doctor":
        print(json.dumps({"mode": cfg.upstream_mode, "capacity": cfg.capacity,
                          "listen": cfg.listen, "port": cfg.port,
                          "clients": len(store.list_clients())}, indent=2))
        return 0
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
