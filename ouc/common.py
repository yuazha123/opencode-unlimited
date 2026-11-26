"""Shared paths, state helpers, and network utilities.

External processes and network access are injectable so tests never touch a
live host.
"""

from __future__ import annotations

import ipaddress
import json
import os
import subprocess
import sys
import time
import urllib.request
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Callable, Iterable

BRAND = "opencode-unlimited"
CREATE_NO_WINDOW = 0x08000000

EGRESS_ENDPOINTS = (
    "https://opencode.ai/cdn-cgi/trace",
    "https://api64.ipify.org",
    "https://cloudflare.com/cdn-cgi/trace",
    "https://1.1.1.1/cdn-cgi/trace",
)


def default_data_root() -> Path:
    if sys.platform == "win32":
        return Path(os.environ.get("LOCALAPPDATA", Path.home() / "AppData" / "Local"))
    return Path(os.environ.get("XDG_DATA_HOME", Path.home() / ".local" / "share"))


LOCAL_APPDATA = default_data_root()
DEST_DIR = LOCAL_APPDATA / BRAND
SCRIPTS_DIR = DEST_DIR / "scripts"
BIN_DIR = (
    DEST_DIR / "bin"
    if sys.platform == "win32"
    else Path(os.environ.get("XDG_BIN_HOME", Path.home() / ".local" / "bin"))
)
GUARD_DIR = DEST_DIR / "guard"
KEEPER_DIR = DEST_DIR / "keeper"
LANE_DIR = DEST_DIR / "lane"
DESKTOP_DIR = DEST_DIR / "desktop"

PAUSE_FILE = DEST_DIR / "keeper.pause"
GUARD_STATE_FILE = GUARD_DIR / "state.json"
GUARD_LOG_FILE = GUARD_DIR / "guard.log"
KEEPER_LOG_FILE = KEEPER_DIR / "keeper.log"
OPENCODE_LOG_FILE = Path.home() / ".local" / "share" / "opencode" / "log" / "opencode.log"
SERVICE_FILE = Path.home() / ".config" / "opencode" / "service.json"
SERVICE_PROXY_PORT = int(os.environ.get("OUC_SERVICE_PROXY_PORT", "41987"))
SERVICE_PROXY_KEYS = ("HTTPS_PROXY", "https_proxy", "HTTP_PROXY", "http_proxy")

TASK_KEEPER = "OpencodeUnlimited-Keeper"
TASK_GUARD = "OpencodeUnlimited-Guard"
TASK_WATCHDOG = "OpencodeUnlimited-Watchdog"

CLOUDFLARE_V6_PREFIXES = (
    ipaddress.IPv6Network("2606:4700::/32"),
    ipaddress.IPv6Network("2a09:bac0::/29"),
)


def ensure_dirs() -> None:
    for directory in (DEST_DIR, SCRIPTS_DIR, BIN_DIR, GUARD_DIR, KEEPER_DIR, LANE_DIR, DESKTOP_DIR):
        directory.mkdir(parents=True, exist_ok=True)


def read_json(path: Path, default=None):
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return default
    return data


def write_json(path: Path, value, *, indent: int | None = None) -> None:
    """Atomic JSON write using a temporary file and rename."""
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_name(path.name + ".tmp")
    tmp.write_text(json.dumps(value, indent=indent, separators=(",", ":") if indent is None else None), encoding="utf-8")
    tmp.replace(path)


def service_proxy_wired(port: int | None = None) -> bool:
    port = SERVICE_PROXY_PORT if port is None else port
    cfg = read_json(SERVICE_FILE, {})
    env = cfg.get("env") if isinstance(cfg, dict) else None
    if not isinstance(env, dict):
        return False
    needle = f"127.0.0.1:{port}"
    return any(needle in str(env.get(key, "")) for key in SERVICE_PROXY_KEYS)


def append_log(path: Path, message: str, *, limit_bytes: int = 1_000_000) -> None:
    """Timestamped append with one-backup rotation."""
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        stamp = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
        if path.is_file() and path.stat().st_size > limit_bytes:
            path.replace(path.with_suffix(path.suffix + ".1"))
        with path.open("a", encoding="utf-8") as handle:
            handle.write(f"{stamp} {message}\n")
    except OSError:
        pass


def heartbeat(path: Path) -> None:
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(str(int(time.time())), encoding="utf-8")
    except OSError:
        pass


def heartbeat_age(path: Path) -> float | None:
    try:
        value = int(path.read_text(encoding="utf-8").strip())
    except (OSError, ValueError):
        return None
    return max(0.0, time.time() - value)


def run(args: list[str], *, timeout: float = 15.0, capture: bool = True) -> subprocess.CompletedProcess[str] | None:
    """Run an argument list without a shell. No dynamic command strings are built."""
    kwargs: dict = {"capture_output": capture, "text": True, "timeout": timeout}
    if sys.platform == "win32":
        kwargs["creationflags"] = CREATE_NO_WINDOW
    try:
        return subprocess.run(args, **kwargs)
    except (OSError, subprocess.SubprocessError):
        return None


def normalize_v6_64(value: str) -> str:
    """Return the /64 network of a public IPv6 address, or '' if unusable."""
    try:
        addr = ipaddress.IPv6Address(value.strip().split("%", 1)[0])
    except ValueError:
        return ""
    if not addr.is_global or addr.is_loopback or addr.is_link_local:
        return ""
    return str(ipaddress.IPv6Network(f"{addr}/64", strict=False).network_address)


def is_cloudflare_v6(value: str) -> bool:
    try:
        addr = ipaddress.IPv6Address(value)
    except ValueError:
        return False
    return any(addr in net for net in CLOUDFLARE_V6_PREFIXES)


def valid_public_ip(text: str) -> str:
    text = text.strip()
    try:
        addr = ipaddress.ip_address(text)
    except ValueError:
        return ""
    return text if addr.is_global else ""


def parse_egress_body(body: str) -> str:
    """Extract an address from ipify text or a Cloudflare trace body."""
    for line in body.splitlines():
        if "=" in line:
            key, _, value = line.partition("=")
            if key.strip().lower() == "ip":
                return valid_public_ip(value.strip())
    return valid_public_ip(body.strip())


def probe_egress(
    *,
    endpoints: Iterable[str] = EGRESS_ENDPOINTS,
    opener: Callable | None = None,
    timeout: float = 8.0,
) -> str:
    """Return the public egress address seen from outside, or '' on failure."""
    open_url = opener or urllib.request.urlopen
    for url in endpoints:
        try:
            with open_url(url, timeout=timeout) as response:  # type: ignore[operator]
                body = response.read(65536).decode("utf-8", "replace")
            found = parse_egress_body(body)
            if found:
                return found
        except Exception:
            continue
    return ""


def next_utc_midnight(now: float | None = None) -> int:
    stamp = datetime.fromtimestamp(int(now or time.time()), timezone.utc)
    nxt = (stamp + timedelta(days=1)).replace(hour=0, minute=0, second=0, microsecond=0)
    return int(nxt.timestamp())


def utc_day(now: float | None = None) -> int:
    return int(now or time.time()) // 86400


def block_of(address: str) -> str:
    """The daily quota key: /64 for IPv6, /32 for IPv4."""
    try:
        addr = ipaddress.ip_address(address.strip())
    except ValueError:
        return ""
    width = 64 if addr.version == 6 else 32
    return str(ipaddress.ip_network(f"{addr}/{width}", strict=False).network_address)
