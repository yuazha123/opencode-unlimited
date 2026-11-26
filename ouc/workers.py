"""Background-worker logic: wall detection, rotation backoff, and liveness.

Behavioral target: ``zen_guard.py``, ``warp_keeper.py``, ``ouc_watchdog.py``.
The reference registers these as OS services; the rewrite exposes one-shot
entry points and never installs or enables a service.
"""

from __future__ import annotations

import re
import time
from typing import Callable, Iterable

from . import auto_resume, common, proxy_chain, zen_proxy

WALL_PATTERNS = (
    re.compile(r"free limit reached", re.I),
    re.compile(r"free usage exceeded", re.I),
    re.compile(r"rate.?limit", re.I),
    re.compile(r"free.?tier.?error", re.I),
    re.compile(r"\b403\b.*\bfree\b", re.I),
    re.compile(r"quota.?exceeded", re.I),
)
KEEPER_HEARTBEAT = common.KEEPER_DIR / "heartbeat"
GUARD_HEARTBEAT = common.GUARD_DIR / "heartbeat"


def default_state() -> dict:
    return {
        "log_offset": 0,
        "burnt": {},
        "walls": [],
        "paused_until": 0,
        "last_hop": 0,
        "last_rescue": 0,
    }


def load_state() -> dict:
    data = common.read_json(common.GUARD_STATE_FILE, {})
    state = default_state()
    if isinstance(data, dict):
        state.update(data)
    return state


def save_state(state: dict) -> None:
    common.write_json(common.GUARD_STATE_FILE, state)


def is_wall(line: str) -> bool:
    return any(pattern.search(line or "") for pattern in WALL_PATTERNS)


def read_new_log(text: str, offset: int) -> tuple[bool, list[str], int]:
    """Return (wall_seen, session_ids, new_offset) for a log snapshot."""
    chunk = text[offset:]
    sessions = []
    wall = False
    for line in chunk.splitlines():
        if is_wall(line):
            wall = True
            sid = auto_resume.session_id_in(line)
            if sid:
                sessions.append(sid)
    return wall, sessions, len(text)


def prune_blacklist(state: dict, now: float | None = None) -> None:
    day = common.utc_day(now)
    state["burnt"] = {key: value for key, value in state.get("burnt", {}).items() if value == day}


def is_burnt(state: dict, block: str, now: float | None = None) -> bool:
    return state.get("burnt", {}).get(block) == common.utc_day(now)


def mark_burnt(state: dict, block: str, now: float | None = None) -> None:
    state.setdefault("burnt", {})[block] = common.utc_day(now)


def note_wall(state: dict, confirmed_blocks: list[str], *, now: float | None = None) -> str:
    """Pause until 00:00 UTC after two confirmed new blocks still hit the wall."""
    now = now or time.time()
    prune_blacklist(state, now)
    walls = [int(ts) for ts in state.get("walls", []) if now - int(ts) <= 3600]
    walls.append(int(now))
    state["walls"] = walls[-10:]
    if len(confirmed_blocks) >= 2 and all(is_burnt(state, b, now) for b in confirmed_blocks):
        state["paused_until"] = common.next_utc_midnight(now)
        return "allowance window"
    return ""


def pause_left(state: dict, *, now: float | None = None) -> int:
    until = int(state.get("paused_until", 0))
    return max(0, until - int(now or time.time()))


def rotation_blocked(state: dict, *, streaming: bool = False, now: float | None = None) -> str:
    """Reason to hold a rotation back, or '' when it is safe to rotate."""
    now = now or time.time()
    if pause_left(state, now=now) > 0:
        return "paused until allowance window"
    if streaming:
        return "response is streaming"
    if now - float(state.get("last_hop", 0)) < 75:
        return "rotation cooldown"
    return ""


def guard_tick(
    *,
    log_text: str = "",
    rotator: Callable[[], tuple[bool, str]] | None = None,
    stream_probe: Callable[[], bool] | None = None,
    state: dict | None = None,
    now: float | None = None,
) -> dict:
    """One guard iteration. No process, network, or app state is touched by default."""
    now = now or time.time()
    state = state if state is not None else load_state()
    wall, sessions, offset = read_new_log(log_text, int(state.get("log_offset", 0)))
    state["log_offset"] = offset
    result = {"wall": wall, "sessions": sessions, "action": "none"}
    if not wall:
        common.heartbeat(GUARD_HEARTBEAT)
        save_state(state)
        return result
    reason = rotation_blocked(state, streaming=bool(stream_probe and stream_probe()), now=now)
    if reason:
        result["action"] = f"hold: {reason}"
        save_state(state)
        return result
    block_before = common.block_of(common.probe_egress())
    ok, block_after = rotator() if rotator else (False, "")
    state["last_hop"] = now
    confirmed = [b for b in (block_before, block_after) if b and b != block_before]
    pause_reason = note_wall(state, confirmed, now=now)
    if pause_reason:
        result["action"] = f"paused: {pause_reason}"
    elif ok:
        result["action"] = "rotated"
    else:
        result["action"] = "rotation failed"
    if ok and auto_resume.is_auto_resume_enabled():
        result["resumed"] = auto_resume.resume_sessions(sessions)
    common.heartbeat(GUARD_HEARTBEAT)
    save_state(state)
    return result


def keeper_tick(
    *,
    connected: bool = True,
    repair: Callable[[], bool] | None = None,
    state: dict | None = None,
) -> dict:
    common.heartbeat(KEEPER_HEARTBEAT)
    if connected:
        return {"action": "healthy"}
    if repair and repair():
        return {"action": "repaired"}
    return {"action": "repair failed"}


def watchdog_check(name: str, *, stale_seconds: float = 300.0, start: Callable[[], bool] | None = None) -> str:
    path = {"keeper": KEEPER_HEARTBEAT, "guard": GUARD_HEARTBEAT}.get(name)
    if path is None:
        return "unknown worker"
    age = common.heartbeat_age(path)
    if age is not None and age <= stale_seconds:
        return "alive"
    if start and start():
        return "restarted"
    return "restart unavailable"
