"""Opt-in session unlock and resume helpers.

Behavioral target: ``src/auto_resume.py``.  The reference enables this by default;
the rewrite requires an explicit flag because it mutates a third-party app's
local database and can inject keystrokes.  All process dispatch goes through an
injectable runner, so tests never send input to a real window.
"""

from __future__ import annotations

import os
import re
import sqlite3
from pathlib import Path
from typing import Callable

from . import common

AUTO_RESUME_FLAG = common.LANE_DIR / "auto_resume.flag"
LOCKOUT_KEYS = (
    "free-limit",
    "go-upsell",
    "free_usage_limit",
    "usage_limit",
    "quota_exceeded",
)
SESSION_ID_RE = re.compile(r"\bsessionID=(ses_[A-Za-z0-9]+)")


def is_auto_resume_enabled() -> bool:
    """Default off in the rewrite (the reference defaults on)."""
    try:
        return AUTO_RESUME_FLAG.read_text(encoding="utf-8").strip() == "1"
    except OSError:
        return False


def set_auto_resume(enable: bool) -> None:
    common.ensure_dirs()
    AUTO_RESUME_FLAG.write_text("1\n" if enable else "0\n", encoding="utf-8")


def draft_db_candidates() -> list[Path]:
    return [
        Path(os.environ.get("APPDATA", Path.home() / "AppData" / "Roaming")) / "ai.opencode.desktop" / "drafts.sqlite",
        Path.home() / ".config" / "ai.opencode.desktop" / "drafts.sqlite",
        Path.home() / ".local" / "share" / "opencode" / "drafts.sqlite",
    ]


def clear_lockouts(paths: list[Path] | None = None) -> int:
    """Delete only the known lockout keys; never touch chat or session tables."""
    deleted = 0
    for path in paths if paths is not None else draft_db_candidates():
        if not path.is_file():
            continue
        try:
            conn = sqlite3.connect(f"file:{path.as_posix()}?mode=rw", uri=True, timeout=5.0)
            try:
                conn.execute("PRAGMA busy_timeout=5000")
                cur = conn.cursor()
                cur.execute(f"DELETE FROM state WHERE key IN ({','.join('?' for _ in LOCKOUT_KEYS)})", LOCKOUT_KEYS)
                deleted += max(0, cur.rowcount)
                conn.commit()
            finally:
                conn.close()
        except sqlite3.Error:
            continue
    return deleted


def latest_session(db: Path | None = None) -> tuple[str, str, str] | None:
    path = db or (Path.home() / ".local" / "share" / "opencode" / "opencode.db")
    if not path.is_file():
        return None
    try:
        conn = sqlite3.connect(f"file:{path.as_posix()}?mode=ro", uri=True, timeout=3.0)
        cur = conn.cursor()
        cur.execute(
            "SELECT id, directory, title FROM session_v2 "
            "WHERE time_archived IS NULL ORDER BY time_updated DESC LIMIT 1"
        )
        row = cur.fetchone()
        conn.close()
        return (str(row[0]), str(row[1] or ""), str(row[2] or "")) if row and row[0] else None
    except sqlite3.Error:
        return None


def session_id_in(text: str) -> str:
    match = SESSION_ID_RE.search(text or "")
    return match.group(1) if match else ""


def resume_sessions(
    session_ids: list[str],
    *,
    runner: Callable[[list[str]], bool] | None = None,
    command: list[str] | None = None,
) -> list[str]:
    """Dispatch a resume for each session; returns the ids actually dispatched.

    ``runner`` receives an argument list.  It defaults to a no-op that records
    the intent in the guard log, never to a live subprocess.
    """
    if not is_auto_resume_enabled():
        return []
    dispatched: list[str] = []
    for sid in session_ids:
        if not sid:
            continue
        args = command or ["opencode", "run", "--session", sid, "continue"]
        try:
            ok = bool(runner(args)) if runner else False
        except Exception:
            ok = False
        if ok:
            dispatched.append(sid)
        common.append_log(common.GUARD_LOG_FILE, f"resume sid={sid} ok={ok}")
    return dispatched
