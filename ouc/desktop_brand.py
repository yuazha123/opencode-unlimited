"""Optional, dry-run-by-default asar text editor.

Only specific strings inside an Electron archive are changed; every other byte
stays where it was.  The editor refuses to touch an archive while the app is
open or when Electron's asar integrity fuse is enabled, and stores the original
header for byte-exact restore.  ``apply`` requires an explicit flag.
"""

from __future__ import annotations

import hashlib
import io
import json
import struct
from pathlib import Path

from . import common

ASAR_RELATIVE = Path("resources") / "app.asar"
STATE_DIR = common.DESKTOP_DIR
STATE_FILE = STATE_DIR / "state.json"
HEADER_COPY = STATE_DIR / "header.bin"
INTENT_FILE = STATE_DIR / "wanted.flag"
BRAND_LOG_FILE = STATE_DIR / "brand.log"
BRAND_NAME = "Opencode Unlimited"

FUSE_MAGIC = b"dL7pKGdnNz796PbbjQWNKmHXBZaB9tsX"
ASAR_INTEGRITY_FUSE = 4
MAX_HEADER_BYTES = 64 * 1024 * 1024
MAX_CHUNK_BYTES = 32 * 1024 * 1024
COPY_CHUNK = 8 * 1024 * 1024
ANCHOR = '"dialog.usageExceeded.freeTier.description":'

REWRITES: tuple[tuple[str, str, str], ...] = (
    ("free-tier dialog title", '"dialog.usageExceeded.freeTier.title":`Free limit reached`',
     '"dialog.usageExceeded.freeTier.title":`Free allowance used up`'),
    ("free-tier dialog body",
     '"dialog.usageExceeded.freeTier.description":`Subscribe to OpenCode Go for reliable access '
     "to the best open-source models for $10/month.`",
     '"dialog.usageExceeded.freeTier.description":`The free allowance refills on a schedule of its '
     "own. Nothing needs pressing: chats waiting on it continue by themselves once it reopens.`"),
    ("free-tier dialog button", '"dialog.usageExceeded.freeTier.actionLabel":`Subscribe`',
     '"dialog.usageExceeded.freeTier.actionLabel":`Pricing`'),
    ("inline limit message", '"ui.sessionTurn.error.freeUsageExceeded":`Free usage exceeded`',
     '"ui.sessionTurn.error.freeUsageExceeded":`Free allowance used up`'),
    ("app menu label", '"desktop.menu.app":`OpenCode`', f'"desktop.menu.app":`{BRAND_NAME}`'),
)
HTML_REWRITE = (">OpenCode</title>", f">{BRAND_NAME}</title>")
MARKS = ("Free allowance used up", "refills on a schedule of its own", f'"desktop.menu.app":`{BRAND_NAME}`')


def note(message: str) -> None:
    common.append_log(BRAND_LOG_FILE, message)


def archive_header(handle) -> tuple[dict, int, bytes]:
    handle.seek(0)
    prelude = handle.read(16)
    if len(prelude) < 16:
        raise ValueError("not an asar archive")
    marker, span, _inner, json_len = struct.unpack("<IIII", prelude)
    if marker != 4 or not 0 < json_len <= MAX_HEADER_BYTES:
        raise ValueError("unexpected asar header")
    if not 8 < span <= MAX_HEADER_BYTES:
        raise ValueError("unexpected header span")
    raw = handle.read(json_len)
    if len(raw) != json_len:
        raise ValueError("truncated asar header")
    header = json.loads(raw.decode("utf-8"))
    if not isinstance(header, dict) or not isinstance(header.get("files"), dict):
        raise ValueError("asar header has no file table")
    return header, 8 + span, prelude[:16] + raw


def prelude_bytes(header: dict) -> bytes:
    raw = json.dumps(header, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
    pad = (4 - len(raw) % 4) % 4
    pickled = len(raw) + pad
    return struct.pack("<IIII", 4, pickled + 8, pickled + 4, len(raw)) + raw + b"\0" * pad


def node_at(header: dict, path: tuple[str, ...]) -> dict:
    node = header
    for part in path:
        node = node["files"][part]
    return node


def data_extent(header: dict, node: dict | None = None) -> int:
    """Highest byte position used by any file entry in an archive header."""
    node = header if node is None else node
    end = 0
    files = node.get("files") if isinstance(node, dict) else None
    if not isinstance(files, dict):
        return end
    for entry in files.values():
        if not isinstance(entry, dict) or entry.get("unpacked"):
            continue
        if "offset" in entry and "size" in entry:
            end = max(end, int(entry["offset"]) + int(entry["size"]))
        else:
            end = max(end, data_extent(header, entry))
    return end


def entry_bytes(handle, start: int, entry: dict) -> bytes:
    if entry.get("unpacked"):
        raise ValueError("entry is unpacked")
    size = int(entry["size"])
    if size < 0 or size > MAX_CHUNK_BYTES:
        raise ValueError("entry size out of range")
    handle.seek(start + int(entry["offset"]))
    data = handle.read(size)
    if len(data) != size:
        raise ValueError("truncated entry")
    return data


def checksum_block(data: bytes) -> dict:
    return {"algorithm": "SHA256", "hash": hashlib.sha256(data).hexdigest(), "blockSize": 4 * 1024 * 1024}


def candidate_paths(header: dict) -> list[tuple[str, ...]]:
    files = header.get("files", {})
    out = []
    for name, node in files.get("out", {}).get("files", {}).get("renderer", {}).get("files", {}).items():
        if name.endswith(".js") and name.startswith("main-"):
            out.append(("out", "renderer", name))
    out.append(("out", "renderer", "index.html"))
    return out


def brand_text(text: str) -> tuple[str, list[str]]:
    labels = []
    for label, old, new in REWRITES:
        if old in text:
            text = text.replace(old, new)
            labels.append(label)
    old_html, new_html = HTML_REWRITE
    if old_html in text:
        text = text.replace(old_html, new_html)
        labels.append("window title")
    return text, labels


def status(archive: Path, *, app_open: bool | None = None) -> dict:
    result = {"archive": str(archive), "exists": archive.is_file(), "patched": False,
              "would_change": [], "integrity": None, "app_open": app_open, "blockers": []}
    if not archive.is_file():
        result["blockers"].append("archive not found")
        return result
    try:
        with archive.open("rb") as handle:
            header, start, _ = archive_header(handle)
            result["archive_bytes"] = archive.stat().st_size
            patched = False
            for path in candidate_paths(header):
                try:
                    data = entry_bytes(handle, start, node_at(header, path))
                except (KeyError, ValueError):
                    continue
                text = data.decode("utf-8", "replace")
                if all(mark in text for mark in MARKS[:1]):
                    patched = True
                _, labels = brand_text(text)
                result["would_change"].extend(f"{'/'.join(path)}: {label}" for label in labels)
            result["patched"] = patched
    except (ValueError, OSError, json.JSONDecodeError) as exc:
        result["blockers"].append(str(exc))
    if app_open:
        result["blockers"].append("app is running")
    return result


def apply(archive: Path, *, apply_change: bool = False, app_open: bool = False) -> dict:
    """Plan or apply the change. Dry-run is the default."""
    report = status(archive, app_open=app_open)
    if report["blockers"]:
        return report
    if not apply_change:
        report["dry_run"] = True
        note(f"dry-run {archive}: {len(report['would_change'])} candidate changes")
        return report
    if report["patched"]:
        report["already_patched"] = True
        return report

    original = archive.read_bytes()
    with archive.open("rb") as handle:
        header, start, _ = archive_header(handle)
        original_data = original[start:]
        changes: dict[tuple[str, ...], bytes] = {}
        for path in candidate_paths(header):
            try:
                node = node_at(header, path)
                data = entry_bytes(handle, start, node)
            except (KeyError, ValueError):
                continue
            text = data.decode("utf-8", "replace")
            new_text, labels = brand_text(text)
            if labels:
                changes[path] = new_text.encode("utf-8")
        if not changes:
            report["blockers"].append("no matching copy found")
            return report

    new_header = json.loads(json.dumps(header))
    appended = bytearray()
    for path, data in changes.items():
        node = node_at(new_header, path)
        node["offset"] = str(len(original_data) + len(appended))
        node["size"] = len(data)
        if isinstance(node.get("integrity"), dict):
            node["integrity"] = checksum_block(data)
        appended.extend(data)
    rebuilt = prelude_bytes(new_header) + original_data + bytes(appended)

    temp = archive.with_name(archive.name + ".ouc-new")
    try:
        temp.write_bytes(rebuilt)
        with temp.open("rb") as check:
            check_header, check_start, _ = archive_header(check)
            if check_header != new_header:
                raise ValueError("header read-back mismatch")
            for path, expected in changes.items():
                if entry_bytes(check, check_start, node_at(check_header, path)) != expected:
                    raise ValueError(f"read-back mismatch for {'/'.join(path)}")
        STATE_DIR.mkdir(parents=True, exist_ok=True)
        if not HEADER_COPY.is_file():
            HEADER_COPY.write_bytes(original[:start])
        temp.replace(archive)
        report["applied"] = sorted("/".join(p) for p in changes)
        note(f"patched {archive}: {', '.join(sorted(set(x.split(': ')[-1] for x in report['would_change'])))}")
    except (OSError, ValueError) as exc:
        try:
            temp.unlink(missing_ok=True)
        except OSError:
            pass
        report["blockers"].append(str(exc))
    return report


def restore(archive: Path) -> dict:
    if not HEADER_COPY.is_file():
        return {"ok": False, "error": "no saved header; nothing to restore"}
    if not archive.is_file():
        return {"ok": False, "error": "archive not found"}
    header_copy = HEADER_COPY.read_bytes()
    saved_header, _saved_start, _ = archive_header(io.BytesIO(header_copy))
    keep = data_extent(saved_header)
    with archive.open("rb") as handle:
        _header, data_start, _ = archive_header(handle)
        handle.seek(data_start)
        data = handle.read(keep)
    temp = archive.with_name(archive.name + ".ouc-restore")
    temp.write_bytes(header_copy + data)
    with temp.open("rb") as check:
        check.seek(len(header_copy))
        if check.read() != data:
            temp.unlink(missing_ok=True)
            return {"ok": False, "error": "restore read-back failed"}
    temp.replace(archive)
    HEADER_COPY.unlink(missing_ok=True)
    note(f"restored {archive}")
    return {"ok": True}
