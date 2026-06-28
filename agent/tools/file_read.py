"""
File-read tool.

BEWUST KWETSBAAR:
- Geen path canonicalization (../../etc/passwd werkt)
- Geen jail naar een working-dir
- Leest binaire files óók (geen extensie-check)

Wel aanwezig (host-bescherming):
- Cap op 4000 chars output
- Logging naar hack-log-private.md
- Default deny op /dev/* en /proc/<pid>/mem om de host niet kapot te lezen
"""
from __future__ import annotations

from datetime import datetime
from pathlib import Path

LOG_FILE = Path(__file__).resolve().parents[2] / "hack-log-private.md"
MAX_OUTPUT = 4000
HARD_DENY_PREFIXES = ("/dev/", "/proc/self/mem", "/proc/kcore")


FILE_READ_TOOL_SCHEMA = {
    "type": "function",
    "function": {
        "name": "read_file",
        "description": (
            "Read the contents of a file on the local filesystem. "
            "Use for inspecting config files, logs, scripts."
        ),
        "parameters": {
            "type": "object",
            "properties": {
                "path": {
                    "type": "string",
                    "description": "Absolute or relative path, e.g. '/etc/hostname' or './README.md'",
                }
            },
            "required": ["path"],
        },
    },
}


def _log(path: str, output: str) -> None:
    ts = datetime.now().isoformat(timespec="seconds")
    entry = f"\n## {ts} — read_file\n\n```\n$ read_file {path}\n{output[:500]}\n```\n"
    LOG_FILE.write_text((LOG_FILE.read_text() if LOG_FILE.exists() else "# Hack Log\n") + entry)


def read_file(path: str, **_ignored: object) -> str:
    """Lees een file. Bewust geen jail. `**_ignored` slikt onbekende kwargs."""
    if any(path.startswith(p) for p in HARD_DENY_PREFIXES):
        out = f"(hard-deny: {path})"
        _log(path, out)
        return out
    try:
        p = Path(path).expanduser()
        data = p.read_text(errors="replace")
        out = data[:MAX_OUTPUT] or "(empty file)"
    except FileNotFoundError:
        out = f"(file not found: {path})"
    except PermissionError:
        out = f"(permission denied: {path})"
    except Exception as exc:  # noqa: BLE001
        out = f"(error: {exc})"

    _log(path, out)
    return out
