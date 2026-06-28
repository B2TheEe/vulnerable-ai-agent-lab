"""
Shell-execution tool — BEWUST KWETSBAAR.

- Geen allowlist, geen sanitization, shell=True (laat ; | $() toe).
- Wel: 5s timeout + 2000-char output cap (host-protectie tijdens experimenteren).
- Alle uitgevoerde commands worden gelogd in hack-log-private.md (in .gitignore).
"""
from __future__ import annotations

import subprocess
from datetime import datetime
from pathlib import Path

LOG_FILE = Path(__file__).resolve().parents[2] / "hack-log-private.md"
MAX_OUTPUT = 2000
TIMEOUT_SEC = 5


SHELL_TOOL_SCHEMA = {
    "type": "function",
    "function": {
        "name": "execute_shell",
        "description": (
            "Execute a shell command on the local Linux system and return "
            "its stdout/stderr. Use for file listings, process info, etc."
        ),
        "parameters": {
            "type": "object",
            "properties": {
                "command": {
                    "type": "string",
                    "description": "The shell command to execute, e.g. 'ls -la /tmp'",
                }
            },
            "required": ["command"],
        },
    },
}


def _log(command: str, output: str) -> None:
    ts = datetime.now().isoformat(timespec="seconds")
    entry = f"\n## {ts}\n\n```bash\n$ {command}\n{output[:500]}\n```\n"
    prev = LOG_FILE.read_text() if LOG_FILE.exists() else "# Hack Log\n"
    LOG_FILE.write_text(prev + entry)


def execute_shell(command: str, **_ignored: object) -> str:
    """Voert command uit via /bin/sh. Bewust geen sanitization. `**_ignored` slikt onbekende kwargs."""
    try:
        result = subprocess.run(
            command,
            shell=True,
            capture_output=True,
            text=True,
            timeout=TIMEOUT_SEC,
        )
        output = (result.stdout or "") + (result.stderr or "")
        output = output[:MAX_OUTPUT] or "(no output)"
    except subprocess.TimeoutExpired:
        output = f"(command timed out after {TIMEOUT_SEC}s)"
    except Exception as exc:  # noqa: BLE001
        output = f"(error: {exc})"

    _log(command, output)
    return output
