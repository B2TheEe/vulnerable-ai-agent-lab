"""
HTTP-fetch tool — BEWUST KWETSBAAR (week 3, SSRF challenge).

- Geen URL-validatie, geen host-allowlist, geen scheme-allowlist behalve hard-deny
  op file://, gopher://, dict:// (anders is het een 2e LFI).
- Volgt redirects niet (anders kun je 302 → file:// niet meer hard-denyen op scheme).
- Geen proxy-bypass: gebruikt Python's urllib zonder env-proxy.

Host-protectie (geen security-defense, alleen om de host niet kapot te trekken):
- 5s timeout
- 8 KB response-cap
- Log naar hack-log-private.md
"""
from __future__ import annotations

from datetime import datetime
from pathlib import Path
from urllib import request
from urllib.error import HTTPError, URLError

LOG_FILE = Path(__file__).resolve().parents[2] / "hack-log-private.md"
MAX_OUTPUT = 8000
TIMEOUT_SEC = 5
HARD_DENY_SCHEMES = ("file", "gopher", "dict", "ftp", "ldap")


HTTP_FETCH_TOOL_SCHEMA = {
    "type": "function",
    "function": {
        "name": "http_fetch",
        "description": (
            "Fetch a URL over HTTP/HTTPS and return the response body. "
            "Use for checking documentation, public APIs, or status pages."
        ),
        "parameters": {
            "type": "object",
            "properties": {
                "url": {
                    "type": "string",
                    "description": "Full URL including scheme, e.g. 'https://api.github.com/'",
                },
            },
            "required": ["url"],
        },
    },
}


def _log(url: str, output: str) -> None:
    ts = datetime.now().isoformat(timespec="seconds")
    entry = f"\n## {ts} — http_fetch\n\n```\n$ http_fetch {url}\n{output[:500]}\n```\n"
    prev = LOG_FILE.read_text() if LOG_FILE.exists() else "# Hack Log\n"
    LOG_FILE.write_text(prev + entry)


def http_fetch(url: str) -> str:
    """Fetch a URL. Bewust geen SSRF-bescherming behalve scheme hard-deny."""
    scheme = url.split(":", 1)[0].lower() if ":" in url else ""
    if scheme in HARD_DENY_SCHEMES:
        out = f"(hard-deny scheme: {scheme}://)"
        _log(url, out)
        return out
    try:
        req = request.Request(url, headers={"User-Agent": "vulnerable-ai-agent-lab/0.3"})
        with request.urlopen(req, timeout=TIMEOUT_SEC) as resp:  # noqa: S310 — bewust kwetsbaar
            body = resp.read(MAX_OUTPUT + 1).decode("utf-8", errors="replace")
            status = resp.status
        truncated = " ...[truncated]" if len(body) > MAX_OUTPUT else ""
        out = f"HTTP {status}\n{body[:MAX_OUTPUT]}{truncated}"
    except HTTPError as e:
        out = f"HTTP {e.code} {e.reason}"
    except URLError as e:
        out = f"(url error: {e.reason})"
    except (TimeoutError, OSError) as e:
        out = f"(network error: {e})"
    except Exception as exc:  # noqa: BLE001
        out = f"(error: {exc})"

    _log(url, out)
    return out
