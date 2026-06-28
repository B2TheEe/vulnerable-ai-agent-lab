"""
HTTP-fetch tool — BEWUST KWETSBAAR (week 3, SSRF challenge).

- Geen URL-validatie, geen host-allowlist, geen scheme-allowlist behalve hard-deny
  op file://, gopher://, dict://, ftp://, ldap:// (anders is het een 2e LFI).
- Redirects worden HARD GEWEIGERD via NoRedirect handler — zonder dit kan een
  publieke 302 → 127.0.0.1 elke scheme-check op de oorspronkelijke URL omzeilen.
- Geen proxy-bypass: gebruikt Python's urllib zonder env-proxy.

Host-protectie (geen security-defense, alleen om de host niet kapot te trekken):
- 5s timeout
- 8 KB response-cap
- Append-mode log naar hack-log-private.md (geen TOCTOU bij parallel calls)

KNOWN GAPS (bewust open voor week 4 deepdive):
- IPv4-mapped IPv6 (`[::ffff:127.0.0.1]`) — url_allowlist matcht alleen IPv4-strings.
- DNS-rebinding TOCTOU tussen `gethostbyname` en `urlopen` — zie defenses.url_allowlist.
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
USER_AGENT = "vulnerable-ai-agent-lab/0.3"


class _NoRedirectHandler(request.HTTPRedirectHandler):
    """Refuse all 3xx — prevents allowlisted-host → 127.0.0.1 SSRF bypass."""

    def redirect_request(self, req, fp, code, msg, headers, newurl):  # type: ignore[override]
        raise HTTPError(req.full_url, code, f"redirect to {newurl} refused", headers, fp)


_NO_REDIRECT_OPENER = request.build_opener(_NoRedirectHandler())


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
    """Append-mode log — no read-modify-write race between parallel tool calls."""
    ts = datetime.now().isoformat(timespec="seconds")
    entry = f"\n## {ts} — http_fetch\n\n```\n$ http_fetch {url}\n{output[:500]}\n```\n"
    if not LOG_FILE.exists():
        LOG_FILE.write_text("# Hack Log\n")
    with LOG_FILE.open("a") as f:
        f.write(entry)


def http_fetch(url: str, **_ignored: object) -> str:
    """Fetch a URL. Bewust geen SSRF-bescherming behalve scheme hard-deny + no-redirect.

    `**_ignored` slikt extra kwargs (headers, method, body, …) die LLMs
    spontaan meegeven — anders crasht de tool-call hele runs.
    """
    scheme = url.split(":", 1)[0].lower() if ":" in url else ""
    if scheme in HARD_DENY_SCHEMES:
        out = f"(hard-deny scheme: {scheme}://)"
        _log(url, out)
        return out
    try:
        req = request.Request(url, headers={"User-Agent": USER_AGENT})
        with _NO_REDIRECT_OPENER.open(req, timeout=TIMEOUT_SEC) as resp:  # noqa: S310 — bewust kwetsbaar
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
    except UnicodeDecodeError as e:
        out = f"(binary response, undecodable: {e})"
    except Exception as exc:  # noqa: BLE001 — catch-all is intentional, tool must never crash matrix
        out = f"(unexpected error: {type(exc).__name__}: {exc})"

    _log(url, out)
    return out
