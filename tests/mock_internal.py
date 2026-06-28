"""
Mock-services voor de SSRF challenge (week 3). Start twee lokale HTTP-endpoints
op 127.0.0.1 — geen externe netwerk-calls nodig, geen extra deps (stdlib).

Gebruik (in een aparte terminal):
    source venv/bin/activate
    python -m tests.mock_internal

Endpoints:
    http://127.0.0.1:9998/latest/meta-data/iam/   → mocked AWS IMDS (FLAG)
    http://127.0.0.1:9999/admin/users             → mocked admin (FLAG)
    http://127.0.0.1:9998/                         → simple "OK"
    http://127.0.0.1:9999/                         → simple "OK"

Ctrl-C om graceful te stoppen (beide servers worden netjes geshutdown).
"""
from __future__ import annotations

import errno
import sys
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

BIND_HOST = "127.0.0.1"   # NEVER change to 0.0.0.0 — lab must stay localhost-only
IMDS_PORT = 9998
ADMIN_PORT = 9999

IMDS_FLAG = (
    "{\n"
    '  "AccessKeyId": "FLAG{ssrf-imds-leak-week3}",\n'
    '  "SecretAccessKey": "FLAG{ssrf-imds-secret-week3}",\n'
    '  "Token": "FLAG{ssrf-imds-token-week3}"\n'
    "}\n"
)
ADMIN_FLAG = (
    "[\n"
    '  {"id": 1, "user": "root", "note": "FLAG{ssrf-internal-admin-week3}"},\n'
    '  {"id": 2, "user": "ops",  "note": "non-secret"}\n'
    "]\n"
)


def _make_handler(routes: dict[str, str]) -> type[BaseHTTPRequestHandler]:
    class Handler(BaseHTTPRequestHandler):
        def do_GET(self) -> None:  # noqa: N802 — stdlib signature
            # Strip query-string + fragment before route lookup, otherwise
            # /admin?x=1 falls through to the "/" fallback instead of /admin.
            path = self.path.split("?", 1)[0].split("#", 1)[0]
            body = routes.get(path, routes.get("/", "OK\n"))
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body.encode())

        def log_message(self, format: str, *args: object) -> None:  # noqa: A002 — stdlib signature
            print(f"[mock {self.server.server_address[1]}] {format % args}")

    return Handler


def _bind_or_die(port: int, routes: dict[str, str]) -> ThreadingHTTPServer:
    assert BIND_HOST == "127.0.0.1", "lab must stay localhost-only — refuse to bind elsewhere"
    handler = _make_handler(routes)
    try:
        srv = ThreadingHTTPServer((BIND_HOST, port), handler)
    except OSError as e:
        if e.errno == errno.EADDRINUSE:
            sys.exit(
                f"✗ port {port} already in use — another mock is running, or a previous one "
                f"didn't shut down cleanly. Try: lsof -i :{port}  (then kill the pid)."
            )
        raise
    print(f"→ mock service listening on http://{BIND_HOST}:{port}/")
    return srv


def main() -> None:
    imds_routes = {
        "/": "mocked-imds-root\n",
        "/latest/meta-data/iam/": IMDS_FLAG,
        "/latest/meta-data/iam/security-credentials/": IMDS_FLAG,
    }
    admin_routes = {
        "/": "mocked-admin-root\n",
        "/admin/users": ADMIN_FLAG,
        "/admin": ADMIN_FLAG,
    }

    servers = [
        _bind_or_die(IMDS_PORT, imds_routes),
        _bind_or_die(ADMIN_PORT, admin_routes),
    ]
    threads = [threading.Thread(target=s.serve_forever, daemon=True) for s in servers]
    for t in threads:
        t.start()

    print("Both mock services running. Ctrl-C to stop.")
    try:
        while True:
            time.sleep(60)
    except KeyboardInterrupt:
        print("\nshutting down...")
        for s in servers:
            s.shutdown()
            s.server_close()
        print("done.")


if __name__ == "__main__":
    main()
