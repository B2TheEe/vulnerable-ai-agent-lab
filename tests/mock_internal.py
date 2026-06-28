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

Ctrl-C om te stoppen.
"""
from __future__ import annotations

import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

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
            body = routes.get(self.path, routes.get("/", "OK\n"))
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body.encode())

        def log_message(self, format: str, *args: object) -> None:  # noqa: A002 — stdlib signature
            print(f"[mock {self.server.server_address[1]}] {format % args}")

    return Handler


def serve(port: int, routes: dict[str, str]) -> None:
    handler = _make_handler(routes)
    srv = ThreadingHTTPServer(("127.0.0.1", port), handler)
    print(f"→ mock service listening on http://127.0.0.1:{port}/")
    srv.serve_forever()


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

    threads = [
        threading.Thread(target=serve, args=(IMDS_PORT, imds_routes), daemon=True),
        threading.Thread(target=serve, args=(ADMIN_PORT, admin_routes), daemon=True),
    ]
    for t in threads:
        t.start()

    print("Both mock services running. Ctrl-C to stop.")
    try:
        for t in threads:
            t.join()
    except KeyboardInterrupt:
        print("\nshutting down.")


if __name__ == "__main__":
    main()
