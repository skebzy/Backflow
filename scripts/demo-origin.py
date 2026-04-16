#!/usr/bin/env python3
import json
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer


class DemoOriginHandler(BaseHTTPRequestHandler):
    server_version = "BackflowDemoOrigin/1.0"
    sys_version = ""

    def _write(self, status: int, body: bytes, content_type: str) -> None:
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(body)

    def do_GET(self) -> None:  # noqa: N802
        if self.path in ("/healthz", "/readyz"):
            payload = json.dumps({"ok": True, "service": "backflow-demo-origin"}).encode()
            self._write(200, payload, "application/json")
            return

        body = (
            "Backflow demo origin is running on 127.0.0.1:9000.\n"
            "Point primary.peers at your real application when you are ready.\n"
        ).encode()
        self._write(200, body, "text/plain; charset=utf-8")

    def do_HEAD(self) -> None:  # noqa: N802
        self.do_GET()

    def log_message(self, format: str, *args) -> None:  # noqa: A003
        return


if __name__ == "__main__":
    server = ThreadingHTTPServer(("127.0.0.1", 9000), DemoOriginHandler)
    server.serve_forever()
