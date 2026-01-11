"""Emulated HTTP login surface. Authentication always fails."""

from __future__ import annotations

from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any

from decoy.config import Config
from decoy.parser import parse_request
from decoy.scorer import RateTracker, score_request
from decoy.store import Event, EventStore, hash_payload, redact_snippet, utc_now

LOGIN_PAGE = """<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <title>Sign in</title>
  <style>
    body { font-family: sans-serif; background: #f4f4f4; }
    .box { max-width: 360px; margin: 12vh auto; background: #fff;
           padding: 2rem; border-radius: 8px; box-shadow: 0 2px 8px #0001; }
    label { display: block; margin: 0.75rem 0 0.25rem; }
    input { width: 100%; padding: 0.5rem; box-sizing: border-box; }
    button { margin-top: 1rem; width: 100%; padding: 0.6rem; }
  </style>
</head>
<body>
  <div class="box">
    <h1>Account login</h1>
    <p>Internal services portal</p>
    <form method="post" action="/login">
      <label for="username">Username</label>
      <input id="username" name="username" autocomplete="username">
      <label for="password">Password</label>
      <input id="password" name="password" type="password" autocomplete="current-password">
      <button type="submit">Sign in</button>
    </form>
  </div>
</body>
</html>
"""

FAIL_PAGE = """<!DOCTYPE html>
<html lang="en">
<head><meta charset="utf-8"><title>Sign in</title></head>
<body>
  <p>Invalid username or password.</p>
  <p><a href="/">Try again</a></p>
</body>
</html>
"""


class DecoyHTTPServer(ThreadingHTTPServer):
    allow_reuse_address = True
    daemon_threads = True


def make_handler(store: EventStore, config: Config, rates: RateTracker) -> type[BaseHTTPRequestHandler]:
    class DecoyHTTPHandler(BaseHTTPRequestHandler):
        server_version = "Apache/2.4.52 (Ubuntu)"
        sys_version = ""

        def log_message(self, format: str, *args: Any) -> None:  # noqa: A003
            return

        def _read_body(self) -> bytes:
            raw_length = self.headers.get("Content-Length", "0") or "0"
            try:
                length = int(raw_length)
            except ValueError:
                return b""
            if length <= 0:
                return b""
            length = min(length, 1_048_576)
            return self.rfile.read(length)

        def _record(self, method: str, body: bytes) -> None:
            parsed = parse_request(
                method=method,
                path=self.path,
                headers=dict(self.headers.items()),
                body=body,
            )
            src_ip, src_port = self.client_address[0], int(self.client_address[1])
            result = score_request(parsed, src_ip=src_ip, rate_tracker=rates)
            raw = body.decode("utf-8", errors="replace") if body else parsed.path
            snippet_src = f"{method} {parsed.path}\n{raw}"
            store.insert(
                Event(
                    timestamp=utc_now(),
                    src_ip=src_ip,
                    src_port=src_port,
                    proto="http",
                    path=parsed.path,
                    score=result.score,
                    reasons=result.reasons,
                    payload_hash=hash_payload(snippet_src),
                    snippet=redact_snippet(snippet_src, parsed.password, config.snippet_max),
                )
            )

        def do_GET(self) -> None:
            self._record("GET", b"")
            path = self.path.split("?", 1)[0]
            if path in ("/", "/login", "/index.html"):
                payload = LOGIN_PAGE.encode("utf-8")
                self.send_response(200)
                self.send_header("Content-Type", "text/html; charset=utf-8")
                self.send_header("Content-Length", str(len(payload)))
                self.end_headers()
                self.wfile.write(payload)
                return
            body = b"Not Found"
            self.send_response(404)
            self.send_header("Content-Type", "text/plain; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def do_POST(self) -> None:
            body = self._read_body()
            self._record("POST", body)
            payload = FAIL_PAGE.encode("utf-8")
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Content-Length", str(len(payload)))
            self.end_headers()
            self.wfile.write(payload)

        def do_HEAD(self) -> None:
            self._record("HEAD", b"")
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.end_headers()

        def do_PUT(self) -> None:
            body = self._read_body()
            self._record("PUT", body)
            self.send_response(405)
            self.end_headers()

    return DecoyHTTPHandler


def create_http_server(
    store: EventStore,
    config: Config,
    rates: RateTracker,
    bind: str | None = None,
    port: int | None = None,
) -> DecoyHTTPServer:
    handler = make_handler(store, config, rates)
    address = (bind if bind is not None else config.bind, port if port is not None else config.http_port)
    return DecoyHTTPServer(address, handler)
