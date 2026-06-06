"""
soc_feed.py — Lightweight HTTP feed for the SIC→SOC rollup.

Exposes the findings rollup over HTTP so francois-landing's admin SystemsTab can
consume it. Runs on 127.0.0.1:9016 (next free port after :9015 sic-billing).

Endpoints:
    GET /api/soc/rollup            -> findings_db.rollup_by_project() JSON
    GET /api/soc/summary[?project=] -> findings_db.findings_summary() JSON
    GET /health                    -> {"ok": true}

Auth: every /api/* request must send the SOC_FEED_SECRET in the Authorization
header (raw value or "Bearer <value>"). Defaults to "dev" for local use.
/health is unauthenticated. stdlib only — no external deps.
"""

from __future__ import annotations

import hmac
import json
import os
import sys
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlparse

sys.path.insert(0, str(Path(__file__).parent))

import findings_db  # noqa: E402

PORT = 9016
SECRET = os.environ.get("SOC_FEED_SECRET", "dev")


class SOCFeedHandler(BaseHTTPRequestHandler):
    def _send(self, status: int, payload: dict | list) -> None:
        body = json.dumps(payload).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _authorized(self) -> bool:
        raw = self.headers.get("Authorization", "")
        token = raw[7:] if raw.startswith("Bearer ") else raw
        # Timing-safe comparison so the secret can't be recovered byte-by-byte.
        return hmac.compare_digest(token.encode(), SECRET.encode())

    def do_GET(self) -> None:  # noqa: N802 (BaseHTTPRequestHandler API)
        parsed = urlparse(self.path)
        path = parsed.path.rstrip("/") or "/"

        if path == "/health":
            self._send(200, {"ok": True})
            return

        if not self._authorized():
            self._send(401, {"error": "unauthorized"})
            return

        try:
            if path == "/api/soc/rollup":
                self._send(200, findings_db.rollup_by_project())
            elif path == "/api/soc/summary":
                qs = parse_qs(parsed.query)
                project = (qs.get("project") or [None])[0]
                self._send(200, findings_db.findings_summary(project=project))
            else:
                self._send(404, {"error": "not found"})
        except Exception as exc:
            print(f"[soc_feed] error serving {path}: {exc}", file=sys.stderr)
            self._send(500, {"error": "internal error"})

    def log_message(self, fmt: str, *args) -> None:
        # Quiet by default — PM2 captures stderr; avoid noisy per-request logs.
        return


def main() -> int:
    server = ThreadingHTTPServer(("127.0.0.1", PORT), SOCFeedHandler)
    print(f"[soc_feed] listening on http://127.0.0.1:{PORT}", file=sys.stderr)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        server.shutdown()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
