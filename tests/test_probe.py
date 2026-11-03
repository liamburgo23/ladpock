"""Live checks, against two small servers on this computer: one leaky, one hardened."""

from __future__ import annotations

import http.server
import json
import threading
import unittest
from pathlib import Path

from helpers import isolated_home, materialize

from ladpock import probe
from ladpock.db import DB
from ladpock.routes import Route
from ladpock.scan import run_scan

HOME = "<!doctype html><html><body>app</body></html>"


class _Base(http.server.BaseHTTPRequestHandler):
    calls: list[tuple[str, str]] = []

    def log_message(self, *args):
        pass

    def reply(self, status: int, body: str, content_type: str = "text/plain", headers: dict | None = None):
        data = body.encode()
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(data)))
        for key, value in (headers or {}).items():
            self.send_header(key, value)
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(data)

    def body(self) -> bytes:
        return self.rfile.read(int(self.headers.get("Content-Length") or 0))


class Leaky(_Base):
    def do_GET(self):
        type(self).calls.append(("GET", self.path))
        if self.path == "/":
            origin = self.headers.get("Origin")
            cors = {"Access-Control-Allow-Origin": origin, "Access-Control-Allow-Credentials": "true"} if origin else {}
            return self.reply(200, HOME, "text/html", {"X-Powered-By": "Express", "Server": "nginx/1.18.0", **cors})
        if self.path == "/.env":
            return self.reply(200, "API_KEY=abc123\nDATABASE_URL=postgres://x\n")
        if self.path == "/.git/HEAD":
            return self.reply(200, "ref: refs/heads/main\n")
        if self.path == "/api/orders/1":
            return self.reply(200, json.dumps({"id": 1, "total": 25}), "application/json")
        if "%ZZ" in self.path:
            return self.reply(500, "Traceback (most recent call last):\n  File \"app.py\", line 3, in view\nKeyError")
        return self.reply(404, "not found")

    do_HEAD = do_GET

    def do_POST(self):
        type(self).calls.append(("POST", self.path))
        self.body()
        return self.reply(401, json.dumps({"error": "invalid"}), "application/json")

    def do_DELETE(self):
        type(self).calls.append(("DELETE", self.path))
        return self.reply(204, "")


class Hardened(_Base):
    attempts = 0
    server_version = "app"  # BaseHTTPRequestHandler announces Python's version unless told not to
    sys_version = ""

    def secure(self):
        return {"Content-Security-Policy": "default-src 'self'; frame-ancestors 'none'", "X-Content-Type-Options": "nosniff",
                "Referrer-Policy": "no-referrer"}

    def do_GET(self):
        if self.path.startswith("/api/"):
            return self.reply(401, json.dumps({"error": "login required"}), "application/json", self.secure())
        if self.path == "/" or self.path.startswith("/."):
            return self.reply(200, HOME, "text/html", self.secure())  # single-page app fallback
        return self.reply(404, "Not found", "text/plain", self.secure())

    do_HEAD = do_GET

    def do_POST(self):
        self.body()
        type(self).attempts += 1
        if type(self).attempts > 5:
            return self.reply(429, "slow down", "text/plain", {"Retry-After": "60"})
        return self.reply(401, json.dumps({"error": "invalid"}), "application/json")


def serve(handler):
    server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), handler)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    return server, f"http://127.0.0.1:{server.server_address[1]}"


ROUTES = [
    Route("GET", "/api/orders/[id]", "app/api/orders/[id]/route.ts", 5, "route", auth="yes", db=True, dynamic=True),
    Route("DELETE", "/api/orders/[id]", "app/api/orders/[id]/route.ts", 20, "route", auth="yes"),
    Route("POST", "/api/login", "app/api/login/route.ts", 3, "route"),
]


class LiveChecks(unittest.TestCase):
    def setUp(self):
        Leaky.calls = []
        Hardened.attempts = 0

    def run_against(self, handler, **kw):
        server, url = serve(handler)
        try:
            return probe.run_probe(url, ROUTES, log=lambda _: None, **kw)
        finally:
            server.shutdown()
            server.server_close()

    def test_leaky_app(self):
        result = self.run_against(Leaky)
        by_id = {}
        for f in result.findings:
            by_id.setdefault(f.check_id, []).append(f)
        self.assertEqual(set(by_id), {"LP-LIVE-001", "LP-LIVE-002", "LP-LIVE-003", "LP-LIVE-004", "LP-LIVE-005",
                                      "LP-LIVE-006", "LP-LIVE-007"})
        unauth = by_id["LP-LIVE-001"][0]
        self.assertEqual((unauth.file, unauth.line), ("app/api/orders/[id]/route.ts", 5))  # linked to the code
        self.assertIn("appears to check the user", unauth.message)
        self.assertEqual(by_id["LP-LIVE-003"][0].severity.label, "high")  # reflected origin with credentials
        self.assertEqual({f.extra["url"].rsplit("/", 2)[-2:][-1] for f in by_id["LP-LIVE-004"]}, {".env", "HEAD"})
        env = next(f for f in by_id["LP-LIVE-004"] if f.extra["url"].endswith(".env"))
        self.assertNotIn("abc123", env.snippet)
        self.assertEqual(result.skipped_writes, 1)
        self.assertNotIn("DELETE", {m for m, _ in Leaky.calls})  # nothing that changes data by default

    def test_writes_only_when_asked(self):
        self.run_against(Leaky, include_writes=True)
        self.assertIn(("DELETE", "/api/orders/1"), Leaky.calls)

    def test_hardened_app_is_clean(self):
        result = self.run_against(Hardened)
        self.assertEqual([f"{f.check_id} {f.snippet}" for f in result.findings], [])

    def test_only_this_computer(self):
        for url in ("https://example.com", "http://10.0.0.5:3000", "ftp://localhost", "http://localhost.example.com"):
            with self.subTest(url), self.assertRaises(probe.ProbeError):
                probe.check_target(url)
        self.assertEqual(probe.check_target("localhost:3000"), "http://localhost:3000")

    def test_nothing_running(self):
        with self.assertRaises(probe.ProbeError):
            probe.run_probe("http://127.0.0.1:9", ROUTES, log=lambda _: None)

    def test_scan_includes_live_results(self):
        home = isolated_home()
        db = DB()
        server, url = serve(Leaky)
        try:
            with materialize("vuln-next-supabase") as tmp:
                root = Path(tmp) / "vuln-next-supabase"
                result = run_scan(root, db, offline=True, external=False, log=lambda _: None, live_url=url)
                live = [f for f in result.findings if f.source == "live"]
                self.assertTrue(any(f.check_id == "LP-LIVE-001" and f.file == "app/api/orders/[id]/route.ts" for f in live))
                summary = json.loads(db.latest_scan(db.get_project(root)["id"])["summary"])
                self.assertEqual(summary["live"]["url"], url)
                self.assertGreater(summary["live"]["routes"], 0)
        finally:
            server.shutdown()
            server.server_close()
            db.close()
            home.cleanup()


if __name__ == "__main__":
    unittest.main()
