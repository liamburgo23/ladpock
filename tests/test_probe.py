"""Live checks, against two small servers on this computer: one leaky, one hardened."""

from __future__ import annotations

import html
import http.server
import json
import tempfile
import threading
import unittest
from pathlib import Path
from urllib.parse import parse_qs, urlsplit

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
            return self.reply(200, HOME, "text/html", {"X-Powered-By": "Express", "Server": "nginx/1.18.0", **cors,
                                                       "Set-Cookie": "session=leaky-cookie-value; Path=/"})
        if "%27" in self.path:
            return self.reply(500, 'error: syntax error at or near "1\'"', "text/plain")
        if self.path.startswith("/search?"):
            query = parse_qs(urlsplit(self.path).query)
            return self.reply(200, f"<html><body>Results for {query.get('q', [''])[0]}</body></html>", "text/html")
        if self.path.startswith("/login?"):
            query = parse_qs(urlsplit(self.path).query)
            return self.reply(302, "", headers={"Location": query.get("next", ["/"])[0]})
        if self.path == "/uploads/":
            return self.reply(200, "<html><title>Index of /uploads</title><body>a.pdf</body></html>", "text/html")
        if self.path == "/openapi.json":
            return self.reply(200, json.dumps({"openapi": "3.0.0"}), "application/json")
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
        if self.path.startswith("/search?"):
            query = parse_qs(urlsplit(self.path).query)
            escaped = html.escape(query.get("q", [""])[0])
            return self.reply(200, f"<html><body>Results for {escaped}</body></html>", "text/html", self.secure())
        if self.path.startswith("/login?"):
            return self.reply(302, "", headers={"Location": "/dashboard", **self.secure()})  # ignores the address it was given
        if self.path == "/" or self.path.startswith("/.") or self.path.startswith("/?"):
            cookies = {"Set-Cookie": "session=safe; Path=/; HttpOnly; SameSite=Lax"}
            return self.reply(200, HOME, "text/html", {**self.secure(), **cookies})  # single-page app fallback
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
    Route("GET", "/search", "app/search/route.ts", 2, "route"),
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
        self.assertEqual(set(by_id), {"LP-LIVE-001", "LP-LIVE-002", "LP-LIVE-003", "LP-LIVE-004", "LP-LIVE-005", "LP-LIVE-006",
                                      "LP-LIVE-007", "LP-LIVE-010", "LP-LIVE-011", "LP-LIVE-012", "LP-LIVE-013", "LP-LIVE-015",
                                      "LP-LIVE-016"})
        self.assertEqual(by_id["LP-LIVE-012"][0].file, "app/api/orders/[id]/route.ts")  # the stray quote, linked to the code
        self.assertEqual(by_id["LP-LIVE-011"][0].file, "app/search/route.ts")
        self.assertIn("HttpOnly", by_id["LP-LIVE-010"][0].snippet)
        self.assertNotIn("leaky-cookie-value", json.dumps([f.snippet for f in result.findings] + [f.message for f in result.findings]))
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


ALICE, BOB = "session=alice-cookie", "Bearer bob-token"
ORDERS = {"alice": [{"id": 101, "total": 25}, {"id": 102, "total": 30}], "bob": [{"id": 201, "total": 7}]}
PROJECTS = {"alice": [{"id": "p1"}], "bob": [{"id": "p2"}]}
TASKS = {"p1": [{"id": "t1", "title": "alice's task"}], "p2": [{"id": "t2", "title": "bob's task"}]}
CATALOG = [{"id": 1, "name": "shared thing"}, {"id": 2, "name": "other shared thing"}]
USERS = {"alice": {"id": "u-alice", "email": "alice@example.invalid"}, "bob": {"id": "u-bob", "email": "bob@example.invalid"}}
PAGE = "<!doctype html><html><head><meta name='csrf' content='{nonce}'></head><body><nav>Signed in as {who}</nav>{main}</body></html>"
PADDING = "Billing details and delivery address for this order are shown below as they were entered at checkout time. "


class TwoUsers(_Base):
    """Every record is reachable by anyone signed in: the classic bug."""
    calls: list[tuple[str, str]] = []
    nonce = 0

    def who(self):
        if self.headers.get("Cookie") == ALICE:
            return "alice"
        if self.headers.get("Authorization") == BOB:
            return "bob"
        return None

    def json(self, data, status=200):
        return self.reply(status, json.dumps(data), "application/json")

    def page(self, who, main, status=200):
        type(self).nonce += 1
        return self.reply(status, PAGE.format(nonce=type(self).nonce, who=who, main=main), "text/html")

    def do_GET(self):
        type(self).calls.append(("GET", self.path))
        who = self.who()
        if self.path == "/":
            return self.reply(200, HOME, "text/html")
        if not who:
            if self.path.startswith("/api/"):
                return self.json({"error": "login required"}, 401)
            return self.reply(302, "", headers={"Location": "/login"})
        return self.answer(who, self.path)

    do_HEAD = do_GET

    def answer(self, who, path):
        parts = path.strip("/").split("/")
        if path == "/api/orders":
            return self.json(ORDERS[who])
        if path == "/api/catalog":
            return self.json({"items": CATALOG})
        if path == "/api/projects":
            return self.json({"projects": PROJECTS[who]})
        if path == "/api/me":
            return self.json({"user": USERS[who]})
        if path == "/api/admin/stats":
            return self.json({"users": 2, "revenue": 62})
        if path == "/orders":
            links = "".join(f"<a href='/orders/{o['id']}'>Order {o['id']}</a>" for o in ORDERS[who])
            return self.page(who, f"<h1>Your orders</h1>{links}")
        if len(parts) == 2 and parts[0] == "orders":
            return self.show_order_page(who, parts[1])
        if len(parts) == 3 and parts[:2] == ["api", "orders"]:
            return self.show_order(who, parts[2])
        if len(parts) == 3 and parts[:2] == ["api", "catalog"]:
            found = [c for c in CATALOG if str(c["id"]) == parts[2]]
            return self.json(found[0]) if found else self.json({"error": "not found"}, 404)
        if len(parts) == 3 and parts[:2] == ["api", "users"]:
            return self.show_user(who, parts[2])
        if len(parts) == 4 and parts[:2] == ["api", "projects"] and parts[3] == "tasks":
            return self.list_tasks(who, parts[2])
        if len(parts) == 5 and parts[:2] == ["api", "projects"] and parts[3] == "tasks":
            return self.show_task(who, parts[2], parts[4])
        return self.json({"error": "not found"}, 404)

    def order(self, record):
        return next((o for orders in ORDERS.values() for o in orders if str(o["id"]) == record), None)

    def show_order(self, who, record):
        found = self.order(record)
        return self.json(found) if found else self.json({"error": "not found"}, 404)

    def show_order_page(self, who, record):
        found = self.order(record)
        if not found:
            return self.page(who, "<h1>Sorry, that order was not found on this account</h1>", 404)
        return self.page(who, f"<h1>Order {record}</h1><p>{PADDING}Total {found['total']}</p>")

    def show_user(self, who, record):
        found = next((u for u in USERS.values() if u["id"] == record), None)
        return self.json(found) if found else self.json({"error": "not found"}, 404)

    def list_tasks(self, who, project):
        return self.json(TASKS.get(project, []))

    def show_task(self, who, project, record):
        found = [t for t in TASKS.get(project, []) if t["id"] == record]
        return self.json(found[0]) if found else self.json({"error": "not found"}, 404)


class Scoped(TwoUsers):
    """The same app with the bug fixed: other people's records are refused."""

    def owns(self, who, record):
        return any(str(o["id"]) == record for o in ORDERS[who])

    def answer(self, who, path):
        if path == "/api/admin/stats":
            return self.json({"error": "admins only"}, 403)
        return super().answer(who, path)

    def show_order(self, who, record):
        return super().show_order(who, record) if self.owns(who, record) else self.json({"error": "not found"}, 404)

    def show_order_page(self, who, record):
        if self.owns(who, record):
            return super().show_order_page(who, record)
        return self.page(who, f"<h1>Sorry, you don't have permission to see this order</h1><p>{PADDING}</p>")

    def show_user(self, who, record):
        return super().show_user(who, record) if USERS[who]["id"] == record else self.json({"error": "forbidden"}, 403)

    def list_tasks(self, who, project):
        return self.json(TASKS[project]) if any(p["id"] == project for p in PROJECTS[who]) else self.json({"error": "forbidden"}, 403)

    def show_task(self, who, project, record):
        if not any(p["id"] == project for p in PROJECTS[who]):
            return self.json({"error": "forbidden"}, 403)
        return super().show_task(who, project, record)


class PoliteRefusal(Scoped):
    """Refuses with a 200 and a page or an error object, which is common and must not look like a leak."""

    def show_order(self, who, record):
        return super().show_order(who, record) if self.owns(who, record) else self.json({"error": "not yours"})

    def show_user(self, who, record):
        return super().show_user(who, record) if USERS[who]["id"] == record else self.json({"success": False, "message": "no"})


class SameAnyId(TwoUsers):
    """Answers the same thing for any ID at all, so the ID isn't selecting a record."""

    def show_order(self, who, record):
        return self.json({"status": "ready", "region": "eu", "version": 4})


def account_routes():
    def get(path, file):
        return Route("GET", path, file, 3, "route", auth="yes", db=True, dynamic="[" in path)
    return [get("/api/orders", "orders.ts"), get("/api/orders/[id]", "order.ts"), get("/api/catalog", "catalog.ts"),
            get("/api/catalog/[id]", "item.ts"), get("/api/me", "me.ts"), get("/api/users/[id]", "user.ts"),
            get("/api/admin/stats", "stats.ts"), get("/api/projects", "projects.ts"),
            get("/api/projects/[projectId]/tasks/[taskId]", "task.ts"), get("/orders", "orders.rb"),
            Route("GET", "/orders/:id", "orders.rb", 9, "rails", auth="yes", dynamic=True),
            Route("DELETE", "/api/orders/[id]", "order.ts", 30, "route", auth="yes")]


class CachedOrders(TwoUsers):
    """Answers correctly, but tells every cache it may keep the answer."""

    def reply(self, status, body, content_type="text/plain", headers=None):
        return super().reply(status, body, content_type, {**(headers or {}), "Cache-Control": "public, max-age=600"})


class SyntaxErrorForAccounts(TwoUsers):
    """The stray quote only causes an error for someone signed in."""

    def answer(self, who, path):
        if "%27" in path:
            return self.reply(500, "SQLSTATE[42000]: You have an error in your SQL syntax", "text/plain")
        return super().answer(who, path)


class TypedIdError(TwoUsers):
    """A parameterised query rejecting a bad value isn't SQL injection."""

    def answer(self, who, path):
        if "%27" in path:
            return self.reply(500, 'SQLSTATE[22P02]: invalid input syntax for type integer: "1\'"', "text/plain")
        return super().answer(who, path)


class TwoAccountChecks(unittest.TestCase):
    def setUp(self):
        TwoUsers.calls = []

    def probe(self, handler, a=ALICE, b=BOB, routes=None, **kw):
        server, url = serve(handler)
        try:
            return probe.run_probe(url, account_routes() if routes is None else routes, log=lambda _: None, user_a=a, user_b=b, **kw)
        finally:
            server.shutdown()
            server.server_close()

    @staticmethod
    def found(result, check_id):
        return sorted(f.file for f in result.findings if f.check_id == check_id)

    def test_finds_every_way_of_reading_another_account(self):
        result = self.probe(TwoUsers)
        self.assertEqual(self.found(result, "LP-LIVE-008"), ["order.ts", "orders.rb", "task.ts", "user.ts"])
        by_file = {f.file: f for f in result.findings if f.check_id == "LP-LIVE-008"}
        self.assertEqual(by_file["order.ts"].confidence, "high")
        self.assertEqual(by_file["order.ts"].line, 3)  # linked to the code that needs fixing
        self.assertEqual(by_file["orders.rb"].confidence, "medium")  # pages are compared by how alike they read
        self.assertIn("/api/me", by_file["user.ts"].message)
        self.assertEqual(self.found(result, "LP-LIVE-009"), ["stats.ts"])

    def test_fixed_app_is_clean(self):
        result = self.probe(Scoped)
        self.assertEqual([f"{f.check_id} {f.snippet}" for f in result.findings if f.check_id in ("LP-LIVE-008", "LP-LIVE-009")], [])
        self.assertGreaterEqual(result.accounts["protected"], 4)
        self.assertEqual(result.accounts["exposed"], 0)

    def test_refusing_with_a_200_is_not_a_leak(self):
        self.assertEqual(self.found(self.probe(PoliteRefusal), "LP-LIVE-008"), [])

    def test_shared_records_are_not_a_leak(self):
        result = self.probe(TwoUsers)
        self.assertNotIn("item.ts", self.found(result, "LP-LIVE-008"))
        self.assertGreaterEqual(result.accounts["shared_skipped"], 1)

    def test_an_answer_that_ignores_the_id_is_not_a_leak(self):
        self.assertNotIn("order.ts", self.found(self.probe(SameAnyId), "LP-LIVE-008"))

    def test_only_reads(self):
        self.probe(TwoUsers, include_writes=False)
        self.assertEqual({method for method, _ in TwoUsers.calls}, {"GET"})

    def test_logins_stay_out_of_everything_reported(self):
        result = self.probe(TwoUsers)
        reported = json.dumps([[f.title, f.message, f.snippet, f.extra, f.fix] for f in result.findings] + [result.notes, result.accounts])
        for secret in ("alice-cookie", "bob-token"):
            self.assertNotIn(secret, reported)

    def test_login_that_does_nothing_gets_a_note(self):
        result = self.probe(TwoUsers, a="session=expired", b="Bearer expired")
        self.assertEqual(self.found(result, "LP-LIVE-008"), [])
        self.assertTrue(any("signed in" in note for note in result.notes), result.notes)

    def test_same_records_for_both_gets_a_note(self):
        routes = [r for r in account_routes() if "catalog" in r.path]
        result = self.probe(TwoUsers, routes=routes)
        self.assertEqual(result.accounts["records_checked"], 0)
        self.assertTrue(any("same records" in note for note in result.notes), result.notes)

    def test_private_answers_marked_cacheable(self):
        self.assertIn("orders.ts", self.found(self.probe(CachedOrders), "LP-LIVE-014"))
        self.assertEqual(self.found(self.probe(TwoUsers), "LP-LIVE-014"), [])

    def test_probes_use_the_login(self):
        self.assertIn("order.ts", self.found(self.probe(SyntaxErrorForAccounts), "LP-LIVE-012"))
        self.assertEqual(self.found(self.probe(TypedIdError), "LP-LIVE-012"), [])

    def test_records_you_name_yourself(self):
        routes = [Route("GET", "/api/orders/[id]", "order.ts", 3, "route", auth="yes", dynamic=True)]
        result = self.probe(TwoUsers, routes=routes, own_urls=["/api/orders/101"])
        self.assertEqual(self.found(result, "LP-LIVE-008"), ["order.ts"])
        self.assertEqual(self.found(self.probe(Scoped, routes=routes, own_urls=["/api/orders/101"]), "LP-LIVE-008"), [])

    def test_needs_both_accounts(self):
        server, url = serve(TwoUsers)
        try:
            with self.assertRaises(probe.ProbeError):
                probe.run_probe(url, [], log=lambda _: None, user_a=ALICE)
        finally:
            server.shutdown()
            server.server_close()

    def test_login_forms(self):
        self.assertEqual(probe.parse_login("Cookie: a=b; c=d", "A"), {"Cookie": "a=b; c=d"})
        self.assertEqual(probe.parse_login("Authorization: Bearer x", "A"), {"Authorization": "Bearer x"})
        self.assertEqual(probe.parse_login("Bearer x", "A"), {"Authorization": "Bearer x"})
        self.assertEqual(probe.parse_login("a=b:c", "A"), {"Cookie": "a=b:c"})
        for bad in ("", "justaword", "Cookie: a=b\r\nX-Evil: 1"):
            with self.subTest(bad), self.assertRaises(probe.ProbeError) as caught:
                probe.parse_login(bad, "Account A")
            if bad:
                self.assertNotIn(bad, str(caught.exception))  # never repeat a login in an error

    def test_record_addresses_stay_on_this_app(self):
        base = "http://localhost:3000"
        self.assertEqual(probe.own_url_path("/api/orders/1", base), "/api/orders/1")
        self.assertEqual(probe.own_url_path("http://localhost:3000/api/orders/1?x=2", base), "/api/orders/1?x=2")
        for bad in ("https://example.com/a", "//example.com/a", "http://localhost:3001/a", "/a b"):
            with self.subTest(bad), self.assertRaises(probe.ProbeError):
                probe.own_url_path(bad, base)

    def test_no_request_can_leave_this_computer(self):
        server, url = serve(TwoUsers)
        try:
            result = probe.ProbeResult(url)
            client = probe.Client(url, result, lambda: False)
            client.send("GET", "/http://example.invalid/steal", {"Cookie": ALICE})
            self.assertIn(("GET", "/http://example.invalid/steal"), TwoUsers.calls)  # stayed on the local server
        finally:
            server.shutdown()
            server.server_close()

    def test_odd_ids_never_go_in_a_url(self):
        self.assertIsNone(probe._id_of({"id": "../../admin"}, ("id",)))
        self.assertIsNone(probe._id_of({"id": "http://example.invalid"}, ("id",)))
        self.assertIsNone(probe._id_of({"id": ".."}, ("id",)))
        self.assertIsNone(probe._id_of({"id": True}, ("id",)))
        self.assertEqual(probe._id_of({"id": 12}, ("id",)), "12")

    def test_scan_never_stores_logins(self):
        home = isolated_home()
        db = DB()
        server, url = serve(TwoUsers)
        try:
            with materialize("vuln-next-supabase") as tmp:
                root = Path(tmp) / "vuln-next-supabase"
                run_scan(root, db, offline=True, external=False, log=lambda _: None, live_url=url, live_user_a=ALICE, live_user_b=BOB)
                row = db.latest_scan(db.get_project(root)["id"])
                summary = json.loads(row["summary"])
                self.assertIn("records_checked", summary["live"]["accounts"])
                db.close()
                stored = b"".join(p.read_bytes() for p in Path(home.name).rglob("*") if p.is_file())
                for secret in (b"alice-cookie", b"bob-token"):
                    self.assertNotIn(secret, stored)
        finally:
            server.shutdown()
            server.server_close()
            db.close()
            home.cleanup()


class Correlation(unittest.TestCase):
    """What the running app did, applied to what the code looked like."""

    def finding(self, check_id, snippet, confidence="medium"):
        from ladpock.models import Finding, Severity
        return Finding(check_id, "t", Severity.HIGH, "authz", message="Base.", snippet=snippet, confidence=confidence)

    def test_refused_without_login_lowers_confidence(self):
        result = probe.ProbeResult("http://x", route_outcomes={"GET /api/invoices": "refused"})
        f = self.finding("LP-AUTHZ-007", "GET /api/invoices")
        probe.correlate([f], result)
        self.assertEqual((f.confidence, f.extra["live"]), ("low", "refused"))
        self.assertIn("refused", f.message)

    def test_answered_without_login_confirms(self):
        result = probe.ProbeResult("http://x", route_outcomes={"GET /api/invoices": "answered"})
        f = self.finding("LP-AUTHZ-007", "GET /api/invoices", "low")
        probe.correlate([f], result)
        self.assertEqual((f.confidence, f.extra["live"]), ("high", "confirmed"))

    def test_two_accounts_settle_ownership(self):
        result = probe.ProbeResult("http://x", account_outcomes={"GET /a/[id]": "protected", "GET /b/[id]": "exposed"})
        a, b, c = (self.finding("LP-AUTHZ-002", s) for s in ("GET /a/[id]", "GET /b/[id]", "DELETE /a/[id]"))
        probe.correlate([a, b, c], result)
        self.assertEqual((a.confidence, b.confidence, c.confidence), ("low", "high", "medium"))  # DELETE wasn't tried
        self.assertEqual(c.extra, {})

    def test_other_checks_and_routes_are_left_alone(self):
        result = probe.ProbeResult("http://x", route_outcomes={"GET /x": "refused"})
        other, elsewhere = self.finding("LP-INJ-003", "GET /x"), self.finding("LP-AUTHZ-007", "GET /y")
        fingerprint = other.fingerprint
        probe.correlate([other, elsewhere], result)
        self.assertEqual((other.confidence, elsewhere.confidence), ("medium", "medium"))
        self.assertEqual(other.fingerprint, fingerprint)

    def test_refs_dont_change(self):
        # Accepted risks are stored by ref, so changing a finding's confidence or message mustn't change its ref.
        result = probe.ProbeResult("http://x", route_outcomes={"GET /x": "refused"})
        f = self.finding("LP-AUTHZ-007", "GET /x")
        before = f.fingerprint
        probe.correlate([f], result)
        self.assertEqual(f.fingerprint, before)

    def test_end_to_end(self):
        home = isolated_home()
        db = DB()
        server, url = serve(Hardened)
        try:
            with tempfile.TemporaryDirectory() as tmp:
                root = Path(tmp) / "demo"
                (root / "app/api/invoices").mkdir(parents=True)
                (root / "next.config.js").write_text("")
                (root / "app/api/invoices/route.ts").write_text(
                    'import { db } from "@/lib/db";\nexport async function GET() { return Response.json(await db.invoice.findMany({ take: 5 })); }\n')
                before = run_scan(root, db, offline=True, external=False, log=lambda _: None)
                after = run_scan(root, db, offline=True, external=False, log=lambda _: None, live_url=url)
                pick = lambda r: next(f for f in r.findings if f.check_id == "LP-AUTHZ-007")
                self.assertEqual(pick(after).extra["live"], "refused")  # Hardened answers 401 to everything under /api/
                self.assertEqual(pick(before).fingerprint, pick(after).fingerprint)
        finally:
            server.shutdown()
            server.server_close()
            db.close()
            home.cleanup()


class DashboardResults(unittest.TestCase):
    """What the dashboard shows after a scan with two test accounts, and after one without."""

    def setUp(self):
        from ladpock.ui.server import make_server

        self.home = isolated_home()
        self.db = DB()
        self.server = make_server(0, "test-token")
        self.tmp = materialize("vuln-next-supabase")
        self.root = Path(self.tmp.name) / "vuln-next-supabase"
        self.addCleanup(self.home.cleanup)
        self.addCleanup(self.tmp.cleanup)
        self.addCleanup(self.db.close)
        self.addCleanup(self.server.server_close)

    def scan(self, **kwargs):
        from ladpock.ui.server import project_payload

        live, url = serve(TwoUsers)
        try:
            run_scan(self.root, self.db, offline=True, external=False, log=lambda _: None, live_url=url, **kwargs)
        finally:
            live.shutdown()
            live.server_close()
        return project_payload(self.server.app, self.db, self.db.get_project(self.root)["id"])

    def test_the_manual_check_shows_what_was_tried(self):
        payload = self.scan(live_user_a=ALICE, live_user_b=BOB)
        item = next(i for i in payload["human"] if i["id"] == "H-11")
        self.assertIn("with two test accounts", item["evidence"])
        self.assertIsNone(item["checked_at"])  # it informs the tick, it doesn't tick it
        self.assertNotIn("accounts", {g["id"] for g in payload["assessment"]["gaps"]})
        self.assertTrue(any(f["check_id"] == "LP-LIVE-008" for f in payload["findings"]))

    def test_without_accounts_it_says_what_was_left_out(self):
        payload = self.scan()
        item = next(i for i in payload["human"] if i["id"] == "H-11")
        self.assertNotIn("evidence", item)
        self.assertIn("accounts", {g["id"] for g in payload["assessment"]["gaps"]})

    def test_code_findings_show_the_live_result(self):
        payload = self.scan(live_user_a=ALICE, live_user_b=BOB)
        confirmed = [f for f in payload["findings"] if f["check_id"] == "LP-AUTHZ-002" and (f.get("extra") or {}).get("live") == "confirmed"]
        self.assertTrue(confirmed)
        self.assertEqual(confirmed[0]["confidence"], "high")

    def test_report_button(self):
        import re

        from ladpock.ui.server import api_report

        self.scan(live_user_a=ALICE, live_user_b=BOB)
        project = self.db.get_project(self.root)["id"]
        status, body = api_report(self.server.app, self.db, re.match(r"/api/projects/(\d+)/report", f"/api/projects/{project}/report"), {}, {})
        self.assertEqual(status, 200)
        self.assertEqual(body["filename"], "ladpock-report-vuln-next-supabase.html")
        self.assertIn("Two test accounts", body["html"])
        self.assertNotIn(str(self.root), body["html"])
        for secret in ("alice-cookie", "bob-token"):
            self.assertNotIn(secret, json.dumps(body))


class Options(unittest.TestCase):
    def test_panel_options(self):
        from ladpock.ui.server import ApiError, run_options
        options = run_options({"live": True, "live_url": "http://localhost:3000", "live_user_a": ALICE, "live_user_b": BOB,
                               "live_own_urls": ["/api/orders/1", " "]})
        self.assertEqual((options["live_user_a"], options["live_user_b"], options["live_own_urls"]), (ALICE, BOB, ("/api/orders/1",)))
        off = run_options({"live": False, "live_user_a": ALICE, "live_user_b": BOB})
        self.assertIsNone(off["live_user_a"])  # ignored unless live checks are on
        for body in ({"live_user_a": ALICE}, {"live_user_b": BOB}, {"live_user_a": "nonsense", "live_user_b": BOB},
                     {"live_own_urls": ["https://example.com/x"]}, {"live_own_urls": "/x"}):
            with self.subTest(body), self.assertRaises(ApiError):
                run_options({"live": True, **body})


if __name__ == "__main__":
    unittest.main()
