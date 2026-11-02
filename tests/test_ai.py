"""Local AI review, tested against a fake Ollama server so no model is needed."""

from __future__ import annotations

import http.server
import json
import os
import threading
import unittest
import xml.etree.ElementTree as ET
from pathlib import Path

from helpers import isolated_home, materialize

from ladpock.ai import system
from ladpock.ai.client import LocalModelError, ModelInfo, OllamaClient, pick_model
from ladpock.ai.grounding import ground
from ladpock.ai.review import run_review
from ladpock.ai.units import build_units
from ladpock.db import DB
from ladpock.files import FileIndex
from ladpock.scan import run_scan

IDOR_LINE = "const order = await db.order.findUnique({ where: { id: params.id } });"


class FakeOllama(http.server.BaseHTTPRequestHandler):
    """Answers like Ollama: one real issue plus one invented one for the IDOR route."""

    chats: list[str] = []

    def log_message(self, *args):
        pass

    def _send(self, payload: dict) -> None:
        body = json.dumps(payload).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        if self.path == "/api/tags":
            self._send({"models": [{"name": "fake:7b", "size": 7_000_000_000, "details": {"parameter_size": "7B"},
                                    "capabilities": ["completion"]}]})
        else:
            self._send({"version": "test"})

    def do_POST(self):
        request = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
        prompt = request["messages"][1]["content"]
        FakeOllama.chats.append(prompt)
        if "Scanner finding:" in prompt:
            content = {"verdict": "real", "reason": "User input reaches the query."}
        elif "Another reviewer made the claim" in prompt:
            # The second look rejects the misreading (auth IS checked) and keeps the real bug.
            content = {"accurate": "ownership" in prompt, "reason": "checked"}
        elif IDOR_LINE in prompt:
            content = {"issues": [
                {"title": "Order loaded without an ownership check", "severity": "critical", "category": "authz",
                 "line": 1, "quote": IDOR_LINE, "explanation": "Any user can read any order.",
                 "fix": "Filter by user id."},
                {"title": "Invented problem", "severity": "high", "category": "injection", "line": 3,
                 "quote": "await db.deleteEverything();", "explanation": "Not real.", "fix": "n/a"},
                {"title": "Missing authentication", "severity": "high", "category": "auth", "line": 6,
                 "quote": "const session = await auth();", "explanation": "No login check.", "fix": "Add one."},
            ]}
        else:
            content = {"issues": []}
        self._send({"message": {"content": json.dumps(content)}, "prompt_eval_count": 100,
                    "prompt_eval_duration": 10_000_000, "eval_count": 20, "eval_duration": 100_000_000})


def start_fake() -> tuple[http.server.ThreadingHTTPServer, str]:
    server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), FakeOllama)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    return server, f"http://127.0.0.1:{server.server_address[1]}"


class Grounding(unittest.TestCase):
    lines = {10: "  const user = await getUser();", 11: f"  {IDOR_LINE}", 12: "  return Response.json(order);",
             40: f"  {IDOR_LINE}"}

    def issue(self, **kw):
        base = {"title": "t", "severity": "high", "category": "authz", "line": 11, "quote": IDOR_LINE,
                "explanation": "e", "fix": "f"}
        base.update(kw)
        return base

    def test_exact_quote_is_kept_and_pinned_to_nearest_line(self):
        self.assertEqual(ground(self.issue(line=38), self.lines).line, 40)
        self.assertEqual(ground(self.issue(line=12), self.lines).line, 11)

    def test_line_numbers_and_whitespace_are_tolerated(self):
        self.assertIsNotNone(ground(self.issue(quote=f"   11|   {IDOR_LINE.replace(' ', '  ')}"), self.lines))

    def test_invented_or_trivial_quotes_are_dropped(self):
        self.assertIsNone(ground(self.issue(quote="await db.deleteEverything();"), self.lines))
        self.assertIsNone(ground(self.issue(quote="order"), self.lines))

    def test_critical_is_capped_and_bad_category_mapped(self):
        lead = ground(self.issue(severity="critical", category="made-up"), self.lines)
        self.assertEqual((lead.severity, lead.category), ("high", "vibe"))


class ClientSafety(unittest.TestCase):
    def test_refuses_non_local_servers(self):
        with self.assertRaises(LocalModelError):
            OllamaClient("http://example.com:11434")

    def test_pick_model_prefers_largest_that_fits(self):
        models = [ModelInfo("small", 6_000_000_000), ModelInfo("mid-coder", 20_000_000_000), ModelInfo("huge", 50_000_000_000)]
        self.assertEqual(pick_model(models, 24_000_000_000).name, "mid-coder")
        self.assertEqual(pick_model(models, 4_000_000_000).name, "small")


class Units(unittest.TestCase):
    def test_units_cover_routes_commands_and_redact_secrets(self):
        with materialize("vuln-next-supabase") as tmp:
            units = build_units(FileIndex(Path(tmp) / "vuln-next-supabase"), [])
        kinds = {u.kind for u in units}
        self.assertTrue({"route", "file"} <= kinds)
        route = next(u for u in units if u.title == "GET /api/orders/[id]")
        self.assertIn("Ownership check: no", route.facts)
        self.assertTrue(all("LadPockFixtureQ1w2E3r4T5y6U7" not in u.code for u in units))
        with materialize("vuln-tauri") as tmp:
            units = build_units(FileIndex(Path(tmp) / "vuln-tauri"), [])
        self.assertIn("Tauri command run_tool", {u.title for u in units})


class ReviewRun(unittest.TestCase):
    def setUp(self):
        self.home = isolated_home()
        self.fake, self.url = start_fake()
        FakeOllama.chats = []
        self.tmp = materialize("vuln-next-supabase")
        self.root = Path(self.tmp.name) / "vuln-next-supabase"
        self.db = DB()
        run_scan(self.root, self.db, offline=True, external=False, log=lambda _: None)
        self.pid = self.db.get_project(self.root)["id"]
        self.client = OllamaClient(self.url, model="fake:7b")

    def tearDown(self):
        self.db.close()
        self.fake.shutdown()
        self.fake.server_close()
        self.tmp.cleanup()
        self.home.cleanup()

    def review(self, **kw):
        return run_review(self.db, self.pid, self.client, log=lambda _: None, **kw)

    def test_full_review_grounds_caches_and_resumes(self):
        first = self.review(max_units=5)
        self.assertEqual(first.done, 5)
        rest = self.review()
        self.assertEqual(rest.status, "done")
        self.assertEqual(rest.cached, 5)  # the first run's work is kept

        leads = self.db.ai_leads(self.pid)
        self.assertEqual([(l["title"], l["severity"]) for l in leads], [("Order loaded without an ownership check", "high")])
        self.assertGreaterEqual(first.dropped + rest.dropped, 1)  # the invented issue never reaches you
        self.assertGreaterEqual(first.rejected + rest.rejected, 1)  # nor does the misreading the second look caught
        self.assertTrue(self.db.ai_verdicts(self.pid))

        calls = len(FakeOllama.chats)
        again = self.review()
        self.assertEqual((again.done, len(FakeOllama.chats)), (0, calls))  # nothing changed, nothing re-read

    def test_dismissed_leads_stay_dismissed_and_changed_code_is_reread(self):
        self.review()
        lead = self.db.ai_leads(self.pid)[0]
        self.db.ai_set_lead_status(self.pid, lead["id"], "dismissed")
        route = self.root / "app" / "api" / "orders" / "[id]" / "route.ts"
        route.write_text(route.read_text(encoding="utf-8") + "\n// touched\n", encoding="utf-8")
        calls = len(FakeOllama.chats)
        rerun = self.review()
        self.assertGreaterEqual(rerun.done, 1)
        self.assertLess(rerun.done, 5)  # only the changed parts
        self.assertGreater(len(FakeOllama.chats), calls)
        self.assertEqual(self.db.ai_leads(self.pid)[0]["status"], "dismissed")

    def test_stop_request_pauses_cleanly(self):
        summary = self.review(should_stop=lambda: True)
        self.assertEqual((summary.status, summary.done), ("stopped", 0))
        self.assertEqual(self.db.ai_last_run(self.pid)["status"], "stopped")


class Scheduling(unittest.TestCase):
    def test_task_xml_is_well_formed_and_safe(self):
        xml = system.task_xml("01:30", "06:45", wake=True)
        root = ET.fromstring(xml.replace('encoding="UTF-16"', ""))
        ns = {"t": "http://schemas.microsoft.com/windows/2004/02/mit/task"}
        self.assertEqual(root.find("t:Settings/t:DisallowStartIfOnBatteries", ns).text, "true")
        self.assertEqual(root.find("t:Settings/t:WakeToRun", ns).text, "true")
        self.assertIn("--until 06:45", root.find("t:Actions/t:Exec/t:Arguments", ns).text)
        self.assertIn("T01:30:00", root.find("t:Triggers/t:CalendarTrigger/t:StartBoundary", ns).text)

    def test_deadline_parsing(self):
        self.assertIsNone(system.deadline_from(None, None))
        self.assertIsNotNone(system.deadline_from("07:00", None))


class DashboardAi(unittest.TestCase):
    def test_review_from_the_dashboard_api(self):
        from test_ui import TOKEN
        from ladpock.ui.server import make_server
        import http.client
        import time

        home = isolated_home()
        fake, url = start_fake()
        os.environ["LADPOCK_OLLAMA_URL"] = url
        server = make_server(0, TOKEN)
        port = server.app.port
        threading.Thread(target=server.serve_forever, daemon=True).start()

        def api(method, path, body=None):
            conn = http.client.HTTPConnection("127.0.0.1", port, timeout=30)
            headers = {"Host": f"127.0.0.1:{port}", "X-LadPock-Token": TOKEN}
            data = None
            if method == "POST":
                headers["Content-Type"] = "application/json"
                data = json.dumps(body or {}).encode()
            conn.request(method, path, body=data, headers=headers)
            resp = conn.getresponse()
            payload = json.loads(resp.read() or b"{}")
            conn.close()
            return resp.status, payload

        try:
            with materialize("vuln-next-supabase") as tmp:
                root = Path(tmp) / "vuln-next-supabase"
                _, added = api("POST", "/api/projects", {"path": str(root)})
                pid = added["id"]
                status, info = api("GET", "/api/ai")
                self.assertTrue(info["available"])
                self.assertEqual(info["model"], "fake:7b")
                status, started = api("POST", f"/api/projects/{pid}/ai/run", {})
                self.assertEqual(status, 202)
                for _ in range(200):
                    _, job = api("GET", f"/api/jobs/{started['job']}")
                    if job["status"] != "running":
                        break
                    time.sleep(0.05)
                self.assertEqual(job["status"], "done", job.get("error"))
                _, project = api("GET", f"/api/projects/{pid}")
                leads = project["ai"]["leads"]
                self.assertEqual(len(leads), 1)
                self.assertEqual(api("POST", f"/api/projects/{pid}/ai/leads/{leads[0]['id']}", {"status": "confirmed"})[0], 200)
                self.assertEqual(api("POST", f"/api/projects/{pid}/ai/leads/{leads[0]['id']}", {"status": "bogus"})[0], 400)
                self.assertEqual(api("POST", f"/api/projects/{pid}/ai/nightly", {"enabled": True})[0], 200)
        finally:
            os.environ.pop("LADPOCK_OLLAMA_URL", None)
            server.shutdown()
            server.server_close()
            fake.shutdown()
            fake.server_close()
            home.cleanup()


if __name__ == "__main__":
    unittest.main()
