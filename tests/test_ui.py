"""The dashboard server: its security rules and the scan flow through the API."""

from __future__ import annotations

import http.client
import json
import threading
import time
import unittest
from pathlib import Path

from helpers import isolated_home, materialize

from ladpock.db import DB
from ladpock.ui.server import make_server

TOKEN = "test-token-0123456789"


class DashboardServer(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.home = isolated_home()
        cls.server = make_server(0, TOKEN)
        cls.port = cls.server.app.port
        cls.thread = threading.Thread(target=cls.server.serve_forever, daemon=True)
        cls.thread.start()

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.server.server_close()
        cls.home.cleanup()

    def request(self, method, path, body=None, headers=None, token=TOKEN, host=None):
        conn = http.client.HTTPConnection("127.0.0.1", self.port, timeout=30)
        hdrs = {"Host": host or f"127.0.0.1:{self.port}"}
        if token is not None:
            hdrs["X-LadPock-Token"] = token
        data = None
        if body is not None:
            data = json.dumps(body).encode()
            hdrs["Content-Type"] = "application/json"
        hdrs.update(headers or {})
        conn.request(method, path, body=data, headers=hdrs)
        resp = conn.getresponse()
        raw = resp.read()
        conn.close()
        return resp, raw

    def api(self, method, path, body=None, **kwargs):
        resp, raw = self.request(method, path, body, **kwargs)
        return resp.status, json.loads(raw or b"{}")

    # security

    def test_page_is_served_with_strict_headers(self):
        resp, raw = self.request("GET", "/", token=None)
        self.assertEqual(resp.status, 200)
        self.assertIn(b"<title>LadPock</title>", raw)
        csp = resp.getheader("Content-Security-Policy")
        self.assertIn("script-src 'self'", csp)
        self.assertIn("frame-ancestors 'none'", csp)
        self.assertEqual(resp.getheader("X-Content-Type-Options"), "nosniff")
        self.assertIsNone(resp.getheader("Access-Control-Allow-Origin"))

    def test_api_requires_token(self):
        self.assertEqual(self.api("GET", "/api/status", token=None)[0], 401)
        self.assertEqual(self.api("GET", "/api/status", token="wrong")[0], 401)
        self.assertEqual(self.api("GET", "/api/status")[0], 200)

    def test_dns_rebinding_host_is_refused(self):
        self.assertEqual(self.api("GET", "/api/status", host=f"evil.example:{self.port}")[0], 403)
        resp, _ = self.request("GET", "/", token=None, host="attacker.example")
        self.assertEqual(resp.status, 403)

    def test_cross_site_requests_are_refused(self):
        self.assertEqual(self.api("GET", "/api/status", headers={"Origin": "https://evil.example"})[0], 403)
        self.assertEqual(self.api("GET", "/api/status", headers={"Sec-Fetch-Site": "cross-site"})[0], 403)
        self.assertEqual(self.api("GET", "/api/status", headers={"Origin": f"http://127.0.0.1:{self.port}"})[0], 200)

    def test_post_requires_json(self):
        resp, _ = self.request("POST", "/api/ack", headers={"Content-Type": "text/plain"})
        self.assertEqual(resp.status, 415)

    def test_static_files_are_allowlisted(self):
        for path in ("/../pyproject.toml", "/..%2f..%2fpyproject.toml", "/server.py", "/app.js/../server.py"):
            resp, _ = self.request("GET", path, token=None)
            self.assertEqual(resp.status, 404, path)
        resp, _ = self.request("GET", "/app.js", token=None)
        self.assertEqual(resp.status, 200)
        self.assertIn("javascript", resp.getheader("Content-Type"))

    def test_bad_input_is_rejected(self):
        self.assertEqual(self.api("POST", "/api/projects", {"path": "relative/path"})[0], 400)
        self.assertEqual(self.api("GET", "/api/projects/999999")[0], 404)
        self.assertEqual(self.api("GET", "/api/nope")[0], 404)

    # the main flow

    def test_add_scan_and_read_project(self):
        with materialize("vuln-next-supabase") as tmp:
            root = Path(tmp) / "vuln-next-supabase"
            status, added = self.api("POST", "/api/projects", {"path": str(root)})
            self.assertEqual(status, 200)
            pid = added["id"]

            status, started = self.api("POST", f"/api/projects/{pid}/scan",
                                       {"profile": "standard", "offline": True, "external": False})
            self.assertEqual(status, 202)
            job = {}
            for _ in range(120):
                _, job = self.api("GET", f"/api/jobs/{started['job']}")
                if job["status"] != "running":
                    break
                time.sleep(0.25)
            self.assertEqual(job["status"], "done", job.get("error"))
            self.assertEqual(job["result"]["grade"], "F")

            status, project = self.api("GET", f"/api/projects/{pid}")
            self.assertEqual(status, 200)
            self.assertGreater(len(project["findings"]), 20)
            self.assertTrue(project["scan"]["summary"]["categories"])
            dump = json.dumps(project)
            self.assertNotIn("LadPockFixtureQ1w2E3r4T5y6U7", dump)  # secrets stay masked

            status, routes = self.api("GET", f"/api/projects/{pid}/routes")
            self.assertTrue(any(r["path"] == "/api/orders/[id]" and "no ownership check" in r["gaps"] for r in routes["routes"]))

            status, prompt = self.api("GET", f"/api/projects/{pid}/fix-prompt")
            self.assertIn("LadPock found these security issues", prompt["prompt"])

            ref = project["findings"][0]["ref"]
            self.assertEqual(self.api("POST", f"/api/projects/{pid}/suppress", {"ref": ref, "reason": ""})[0], 400)
            self.assertEqual(self.api("POST", f"/api/projects/{pid}/suppress", {"ref": ref, "reason": "test", "days": 30})[0], 200)

            self.assertEqual(self.api("POST", f"/api/projects/{pid}/human", {"item": "H-01", "checked": True})[0], 200)
            _, project = self.api("GET", f"/api/projects/{pid}")
            self.assertTrue(next(i for i in project["human"] if i["id"] == "H-01")["checked_at"])

            _, status_payload = self.api("GET", "/api/status")
            self.assertIn(pid, [p["id"] for p in status_payload["projects"]])

            self.assertEqual(self.api("DELETE", f"/api/projects/{pid}")[0], 200)
            db = DB()
            try:
                self.assertIsNone(db.get_project_by_id(pid))
            finally:
                db.close()

    def test_browse_lists_folders_only(self):
        with materialize("clean-next-supabase") as tmp:
            status, listing = self.api("GET", f"/api/browse?path={tmp}")
        self.assertEqual(status, 200)
        names = {d["name"]: d for d in listing["dirs"]}
        self.assertTrue(names["clean-next-supabase"]["project"])
        self.assertFalse(listing["project"])
        self.assertEqual(listing["projects_inside"], 1)
        self.assertEqual(self.api("GET", "/api/browse?path=Z:%5Cdefinitely%5Cmissing")[0], 400)


if __name__ == "__main__":
    unittest.main()
