"""Fixing findings one at a time from a chat: the loop, accepted risks, the MCP side, the dashboard API and `ladpock connect`."""

from __future__ import annotations

import http.client
import json
import os
import shutil
import subprocess
import tempfile
import threading
import time
import unittest
from pathlib import Path
from unittest import mock

from helpers import isolated_home, materialize

from ladpock import connect, fixloop, github, integrations
from ladpock.db import DB
from ladpock.ui.server import make_server

EVAL_LINE = "  res.json({ value: vm.runInNewContext(rule) });"
SHELL_LINE = "  exec(cmd);"
HAS_GIT = shutil.which("git") is not None


def git(root: Path, *args: str) -> None:
    subprocess.run(["git", "-c", "user.name=LadPock test", "-c", "user.email=test@example.invalid", "-c", "commit.gpgsign=false",
                    "-C", str(root), *args], check=True, capture_output=True)


class Loop(unittest.TestCase):
    def setUp(self):
        self.home = isolated_home()
        self.fixture = materialize("vuln-flows")
        self.root = Path(self.fixture.name) / "vuln-flows"
        self.db = DB()
        self.orders = self.root / "server" / "orders.js"

    def tearDown(self):
        self.db.close()
        self.fixture.cleanup()
        self.home.cleanup()

    def edit(self, old: str, new: str) -> None:
        text = self.orders.read_text(encoding="utf-8")
        self.assertIn(old, text)
        self.orders.write_bytes(text.replace(old, new).encode("utf-8"))

    def start(self, **kwargs) -> str:
        return fixloop.start(self.db, str(self.root), offline=True, **kwargs)

    def check(self, note: str = "") -> str:
        return fixloop.check(self.db, str(self.root), note, offline=True)

    def run_items(self):
        run = self.db.latest_fix_run(self.db.get_project(self.root)["id"])
        return {i["ref"]: i for i in self.db.fix_items(run["id"])}, run

    def test_worst_first_and_a_fix_is_confirmed_by_a_rescan(self):
        text = self.start(which="high")
        self.assertIn("worst first", text)
        self.assertIn("[CRITICAL] Request data runs as code", text)
        self.assertIn("ladpock_fix_check", text)
        self.edit(EVAL_LINE, "  res.json({ value: JSON.parse(rule) });")
        result = self.check("Parsed the formula as JSON instead of running it")
        self.assertIn("Fixed: LadPock no longer finds Request data runs as code", result)
        self.assertIn("Next (1 of", result)
        items, run = self.run_items()
        fixed = [i for i in items.values() if i["status"] == "fixed"]
        self.assertEqual(len(fixed), 1)
        self.assertEqual(fixed[0]["note"], "Parsed the formula as JSON instead of running it")
        self.assertEqual(run["status"], "active")
        self.assertEqual(run["scope"], "high")

    def test_changing_the_code_without_fixing_it_doesnt_count(self):
        self.start(which="critical")
        self.edit(EVAL_LINE, "  const out = vm.runInNewContext(rule);\n  res.json({ value: out });")
        first = self.check()
        self.assertIn("Not fixed yet", first)
        self.assertIn("same problem is still there", first)
        second = self.check()
        self.assertIn("STOP", second)
        items, _ = self.run_items()
        self.assertEqual([i["status"] for i in items.values()], ["needs_you"])

    def test_a_fix_that_breaks_something_else_stops_and_joins_the_list(self):
        self.start(which="critical")
        self.edit(EVAL_LINE, "  res.json({ value: JSON.parse(rule) });\n});\n\nrouter.get(\"/orders/run\", async (req, res) => {\n"
                             "  const job = req.query.job;\n  const line = `run ${job}`;\n  exec(line);\n  res.end();")
        result = self.check()
        self.assertIn("Fixed", result)
        self.assertIn("new finding(s) appeared", result)
        self.assertIn("STOP", result)
        items, _ = self.run_items()
        self.assertTrue(any(i["status"] == "queued" and i["check_id"] == "LP-FLOW-002" for i in items.values()))

    def test_skip_and_stop(self):
        self.start(which="high")
        with self.assertRaises(fixloop.FixError):
            fixloop.skip(self.db, str(self.root), "dunno")
        text = fixloop.skip(self.db, str(self.root), "Needs the user to choose which formula language to support")
        self.assertIn("Left for the user", text)
        self.assertIn("Stopped", fixloop.stop(self.db, str(self.root)))
        with self.assertRaises(fixloop.FixError):
            fixloop.next_item(self.db, str(self.root))

    def test_nothing_to_fix(self):
        with materialize("clean-flows") as tmp:
            text = fixloop.start(self.db, str(Path(tmp) / "clean-flows"), which="high", offline=True)
        self.assertIn("Nothing to fix", text)

    def test_accepting_a_risk_keeps_it_visible(self):
        self.start(which="high")
        items, _ = self.run_items()
        critical = next(i for i in items.values() if i["severity"] == "critical")
        high = next(i for i in items.values() if i["severity"] == "high")
        with self.assertRaises(fixloop.FixError) as caught:
            fixloop.accept_risk(self.db, str(self.root), critical["ref"], "It's only used by the admin team on localhost.")
        self.assertIn("Critical findings can't be accepted", str(caught.exception))
        for reason, days in (("short", 30), ("Only the admin CLI calls this, on localhost, by design.", 0),
                             ("Only the admin CLI calls this, on localhost, by design.", 400)):
            with self.subTest(reason=reason, days=days), self.assertRaises(fixloop.FixError):
                fixloop.accept_risk(self.db, str(self.root), high["ref"], reason, days)
        text = fixloop.accept_risk(self.db, str(self.root), high["ref"], "Only the admin CLI calls this, on localhost, by design.", 30)
        self.assertIn("It isn't hidden", text)
        items, _ = self.run_items()
        self.assertEqual(items[high["ref"]]["status"], "accepted")

        # The next scan lists it, says who accepted it and why, and every findings answer repeats it.
        answer = integrations.call_tool(self.db, "ladpock_scan", {"path": str(self.root), "offline": True})
        self.assertIn("Known risks (1, accepted, not counted in the grade)", answer)
        self.assertIn("accepted by an AI assistant: Only the admin CLI calls this", answer)
        summary = json.loads(self.db.latest_scan(self.db.get_project(self.root)["id"])["summary"])
        self.assertEqual([(a["ref"], a["by"]) for a in summary["accepted"]], [(high["ref"], "agent")])
        self.assertIsNotNone(summary["accepted"][0]["expires"])

    def test_ladpocks_own_github_copy_is_refused(self):
        copy = github.copy_path("octo/app")
        shutil.copytree(self.root, copy)
        with self.assertRaises(fixloop.FixError) as caught:
            fixloop.start(self.db, str(copy), offline=True)
        self.assertIn("own clone of github.com/octo/app", str(caught.exception))

    def test_the_path_must_be_absolute(self):
        # An empty or relative path would quietly mean "wherever LadPock happens to be running".
        for path in ("", "  ", "server", "./vuln-flows"):
            with self.subTest(path=path), self.assertRaises(fixloop.FixError):
                fixloop.start(self.db, path, offline=True)
        with self.assertRaises(integrations.ToolError):
            integrations.call_tool(self.db, "ladpock_findings", {"path": ""})

    def test_a_subfolder_belongs_to_its_project(self):
        self.start(which="critical")
        folder, row = fixloop.find_project(self.db, str(self.root / "server"))
        self.assertEqual(folder, self.root.resolve())
        self.assertIsNotNone(row)

    @unittest.skipUnless(HAS_GIT, "needs git")
    def test_commits_are_asked_for_and_matched_to_fixes(self):
        git(self.root, "init", "-q")
        git(self.root, "add", "-A")
        git(self.root, "commit", "-q", "-m", "start")
        self.start(which="critical")
        self.edit(EVAL_LINE, "  res.json({ value: JSON.parse(rule) });")
        result = self.check()
        items, _ = self.run_items()
        ref = next(iter(items))
        self.assertIn(f'git commit -m "Fix: Request data runs as code (LadPock {ref})"', result)
        self.assertIn("Don't push", result)
        git(self.root, "commit", "-q", "-am", f"Fix: Request data runs as code (LadPock {ref})")
        run = self.db.latest_fix_run(self.db.get_project(self.root)["id"])
        self.assertEqual(run["status"], "done")
        fixloop.note_commits(self.db, run, self.root)  # what the dashboard does when it shows the run
        self.assertTrue(self.db.fix_items(run["id"])[0]["commit_sha"])

    def test_the_commit_setting(self):
        if HAS_GIT:
            git(self.root, "init", "-q")
        fixloop.set_commits(self.db, False)
        text = self.start(which="critical")
        self.assertIn("switched that off" if HAS_GIT else "isn't a git repository", text)
        self.edit(EVAL_LINE, "  res.json({ value: JSON.parse(rule) });")
        self.assertNotIn("git commit", self.check())

    def test_github_remote(self):
        git_dir = self.root / ".git"
        git_dir.mkdir()
        for url, expected in (("https://github.com/octo/app.git", "octo/app"), ("git@github.com:octo/my.app.git", "octo/my.app"),
                              ("https://gitlab.com/octo/app.git", None)):
            (git_dir / "config").write_text(f'[core]\n\tbare = false\n[remote "origin"]\n\turl = {url}\n', encoding="utf-8")
            self.assertEqual(fixloop.github_remote(self.root), expected)


class Mcp(unittest.TestCase):
    def setUp(self):
        self.home = isolated_home()

    def tearDown(self):
        self.home.cleanup()

    def call(self, method, params=None):
        return integrations.handle({"jsonrpc": "2.0", "id": 1, "method": method, "params": params or {}}, DB)

    def test_prompts_and_client_name(self):
        init = self.call("initialize", {"protocolVersion": "2025-06-18", "clientInfo": {"name": "claude-code", "version": "2"}})
        self.assertIn("prompts", init["result"]["capabilities"])
        self.assertEqual(integrations.CLIENT["name"], "claude-code")
        names = [p["name"] for p in self.call("prompts/list")["result"]["prompts"]]
        self.assertEqual(names, ["ladpock", "fix"])
        fix = self.call("prompts/get", {"name": "fix", "arguments": {"which": "all"}})["result"]
        self.assertIn("which='all'", fix["messages"][0]["content"]["text"])
        self.assertIn("error", self.call("prompts/get", {"name": "nope"}))
        tools = {t["name"] for t in self.call("tools/list")["result"]["tools"]}
        self.assertTrue({"ladpock_fix_start", "ladpock_fix_check", "ladpock_fix_next", "ladpock_fix_skip", "ladpock_accept_risk",
                         "ladpock_fix_stop"} <= tools)

    def test_the_whole_loop_through_mcp(self):
        with materialize("vuln-flows") as tmp:
            root = Path(tmp) / "vuln-flows"
            reply = self.call("tools/call", {"name": "ladpock_fix_start", "arguments": {"path": str(root), "which": "critical", "offline": True}})
            self.assertFalse(reply["result"]["isError"])
            self.assertIn("Request data runs as code", reply["result"]["content"][0]["text"])
            no_run = self.call("tools/call", {"name": "ladpock_fix_next", "arguments": {"path": tempfile.gettempdir()}})
            self.assertTrue(no_run["result"]["isError"])


class Dashboard(unittest.TestCase):
    TOKEN = "test-token-fixloop-0123456789"

    @classmethod
    def setUpClass(cls):
        cls.home = isolated_home()
        cls.server = make_server(0, cls.TOKEN)
        cls.port = cls.server.app.port
        threading.Thread(target=cls.server.serve_forever, daemon=True).start()

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.server.server_close()
        cls.home.cleanup()

    def api(self, method, path, body=None):
        conn = http.client.HTTPConnection("127.0.0.1", self.port, timeout=60)
        headers = {"Host": f"127.0.0.1:{self.port}", "X-LadPock-Token": self.TOKEN}
        data = None
        if body is not None:
            data = json.dumps(body).encode()
            headers["Content-Type"] = "application/json"
        conn.request(method, path, body=data, headers=headers)
        resp = conn.getresponse()
        raw = resp.read()
        conn.close()
        return resp.status, json.loads(raw or b"{}")

    def test_progress_risks_and_the_commit_toggle(self):
        with materialize("vuln-flows") as tmp:
            root = Path(tmp) / "vuln-flows"
            db = DB()
            fixloop.start(db, str(root), which="high", offline=True)
            pid = db.get_project(root)["id"]
            items = db.fix_items(db.active_fix_run(pid)["id"])
            high = next(i for i in items if i["severity"] == "high")
            fixloop.accept_risk(db, str(root), high["ref"], "Only the admin CLI calls this, on localhost, by design.", 30)
            integrations.call_tool(db, "ladpock_scan", {"path": str(root), "offline": True})
            db.close()

            status, project = self.api("GET", f"/api/projects/{pid}")
            self.assertEqual(status, 200)
            self.assertEqual(project["project"]["accepted_by_agent"], 1)
            self.assertEqual(project["project"]["fixing"]["total"], len(items))
            run = project["fixes"]["run"]
            self.assertEqual(run["status"], "active")
            self.assertEqual({i["ref"]: i["status"] for i in run["items"]}[high["ref"]], "accepted")
            self.assertEqual(project["scan"]["summary"]["accepted"][0]["by"], "agent")
            risk = project["fixes"]["risks"][0]
            self.assertEqual((risk["ref"], risk["by"], risk["severity"]), (high["ref"], "agent", "high"))
            self.assertIn("admin CLI", risk["reason"])

            self.assertEqual(self.api("POST", "/api/settings/fix-commits", {"enabled": False})[1], {"commits": False})
            self.assertFalse(self.api("GET", f"/api/projects/{pid}/fixes")[1]["commits"])
            self.api("POST", "/api/settings/fix-commits", {"enabled": True})

            self.assertEqual(self.api("POST", f"/api/projects/{pid}/risks/undo", {"ref": high["ref"]})[0], 200)
            self.assertEqual(self.api("POST", f"/api/projects/{pid}/risks/undo", {"ref": high["ref"]})[0], 404)
            self.assertEqual(self.api("POST", f"/api/projects/{pid}/risks/undo", {"ref": "../x"})[0], 400)
            _, status_payload = self.api("GET", "/api/status")
            self.assertEqual(next(p for p in status_payload["projects"] if p["id"] == pid)["accepted_by_agent"], 0)


class Connect(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.home = Path(self.tmp.name)
        self.patches = [mock.patch.object(Path, "home", lambda: self.home),
                        mock.patch.dict(os.environ, {"APPDATA": str(self.home / "AppData")}),
                        mock.patch.object(connect, "COMMAND_FILE", self.home / ".claude" / "commands" / "ladpock.md"),
                        mock.patch.object(connect, "server_command", lambda: ["C:\\Tools\\ladpock.exe", "mcp"])]
        for p in self.patches:
            p.start()

    def tearDown(self):
        for p in reversed(self.patches):
            p.stop()
        self.tmp.cleanup()

    def test_claude_code_keeps_other_settings_and_gets_the_command(self):
        config = self.home / ".claude.json"
        config.write_text(json.dumps({"theme": "dark", "mcpServers": {"other": {"command": "x"}}}), encoding="utf-8")
        lines = connect.connect("claude")
        data = json.loads(config.read_text(encoding="utf-8"))
        self.assertEqual(data["theme"], "dark")
        self.assertEqual(data["mcpServers"]["other"], {"command": "x"})
        self.assertEqual(data["mcpServers"]["ladpock"], {"type": "stdio", "command": "C:\\Tools\\ladpock.exe", "args": ["mcp"]})
        self.assertTrue((self.home / ".claude.json.ladpock-backup").exists())
        self.assertIn("$ARGUMENTS", connect.COMMAND_FILE.read_text(encoding="utf-8"))
        self.assertTrue(any("/ladpock" in line for line in lines))
        self.assertIn("already has", connect.connect("claude")[0])
        connect.connect("claude", remove=True)
        self.assertNotIn("ladpock", json.loads(config.read_text(encoding="utf-8"))["mcpServers"])
        self.assertFalse(connect.COMMAND_FILE.exists())

    def test_your_own_ladpock_command_is_left_alone(self):
        connect.COMMAND_FILE.parent.mkdir(parents=True)
        connect.COMMAND_FILE.write_text("my own command", encoding="utf-8")
        self.assertIn("left as it is", connect.add_command())
        self.assertEqual(connect.COMMAND_FILE.read_text(encoding="utf-8"), "my own command")

    def test_codex_toml(self):
        config = self.home / ".codex" / "config.toml"
        config.parent.mkdir()
        config.write_text('model = "x"\n\n[mcp_servers.other]\ncommand = "y"\n', encoding="utf-8")
        connect.connect("codex")
        text = config.read_text(encoding="utf-8")
        import tomllib

        data = tomllib.loads(text)
        self.assertEqual(data["mcp_servers"]["ladpock"], {"command": "C:\\Tools\\ladpock.exe", "args": ["mcp"]})
        self.assertEqual(data["mcp_servers"]["other"], {"command": "y"})
        connect.connect("codex", remove=True)
        data = tomllib.loads(config.read_text(encoding="utf-8"))
        self.assertNotIn("ladpock", data["mcp_servers"])
        self.assertEqual(data["model"], "x")

    def test_vscode_shape_and_a_file_with_comments_is_not_touched(self):
        app = connect.find("vscode")
        app.config.parent.mkdir(parents=True)
        app.config.write_text('{\n  // my servers\n  "servers": {}\n}\n', encoding="utf-8")
        with self.assertRaises(connect.ConnectError) as caught:
            connect.connect("vscode")
        self.assertIn('"servers"', str(caught.exception))
        self.assertIn("// my servers", app.config.read_text(encoding="utf-8"))
        app.config.write_text('{"servers": {}}', encoding="utf-8")
        connect.connect("vscode")
        self.assertEqual(json.loads(app.config.read_text(encoding="utf-8"))["servers"]["ladpock"]["type"], "stdio")

    def test_cursor_from_nothing(self):
        connect.connect("cursor")
        data = json.loads((self.home / ".cursor" / "mcp.json").read_text(encoding="utf-8"))
        self.assertEqual(data, {"mcpServers": {"ladpock": {"command": "C:\\Tools\\ladpock.exe", "args": ["mcp"]}}})


if __name__ == "__main__":
    unittest.main()
