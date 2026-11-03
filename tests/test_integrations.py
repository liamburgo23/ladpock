"""The MCP server for Claude Code, and the git pre-commit hook."""

from __future__ import annotations

import io
import json
import shutil
import subprocess
import unittest
from pathlib import Path

from helpers import FAKES, isolated_home, materialize

from ladpock import integrations


def rpc(*messages: dict) -> list[dict]:
    stdin = io.StringIO("\n".join(json.dumps(m) for m in messages) + "\n")
    stdout = io.StringIO()
    integrations.serve_mcp(stdin, stdout)
    return [json.loads(line) for line in stdout.getvalue().splitlines()]


def call(tool: str, **arguments) -> dict:
    return rpc({"jsonrpc": "2.0", "id": 1, "method": "tools/call", "params": {"name": tool, "arguments": arguments}})[0]["result"]


class McpServer(unittest.TestCase):
    def setUp(self):
        self.home = isolated_home()

    def tearDown(self):
        self.home.cleanup()

    def test_handshake_and_tool_list(self):
        replies = rpc(
            {"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {"protocolVersion": "2025-03-26"}},
            {"jsonrpc": "2.0", "method": "notifications/initialized"},
            {"jsonrpc": "2.0", "id": 2, "method": "tools/list"},
            {"jsonrpc": "2.0", "id": 3, "method": "resources/list"},
        )
        self.assertEqual([r["id"] for r in replies], [1, 2, 3])  # the notification gets no reply
        self.assertEqual(replies[0]["result"]["protocolVersion"], "2025-03-26")
        names = {t["name"] for t in replies[1]["result"]["tools"]}
        self.assertEqual(names, {"ladpock_scan", "ladpock_findings", "ladpock_routes", "ladpock_explain_grade",
                                 "ladpock_fix_prompt"})
        self.assertEqual(replies[2]["error"]["code"], -32601)

    def test_scan_then_read_results(self):
        with materialize("vuln-next-supabase") as tmp:
            root = str(Path(tmp) / "vuln-next-supabase")
            self.assertTrue(call("ladpock_findings", path=root)["isError"])  # not scanned yet

            scanned = call("ladpock_scan", path=root, offline=True)
            self.assertFalse(scanned["isError"])
            text = scanned["content"][0]["text"]
            self.assertIn("grade F", text)
            self.assertIn("app/api/orders/[id]/route.ts", text)
            self.assertNotIn("LadPockFixtureQ1w2E3r4", text)  # secrets stay masked

            only = call("ladpock_scan", path=root, offline=True, files=["lib/db.ts"])["content"][0]["text"]
            self.assertIn("in the requested files", only)
            self.assertNotIn("route.ts", only.split("\n", 1)[1])

            critical = call("ladpock_findings", path=root, min_severity="critical")["content"][0]["text"]
            self.assertIn("[critical]", critical)
            self.assertNotIn("[low]", critical)
            self.assertIn("GAPS", call("ladpock_routes", path=root)["content"][0]["text"])
            self.assertIn("Step 1: fix", call("ladpock_explain_grade", path=root)["content"][0]["text"])
            self.assertIn("LadPock found these security issues", call("ladpock_fix_prompt", path=root)["content"][0]["text"])

    def test_bad_input_is_reported_not_raised(self):
        self.assertTrue(call("ladpock_scan", path="Z:/definitely/missing")["isError"])
        self.assertTrue(call("ladpock_nope", path=".")["isError"])


@unittest.skipUnless(shutil.which("git"), "git not installed")
class PreCommitHook(unittest.TestCase):
    def setUp(self):
        self.home = isolated_home()
        self.tmp = materialize("clean-next-supabase")
        self.root = Path(self.tmp.name) / "clean-next-supabase"
        self.git("init", "-q")
        self.git("config", "user.email", "test@example.invalid")
        self.git("config", "user.name", "Test")
        self.git("config", "commit.gpgsign", "false")
        self.git("add", "-A")
        self.git("commit", "-q", "-m", "start", "--no-verify")

    def tearDown(self):
        self.tmp.cleanup()
        self.home.cleanup()

    def git(self, *args: str) -> subprocess.CompletedProcess:
        return subprocess.run(["git", "-C", str(self.root), *args], capture_output=True, text=True)

    def stage(self, name: str, text: str) -> None:
        (self.root / name).parent.mkdir(parents=True, exist_ok=True)
        (self.root / name).write_text(text, encoding="utf-8")
        self.git("add", name)

    def test_blocks_secrets_and_allows_clean_commits(self):
        out = io.StringIO()
        self.stage("lib/payments.ts", f'export const key = "{FAKES["{{FAKE_STRIPE_SECRET}}"]}";\n')
        self.assertEqual(integrations.precommit(self.root, out), 1)
        self.assertIn("Hardcoded credential", out.getvalue())
        self.assertNotIn("LadPockFixtureQ1w2E3r4", out.getvalue())

        self.stage("lib/payments.ts", 'export const key = process.env.STRIPE_SECRET_KEY;\n')
        self.assertEqual(integrations.precommit(self.root, io.StringIO()), 0)

    def test_installed_hook_stops_a_real_commit(self):
        hook = Path(integrations.install_hook(self.root))
        self.assertIn(integrations.HOOK_MARKER, hook.read_text(encoding="utf-8"))
        self.stage("config/keys.ts", 'export const openai = "' + FAKES["{{FAKE_OPENAI_KEY}}"] + '";\n')
        blocked = self.git("commit", "-m", "add keys")
        self.assertNotEqual(blocked.returncode, 0, blocked.stdout + blocked.stderr)
        self.assertIn("LadPock stopped this commit", blocked.stderr)

        self.git("reset", "-q", "config/keys.ts")
        self.stage("README.md", "# Notes\n")
        allowed = self.git("commit", "-m", "docs")
        self.assertEqual(allowed.returncode, 0, allowed.stdout + allowed.stderr)
        self.assertTrue(integrations.remove_hook(self.root))
        self.assertFalse(hook.exists())

    def test_existing_hooks_are_respected(self):
        hooks = self.root / ".git" / "hooks"
        hooks.mkdir(parents=True, exist_ok=True)
        (hooks / "pre-commit").write_text("#!/bin/sh\necho mine\n", encoding="utf-8")
        with self.assertRaises(integrations.ToolError):
            integrations.install_hook(self.root)
        integrations.install_hook(self.root, force=True)
        self.assertTrue((hooks / "pre-commit.before-ladpock").exists())
        integrations.remove_hook(self.root)
        self.assertIn("echo mine", (hooks / "pre-commit").read_text(encoding="utf-8"))  # put back


if __name__ == "__main__":
    unittest.main()
