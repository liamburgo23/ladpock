"""The one-page report, the GitHub outputs, and that nothing hostile or secret gets through either."""

from __future__ import annotations

import json
import os
import re
import unittest
from contextlib import redirect_stderr, redirect_stdout
from io import StringIO
from pathlib import Path
from unittest import mock

from helpers import FAKES, isolated_home, materialize

from ladpock import cli, report, report_html
from ladpock.db import DB
from ladpock.scan import run_scan

HOSTILE = '<script>alert(1)</script><img src=x onerror=alert(2)>'


def _page(**overrides) -> str:
    finding = {"ref": "a", "check_id": "LP-X", "title": HOSTILE, "severity": "high", "category": "secrets", "message": HOSTILE,
               "fix": HOSTILE, "file": f"{HOSTILE}.js", "line": 3, "snippet": HOSTILE, "confidence": "low", "cwe": ["CWE-79"]}
    options = dict(grade="C+", score=79, profile="full", started="2026-11-05T10:00:00+00:00", categories=[{"name": HOSTILE, "grade": "C+", "counts": {"high": 1}}],
                   findings=[finding], coverage={"deep": [HOSTILE], "generic": []}, checks_run=10, dependencies=1,
                   scanners=[{"name": HOSTILE, "available": False}], feeds=[{"name": HOSTILE, "ok": False}],
                   live={"url": "http://localhost:1", "error": HOSTILE}, routes=[{"method": "GET", "path": HOSTILE, "file": HOSTILE, "line": 1, "gaps": [HOSTILE]}])
    return report_html.render(HOSTILE, **{**options, **overrides})


class HtmlReport(unittest.TestCase):
    def test_nothing_from_a_scan_can_run(self):
        page = _page()
        self.assertNotIn("<script", page)
        self.assertNotIn("<img", page)
        self.assertNotRegex(page, r"(?i)<[a-z]+[^>]*\son\w+=")
        self.assertIn("&lt;script&gt;", page)
        self.assertIn("default-src 'none'", page)  # the page's own policy forbids scripts anyway
        self.assertNotRegex(page, r"(?i)https?://(?!localhost)")  # nothing loaded from elsewhere

    def test_says_what_it_is(self):
        page = _page()
        self.assertIn("How to fix it", page)
        self.assertIn("Unconfirmed", page)  # low confidence is labelled
        self.assertIn("5 November 2026", page)
        clean = report_html.render("demo", grade="A+", score=100, profile="standard", started=None, categories=[], findings=[])
        self.assertIn("No open findings", clean)
        self.assertIn("wasn&#x27;t tested", clean)  # says the running app wasn't checked

    def test_says_when_it_was_confirmed_live(self):
        finding = {"title": "t", "severity": "critical", "source": "live", "message": "m", "fix": "f"}
        page = report_html.render("demo", grade="F", score=40, profile="standard", started=None, categories=[], findings=[finding],
                                  live={"requests": 5, "confirmed": 1, "accounts": {"records_checked": 2, "exposed": 1, "protected": 1}})
        self.assertIn("Confirmed on the running app", page)
        self.assertIn("2 records tried as the other account", page)

    def test_cli_report_masks_secrets_and_leaves_out_the_folder(self):
        home = isolated_home()
        try:
            with materialize("vuln-next-supabase") as tmp:
                root = Path(tmp) / "vuln-next-supabase"
                out = Path(tmp) / "report.html"
                with redirect_stderr(StringIO()), redirect_stdout(StringIO()):
                    code = cli.main(["scan", str(root), "--offline", "--no-external", "--format", "html", "-o", str(out)])
                self.assertEqual(code, 0)
                page = out.read_text(encoding="utf-8")
                self.assertIn("What to fix, most serious first", page)
                self.assertIn("Endpoints", page)
                self.assertNotIn(str(root), page)
                for real_looking in FAKES.values():
                    self.assertNotIn(real_looking, page)
        finally:
            home.cleanup()


class GithubOutputs(unittest.TestCase):
    def scan(self, name, tmp):
        db = DB()
        try:
            return run_scan(Path(tmp) / name, db, offline=True, external=False, log=lambda _: None)
        finally:
            db.close()

    def test_annotations_and_summary(self):
        home = isolated_home()
        try:
            with materialize("vuln-next-supabase") as tmp:
                result = self.scan("vuln-next-supabase", tmp)
                lines = report.github_annotations(result)
                self.assertTrue(lines[0].startswith("::error "))  # the worst come first
                self.assertLessEqual(len(lines), report.MAX_ANNOTATIONS)
                self.assertTrue(all("\n" not in line for line in lines))
                summary = report.github_summary(result)
                self.assertTrue(summary.startswith("## LadPock: "))
                for real_looking in FAKES.values():
                    self.assertNotIn(real_looking, summary + "".join(lines))
        finally:
            home.cleanup()

    def test_values_cant_become_workflow_commands(self):
        self.assertEqual(report._workflow_value("a\n::error::x%"), "a%0A::error::x%25")
        self.assertEqual(report._workflow_property("a:b,c\nd"), "a%3Ab%2Cc%0Ad")

    def test_step_outputs(self):
        home = isolated_home()
        try:
            with materialize("clean-next-supabase") as tmp:
                out, summary = Path(tmp) / "out", Path(tmp) / "summary"
                env = {"GITHUB_OUTPUT": str(out), "GITHUB_STEP_SUMMARY": str(summary)}
                with mock.patch.dict(os.environ, env), redirect_stderr(StringIO()), redirect_stdout(StringIO()):
                    code = cli.main(["scan", str(Path(tmp) / "clean-next-supabase"), "--offline", "--no-external", "--github",
                                     "--format", "sarif", "-o", str(Path(tmp) / "r.sarif")])
                self.assertEqual(code, 0)
                self.assertEqual(re.findall(r"(?m)^grade=(.+)$", out.read_text()), ["A+"])
                self.assertIn("findings=0", out.read_text())
                self.assertIn("No open findings", summary.read_text())
                self.assertEqual(json.loads((Path(tmp) / "r.sarif").read_text())["version"], "2.1.0")
        finally:
            home.cleanup()


class ActionFile(unittest.TestCase):
    def test_inputs_never_go_straight_into_a_script(self):
        text = (Path(__file__).parent.parent / "action.yml").read_text(encoding="utf-8")
        for block in re.findall(r"(?ms)^\s+run: \|?.*?(?=^\s+- |\Z)", text):
            self.assertNotIn("${{", block)


if __name__ == "__main__":
    unittest.main()
