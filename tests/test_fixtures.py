"""End-to-end: every check must fire on the vulnerable app and stay quiet on the clean one."""

from __future__ import annotations

import shutil
import subprocess
import unittest
from pathlib import Path

from helpers import isolated_home, materialize

from ladpock.checks import REGISTRY, ScanContext, run_all
from ladpock.db import DB
from ladpock.files import FileIndex
from ladpock.gitutil import tracked_files
from ladpock.routes import analyze
from ladpock.scan import run_scan
from ladpock.stack import detect

EXPECTED_VULN = {
    "LP-SEC-001", "LP-SEC-002", "LP-SEC-003", "LP-SEC-005", "LP-SEC-006",
    "LP-AUTH-001", "LP-AUTH-002", "LP-AUTH-003", "LP-AUTH-004", "LP-AUTH-005", "LP-AUTH-010",
    "LP-SUPA-001", "LP-SUPA-002", "LP-SUPA-003", "LP-SUPA-004",
    "LP-AUTHZ-001", "LP-AUTHZ-002", "LP-AUTHZ-003",
    "LP-ABUSE-001", "LP-ABUSE-002", "LP-ABUSE-010", "LP-ABUSE-011",
    "LP-INJ-001", "LP-INJ-002", "LP-INJ-003", "LP-INJ-004", "LP-INJ-005",
    "LP-PAY-001", "LP-PAY-002", "LP-CRYPTO-001", "LP-CFG-001", "LP-CFG-002",
    "LP-SUP-001", "LP-SUP-002", "LP-SUP-003", "LP-SUP-004",
    "LP-VIBE-001", "LP-VIBE-002", "LP-VIBE-003", "LP-VIBE-004", "LP-VIBE-005",
}
EXPECTED_TAURI = {
    "LP-TAURI-001", "LP-TAURI-002", "LP-TAURI-003", "LP-TAURI-004", "LP-TAURI-005", "LP-TAURI-006",
    "LP-TAURI-007", "LP-TAURI-008", "LP-TAURI-009", "LP-TAURI-010", "LP-RUST-001", "LP-VIBE-001",
}
# Produced only with network access or git, covered by their own tests.
NOT_IN_OFFLINE_FIXTURE = {"LP-SEC-004", "LP-DEP-001", "LP-SUP-005"}


def _context(root: Path) -> ScanContext:
    index = FileIndex(root)
    return ScanContext(root=root, index=index, stack=set(detect(index)), git_files=tracked_files(root))


class VulnerableFixture(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = materialize("vuln-next-supabase")
        cls.root = Path(cls.tmp.name) / "vuln-next-supabase"
        cls.findings, cls.errors = run_all(_context(cls.root))
        cls.ids = {f.check_id for f in cls.findings}

    @classmethod
    def tearDownClass(cls):
        cls.tmp.cleanup()

    def test_no_check_crashed(self):
        self.assertEqual(self.errors, [])

    def test_every_expected_check_fires(self):
        self.assertEqual(sorted(EXPECTED_VULN - self.ids), [])

    def test_catalogue_is_fully_covered(self):
        untested = set(REGISTRY) - EXPECTED_VULN - EXPECTED_TAURI - NOT_IN_OFFLINE_FIXTURE
        self.assertEqual(sorted(untested), [], "add these checks to a vulnerable fixture")

    def test_secrets_are_masked_in_output(self):
        for finding in self.findings:
            text = f"{finding.snippet} {finding.message}"
            self.assertNotIn("LadPockFixtureQ1w2E3r4T5y6U7", text)
            self.assertNotIn("LadPockFixtureSignature0123", text)
            self.assertNotIn("LadPockFixtureToken", text)
            self.assertNotIn("LadPockFixtureA1b2", text)

    def test_specific_locations(self):
        def at(check_id: str) -> set[str]:
            return {f.location for f in self.findings if f.check_id == check_id}

        self.assertIn("app/api/orders/[id]/route.ts:5", at("LP-AUTHZ-002"))
        self.assertIn("lib/db.ts:10", at("LP-INJ-003"))
        self.assertIn("components/Dashboard.tsx:11", at("LP-ABUSE-001"))
        self.assertTrue(any(loc.startswith("supabase/migrations/0001_init.sql:8") for loc in at("LP-SUPA-001")))
        self.assertTrue(any("action deleteAccount()" in (f.snippet or "") for f in self.findings if f.check_id == "LP-AUTHZ-001"))


class CleanFixture(unittest.TestCase):
    def test_clean_apps_have_no_findings(self):
        for name in ("clean-next-supabase", "clean-tauri"):
            with self.subTest(name), materialize(name) as tmp:
                findings, errors = run_all(_context(Path(tmp) / name))
                self.assertEqual(errors, [])
                self.assertEqual([f"{f.check_id} {f.location} {f.snippet}" for f in findings], [])


class TauriFixture(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = materialize("vuln-tauri")
        cls.root = Path(cls.tmp.name) / "vuln-tauri"
        cls.findings, cls.errors = run_all(_context(cls.root))

    @classmethod
    def tearDownClass(cls):
        cls.tmp.cleanup()

    def test_every_tauri_check_fires(self):
        self.assertEqual(self.errors, [])
        self.assertEqual(sorted(EXPECTED_TAURI - {f.check_id for f in self.findings}), [])

    def test_stack_and_severity(self):
        self.assertIn("tauri", detect(FileIndex(self.root)))
        remote = [f for f in self.findings if f.check_id == "LP-TAURI-003" and "https://*" in (f.snippet or "")]
        self.assertEqual(remote[0].severity.label, "critical")

    def test_command_matrix(self):
        from ladpock.tauri import analyze_commands

        with materialize("vuln-tauri") as tmp:
            vuln = {c.name: c for c in analyze_commands(FileIndex(Path(tmp) / "vuln-tauri"))}
        with materialize("clean-tauri") as tmp:
            clean = {c.name: c for c in analyze_commands(FileIndex(Path(tmp) / "clean-tauri"))}
        self.assertEqual((vuln["save_note"].file_access, vuln["save_note"].path_check), ("write", "none"))
        self.assertTrue(vuln["run_tool"].runs_programs)
        self.assertEqual(vuln["run_tool"].inputs, ["tool", "args"])  # State<'_, ..> is injected, not page input
        self.assertEqual((clean["save_note"].file_access, clean["save_note"].path_check), ("write", "dir"))
        self.assertEqual(clean["word_count"].file_access, "none")


class RouteMatrix(unittest.TestCase):
    def test_vulnerable_routes(self):
        with materialize("vuln-next-supabase") as tmp:
            routes = {(r.method, r.path): r for r in analyze(FileIndex(Path(tmp) / "vuln-next-supabase"))}
        orders = routes[("GET", "/api/orders/[id]")]
        self.assertEqual((orders.auth, orders.owner), ("yes", "no"))
        admin = routes[("DELETE", "/api/admin/users/[id]")]
        self.assertEqual(admin.auth, "mw")
        chat = routes[("POST", "/api/chat")]
        self.assertTrue(chat.paid_api)
        self.assertEqual(chat.auth, "no")
        self.assertFalse(chat.mutates)
        self.assertEqual(routes[("POST", "/api/webhook/stripe")].auth, "no")
        self.assertEqual(routes[("ACTION", "action deleteAccount()")].auth, "no")

    def test_clean_routes(self):
        with materialize("clean-next-supabase") as tmp:
            routes = {(r.method, r.path): r for r in analyze(FileIndex(Path(tmp) / "clean-next-supabase"))}
        orders = routes[("GET", "/api/orders/[id]")]
        self.assertEqual((orders.auth, orders.owner), ("yes", "yes"))
        chat = routes[("POST", "/api/chat")]
        self.assertEqual((chat.auth, chat.rate_limit, chat.validation), ("yes", "yes", "yes"))
        self.assertEqual(routes[("POST", "/api/webhook/stripe")].auth, "sig")


@unittest.skipUnless(shutil.which("git"), "git not installed")
class CommittedEnvFile(unittest.TestCase):
    def test_committed_env_is_flagged(self):
        with materialize("vuln-next-supabase") as tmp:
            root = Path(tmp) / "vuln-next-supabase"
            subprocess.run(["git", "init", "-q"], cwd=root, check=True)
            subprocess.run(["git", "add", ".env.local"], cwd=root, check=True)
            findings, _ = run_all(_context(root))
        hits = [f for f in findings if f.check_id == "LP-SEC-004"]
        self.assertEqual(len(hits), 1)
        self.assertEqual(hits[0].file, ".env.local")
        self.assertFalse(any(f.check_id == "LP-SEC-005" and f.file == ".env.local" for f in findings))

    def test_fixture_env_only_flagged_with_real_secret(self):
        with materialize("vuln-next-supabase") as tmp:
            root = Path(tmp) / "repo"
            (root / "tests" / "fixtures").mkdir(parents=True)
            (root / "tests" / "fixtures" / ".env.local").write_text("API_URL=http://localhost:3000\n", encoding="utf-8")
            secret = (Path(tmp) / "vuln-next-supabase" / "lib" / "config.ts").read_text(encoding="utf-8")
            (root / "tests" / ".env").write_text(secret, encoding="utf-8")
            subprocess.run(["git", "init", "-q"], cwd=root, check=True)
            subprocess.run(["git", "add", "-A"], cwd=root, check=True)
            findings, _ = run_all(_context(root))
        flagged = {f.file for f in findings if f.check_id == "LP-SEC-004"}
        self.assertEqual(flagged, {"tests/.env"})


class OfflinePipeline(unittest.TestCase):
    def test_scan_offline_scores_and_stores(self):
        home = isolated_home()
        db = DB()
        try:
            with materialize("vuln-next-supabase") as tmp:
                root = Path(tmp) / "vuln-next-supabase"
                result = run_scan(root, db, offline=True, external=False, log=lambda _: None)
                self.assertEqual(result.scorecard.grade, "F")
                self.assertGreater(result.components, 0)
                project = db.get_project(root)
                self.assertEqual(project["last_grade"], "F")
                stored = db.scan_findings(db.latest_scan(project["id"])["id"])
                self.assertEqual(len(stored), len(result.findings))
        finally:
            db.close()
            home.cleanup()


if __name__ == "__main__":
    unittest.main()
