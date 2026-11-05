"""What it takes to use LadPock on a real project: a baseline, project settings, and a bill of materials."""

from __future__ import annotations

import json
import os
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
from io import StringIO
from pathlib import Path
from unittest import mock

from helpers import isolated_home

from ladpock import cli, config, sbom
from ladpock.checks import ScanContext, run_all
from ladpock.files import FileIndex
from ladpock.models import Component
from ladpock.routes import analyze, gaps
from ladpock.stack import detect

ROUTE = 'import { db } from "@/lib/db";\nexport async function POST() {\n  %s\n  await db.thing.create({ data: {} });\n  return Response.json({});\n}\n'


def project(tmp: str, files: dict[str, str]) -> Path:
    root = Path(tmp) / "demo"
    for rel, text in {"next.config.js": "", **files}.items():
        path = root / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text, encoding="utf-8")
    return root


def findings(root: Path) -> set[str]:
    index = FileIndex(root)
    found, errors = run_all(ScanContext(root=root, index=index, stack=set(detect(index))))
    assert errors == [], errors
    return {f.check_id for f in found}


def run(*argv: str) -> tuple[int, str]:
    err = StringIO()
    with redirect_stderr(err), redirect_stdout(StringIO()):
        code = cli.main(list(argv))
    return code, err.getvalue()


class Baseline(unittest.TestCase):
    def setUp(self):
        self.home = isolated_home()
        self.addCleanup(self.home.cleanup)
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = project(self.tmp.name, {"app/api/old/route.ts": ROUTE % ""})
        self.baseline = str(Path(self.tmp.name) / "baseline.json")
        self.scan = ["scan", str(self.root), "--offline", "--no-external", "--format", "json", "-o", str(Path(self.tmp.name) / "out.json")]

    def test_only_new_problems_fail(self):
        self.assertEqual(run(*self.scan, "--fail-on", "high")[0], 1)  # the old problem fails with no baseline
        self.assertEqual(run(*self.scan, "--write-baseline", self.baseline)[0], 0)
        code, err = run(*self.scan, "--fail-on", "high", "--baseline", self.baseline)
        self.assertEqual(code, 0)
        self.assertIn("0 new", err)
        (self.root / "app/api/new/route.ts").parent.mkdir(parents=True)
        (self.root / "app/api/new/route.ts").write_text(ROUTE % "", encoding="utf-8")
        code, err = run(*self.scan, "--fail-on", "high", "--baseline", self.baseline)
        self.assertEqual(code, 1)
        self.assertIn("1 new", err)

    def test_moving_code_doesnt_make_it_new(self):
        run(*self.scan, "--write-baseline", self.baseline)
        path = self.root / "app/api/old/route.ts"
        path.write_text("// a comment\n// and another\n" + path.read_text(encoding="utf-8"), encoding="utf-8")
        self.assertEqual(run(*self.scan, "--fail-on", "high", "--baseline", self.baseline)[0], 0)

    def test_says_when_something_was_fixed(self):
        run(*self.scan, "--write-baseline", self.baseline)
        (self.root / "app/api/old/route.ts").unlink()
        self.assertIn("1 from the baseline now fixed", run(*self.scan, "--baseline", self.baseline)[1])

    def test_a_missing_or_broken_baseline_protects_nothing(self):
        code, err = run(*self.scan, "--fail-on", "high", "--baseline", str(Path(self.tmp.name) / "nope.json"))
        self.assertEqual(code, 1)
        self.assertIn("every finding counts as new", err)
        Path(self.baseline).write_text("not json", encoding="utf-8")
        self.assertEqual(run(*self.scan, "--fail-on", "high", "--baseline", self.baseline)[0], 1)

    def test_github_marks_only_new_problems(self):
        run(*self.scan, "--write-baseline", self.baseline)
        (self.root / "app/api/new/route.ts").parent.mkdir(parents=True)
        (self.root / "app/api/new/route.ts").write_text(ROUTE % "", encoding="utf-8")
        output, summary = Path(self.tmp.name) / "o", Path(self.tmp.name) / "s"
        with mock.patch.dict(os.environ, {"GITHUB_OUTPUT": str(output), "GITHUB_STEP_SUMMARY": str(summary)}):
            _, err = run(*self.scan, "--baseline", self.baseline, "--github")
        self.assertIn("app/api/new/route.ts", err)
        self.assertNotIn("app/api/old/route.ts", err)
        self.assertIn("new=1", output.read_text())
        self.assertIn("**1 new**", summary.read_text())


class ProjectSettings(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)

    def test_your_own_login_helpers(self):
        files = {"app/api/thing/route.ts": ROUTE % "await requireTeamMember();"}
        without = project(self.tmp.name, files)
        self.assertIn("LP-AUTHZ-001", findings(without))
        (without / "ladpock.toml").write_text('[routes]\nauth_functions = ["requireTeamMember"]\n', encoding="utf-8")
        self.assertNotIn("LP-AUTHZ-001", findings(without))
        self.assertEqual(analyze(FileIndex(without))[0].auth, "yes")

    def test_a_helper_elsewhere_in_the_file_doesnt_count(self):
        code = (ROUTE % "") + "export async function GET() {\n  await requireTeamMember();\n  return Response.json({});\n}\n"
        root = project(self.tmp.name, {"app/api/thing/route.ts": code, "ladpock.toml": '[routes]\nauth_functions = ["requireTeamMember"]\n'})
        routes = {r.method: r for r in analyze(FileIndex(root))}
        self.assertEqual((routes["POST"].auth, routes["GET"].auth), ("no", "yes"))

    def test_public_on_purpose(self):
        root = project(self.tmp.name, {"app/api/orders/route.ts": ROUTE % "", "ladpock.toml": '[routes]\npublic = ["/api/orders"]\n'})
        self.assertNotIn("LP-AUTHZ-001", findings(root))

    def test_hidden_findings_are_still_counted(self):
        home = isolated_home()
        self.addCleanup(home.cleanup)
        root = project(self.tmp.name, {"legacy/api.py": "eval(input())\n", "src/a.py": "eval(input())\n", "ladpock.toml": '[ignore]\npaths = ["legacy/*"]\nchecks = ["LP-VIBE-999"]\n'})
        out = Path(self.tmp.name) / "out.json"
        run("scan", str(root), "--offline", "--no-external", "--format", "json", "-o", str(out))
        data = json.loads(out.read_text())
        self.assertTrue(any(f["file"] == "src/a.py" for f in data["findings"]))
        self.assertFalse(any(f["file"] == "legacy/api.py" for f in data["findings"]))
        self.assertTrue(data["suppressed"])  # hiding is never silent

    def test_broken_settings_are_reported_and_ignored(self):
        root = project(self.tmp.name, {"ladpock.toml": "this isn't toml ["})
        loaded = config.load(FileIndex(root))
        self.assertTrue(loaded.warnings)
        self.assertEqual(loaded.ignore_paths, ())
        root2 = project(tempfile.mkdtemp(dir=self.tmp.name), {"ladpock.toml": '[ignor]\npaths = ["*"]\n[ignore]\npath = ["*"]\nchecks = "LP-X"\n[routes]\nauth_functions = ["a b"]\n'})
        loaded = config.load(FileIndex(root2))
        self.assertEqual(len(loaded.warnings), 4)
        self.assertFalse(loaded.hides("LP-X", "a.py"))


class SecretUrls(unittest.TestCase):
    def test_a_url_holding_a_secret_is_its_own_login(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = project(tmp, {"app/api/invite/[token]/route.ts": ROUTE % ""})
            self.assertNotIn("LP-AUTHZ-001", findings(root))
            self.assertEqual(gaps(analyze(FileIndex(root))[0]), [])

    def test_an_id_or_a_short_code_isnt(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = project(tmp, {"app/api/rooms/[code]/route.ts": ROUTE % "", "app/api/orders/[id]/route.ts": ROUTE % ""})
            self.assertTrue(all("no auth" in gaps(r) for r in analyze(FileIndex(root))))


class KeyFiles(unittest.TestCase):
    """Only what git tracks counts, because a key that's correctly ignored isn't in the repository."""

    def test_ignored_keys_arent_reported(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "server.key").write_text("-----BEGIN " + "PRIVATE KEY-----\\nabc\\n", encoding="utf-8")
            (root / "tracked.key").write_text("-----BEGIN " + "PRIVATE KEY-----\\nabc\\n", encoding="utf-8")
            index = FileIndex(root)
            found, _ = run_all(ScanContext(root=root, index=index, stack=set(), git_files={"tracked.key"}))
            self.assertEqual([f.file for f in found if f.check_id == "LP-SEC-010"], ["tracked.key"])

    def test_keys_in_test_folders_arent_reported(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "tests").mkdir()
            (root / "tests" / "server.key").write_text("-----BEGIN " + "PRIVATE KEY-----\\nabc\\n", encoding="utf-8")
            index = FileIndex(root)
            found, _ = run_all(ScanContext(root=root, index=index, stack=set()))
            self.assertEqual([f for f in found if f.check_id == "LP-SEC-010"], [])


class BillOfMaterials(unittest.TestCase):
    def test_package_urls(self):
        for component, expected in (
            (Component("npm", "@scope/name", "1.2.3", "x"), "pkg:npm/%40scope/name@1.2.3"),
            (Component("PyPI", "flask", "3.0.0", "x"), "pkg:pypi/flask@3.0.0"),
            (Component("Go", "github.com/a/b", "1.0.0", "x"), "pkg:golang/github.com/a/b@1.0.0"),
            (Component("Maven", "org.a:b", "2.0", "x"), "pkg:maven/org.a/b@2.0"),
            (Component("crates.io", "serde", "1.0.0", "x"), "pkg:cargo/serde@1.0.0"),
            (Component("npm", "x", None, "x"), None),
        ):
            with self.subTest(component.name):
                self.assertEqual(sbom.purl(component), expected)

    def test_document(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "demo"
            root.mkdir()
            (root / "requirements.txt").write_text("flask==3.0.0\nflask==3.0.0\n", encoding="utf-8")
            out = Path(tmp) / "bom.json"
            home = isolated_home()
            self.addCleanup(home.cleanup)
            self.assertEqual(run("sbom", str(root), "-o", str(out))[0], 0)
            document = json.loads(out.read_text())
        self.assertEqual((document["bomFormat"], document["specVersion"]), ("CycloneDX", "1.5"))
        self.assertEqual([c["purl"] for c in document["components"]], ["pkg:pypi/flask@3.0.0"])
        self.assertEqual(document["metadata"]["component"]["name"], "demo")  # the folder's name, not its path


if __name__ == "__main__":
    unittest.main()
