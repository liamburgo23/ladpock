"""End-to-end: every check must fire on the vulnerable app and stay quiet on the clean one."""

from __future__ import annotations

import shutil
import subprocess
import unittest
from pathlib import Path

from helpers import FAKES, isolated_home, materialize

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
EXPECTED_NODE = {
    "LP-AUTHZ-001", "LP-AUTHZ-002", "LP-AUTHZ-004", "LP-ABUSE-003", "LP-ABUSE-004", "LP-ABUSE-010",
    "LP-API-001", "LP-API-002", "LP-AUTH-006", "LP-AUTH-007", "LP-AUTH-008", "LP-AUTH-009", "LP-AUTH-010", "LP-AUTH-011",
    "LP-CFG-005", "LP-CFG-006", "LP-CRYPTO-002", "LP-INJ-006", "LP-INJ-007", "LP-INJ-009", "LP-INJ-010", "LP-INJ-011",
    "LP-SEC-007",
}
EXPECTED_PYTHON = {
    "LP-AUTHZ-001", "LP-AUTHZ-002", "LP-AUTHZ-004", "LP-AUTHZ-005", "LP-ABUSE-010", "LP-AUTH-005", "LP-AUTH-006",
    "LP-AUTH-007", "LP-AUTH-009", "LP-AUTH-010", "LP-CFG-001", "LP-CFG-003", "LP-CFG-004", "LP-INJ-003", "LP-INJ-006",
    "LP-INJ-007", "LP-INJ-008", "LP-INJ-009", "LP-INJ-012", "LP-SEC-007", "LP-VIBE-004",
}
EXPECTED_INFRA = {
    "LP-DOCKER-001", "LP-DOCKER-002", "LP-DOCKER-003", "LP-DOCKER-004", "LP-INFRA-001", "LP-INFRA-002", "LP-INFRA-003",
    "LP-INFRA-004", "LP-INFRA-005", "LP-TF-001", "LP-TF-002", "LP-TF-003", "LP-TF-004", "LP-TF-005", "LP-SUP-006",
    "LP-SUP-007",
}
EXPECTED_APPS = {
    "LP-ELEC-001", "LP-ELEC-002", "LP-ELEC-003", "LP-ELEC-004", "LP-ELEC-005", "LP-ELEC-006", "LP-ELEC-007",
    "LP-ELEC-008", "LP-ELEC-009", "LP-MOB-001", "LP-MOB-002", "LP-MOB-003", "LP-MOB-004", "LP-MOB-005",
}
EXPECTED_POLYGLOT = {"LP-AUTHZ-006", "LP-CFG-007", "LP-CFG-008", "LP-ABUSE-005"}
EXPECTED_FUNCTIONS = {
    "LP-AI-001", "LP-AI-002", "LP-AI-003", "LP-AI-004", "LP-AI-005", "LP-UPLOAD-001", "LP-UPLOAD-002", "LP-UPLOAD-003", "LP-LOG-001",
    "LP-AUTHZ-007", "LP-AUTHZ-008", "LP-AUTHZ-009", "LP-AUTHZ-010", "LP-SEC-008", "LP-SEC-009", "LP-AUTH-012", "LP-AUTH-013",
    "LP-AUTH-014", "LP-AUTH-015", "LP-CRYPTO-003", "LP-CFG-009", "LP-VIBE-006", "LP-PAY-003", "LP-INJ-013", "LP-ABUSE-012",
    "LP-ABUSE-013", "LP-API-003", "LP-API-004", "LP-SUPA-005", "LP-SUPA-006", "LP-SUPA-007", "LP-SUPA-008", "LP-SUPA-009",
    "LP-VIBE-007", "LP-AUTHZ-011", "LP-CFG-010", "LP-CFG-011", "LP-INFRA-006", "LP-SUP-008", "LP-SUP-009", "LP-SUP-010", "LP-SUP-011",
    "LP-SUP-012", "LP-SUP-013",
}
EXPECTED_NATIVE = {
    "LP-NATIVE-001", "LP-NATIVE-002", "LP-NATIVE-003", "LP-NATIVE-004", "LP-NATIVE-005", "LP-SHELL-001", "LP-SHELL-002", "LP-SHELL-003",
    "LP-AI-006", "LP-AI-007", "LP-AI-008", "LP-AI-009", "LP-INJ-014", "LP-EXT-001", "LP-EXT-002", "LP-IOT-001", "LP-IOT-002",
    "LP-SEC-010", "LP-SHELL-004", "LP-SHELL-005", "LP-RUST-002", "LP-RUST-003", "LP-SOL-001", "LP-SOL-002", "LP-SOL-003", "LP-SOL-004", "LP-SOL-005", "LP-SOL-006",
}
# Produced only with network access or git, covered by their own tests.
NOT_IN_OFFLINE_FIXTURE = {"LP-SEC-004", "LP-DEP-001", "LP-SUP-005"} | {f"LP-LIVE-{i:03d}" for i in range(1, 17)}  # live: test_probe


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
        untested = (set(REGISTRY) - EXPECTED_VULN - EXPECTED_TAURI - EXPECTED_NODE - EXPECTED_PYTHON - EXPECTED_INFRA
                    - EXPECTED_APPS - EXPECTED_POLYGLOT - EXPECTED_FUNCTIONS - EXPECTED_NATIVE - NOT_IN_OFFLINE_FIXTURE)
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
        for name in ("clean-next-supabase", "clean-tauri", "clean-node-api", "clean-python-web", "clean-infra",
                     "clean-electron", "clean-mobile", "clean-polyglot", "clean-fullstack", "clean-functions", "clean-starters", "clean-native"):
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


class ServerFixtures(unittest.TestCase):
    """Express, Fastify, NestJS, FastAPI, Flask and Django: every check fires, and routes are read correctly."""

    def findings(self, name):
        with materialize(name) as tmp:
            root = Path(tmp) / name
            findings, errors = run_all(_context(root))
            routes = {(r.kind, r.method, r.path): r for r in analyze(FileIndex(root))}
        self.assertEqual(errors, [])
        return findings, routes

    def test_node_server(self):
        findings, routes = self.findings("vuln-node-api")
        self.assertEqual(sorted(EXPECTED_NODE - {f.check_id for f in findings}), [])
        self.assertEqual(routes[("express", "POST", "/api/users")].auth, "no")
        self.assertEqual(routes[("express", "GET", "/api/orders/:id")].auth, "mw")  # mounted at /api/orders, router.use(checkJwt)
        self.assertEqual((routes[("express", "DELETE", "/api/posts/:id")].auth,
                          routes[("express", "DELETE", "/api/posts/:id")].owner), ("yes", "no"))
        self.assertTrue(routes[("express", "POST", "/api/ai/summarise")].paid_api)
        self.assertFalse(routes[("express", "POST", "/api/ai/summarise")].db)  # openai...create() isn't a database write
        self.assertEqual(routes[("nest", "POST", "/users")].validation, "no")
        self.assertEqual(routes[("nest", "DELETE", "/users/:id")].auth, "yes")

    def test_python_web(self):
        findings, routes = self.findings("vuln-python-web")
        self.assertEqual(sorted(EXPECTED_PYTHON - {f.check_id for f in findings}), [])
        self.assertEqual(routes[("flask", "POST", "/api/notes")].auth, "no")
        self.assertEqual(routes[("flask", "DELETE", "/api/notes/<int:note_id>")].owner, "no")
        self.assertTrue(routes[("flask", "POST", "/api/ask")].paid_api)
        self.assertFalse(routes[("flask", "GET", "/hello")].paid_api)  # same module, but this route doesn't call OpenAI
        self.assertEqual(routes[("fastapi", "POST", "/items")].validation, "no")
        self.assertEqual(routes[("fastapi", "GET", "/users/{user_id}")].auth, "yes")
        self.assertEqual(routes[("django", "ANY", "/shop/api/invoices/")].auth, "no")  # ModelViewSet without permission_classes
        secrets = [f for f in findings if f.check_id == "LP-SEC-007"]
        self.assertTrue(all("q8w7e6r5" not in (f.snippet or "") for f in secrets))  # masked

    def test_clean_server_routes(self):
        _, node = self.findings("clean-node-api")
        self.assertEqual(node[("nest", "POST", "/notes")].validation, "yes")  # typed DTO + global ValidationPipe
        self.assertEqual(node[("nest", "DELETE", "/notes/:id")].auth, "yes")  # class-level guard above @Controller
        self.assertEqual(node[("express", "POST", "/api/login")].rate_limit, "yes")
        _, py = self.findings("clean-python-web")
        self.assertEqual((py[("django", "ANY", "/api/invoices/")].auth, py[("django", "ANY", "/api/invoices/")].owner), ("yes", "yes"))
        self.assertEqual(py[("fastapi", "POST", "/items")].validation, "yes")  # pydantic model parameter


class InfraFixture(unittest.TestCase):
    def test_every_infra_check_fires(self):
        with materialize("vuln-infra") as tmp:
            root = Path(tmp) / "vuln-infra"
            findings, errors = run_all(_context(root))
            stack = detect(FileIndex(root))
        self.assertEqual(errors, [])
        self.assertEqual(sorted(EXPECTED_INFRA - {f.check_id for f in findings}), [])
        self.assertTrue({"docker", "kubernetes", "terraform", "github-actions"} <= set(stack))

        def at(check_id):
            return {f.location for f in findings if f.check_id == check_id}

        self.assertEqual(at("LP-TF-002"), {"infra/main.tf:20"})  # SSH from anywhere; HTTPS and egress are fine
        self.assertEqual(at("LP-INFRA-002"), {"docker-compose.yml:16", "docker-compose.yml:20"})  # not the app's port 3000
        baked = [f.snippet for f in findings if f.check_id == "LP-DOCKER-002" and "ENV" in (f.snippet or "")]
        self.assertTrue(baked and all("****" in s for s in baked))  # values masked in reports


class AppFixtures(unittest.TestCase):
    def test_desktop_and_mobile_checks_fire(self):
        found = set()
        for name in ("vuln-electron", "vuln-mobile"):
            with materialize(name) as tmp:
                findings, errors = run_all(_context(Path(tmp) / name))
            self.assertEqual(errors, [])
            found |= {f.check_id for f in findings}
            if name == "vuln-mobile":
                exported = {f.location for f in findings if f.check_id == "LP-MOB-003"}
                self.assertNotIn("android/app/src/main/AndroidManifest.xml:7", exported)  # the launcher activity
                self.assertIn("LP-VIBE-001", found)  # Flutter badCertificateCallback => true
        self.assertEqual(sorted(EXPECTED_APPS - found), [])


class PolyglotFixture(unittest.TestCase):
    """Go, PHP, Rails, Spring and .NET spellings of the same mistakes."""

    def test_each_language_is_covered(self):
        with materialize("vuln-polyglot") as tmp:
            root = Path(tmp) / "vuln-polyglot"
            findings, errors = run_all(_context(root))
            stack = set(detect(FileIndex(root)))
        self.assertEqual(errors, [])
        self.assertEqual(sorted(EXPECTED_POLYGLOT - {f.check_id for f in findings}), [])
        self.assertTrue({"go", "php", "rails", "spring", "dotnet"} <= stack)

        def files(check_id):
            return {f.file.split("/")[0] for f in findings if f.check_id == check_id}

        self.assertEqual(files("LP-INJ-003"), {"go", "php", "rails", "java", "dotnet"})  # SQL built from strings
        self.assertEqual(files("LP-INJ-002"), {"go", "php", "rails", "dotnet"})  # shell commands built from input
        self.assertEqual(files("LP-INJ-006"), {"php", "dotnet"})  # unserialize, BinaryFormatter
        self.assertEqual(files("LP-AUTH-003"), {"php", "java"})  # md5 / MessageDigest for passwords
        self.assertIn("java", files("LP-CFG-001"))  # @CrossOrigin(origins = "*")
        self.assertIn("go", files("LP-CRYPTO-001"))  # math/rand for a reset token


class NativeAndMoreFrameworks(unittest.TestCase):
    """Software that isn't a web app, and the remaining popular frameworks."""

    def load(self, name):
        with materialize(name) as tmp:
            root = Path(tmp) / name
            findings, errors = run_all(_context(root))
            routes = {(r.kind, r.method, r.path): r for r in analyze(FileIndex(root))}
        self.assertEqual(errors, [])
        return findings, routes

    def test_checks_fire(self):
        findings, _ = self.load("vuln-native")
        self.assertEqual(sorted(EXPECTED_NATIVE - {f.check_id for f in findings}), [])

    def test_keys_in_notebooks_are_found(self):
        findings, _ = self.load("vuln-native")
        found = [f for f in findings if f.check_id == "LP-SEC-003" and f.file == "notebooks/analysis.ipynb"]
        self.assertTrue(found)
        self.assertNotIn(FAKES["{{FAKE_OPENAI_KEY}}"], found[0].snippet)  # masked

    def test_credential_files(self):
        findings, _ = self.load("vuln-native")
        found = {f.file: f for f in findings if f.check_id == "LP-SEC-010"}
        self.assertEqual(set(found), {"deploy/server.key", "keys/id_ed25519", "firebase/serviceAccountKey.json", ".git-credentials", "deploy/signing.p12"})
        self.assertEqual(found["firebase/serviceAccountKey.json"].severity.label, "critical")
        self.assertEqual(found["deploy/signing.p12"].severity.label, "high")  # it might not be real, so a person should look
        for f in found.values():
            self.assertNotIn("LadPockFixture", (f.snippet or "") + f.message)  # the name, never the contents

    def test_routes_vulnerable(self):
        findings, routes = self.load("vuln-native")
        expected = {
            ("axum", "GET", "/orders"): ("yes", "n/a"), ("axum", "POST", "/orders"): ("no", "no"), ("axum", "DELETE", "/orders/:id"): ("no", "no"),
            ("axum", "GET", "/api/me/orders/:id"): ("yes", "no"),
            ("actix", "POST", "/notes"): ("no", "no"), ("actix", "GET", "/notes/{id}"): ("yes", "no"),
            ("rocket", "POST", "/api/invoices"): ("no", "no"),
            ("elysia", "DELETE", "/api/things/:id"): ("no", "no"), ("elysia", "POST", "/api/v2/things"): ("no", "no"),
            ("hapi", "POST", "/api/widgets"): ("no", "no"), ("hapi", "DELETE", "/api/widgets/{id}"): ("yes", "no"),
            ("sinatra", "POST", "/comments"): ("no", "no"), ("sinatra", "DELETE", "/comments/:id"): ("yes", "yes"),
            ("symfony", "POST", "/api/orders"): ("no", "no"), ("symfony", "GET", "/api/orders/{id}"): ("yes", "no"),
            ("ktor", "POST", "/api/tickets"): ("no", "no"), ("ktor", "DELETE", "/api/tickets/{id}"): ("mw", "no"),
            ("jaxrs", "POST", "/api/accounts"): ("no", "no"), ("jaxrs", "GET", "/api/accounts/{id}"): ("yes", "no"),
        }
        for key, (auth, owner) in expected.items():
            with self.subTest(key):
                self.assertIn(key, routes)
                self.assertEqual((routes[key].auth, routes[key].owner), (auth, owner))
        where = {(f.check_id, f.snippet) for f in findings}
        self.assertIn(("LP-AUTHZ-001", "POST /notes"), where)
        self.assertIn(("LP-AUTHZ-001", "POST /api/tickets"), where)

    def test_routes_clean(self):
        _, routes = self.load("clean-native")
        for key, auth, owner in (
            (("axum", "DELETE", "/orders/:id"), "yes", "yes"), (("sinatra", "DELETE", "/comments/:id"), "yes", "yes"),
            (("symfony", "DELETE", "/api/orders/{id}"), "yes", "yes"), (("ktor", "DELETE", "/api/tickets/{id}"), "yes", "yes"),
            (("jaxrs", "DELETE", "/api/accounts/{id}"), "yes", "yes"),
        ):
            with self.subTest(key):
                self.assertIn(key, routes)
                self.assertEqual((routes[key].auth, routes[key].owner), (auth, owner))
        self.assertTrue(routes[("jaxrs", "GET", "/api/accounts/plans")].public)  # @PermitAll beats the class's @RolesAllowed


class Starters(unittest.TestCase):
    """Correct code written the way the usual starter templates write it. Nothing should be said about it."""

    def routes(self):
        with materialize("clean-starters") as tmp:
            return {(r.kind, r.method, r.path): r for r in analyze(FileIndex(Path(tmp) / "clean-starters"))}

    def test_the_url_carrying_trpc_isnt_an_endpoint(self):
        routes = self.routes()
        self.assertFalse(any(kind != "trpc" and "/trpc" in path for kind, _, path in routes))
        self.assertIn(("trpc", "POST", "/api/trpc/post.create"), routes)

    def test_trpc_query_isnt_a_database_query(self):
        routes = self.routes()
        self.assertFalse(routes[("trpc", "GET", "/api/trpc/post.hello")].db)
        self.assertTrue(routes[("trpc", "GET", "/api/trpc/post.list")].db)

    def test_what_protects_each_route_is_understood(self):
        routes = self.routes()
        for key, auth, owner in (
            (("trpc", "GET", "/api/trpc/order.byId"), "yes", "yes"), (("route", "DELETE", "/api/notes/[id]"), "yes", "yes"),
            (("express", "DELETE", "/api/orders/:id"), "yes", "yes"), (("fastapi", "GET", "/items/{item_id}"), "yes", "yes"),
            (("django", "GET", "/orders/<int:pk>/"), "yes", "yes"), (("convex", "POST", "convex/tasks:create"), "yes", "yes"),
            (("firebase-fn", "POST", "functions/addNote"), "yes", "yes"), (("graphql", "POST", "graphql/Mutation.renameMe"), "yes", "yes"),
        ):
            with self.subTest(key):
                self.assertEqual((routes[key].auth, routes[key].owner), (auth, owner))
        self.assertEqual(routes[("route", "POST", "/api/stripe/webhook")].auth, "sig")
        self.assertEqual(routes[("route", "GET", "/api/cron/daily")].auth, "sig")
        self.assertTrue(routes[("hono", "GET", "/api/notes")].db)  # Cloudflare D1


class FunctionBackends(unittest.TestCase):
    """Backends with no web server to read: tRPC, Convex, GraphQL, Firebase, Supabase Edge, Vercel, Netlify, Cloudflare, Lambda."""

    def load(self, name):
        with materialize(name) as tmp:
            root = Path(tmp) / name
            findings, errors = run_all(_context(root))
            routes = {(r.kind, r.method, r.path): r for r in analyze(FileIndex(root))}
        self.assertEqual(errors, [])
        return findings, routes

    def test_vulnerable(self):
        findings, routes = self.load("vuln-functions")
        expected = {
            ("trpc", "GET", "/api/trpc/order.getById"): ("yes", "no"), ("trpc", "POST", "/api/trpc/order.remove"): ("no", "no"),
            ("convex", "POST", "convex/messages:remove"): ("no", "no"), ("convex", "GET", "convex/messages:read"): ("yes", "yes"),
            ("graphql", "GET", "graphql/Query.secretReport"): ("yes", "no"), ("graphql", "POST", "graphql/Mutation.deleteUser"): ("no", "no"),
            ("graphql", "POST", "graphql/Mutation.cancelOrder"): ("no", "no"),  # NestJS, no guard
            ("firebase-fn", "POST", "functions/deleteAccount"): ("no", "no"), ("firebase-fn", "POST", "functions/readProfile"): ("yes", "no"),
            ("supabase-edge", "ANY", "/functions/v1/admin-export"): ("no", "no"),
            ("vercel", "DELETE", "/api/orders/[id]"): ("no", "no"), ("netlify", "ANY", "/.netlify/functions/delete-account"): ("no", "no"),
            ("cloudflare", "DELETE", "/api/notes/[id]"): ("no", "no"), ("cloudflare", "POST", "/api/feedback"): ("no", "no"),
            ("lambda", "POST", "/orders"): ("no", "no"), ("lambda", "GET", "/orders/{id}"): ("no", "no"), ("lambda", "POST", "/refunds"): ("no", "no"),
        }
        for key, (auth, owner) in expected.items():
            with self.subTest(key):
                self.assertEqual((routes[key].auth, routes[key].owner), (auth, owner))
        self.assertTrue(routes[("trpc", "POST", "/api/trpc/order.summarise")].paid_api)
        self.assertEqual(routes[("lambda", "GET", "/admin/stats")].auth, "mw")  # API Gateway authorizer
        self.assertIn("verify_jwt", routes[("supabase-edge", "ANY", "/functions/v1/admin-export")].notes[0])
        self.assertNotIn(("convex", "POST", "convex/messages:purge"), routes)  # internal functions can't be called from outside
        self.assertFalse(any(path == "/api/_lib/helper" for _, _, path in routes))  # Vercel doesn't deploy _ files
        self.assertEqual(sorted(EXPECTED_FUNCTIONS - {f.check_id for f in findings}), [])
        where = {(f.check_id, f.snippet) for f in findings}
        self.assertIn(("LP-AUTHZ-001", "POST convex/messages:remove"), where)
        self.assertIn(("LP-ABUSE-010", "POST /api/trpc/order.summarise"), where)
        self.assertIn(("LP-AUTHZ-007", "GET /api/customers"), where)
        self.assertIn(("LP-AUTHZ-007", "GET /api/trpc/order.allInvoices"), where)
        self.assertIn(("LP-API-003", "POST /api/seed"), where)
        logged = {f.snippet for f in findings if f.check_id == "LP-LOG-001"}
        self.assertFalse(any("Invalid password" in s or "password rejected" in s for s in logged))  # just words in a string
        self.assertEqual(len(logged), 4)

    def test_clean(self):
        _, routes = self.load("clean-functions")
        for key in (("trpc", "POST", "/api/trpc/order.remove"), ("convex", "POST", "convex/messages:remove"),
                    ("graphql", "POST", "graphql/Mutation.cancelOrder"), ("firebase-fn", "POST", "functions/deleteAccount"),
                    ("vercel", "ANY", "/api/orders/[id]"), ("netlify", "ANY", "/.netlify/functions/delete-account"),
                    ("cloudflare", "DELETE", "/api/notes/[id]")):
            with self.subTest(key):
                self.assertEqual((routes[key].auth, routes[key].owner), ("yes", "yes"))
        edge = routes[("supabase-edge", "ANY", "/functions/v1/my-notes")]
        self.assertEqual((edge.auth, edge.owner), ("yes", "rls"))  # the caller's token, so Row Level Security applies


class MoreFrameworkRoutes(unittest.TestCase):
    """File-based JS frameworks, then Spring, Go, Rails, Laravel and ASP.NET."""

    def load(self, name):
        with materialize(name) as tmp:
            root = Path(tmp) / name
            findings, errors = run_all(_context(root))
            routes = {(r.kind, r.method, r.path): r for r in analyze(FileIndex(root))}
        self.assertEqual(errors, [])
        return findings, routes

    def test_fullstack_vulnerable(self):
        findings, routes = self.load("vuln-fullstack")
        self.assertEqual(routes[("sveltekit", "POST", "/api/notes")].auth, "no")
        self.assertEqual(routes[("sveltekit", "DELETE", "/api/notes/[id]")].owner, "no")
        self.assertTrue(routes[("sveltekit", "POST", "/api/ask")].paid_api)  # (marketing) group left out of the URL
        self.assertIn(("sveltekit", "ACTION", "/settings?/reset"), routes)
        self.assertEqual(routes[("remix", "GET", "/api/orders/:id")].owner, "no")
        self.assertEqual(routes[("nuxt", "DELETE", "/api/posts/[id]")].auth, "no")
        self.assertEqual(routes[("nuxt", "GET", "/api/admin/users")].auth, "mw")  # guard only covers /api/admin
        self.assertEqual(routes[("astro", "ACTION", "action removeAccount()")].auth, "no")
        self.assertNotIn(("pages-api", "ANY", "/api/comments"), routes)  # Astro's src/pages/api isn't Next.js
        where = {(f.check_id, f.snippet) for f in findings}
        self.assertIn(("LP-AUTHZ-001", "ACTION /settings?/reset"), where)  # an action called reset isn't a public page
        self.assertIn(("LP-AUTH-010", "POST /login"), where)
        self.assertIn(("LP-ABUSE-010", "POST /api/chat"), where)
        self.assertIn(("LP-AUTHZ-003", "GET /api/admin/users"), where)  # a path-matched guard

    def test_fullstack_clean(self):
        _, routes = self.load("clean-fullstack")
        self.assertEqual((routes[("remix", "GET", "/api/orders/:id")].auth, routes[("remix", "GET", "/api/orders/:id")].owner),
                         ("yes", "yes"))
        self.assertEqual(routes[("sveltekit", "POST", "/api/notes")].rate_limit, "mw")  # hooks.server.ts

    def test_backends_vulnerable(self):
        findings, routes = self.load("vuln-polyglot")
        expected = {
            ("spring", "POST", "/api/invoices"): ("no", "no"), ("spring", "DELETE", "/api/invoices/{id}"): ("yes", "no"),
            ("go", "POST", "/api/orders"): ("no", "no"), ("go", "GET", "/api/me/orders/:id"): ("mw", "no"),
            ("rails", "DELETE", "/api/invoices/:id"): ("yes", "no"), ("rails", "POST", "/api/invoices/:id/refund"): ("yes", "no"),
            ("rails", "POST", "/users"): ("no", "no"),  # skip_before_action :authenticate_user!
            ("laravel", "GET", "/api/orders/{order}"): ("yes", "no"), ("laravel", "DELETE", "/api/orders/{order}"): ("no", "no"),
            ("laravel", "POST", "/api/comments"): ("no", "no"),
            ("aspnet", "POST", "/api/invoices"): ("no", "no"), ("aspnet", "DELETE", "/api/invoices/{id}"): ("yes", "no"),
            ("aspnet", "POST", "/api/feedback"): ("no", "no"),
        }
        for key, (auth, owner) in expected.items():
            with self.subTest(key):
                self.assertEqual((routes[key].auth, routes[key].owner), (auth, owner))
        self.assertFalse(routes[("rails", "GET", "/api/invoices/:id")].mutates)
        self.assertFalse(routes[("spring", "GET", "/orders")].mutates)  # JDBC createStatement() only reads here
        sign_ins = {f.snippet for f in findings if f.check_id == "LP-AUTH-010"}
        self.assertEqual(sign_ins, {"POST /login", "POST /api/login"})
        self.assertFalse(any(f.check_id == "LP-AUTHZ-003" for f in findings))  # router-level middleware is fine

    def test_backends_clean(self):
        _, routes = self.load("clean-polyglot")
        for key in (("spring", "DELETE", "/api/invoices/{id}"), ("rails", "DELETE", "/api/invoices/:id"),
                    ("laravel", "DELETE", "/api/orders/{order}"), ("aspnet", "DELETE", "/api/invoices/{id}")):
            with self.subTest(key):
                self.assertEqual((routes[key].auth, routes[key].owner), ("yes", "yes"))
        self.assertEqual((routes[("go", "GET", "/api/orders/:id")].auth, routes[("go", "GET", "/api/orders/:id")].owner), ("mw", "yes"))
        self.assertEqual(routes[("laravel", "POST", "/api/login")].rate_limit, "mw")
        self.assertEqual(routes[("rails", "POST", "/login")].rate_limit, "yes")
        self.assertEqual(routes[("aspnet", "GET", "/api/profile")].auth, "yes")  # MapGroup(...).RequireAuthorization()


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
