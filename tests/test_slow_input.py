"""Scanned code can be huge, or written to be slow. No file should be able to stall a scan."""

from __future__ import annotations

import tempfile
import time
import unittest
from pathlib import Path

from ladpock.checks import ScanContext, run_all
from ladpock.files import FileIndex
from ladpock.stack import detect

FULL_ANALYSIS = 390_000  # just small enough to get the full analysis
TOO_BIG = 900_000
TOO_BIG_CASES = {"words-procedure.js", "braces.js", "logs.js", "migrations.sql", "requirements.txt"}
WORST_CASES = {
    "words-procedure.js": "var a=publicProcedure;var b={x:protectedProcedure};",
    "words-procedure-lines.ts": "a: publicProcedure.input(z).query(() => {\n",
    "resolvers.graphql.ts": 'var Query={a:1};var Mutation={b:2};function x(){return "Query"}\n',
    "prompts.ts": 'import "openai";var m={role:"system",content:`hi ${a} ${b}`};var s={system:`x ${y}`};\n',
    "braces.js": "{",
    "backticks.js": "`",
    "quotes.js": "'",
    "star-comment.js": "/*",
    "nested.js": "(",
    "on-request.js": "export const onRequest=1;fetch(x);\n",
    "worker.js": "export default {\n",
    "firebase.js": "exports.a = functions.https.onCall(\n",
    "logs.js": "console.log(password,token);\n",
    "multer.js": "multer(",
    "vite.config.js": "define:{a:1,",
    "convex/big.ts": "export const a = query({\n",
    "api/big.ts": "export function GET(req) {\n",
    "netlify/functions/big.ts": "exports.handler = async () => {\n",
    "migrations.sql": "create view a as select ",
    "storage.sql": "insert into storage.buckets values (",
    "functions.sql": "create function a() returns void security definer as $$ select 1; $$;\n",
    "policies.sql": "create policy a on storage.objects for update using (",
    "nginx.conf": "location /a { ",
    "firestore.rules": "allow read: if request.auth != null;\n",
    "requirements.txt": "--extra-index-url http://x\n",
    "Program.cs": "[Authorize] public class A { [HttpGet] public void B() { }\n",
    "routes.rb": "resources :orders do\n",
    "Main.java": "@RestController class A { @GetMapping void b() {\n",
    "main.go": 'r.HandleFunc("/a", func(w, r) {\n',
    "server.py": '@app.route("/a")\ndef a():\n',
    "server.js": 'app.get("/a", (req, res) => {\n',
    "axum.rs": 'use axum;\n.route("/a", get(b))\nfn b(x: y) {\n',
    "actix.rs": 'use actix_web;\n#[get("/a")]\nasync fn b() {\n',
    "elysia.ts": 'import "elysia";\n.get("/a", () => {\n.group("/b", (app) => {\n',
    "hapi.js": 'require("@hapi/hapi");\nserver.route({ method: "GET", path: "/a",\n',
    "sinatra.rb": 'require "sinatra"\nget "/a" do\nbefore do\n',
    "Sym.php": '<?php // Symfony Route\nclass A {\n#[Route("/a")]\npublic function b() {\n',
    "routes.kt": 'routing {\nroute("/a") {\nget("/b") {\nauthenticate("c") {\n',
    "Res.java": 'import jakarta.ws.rs.*;\n@Path("/a") public class A {\n@GET public void b() {\n',
    "Vault.sol": 'function withdraw() public { x.call{value: 1}(""); a[b] = 1;\n',
    "a.c": "strcpy(a, b); printf(x); system(y);\n",
    "mcp.py": "from mcp import x\n@mcp.tool()\ndef a():\n    subprocess.run(b)\n",
    "mcp.ts": 'import "@modelcontextprotocol/sdk";\nserver.tool("a", () => {\n',
    "listen.js": 'window.addEventListener("message", (e) => {\n',
    "sensor.ino": 'const char* password = "abcd"; WiFi.begin("a", "bcde");\n',
    "manifest.json": '{"manifest_version": 3, "permissions": ["<all_urls>",\n',
    "demo.py": "demo.launch(share=True) # x\n",
    "nb.ipynb": '{"source": ["print(1)\\n",\n',
    "a.sh": 'eval "$x"; rm -rf "$y"; curl -k z; sshpass -p abcd e\n',
}


class SlowInput(unittest.TestCase):
    def test_no_file_stalls_a_scan(self):
        with tempfile.TemporaryDirectory(prefix="ladpock-slow-") as tmp:
            root = Path(tmp)
            (root / "wrangler.toml").write_text("name = 'x'\n")
            (root / "supabase").mkdir()
            (root / "package.json").write_text(
                '{"dependencies": {"next": "1", "@trpc/server": "1", "convex": "1", "graphql": "1", "express": "1", "openai": "1"}}')
            for rel, chunk in WORST_CASES.items():
                for size in (FULL_ANALYSIS, TOO_BIG) if rel in TOO_BIG_CASES else (FULL_ANALYSIS,):
                    path = root / str(size) / rel
                    path.parent.mkdir(parents=True, exist_ok=True)
                    path.write_text((chunk * (size // len(chunk) + 1))[:size], encoding="utf-8")
            index = FileIndex(root)
            started = time.monotonic()
            _, errors = run_all(ScanContext(root=root, index=index, stack=set(detect(index))))
            took = time.monotonic() - started
        self.assertEqual(errors, [])
        # Generous, so a slow CI machine doesn't fail it: what it guards against is minutes, or never finishing.
        self.assertLess(took, 240, f"the worst-case files took {took:.0f}s")


# Every file LadPock parses for its structure.
PARSED = [
    "package.json", "package-lock.json", "npm-shrinkwrap.json", "yarn.lock", "pnpm-lock.yaml", "bun.lock", "manifest.json", ".mcp.json", "mcp.json",
    ".cursor/mcp.json", "tauri.conf.json", "src-tauri/tauri.conf.json", "src-tauri/capabilities/main.json", "src-tauri/Cargo.toml", "firebase.json",
    "database.rules.json", "firestore.rules", "composer.json", "composer.lock", "Pipfile.lock", "pyproject.toml", "poetry.lock", "uv.lock", "ladpock.toml",
    "vercel.json", "tsconfig.json", ".vscode/tasks.json", ".vscode/mcp.json", ".claude/settings.json", ".devcontainer/devcontainer.json", "packages.lock.json",
    "pubspec.lock", "pubspec.yaml", "requirements.txt", "go.mod", "Cargo.toml", "Cargo.lock", "serverless.yml", "template.yaml", "docker-compose.yml",
    "AndroidManifest.xml", "Info.plist", "pom.xml", "build.gradle", "gradle.lockfile", "gradle/libs.versions.toml", "app.csproj", "Directory.Packages.props",
    "packages.config", "settings.py", "Gemfile", "Gemfile.lock", "mix.lock", "Package.resolved", "Podfile.lock", "nginx.conf", "next.config.js", "vite.config.ts",
    "wrangler.toml", "netlify.toml", ".npmrc", ".github/workflows/ci.yml", "supabase/config.toml", "supabase/migrations/1.sql", "app.json", "Dockerfile",
]
ODD_TEXT = [
    "", "null", "true", "5", '"x"', "[]", "{}", "[1, 2]", "{", "not json at all", "\ufeff{}",
    '{"dependencies": 5, "devDependencies": [1, 2], "scripts": 5, "packages": 5, "default": 5, "develop": [], "require": 5, "packages-dev": 5}',
    '{"dependencies": {"a": 5, "b": null, "c": [], "d": {"version": 5}}, "scripts": {"postinstall": 5}, "packages": {"a": 5, "b": {"version": 5}}}',
    '{"packages": [5, {"name": 5, "version": 5}], "default": {"a": 5}, "develop": {"b": {"version": 5}}, "dependencies": [{"a": 5}]}',
    '{"mcpServers": 5, "servers": []}', '{"mcpServers": [], "servers": 5}', '{"mcpServers": {"a": 5, "b": {"command": 5, "args": 5, "url": 5}, "c": {"command": "npx", "args": [5, null]}}}',
    '{"manifest_version": 3, "permissions": 5, "host_permissions": "x", "content_scripts": 5, "web_accessible_resources": [5], "externally_connectable": 5, "content_security_policy": 5}',
    '{"manifest_version": 3, "content_scripts": [5, {"matches": 5}], "web_accessible_resources": [{"resources": 5, "matches": 5}], "externally_connectable": {"matches": [5]}, "content_security_policy": {"a": 5}}',
    '{"tauri": 5, "app": 5, "plugins": 5, "build": 5, "bundle": 5, "permissions": 5, "windows": 5, "remote": 5}',
    '{"tauri": {"security": 5, "allowlist": 5, "updater": 5}, "app": {"security": 5, "windows": 5}, "plugins": {"updater": 5}, "permissions": [5, {"identifier": 5, "allow": 5}]}',
    '{"rules": 5, "hooks": 5, "tasks": 5, "version": 5, "postCreateCommand": 5, "routes": 5, "env": 5}',
    "[project]\ndependencies = 5\nname = 5\n[tool.poetry]\ndependencies = 5\n[dependencies]\ntauri = 5\n[[package]]\nname = 5\nversion = 5\n[versions]\na = 5\n[libraries]\nb = 5\n",
    '[[package]]\nversion = "1"\n[[package]]\nname = "a"\n[libraries]\nb = { module = 5 }\nc = "x"\n[routes]\nauth_functions = 5\npublic = [5]\n[ignore]\npaths = 5\nchecks = [5]\n',
    "routes = 5\nignore = 5\n",
    "functions:\n  a: 5\n  b:\n    handler: 5\n    events:\n      - http: 5\n      - httpApi: {}\n      - http:\n          path:\n",
    "Resources:\n  A:\n    Type: AWS::Serverless::Function\n    Properties:\n      Events:\n        B:\n          Type: Api\n          Properties:\n            Path:\n            Method:\n",
    "services:\n  a: 5\n  b:\n    ports: 5\n    image:\n",
    "<project><dependencies><dependency></dependency></dependencies></project>", "<manifest><application></manifest>", "<Project><PackageReference /></Project>",
    "[" * 200_000, '{"a":' * 100_000, "(" * 200_000, "<" * 200_000, "=" * 200_000, "\x00\x01\x02binary", "é" * 5000, " \n" * 100_000, "a" * 990_000,
]


class OddFiles(unittest.TestCase):
    """Valid or not, the right shape or not: nothing in a project should be able to break a scan."""

    def test_nothing_breaks(self):
        from ladpock import sbom
        from ladpock.inventory import collect, direct_dependencies
        from ladpock.routes import analyze
        from ladpock.tauri import analyze_commands, is_tauri_project

        problems = []
        for text in ODD_TEXT:
            with tempfile.TemporaryDirectory(prefix="ladpock-odd-") as tmp:
                root = Path(tmp)
                for rel in PARSED:
                    path = root / rel
                    path.parent.mkdir(parents=True, exist_ok=True)
                    path.write_bytes(text.encode("utf-8", "replace"))
                label = repr(text[:50])
                try:
                    index = FileIndex(root)
                    stack = set(detect(index))
                    _, errors = run_all(ScanContext(root=root, index=index, stack=stack | {"tauri", "supabase", "firebase", "nextjs", "express", "mcp"}))
                    problems.extend(f"{label}: {e[:150]}" for e in errors)
                    collect(index)
                    direct_dependencies(index)
                    analyze(index)
                    if is_tauri_project(index):
                        analyze_commands(index)
                    sbom.build(root)
                except Exception as exc:  # a crash here would stop a whole scan, so it's the failure this test exists to find
                    problems.append(f"{label}: CRASH {type(exc).__name__}: {str(exc)[:150]}")
        self.assertEqual(problems, [])

    def test_the_whole_scan_and_every_report(self):
        """From scan to stored results to each output format, because a bad value can get a long way before something trips on it."""
        from helpers import isolated_home

        from ladpock import report
        from ladpock.db import DB
        from ladpock.scan import run_scan

        home = isolated_home()
        db = DB()
        try:
            for text in (ODD_TEXT[11], ODD_TEXT[12], ODD_TEXT[13], ODD_TEXT[15], "[" * 200_000, "\x00\x01\x02binary"):
                with self.subTest(text[:40]), tempfile.TemporaryDirectory(prefix="ladpock-odd-") as tmp:
                    root = Path(tmp) / "odd"
                    for rel in PARSED:
                        path = root / rel
                        path.parent.mkdir(parents=True, exist_ok=True)
                        path.write_bytes(text.encode("utf-8", "replace"))
                    result = run_scan(root, db, offline=True, external=False, log=lambda _: None)
                    # "Couldn't read Cargo.lock" is the right thing to tell someone. A check or a route reader failing isn't.
                    self.assertEqual([e for e in result.errors if e.startswith("LP-") or "read routes" in e], [])
                    for output in (report.to_html(result), report.github_summary(result), report.to_sarif(result), result.to_dict(),
                                   report.render_scan(result, report.Style(False))):
                        self.assertTrue(output)
        finally:
            db.close()
            home.cleanup()


if __name__ == "__main__":
    unittest.main()
