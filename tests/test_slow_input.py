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


if __name__ == "__main__":
    unittest.main()
