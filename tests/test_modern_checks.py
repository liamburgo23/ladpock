"""Pattern checks, one line at a time: what each must find, and the similar-looking lines it must leave alone."""

from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from ladpock.checks import ScanContext, run_all
from ladpock.files import FileIndex
from ladpock.stack import detect

AI_JS = 'import OpenAI from "openai";\n'
AI_PY = "import openai\n"
# (file name, code, check that must fire, or None for lines nothing new should say anything about)
FIRES = [
    ("a.ts", AI_JS + "const c = new OpenAI({ dangerouslyAllowBrowser: true });", "LP-AI-001"),
    ("a.ts", AI_JS + "eval(reply);", "LP-AI-002"),
    ("a.ts", AI_JS + "child_process.exec(completion);", "LP-AI-002"),
    ("a.ts", AI_JS + "await db.$queryRawUnsafe(answer);", "LP-AI-002"),
    ("a.py", AI_PY + "exec(response.text)", "LP-AI-002"),
    ("a.py", AI_PY + "cursor.execute(completion)", "LP-AI-002"),
    ("a.py", AI_PY + "subprocess.run(answer, shell=True)", "LP-AI-002"),
    ("a.ts", AI_JS + "create({ model: req.body.model });", "LP-AI-003"),
    ("a.ts", AI_JS + "create({ max_tokens: body.maxTokens });", "LP-AI-003"),
    ("a.ts", AI_JS + "const { model, messages } = await req.json();", "LP-AI-003"),
    ("a.py", AI_PY + "client.create(model=request.json['model'])", "LP-AI-003"),
    ("a.ts", AI_JS + "m = [{ role: 'system', content: `Help ${req.body.name}` }];", "LP-AI-004"),
    ("a.ts", AI_JS + "streamText({ system: `You help ${user.name}` });", "LP-AI-004"),
    ("a.py", AI_PY + "m = [{'role': 'system', 'content': f'Help {request.json}'}]", "LP-AI-004"),
    ("a.py", "agent = build(allow_dangerous_code=True)", "LP-AI-005"),
    ("a.py", "tools = [ShellTool()]", "LP-AI-005"),
    ("a.js", "fs.writeFileSync(path.join(dir, file.originalname), data);", "LP-UPLOAD-001"),
    ("a.py", "upload.save(os.path.join(base, upload.filename))", "LP-UPLOAD-001"),
    ("a.php", "<?php move_uploaded_file($tmp, 'up/' . $_FILES['f']['name']);", "LP-UPLOAD-001"),
    ("a.go", "dst := filepath.Join(dir, header.Filename)", "LP-UPLOAD-001"),
    ("a.cs", "var p = Path.Combine(dir, file.FileName);", "LP-UPLOAD-001"),
    ("a.java", "File f = new File(dir, file.getOriginalFilename());", "LP-UPLOAD-001"),
    ("a.js", 'const u = multer({ dest: "/tmp" });', "LP-UPLOAD-002"),
    ("a.js", "app.use(fileUpload({ useTempFiles: true }));", "LP-UPLOAD-002"),
    ("a.js", 'const u = multer({ dest: "public/uploads" });', "LP-UPLOAD-003"),
    ("a.js", 'console.log("pw", password);', "LP-LOG-001"),
    ("a.js", "console.log(`key ${apiKey}`);", "LP-LOG-001"),
    ("a.js", "console.log(req.headers.authorization);", "LP-LOG-001"),
    ("a.py", 'logger.info(f"logging in {password}")', "LP-LOG-001"),
    ("a.go", 'fmt.Println("secret", clientSecret)', "LP-LOG-001"),
    ("auth/session.js", "console.log(token);", "LP-LOG-001"),
    ("auth/login.js", "console.log(req.body);", "LP-LOG-001"),
    ("a.js", "create({ data: { email, role: req.body.role } });", "LP-AUTHZ-008"),
    ("a.py", "User(email=email, is_admin=request.json['admin'])", "LP-AUTHZ-008"),
    ("a.rb", "params.require(:user).permit(:email, :admin)", "LP-AUTHZ-008"),
    ("a.ts", 'if (localStorage.getItem("isAdmin")) show();', "LP-AUTHZ-009"),
    ("a.js", "if (req.cookies.role === 'admin') allow();", "LP-AUTHZ-009"),
    ("a.ts", 'const who = request.headers.get("x-user-id");', "LP-AUTHZ-009"),
    ("a.js", "where: { userId: req.body.userId }", "LP-AUTHZ-010"),
    ("a.ts", "const { userId } = await req.json();", "LP-AUTHZ-010"),
    ("a.py", "Order.get(user_id=request.json['user_id'])", "LP-AUTHZ-010"),
    ("a.js", "res.json(process.env);", "LP-SEC-008"),
    ("a.py", "return jsonify(dict(os.environ))", "LP-SEC-008"),
    ("vite.config.ts", 'export default { define: { "process.env": env } };', "LP-SEC-009"),
    ("next.config.js", "module.exports = { env: { ...process.env } };", "LP-SEC-009"),
    ("webpack.config.js", 'new DefinePlugin({ "process.env": JSON.stringify(process.env) });', "LP-SEC-009"),
    ("a.ts", "Google({ allowDangerousEmailAccountLinking: true })", "LP-AUTH-012"),
    ("a.ts", 'const u = "https://accounts.google.com/o/oauth2/v2/auth?client_id=x";', "LP-AUTH-013"),
    ("a.js", "const link = `https://${req.headers.host}/reset?token=${t}`;", "LP-AUTH-014"),
    ("a.py", 'url = f"{request.url_root}reset/{token}"', "LP-AUTH-014"),
    ("a.ts", "document.cookie = `session=${s}`;", "LP-AUTH-015"),
    ("a.ts", 'Cookies.set("authToken", t);', "LP-AUTH-015"),
    ("a.js", "if (apiKey === process.env.API_KEY) ok();", "LP-CRYPTO-003"),
    ("a.js", 'if (req.headers["x-api-key"] !== process.env.KEY) deny();', "LP-CRYPTO-003"),
    ("a.py", "if token == settings.API_TOKEN: ok()", "LP-CRYPTO-003"),
    ("next.config.js", 'module.exports = { images: { remotePatterns: [{ hostname: "**" }] } };', "LP-CFG-009"),
    ("a.ts", "typescript: { ignoreBuildErrors: true }", "LP-VIBE-006"),
    ("a.ts", "create({ success_url: `${o}/ok?paid=true` });", "LP-PAY-003"),
    ("a.py", "import tarfile\ntarfile.open(p).extractall(d)", "LP-INJ-013"),
    ("a.js", "zip.extractAllTo(dir, true);", "LP-INJ-013"),
    ("a.js", "sendMail({ to: req.body.email, text });", "LP-ABUSE-012"),
    ("a.js", "sequelize.sync({ force: true });", "LP-VIBE-007"),
    ("a.js", 'const hash = crypto.createHash("sha256").update(password);', "LP-AUTH-003"),
    ("a.py", "db.drop_all()", "LP-VIBE-007"),
    ("a.ts", "new DataSource({ synchronize: true });", "LP-VIBE-007"),
    ("Procfile", "web: rails db:reset && rails server", "LP-VIBE-007"),
    ("a.js", 'if (process.env.DISABLE_AUTH) return next();', "LP-AUTHZ-011"),
    ("a.py", 'if os.environ.get("SKIP_AUTH"): return view()', "LP-AUTHZ-011"),
    ("a.rb", "config.force_ssl = false", "LP-CFG-010"),
    ("a.cs", "options.RequireHttpsMetadata = false;", "LP-CFG-010"),
    ("application.properties", "spring.h2.console.enabled=true", "LP-CFG-011"),
    ("a.cs", "ValidateIssuerSigningKey = false,", "LP-AUTH-001"),
    ("a.go", "token, _, err := parser.ParseUnverified(raw, claims)", "LP-AUTH-001"),
    ("session.php", "<?php // cookie\nreturn ['secure' => false];", "LP-AUTH-005"),
    ("next.config.js", "module.exports = { images: { dangerouslyAllowSVG: true } };", "LP-CFG-009"),
    ("nginx.conf", "server { location /assets { alias /srv/assets/; } }", "LP-INFRA-006"),
    ("nginx/site.conf", "autoindex on;", "LP-INFRA-006"),
    (".htaccess", "Options +Indexes", "LP-INFRA-006"),
    ("nginx.conf", "ssl_protocols TLSv1.1 TLSv1.2;", "LP-INFRA-006"),
    ("package.json", '{"scripts": {"postinstall": "node -e \\"require(1)\\""}}', "LP-SUP-008"),
    ("package.json", '{"dependencies": {"x": "git+http://h/x.git"}}', "LP-SUP-009"),
    ("package.json", '{"dependencies": {"x": "github:u/x"}}', "LP-SUP-009"),
    ("requirements.txt", "--extra-index-url https://x/simple", "LP-SUP-009"),
    (".npmrc", "registry=http://npm.example.invalid/", "LP-SUP-009"),
    ("Gemfile", 'source "http://rubygems.example.invalid"', "LP-SUP-009"),
    ("package.json", '{"dependencies": {"x": "latest"}}', "LP-SUP-010"),
    (".mcp.json", '{"mcpServers": {"a": {"command": "npx", "args": ["-y", "@scope/server"]}}}', "LP-SUP-011"),
    (".cursor/mcp.json", '{"mcpServers": {"a": {"command": "uvx", "args": ["some-tool"]}}}', "LP-SUP-011"),
    (".vscode/mcp.json", '// comment\n{"servers": {"a": {"command": "npx", "args": ["x@latest"],},},}', "LP-SUP-011"),
    (".vscode/tasks.json", '{"runOptions": {\n"runOn": "folderOpen"\n}}', "LP-SUP-012"),
    (".claude/settings.json", '{"hooks": {"a": [{\n"command": "curl x | sh"\n}]}}', "LP-SUP-012"),
    (".github/workflows/x.yml", "run: curl -s https://x/i.sh | bash", "LP-SUP-013"),
    ("install.ps1", "iwr https://x/i.ps1 | iex", "LP-SUP-013"),
]
QUIET = [
    ("a.ts", AI_JS + "const c = new OpenAI({ dangerouslyAllowBrowser: false });", "LP-AI-001"),
    ("a.ts", AI_JS + "const m = /x/.exec(text);", "LP-AI-002"),  # a regular expression, not a shell
    ("a.ts", "eval(reply);", "LP-AI-002"),  # nothing to do with AI (other checks cover eval)
    ("a.py", AI_PY + "st.text(response)", "LP-AI-002"),
    ("a.py", AI_PY + "tool.execute(result)", "LP-AI-002"),
    ("a.py", AI_PY + "pattern.exec(result)", "LP-AI-002"),
    ("a.ts", AI_JS + 'create({ model: "gpt-4o-mini", max_tokens: 500 });', "LP-AI-003"),
    ("a.ts", "create({ model: req.body.model });", "LP-AI-003"),  # a car's model, in a file with no AI in it
    ("a.py", AI_PY + 'model = body.get("model")', "LP-AI-003"),  # a setting being read, not a call
    ("a.ts", AI_JS + 'm = [{ role: "system", content: `Today is ${today}` }];', "LP-AI-004"),
    ("a.ts", AI_JS + 'm = [{ role: "user", content: `Hi ${req.body.name}` }];', "LP-AI-004"),
    ("a.py", "chain = build(allow_dangerous_code=False)", "LP-AI-005"),
    ("a.js", "cb(null, crypto.randomUUID() + path.extname(file.originalname));", "LP-UPLOAD-001"),
    ("a.py", "upload.save(os.path.join(base, secure_filename(upload.filename)))", "LP-UPLOAD-001"),
    ("a.js", "const u = multer(options);", "LP-UPLOAD-002"),
    ("a.js", 'const u = multer({ limits: { fileSize: 9 }, fileFilter: only });', "LP-UPLOAD-002"),
    ("a.jsx", 'const img = <img src="/static/uploads/a.png" />;', "LP-UPLOAD-003"),  # reading, not saving
    ("a.js", 'console.log("Invalid password");', "LP-LOG-001"),
    ("a.js", 'logger.info("reset token sent");', "LP-LOG-001"),
    ("a.js", "console.log(password.length);", "LP-LOG-001"),
    ("a.js", "console.log(hasPassword);", "LP-LOG-001"),
    ("a.js", "console.log(maskToken(accessToken));", "LP-LOG-001"),
    ("a.py", 'print("token expired")', "LP-LOG-001"),
    ("a.py", "print(token)", "LP-LOG-001"),  # could be a parser's token: only counts in sign-in code
    ("a.js", 'console.log(`user ${user.id} signed in`);', "LP-LOG-001"),
    ("admin/users.js", "update({ role: req.body.role });", "LP-AUTHZ-008"),
    ("a.ts", "messages.push({ role: body.role, content: body.content });", "LP-AUTHZ-008"),
    ("a.js", 'create({ data: { email, role: "member" } });', "LP-AUTHZ-008"),
    ("a.ts", 'localStorage.getItem("theme");', "LP-AUTHZ-009"),
    ("a.ts", 'localStorage.getItem("plan");', "LP-AUTHZ-009"),
    ("a.js", "where: { userId: session.user.id }", "LP-AUTHZ-010"),
    ("a.js", 'res.json({ node: process.env.NODE_ENV });', "LP-SEC-008"),
    ("vite.config.ts", 'export default { define: { __V__: "1" } };', "LP-SEC-009"),
    ("a.ts", "const x = { define: { 'process.env': env } };", "LP-SEC-009"),  # not a build config
    ("a.ts", "const u = `https://accounts.google.com/o/oauth2/v2/auth?client_id=x&state=${state}`;", "LP-AUTH-013"),
    ("a.js", "const home = `https://${req.headers.host}/about`;", "LP-AUTH-014"),
    ("a.ts", 'document.cookie = "theme=dark";', "LP-AUTH-015"),
    ("a.js", "if (tokenCount === process.env.MAX) stop();", "LP-CRYPTO-003"),
    ("a.js", "if (process.env.API_KEY === undefined) stop();", "LP-CRYPTO-003"),
    ("a.js", "crypto.timingSafeEqual(a, b);", "LP-CRYPTO-003"),
    ("next.config.js", 'module.exports = { images: { remotePatterns: [{ hostname: "cdn.example.com" }] } };', "LP-CFG-009"),
    ("a.ts", "create({ success_url: `${o}/ok?session_id={CHECKOUT_SESSION_ID}` });", "LP-PAY-003"),
    ("a.py", "import zipfile\nzipfile.ZipFile(p).extractall(d)", "LP-INJ-013"),  # zipfile cleans the names itself
    ("a.py", 'import tarfile\ntarfile.open(p).extractall(d, filter="data")', "LP-INJ-013"),
    ("a.py", "import zlib\nzlib.decompress(blob)", "LP-INJ-013"),
    ("a.js", "sendMail({ to: user.email, text });", "LP-ABUSE-012"),
    ("a.js", "track({ to: req.body.page });", "LP-ABUSE-012"),  # not sending a message
    ("a.js", 'if (process.env.NODE_ENV === "test") sequelize.sync({ force: true });', "LP-VIBE-007"),
    ("a.js", "sequelize.sync({ alter: false });", "LP-VIBE-007"),
    ("a.js", 'const hash = crypto.createHash("sha256").update(resetToken); // password reset', "LP-AUTH-003"),
    ("policy.sql", "create table public.posts (id int);\nalter table public.posts enable row level security;\ncreate policy p on public.posts for select using (true);\n-- supabase", "LP-SUPA-002"),
    ("a.rb", "config.force_ssl = true", "LP-CFG-010"),
    ("a.cs", "options.RequireHttpsMetadata = !env.IsDevelopment();", "LP-CFG-010"),
    ("application.properties", "spring.h2.console.enabled=false", "LP-CFG-011"),
    ("a.cs", "ValidateIssuerSigningKey = true,", "LP-AUTH-001"),
    ("nginx.conf", "server { location /assets/ { alias /srv/assets/; } }", "LP-INFRA-006"),
    ("nginx.conf", "server { location /assets { alias /srv/assets; } }", "LP-INFRA-006"),
    ("nginx.conf", "ssl_protocols TLSv1.2 TLSv1.3;", "LP-INFRA-006"),
    (".htaccess", "Options -Indexes", "LP-INFRA-006"),
    ("notes.conf", "autoindex on;", "LP-INFRA-006"),  # not a web server's config file
    ("package.json", '{"scripts": {"postinstall": "prisma generate", "start": "curl x"}}', "LP-SUP-008"),
    ("package.json", '{"dependencies": {"x": "^1.2.3", "y": "workspace:*", "z": "file:../z", "w": "npm:other@1"}}', "LP-SUP-009"),
    ("requirements.txt", "flask==3.0.0\n--index-url https://pypi.example.invalid/simple", "LP-SUP-009"),
    (".npmrc", "registry=https://npm.example.invalid/", "LP-SUP-009"),
    ("package.json", '{"dependencies": {"x": "^1.0.0"}}', "LP-SUP-010"),
    (".mcp.json", '{"mcpServers": {"a": {"command": "npx", "args": ["-y", "@scope/server@1.2.3"]}}}', "LP-SUP-011"),
    (".mcp.json", '{"mcpServers": {"a": {"command": "node", "args": ["server.js"]}}}', "LP-SUP-011"),
    (".mcp.json", '{"mcpServers": {"a": {"url": "http://localhost:9/sse"}}}', "LP-SUP-011"),
    (".mcp.json", '{"mcpServers": {"a": {"url": "https://mcp.example.invalid/sse"}}}', "LP-SUP-011"),
    (".vscode/tasks.json", '{"tasks": [{"command": "npm test"}]}', "LP-SUP-012"),
    (".claude/settings.json", '{"hooks": {"a": [{\n"command": "npm run lint"\n}]}}', "LP-SUP-012"),
    ("settings.json", '{"hooks": {"a": [{\n"command": "curl x | sh"\n}]}}', "LP-SUP-012"),  # not in an AI tool's folder
    (".github/workflows/x.yml", "run: curl -s https://x/data.json -o data.json", "LP-SUP-013"),
    ("a.sh", "# curl https://x | sh", "LP-SUP-013"),
    ("README.md", "curl https://x/i.sh | sh", "LP-SUP-013"),
]


def findings_for(name: str, code: str) -> set[str]:
    with tempfile.TemporaryDirectory(prefix="ladpock-line-") as tmp:
        root = Path(tmp)
        path = root / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(code, encoding="utf-8")
        index = FileIndex(root)
        found, errors = run_all(ScanContext(root=root, index=index, stack=set(detect(index))))
        assert errors == [], errors
        return {f.check_id for f in found}


class Lines(unittest.TestCase):
    def test_finds(self):
        for name, code, check_id in FIRES:
            with self.subTest(code=code):
                self.assertIn(check_id, findings_for(name, code))

    def test_leaves_alone(self):
        for name, code, check_id in QUIET:
            with self.subTest(code=code):
                self.assertNotIn(check_id, findings_for(name, code))


def routes_project(files: dict[str, str]) -> list:
    with tempfile.TemporaryDirectory(prefix="ladpock-routes-") as tmp:
        root = Path(tmp)
        for rel, text in files.items():
            path = root / rel
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(text, encoding="utf-8")
        index = FileIndex(root)
        found, errors = run_all(ScanContext(root=root, index=index, stack=set(detect(index))))
        assert errors == [], errors
        return found


HANDLER = 'import { db } from "@/lib/db";\nexport async function GET() { return Response.json(await db.%s); }\n'


class RouteNames(unittest.TestCase):
    def fired(self, path: str, query: str = "thing.findMany({ take: 5 })") -> set[str]:
        return {f.check_id for f in routes_project({"next.config.js": "", f"app{path}/route.ts": HANDLER % query})}

    def test_private_reads(self):
        self.assertIn("LP-AUTHZ-007", self.fired("/api/invoices"))
        self.assertIn("LP-AUTHZ-007", self.fired("/api/users/[id]"))
        for path in ("/api/products", "/api/blog/[slug]", "/api/health", "/api/users/[id]/posts", "/api/widgets"):
            with self.subTest(path):
                self.assertNotIn("LP-AUTHZ-007", self.fired(path))

    def test_debug_endpoints(self):
        for path in ("/api/seed", "/api/debug", "/api/test", "/api/reset-db", "/api/dev/users"):
            with self.subTest(path):
                self.assertIn("LP-API-003", self.fired(path))
        for path in ("/api/dropdown", "/api/seedlings", "/api/testimonials", "/api/developers", "/api/mockups"):
            with self.subTest(path):
                self.assertNotIn("LP-API-003", self.fired(path))

    def test_cron(self):
        self.assertIn("LP-API-004", self.fired("/api/cron/daily"))

    def test_whole_table(self):
        self.assertIn("LP-ABUSE-013", self.fired("/api/widgets", "widget.findMany()"))
        self.assertNotIn("LP-ABUSE-013", self.fired("/api/widgets", "widget.findMany({ take: 20 })"))


if __name__ == "__main__":
    unittest.main()
