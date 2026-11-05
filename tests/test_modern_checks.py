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
    (".env", "OLLAMA_HOST=0.0.0.0:11434", "LP-AI-006"),
    ("a.py", 'demo.launch(server_name="0.0.0.0")', "LP-AI-006"),
    ("a.sh", "llama-server -m model.gguf --host 0.0.0.0", "LP-AI-006"),
    ("compose.yml", "      - WEBUI_AUTH=False", "LP-AI-006"),
    ("a.py", "st.markdown(reply, unsafe_allow_html=True)", "LP-AI-007"),
    ("a.js", 'window.addEventListener("message", (e) => { run(e.data); });', "LP-INJ-014"),
    ("a.js", "window.onmessage = (e) => run(e.data);", "LP-INJ-014"),
    ("a.ino", '#define WIFI_PASSWORD "hunter2hunter"', "LP-IOT-001"),
    ("a.ino", 'char secret[] = "x"; const char mqtt_pass[] = "hunter2hunter";', "LP-IOT-001"),
    ("a.ino", "client.setInsecure();", "LP-IOT-002"),
    ("manifest.json", '{"manifest_version": 2, "permissions": ["tabs", "http://*/*"]}', "LP-EXT-001"),
    ("manifest.json", '{"manifest_version": 3, "content_scripts": [{"matches": ["<all_urls>"], "js": ["a.js"]}]}', "LP-EXT-001"),
    ("manifest.json", """{"manifest_version": 2, "content_security_policy": "script-src 'self' https://cdn.example.invalid"}""", "LP-EXT-002"),
    ("a.c", "gets(buffer);", "LP-NATIVE-001"),
    ("a.cpp", "strcat(path, input);", "LP-NATIVE-001"),
    ("a.c", 'scanf("%s", name);', "LP-NATIVE-001"),
    ("a.c", "printf(name);", "LP-NATIVE-002"),
    ("a.c", "printf(user->name);", "LP-NATIVE-002"),
    ("a.c", "system(command);", "LP-NATIVE-003"),
    ("a.c", "popen(cmd, mode);", "LP-NATIVE-003"),
    ("a.py", "path = tempfile.mktemp()", "LP-NATIVE-004"),
    ("a.cs", 'client.DownloadFile("http://x.example.invalid/setup.exe", dest);', "LP-NATIVE-005"),
    ("a.py", 'requests.get("http://x.example.invalid/tool.deb")', "LP-NATIVE-005"),
    ("a.sh", 'wget http://x.example.invalid/i.sh', "LP-NATIVE-005"),
    ("a.sh", 'eval "$USER_INPUT"', "LP-SHELL-001"),
    ("a.ps1", "iex $payload", "LP-SHELL-001"),
    ("a.sh", "chmod 777 file", "LP-SHELL-002"),
    ("a.py", "os.chmod(path, 0o777)", "LP-SHELL-002"),
    ("Dockerfile", "RUN chmod -R a+w /app", "LP-SHELL-002"),
    ("a.sh", 'rm -rf "$DIR"/*', "LP-SHELL-003"),
    ("a.sh", "curl --insecure https://x", "LP-SHELL-004"),
    ("a.sh", "git config --global http.sslVerify false", "LP-SHELL-004"),
    ("a.py", "ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())", "LP-SHELL-004"),
    (".github/workflows/x.yml", "run: ssh -o StrictHostKeyChecking=no h", "LP-SHELL-004"),
    ("a.sh", "mysql -u root -phunter2 db", "LP-SHELL-005"),
    ("a.sh", "curl -u admin:hunter2 https://x", "LP-SHELL-005"),
    ("a.rs", 'Command::new("bash").args(["-c", &format!("ls {}", dir)]);', "LP-RUST-002"),
    ("a.rs", 'conn.execute(&format!("DELETE FROM t WHERE id = {}", id), []);', "LP-RUST-003"),
    ("a.sol", "require(tx.origin == owner);", "LP-SOL-001"),
    ("a.sol", 'function take() public { msg.sender.call{value: 1}(""); total -= 1; }', "LP-SOL-002"),
    ("a.sol", "function setAdmin(address a) external { admin = a; }", "LP-SOL-003"),
    ("a.sol", "function sweep() public { msg.sender.transfer(1); }", "LP-SOL-003"),
    ("a.sol", "uint r = uint(blockhash(block.number - 1)); uint s = uint(keccak256(abi.encode(blockhash(1))));", "LP-SOL-004"),
    ("a.sol", "pragma solidity >=0.4.0;", "LP-SOL-005"),
    ("a.sol", "selfdestruct(payable(owner));", "LP-SOL-006"),
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
    (".env", "OLLAMA_HOST=127.0.0.1:11434", "LP-AI-006"),
    ("a.py", 'demo.launch(server_name="127.0.0.1")', "LP-AI-006"),
    ("a.py", 'demo.launch(share=True, auth=("a", password))', "LP-AI-006"),
    ("a.py", "app.launch()", "LP-AI-006"),
    ("a.py", "st.write(reply)", "LP-AI-007"),
    ("a.py", 'st.markdown("<style>a { color: red }</style>", unsafe_allow_html=True)', "LP-AI-007"),
    ("a.js", 'window.addEventListener("message", (e) => {\n  if (e.origin !== SITE) return;\n  run(e.data);\n});', "LP-INJ-014"),
    ("a.js", 'worker.addEventListener("message", (e) => run(e.data));', "LP-INJ-014"),  # your own worker, not another site
    ("a.js", 'window.addEventListener("resize", run);', "LP-INJ-014"),
    ("a.ino", '#define WIFI_PASSWORD "your_password"', "LP-IOT-001"),
    ("a.ino", "WiFi.begin(ssid, password);", "LP-IOT-001"),
    ("a.c", 'const char *password = "hunter2hunter";', "LP-IOT-001"),  # a C file isn't a sketch: other checks look at C
    ("a.ino", 'mqttClient.setServer("x", 8883);', "LP-IOT-002"),
    ("manifest.json", '{"permissions": ["<all_urls>"]}', "LP-EXT-001"),  # a web app manifest or some other file
    ("manifest.json", '{"manifest_version": 3, "permissions": ["activeTab", "storage"]}', "LP-EXT-001"),
    ("manifest.json", '{"manifest_version": 3, "host_permissions": ["https://api.example.invalid/*"]}', "LP-EXT-001"),
    ("manifest.json", """{"manifest_version": 3, "content_security_policy": {"extension_pages": "script-src 'self'"}}""", "LP-EXT-002"),
    ("a.c", "fgets(buffer, sizeof(buffer), stdin);", "LP-NATIVE-001"),
    ("a.c", 'snprintf(a, sizeof(a), "%s", b);', "LP-NATIVE-001"),
    ("a.cpp", "my_strcpy(a, b); obj.strcpy(a, b); ptr->gets(c);", "LP-NATIVE-001"),
    ("a.c", '// strcpy(a, b);', "LP-NATIVE-001"),
    ("a.js", "strcpy(a, b);", "LP-NATIVE-001"),  # not C
    ("a.c", 'printf("hello\\n");', "LP-NATIVE-002"),
    ("a.c", 'printf("%s", name);', "LP-NATIVE-002"),
    ("a.c", 'fprintf(stderr, "failed");', "LP-NATIVE-002"),
    ("a.c", 'system("clear");', "LP-NATIVE-003"),
    ("a.c", "int system(const char *s);", "LP-NATIVE-003"),
    ("a.py", "handle, path = tempfile.mkstemp()", "LP-NATIVE-004"),
    ("a.cs", 'client.DownloadFile("https://x.example.invalid/setup.exe", dest);', "LP-NATIVE-005"),
    ("a.py", 'requests.get("http://localhost:3000/health")', "LP-NATIVE-005"),
    ("a.py", 'requests.get("http://x.example.invalid/data.json")', "LP-NATIVE-005"),
    ("a.sh", "echo eval", "LP-SHELL-001"),
    ("a.sh", "chmod 755 file", "LP-SHELL-002"),
    ("a.sh", 'rm -rf "${DIR:?}"/', "LP-SHELL-003"),
    ("a.sh", "rm -rf build", "LP-SHELL-003"),
    ("a.sh", "curl -fsS https://x", "LP-SHELL-004"),
    ("a.sh", "curl -L https://x", "LP-SHELL-004"),
    ("a.sh", 'mysql -u root -p"$PASSWORD" db', "LP-SHELL-005"),
    ("a.sh", 'curl -u "$USER:$TOKEN" https://x', "LP-SHELL-005"),
    (".github/workflows/x.yml", "run: tool --password ${{ secrets.PASSWORD }}", "LP-SHELL-005"),
    ("a.rs", 'Command::new("git").arg("clone").arg(url);', "LP-RUST-002"),
    ("a.rs", 'println!("{}", format!("x {}", y));', "LP-RUST-003"),
    ("a.rs", 'sqlx::query("SELECT 1").execute(&pool);', "LP-RUST-003"),
    ("a.sol", "require(msg.sender == tx.origin);", "LP-SOL-001"),  # a common way to allow only wallets
    ("a.sol", 'function take() public nonReentrant { total -= 1; msg.sender.call{value: 1}(""); }', "LP-SOL-002"),
    ("a.sol", 'function take() public { total -= 1; msg.sender.call{value: 1}(""); }', "LP-SOL-002"),
    ("a.sol", "function setAdmin(address a) external onlyOwner { admin = a; }", "LP-SOL-003"),
    ("a.sol", 'function setAdmin(address a) external { require(msg.sender == owner, "no"); admin = a; }', "LP-SOL-003"),
    ("a.sol", "function _mint(address a) internal { x = a; }", "LP-SOL-003"),
    ("a.sol", "function withdraw() external { uint a = balances[msg.sender]; balances[msg.sender] = 0; payable(msg.sender).transfer(a); }", "LP-SOL-003"),
    ("a.sol", "pragma solidity ^0.8.20;", "LP-SOL-005"),
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
