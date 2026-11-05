"""Following request data through variables: bugs split over several lines, and safe code that looks similar."""

from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from ladpock.checks import ScanContext, run_all
from ladpock.files import FileIndex
from ladpock.stack import detect

SQL, SHELL, FILE, SSRF, REDIRECT, EVAL, HTML, TEMPLATE = (f"LP-FLOW-00{i}" for i in range(1, 9))
ANY_FLOW = {SQL, SHELL, FILE, SSRF, REDIRECT, EVAL, HTML, TEMPLATE}
# What the line-at-a-time checks would say about the same line instead, which counts as caught.
ALSO = {SQL: {"LP-INJ-003"}, SHELL: {"LP-INJ-002"}, EVAL: {"LP-INJ-002"}, FILE: {"LP-INJ-009"}, SSRF: {"LP-INJ-005"}, REDIRECT: {"LP-INJ-004"},
        HTML: {"LP-INJ-001", "LP-INJ-007"}, TEMPLATE: {"LP-INJ-012"}}

BUGS = [
    # ---------- SQL ----------
    (SQL, "a.js", "const { id } = req.params;\nconst sql = `SELECT * FROM users WHERE id = ${id}`;\nawait db.query(sql);\n"),
    (SQL, "a.js", 'const name = req.query.name;\nconst q = "SELECT * FROM users WHERE name = \'" + name + "\'";\nawait pool.query(q);\n'),
    (SQL, "a.js", "const sql = `SELECT * FROM users WHERE id = ${req.params.id}`;\nawait db.query(sql);\n"),
    (SQL, "a.js", "const { id } = req.params;\nconst sql = `\n  SELECT *\n  FROM users\n  WHERE id = ${id}\n`;\nconst rows = await db.query(sql);\n"),
    (SQL, "a.ts", "const id: string = req.params.id;\nconst sql: string = `SELECT * FROM users WHERE id = ${id}`;\nawait db.query(sql);\n"),
    (SQL, "a.js", 'const name = req.query.name;\nlet q = "SELECT * FROM users WHERE 1=1";\nif (name) {\n  q += " AND name = \'" + name + "\'";\n}\nawait db.query(q);\n'),
    (SQL, "a.js", 'const id = req.params.id;\nconst q = "SELECT * FROM t WHERE id = " +\n  id;\nawait db\n  .query(q);\n'),
    (SQL, "a.ts", 'import { NextRequest } from "next/server";\nexport async function GET(request: NextRequest) {\n  const { searchParams } = new URL(request.url);\n  const q = searchParams.get("q");\n  const sql = `SELECT * FROM t WHERE q = \'${q}\'`;\n  return Response.json(await db.query(sql));\n}\n'),
    (SQL, "app/api/x/[id]/route.ts", "export async function GET(req, { params }) {\n  const { id } = await params;\n  const sql = `SELECT * FROM t WHERE id = ${id}`;\n  return Response.json(await db.query(sql));\n}\n"),
    (SQL, "a.ts", 'const id = c.req.param("id");\nconst sql = `SELECT * FROM t WHERE id = ${id}`;\nawait c.env.DB.prepare(sql).all();\n'),
    (SQL, "a.ts", "export const r = t.router({\n  get: publicProcedure.input(z.string()).query(async ({ input }) => {\n    const id = input.id;\n    const sql = `SELECT * FROM t WHERE id = ${id}`;\n    return db.execute(sql);\n  }),\n});\n"),
    (SQL, "convex/a.ts", "export const x = query({\n  handler: async (ctx, args) => {\n    const name = args.name;\n    const sql = `SELECT * FROM t WHERE n = ${name}`;\n    return db.query(sql);\n  },\n});\n"),
    (SQL, "a.py", 'user_id = request.args.get("id")\nquery = f"SELECT * FROM users WHERE id = {user_id}"\ncursor.execute(query)\n'),
    (SQL, "a.py", 'name = request.form["name"]\nsql = "SELECT * FROM users WHERE name = \'%s\'" % name\ndb.execute(sql)\n'),
    (SQL, "a.py", 'name = request.args["n"]\nname = name.strip()\nq = "SELECT * FROM t WHERE n = \'{}\'".format(name)\ncur.execute(q)\n'),
    (SQL, "a.py", 'q = """\n    SELECT * FROM t\n    WHERE n = \'%s\'\n""" % request.args["n"]\ncur.execute(q)\n'),
    (SQL, "a.py", '@app.get("/x")\ndef x(name: str, db=Depends(get_db)):\n    q = f"SELECT * FROM t WHERE n = \'{name}\'"\n    return db.execute(q)\n'),
    (SQL, "a.py", '@router.post("/x")\nasync def x(body: ItemIn):\n    q = f"DELETE FROM t WHERE n = \'{body.name}\'"\n    await db.execute(q)\n'),
    (SQL, "a.php", '<?php\n$id = $_GET["id"];\n$sql = "SELECT * FROM users WHERE id = $id";\nmysqli_query($conn, $sql);\n'),
    (SQL, "a.php", '<?php\n$name = $request->input("name");\n$q = "SELECT * FROM t WHERE n = \'" . $name . "\'";\nDB::select($q);\n'),
    (SQL, "a.go", 'id := r.URL.Query().Get("id")\nq := "SELECT * FROM users WHERE id = " + id\nrows, _ := db.Query(q)\n'),
    (SQL, "a.go", 'id := c.Param("id")\nq := fmt.Sprintf("SELECT * FROM t WHERE id = %s", id)\ndb.Exec(q)\n'),
    (SQL, "A.java", 'String id = request.getParameter("id");\nString q = "SELECT * FROM users WHERE id = " + id;\nstmt.executeQuery(q);\n'),
    (SQL, "A.java", 'public List<User> find(@RequestParam String name) {\n    String q = "SELECT * FROM t WHERE n = \'" + name + "\'";\n    return jdbc.queryForList(q);\n}\n'),
    (SQL, "A.kt", 'val id = call.parameters["id"]\nval q = "SELECT * FROM t WHERE id = $id"\nstmt.executeQuery(q)\n'),
    (SQL, "A.cs", 'var id = Request.Query["id"];\nvar q = $"SELECT * FROM t WHERE id = {id}";\nnew SqlCommand(q, conn);\n'),
    (SQL, "a.rb", 'id = params[:id]\nq = "SELECT * FROM t WHERE id = #{id}"\nActiveRecord::Base.connection.execute(q)\n'),
    # ---------- shell ----------
    (SHELL, "a.js", "const host = req.body.host;\nconst cmd = `ping -c 1 ${host}`;\nexec(cmd);\n"),
    (SHELL, "a.js", 'const { file } = req.body;\nchild_process.execSync("convert " + file);\n'),
    (SHELL, "a.py", 'host = request.args.get("host")\ncmd = f"ping -c 1 {host}"\nos.system(cmd)\n'),
    (SHELL, "a.py", 'host = request.args.get("host")\ncmd = "ping " + host\nsubprocess.run(cmd, shell=True)\n'),
    (SHELL, "a.go", 'name := r.FormValue("n")\ncmd := exec.Command("sh", "-c", "convert "+name)\n'),
    (SHELL, "a.php", '<?php\n$host = $_POST["host"];\n$cmd = "ping " . $host;\nshell_exec($cmd);\n'),
    (SHELL, "a.rb", 'host = params[:host]\ncmd = "ping #{host}"\nsystem(cmd)\n'),
    # ---------- files ----------
    (FILE, "a.js", "const file = req.query.file;\nconst full = path.join(__dirname, 'uploads', file);\nres.sendFile(full);\n"),
    (FILE, "a.js", "const { name } = req.params;\nconst data = fs.readFileSync(`./data/${name}`);\n"),
    (FILE, "a.py", 'name = request.args.get("name")\npath = os.path.join("/data", name)\nreturn open(path).read()\n'),
    (FILE, "a.go", 'name := r.FormValue("n")\np := filepath.Join("/data", name)\nb, _ := os.ReadFile(p)\n'),
    (FILE, "a.php", '<?php\n$page = $_GET["page"];\ninclude $page . ".php";\n'),
    # ---------- connecting out ----------
    (SSRF, "a.js", "const { url } = await req.json();\nconst r = await fetch(url);\n"),
    (SSRF, "a.js", "const target = req.body.url;\nconst r = await axios.get(target);\n"),
    (SSRF, "a.js", "const u = new URL(req.query.url);\nconst r = await fetch(u);\n"),
    (SSRF, "a.js", "const host = req.query.host;\nconst r = await fetch(`https://${host}/status`);\n"),
    (SSRF, "a.py", 'target = request.json["url"]\nresp = requests.get(target)\n'),
    (SSRF, "a.go", 'target := r.FormValue("url")\nresp, _ := http.Get(target)\n'),
    # ---------- redirects ----------
    (REDIRECT, "a.js", "const next = req.query.next;\nres.redirect(next);\n"),
    (REDIRECT, "a.js", 'const next = req.query.next || "/";\nres.redirect(302, next);\n'),
    (REDIRECT, "a.ts", 'const next = searchParams.get("next");\nreturn NextResponse.redirect(next);\n'),
    (REDIRECT, "a.ts", 'const next = c.req.query("next");\nreturn c.redirect(next);\n'),
    (REDIRECT, "a.py", 'next_url = request.args.get("next")\nreturn redirect(next_url)\n'),
    (REDIRECT, "a.php", '<?php\n$next = $_GET["next"];\nheader("Location: $next");\n'),
    (REDIRECT, "a.go", 'next := r.FormValue("next")\nhttp.Redirect(w, r, next, 302)\n'),
    (REDIRECT, "a.rb", "target = params[:next]\nredirect_to target\n"),
    (REDIRECT, "components/a.js", 'const next = new URLSearchParams(location.search).get("next");\nwindow.location.href = next;\n'),
    # ---------- code, pages, templates ----------
    (EVAL, "a.js", "const code = req.body.code;\nconst run = code.trim();\neval(run);\n"),
    (EVAL, "a.py", 'code = request.json["code"]\nexec(code)\n'),
    (EVAL, "a.js", "const code = req.body.code;\nconst r = vm.runInNewContext(code);\n"),
    (EVAL, "a.rb", "action = params[:action]\nresult = order.public_send(action)\n"),
    (HTML, "a.js", 'const name = req.query.name;\nconst page = "<h1>" + name + "</h1>";\nres.send(page);\n'),
    (HTML, "a.py", 'name = request.args.get("name")\nreturn f"<h1>Hello {name}</h1>"\n'),
    (HTML, "a.php", '<?php\n$name = $_GET["name"];\necho "<h1>$name</h1>";\n'),
    (HTML, "a.go", 'name := r.FormValue("n")\nfmt.Fprintf(w, "<h1>%s</h1>", name)\n'),
    (HTML, "components/a.js", 'const q = new URLSearchParams(location.search).get("q");\nel.innerHTML = q;\n'),
    (TEMPLATE, "a.py", 'text = request.args.get("t")\nreturn render_template_string(text)\n'),
    (TEMPLATE, "a.js", "const t = req.body.template;\nconst html = ejs.render(t);\n"),
]

SAFE = [
    # ---------- SQL done properly ----------
    ("a.js", 'const { id } = req.params;\nconst sql = "SELECT * FROM users WHERE id = $1";\nawait db.query(sql, [id]);\n'),
    ("a.js", 'const name = req.body.name;\nawait db.query("INSERT INTO t (n) VALUES ($1)", [name]);\n'),
    ("a.js", "const id = parseInt(req.params.id, 10);\nconst sql = `SELECT * FROM users WHERE id = ${id}`;\nawait db.query(sql);\n"),
    ("a.js", "const limit = Math.min(Number(req.query.limit), 100);\nconst sql = `SELECT * FROM t LIMIT ${limit}`;\nawait db.query(sql);\n"),
    ("a.js", 'const sort = req.query.sort === "asc" ? "ASC" : "DESC";\nconst sql = `SELECT * FROM t ORDER BY x ${sort}`;\nawait db.query(sql);\n'),
    ("a.js", 'const table = "users";\nconst sql = `SELECT * FROM ${table}`;\nawait db.query(sql);\n'),
    ("a.js", "const name = req.query.name;\nconst sql = `SELECT * FROM users WHERE id = ${userId}`;\nawait db.query(sql);\n"),
    ("a.js", 'const name = req.query.name;\nconst sql = "SELECT name FROM users";\nawait db.query(sql);\n'),  # the word, not the variable
    ("a.js", "const name = req.body.name;\nconst user = await db.user.findUnique({ where: { name } });\nres.json(user);\n"),
    ("a.js", "const { id } = req.params;\nconst user = await db.query(sql, [id]);\nres.redirect(user.homepage);\n"),  # a row isn't the request
    ("a.ts", 'const id = req.params.id;\nconst row = await db.get(id);\nconst sql = `SELECT * FROM t WHERE id = ${row.id}`;\nawait db.query(sql);\n'),
    ("a.py", 'user_id = request.args.get("id")\ncursor.execute("SELECT * FROM users WHERE id = %s", (user_id,))\n'),
    ("a.py", 'name = request.args.get("n")\nstmt = select(User).where(User.name == name)\ndb.execute(stmt)\n'),
    ("a.py", 'name = request.args.get("n")\ndb.execute(select(User).filter_by(name=name))\n'),
    ("a.py", '@app.get("/x")\ndef x(item_id: int, db=Depends(get_db)):\n    q = f"SELECT * FROM t WHERE id = {item_id}"\n    return db.execute(q)\n'),  # FastAPI checks it's a number
    ("a.py", '@app.get("/x")\ndef x(user=Depends(get_user), db=Depends(get_db)):\n    q = f"SELECT * FROM t WHERE id = {user.id}"\n    return db.execute(q)\n'),
    ("a.py", 'def helper(name):\n    q = f"SELECT * FROM t WHERE n = \'{name}\'"\n    return db.execute(q)\n'),  # no sign this holds request data
    ("a.go", 'id := r.FormValue("id")\nrows, _ := db.Query("SELECT * FROM t WHERE id = ?", id)\n'),
    ("a.go", 'id, _ := strconv.Atoi(r.FormValue("id"))\nq := fmt.Sprintf("SELECT * FROM t WHERE id = %d", id)\ndb.Query(q)\n'),
    ("a.php", '<?php\n$id = $_GET["id"];\n$stmt = $pdo->prepare("SELECT * FROM t WHERE id = ?");\n$stmt->execute([$id]);\n'),
    ("a.php", '<?php\n$id = intval($_GET["id"]);\n$sql = "SELECT * FROM t WHERE id = $id";\nmysqli_query($conn, $sql);\n'),
    ("a.php", "<?php\n$id = $_GET['id'];\n$sql = 'SELECT * FROM t WHERE id = $id';\nmysqli_query($conn, $sql);\n"),  # single quotes don't interpolate
    ("A.java", 'String id = request.getParameter("id");\nPreparedStatement p = conn.prepareStatement("SELECT * FROM t WHERE id = ?");\np.setString(1, id);\n'),
    ("A.java", 'public User find(@PathVariable Long id) {\n    String q = "SELECT * FROM t WHERE id = " + id;\n    return jdbc.queryForObject(q);\n}\n'),
    ("a.rb", 'id = params[:id]\nUser.where("id = ?", id)\n'),
    ("a.rb", "id = params[:id].to_i\nq = \"SELECT * FROM t WHERE id = #{id}\"\nconn.execute(q)\n"),
    # ---------- commands ----------
    ("a.py", 'host = request.args.get("host")\nsubprocess.run(["ping", "-c", "1", host])\n'),
    ("a.py", 'host = shlex.quote(request.args.get("host"))\nos.system(f"ping {host}")\n'),
    ("a.js", "const cmd = `ls -la`;\nexec(cmd);\n"),
    ("a.js", 'const name = req.body.name;\nexecFile("convert", [name]);\n'),
    ("a.js", "const name = req.body.name;\nconst m = /x/.exec(name);\n"),  # a regular expression
    ("a.js", "const name = req.body.name;\nconst u = await User.find({ name }).exec();\n"),  # Mongoose
    ("a.go", 'name := r.FormValue("n")\ncmd := exec.Command("convert", name)\n'),
    ("A.cs", 'var name = Request.Query["n"];\nProcess.Start("notepad.exe", name);\n'),
    # ---------- files ----------
    ("a.js", "const file = path.basename(req.query.file);\nres.sendFile(path.join(root, file));\n"),
    ("a.js", "const file = req.query.file;\nif (!ALLOWED.includes(file)) return res.sendStatus(400);\nres.sendFile(file, { root });\n"),
    ("a.js", "const name = req.params.name;\nconst full = path.resolve(base, name);\nif (!full.startsWith(base)) return res.sendStatus(400);\nres.sendFile(full);\n"),
    ("a.py", 'name = secure_filename(request.args.get("name"))\nreturn open(os.path.join("/data", name)).read()\n'),
    ("a.py", 'name = request.args.get("name")\nif name not in ALLOWED:\n    abort(400)\nreturn open(name).read()\n'),
    ("a.js", 'const body = req.body;\nconst data = fs.readFileSync("config.json");\n'),
    ("a.js", "const file = req.file;\nawait fs.promises.unlink(file.path);\n"),  # multer chose that path
    # ---------- connecting out ----------
    ("a.js", 'const { url } = await req.json();\nif (!ALLOWED_HOSTS.has(new URL(url).host)) throw new Error("no");\nconst r = await fetch(url);\n'),
    ("a.js", "const url = process.env.API_URL;\nconst r = await fetch(url);\n"),
    ("a.js", 'const { url } = req.body;\nconst r = await fetch("https://api.example.invalid/scan", { method: "POST", body: JSON.stringify({ url }) });\n'),
    ("a.js", "const { id } = req.params;\nconst r = await fetch(`https://api.example.invalid/items/${id}`);\n"),  # can't change the host
    ("a.js", "const { id } = req.params;\nconst r = await fetch(`${API_BASE}/items/${id}`);\n"),
    ("a.js", "const { id } = req.params;\nconst u = `https://api.example.invalid/items/${id}`;\nconst r = await fetch(u);\n"),
    ("a.py", 'item = request.args.get("id")\nresp = requests.get(f"https://api.example.invalid/items/{item}")\n'),
    ("a.go", 'id := r.FormValue("id")\nresp, _ := http.Get("https://api.example.invalid/items/" + id)\n'),
    ("components/a.jsx", 'const q = searchParams.get("q");\nconst r = await fetch(q);\n'),  # a browser fetching isn't your server fetching
    ('b.tsx', '"use client";\nconst q = searchParams.get("q");\nconst r = await fetch(q);\n'),
    # ---------- redirects ----------
    ("a.js", 'const next = req.query.next;\nif (!next.startsWith("/")) return res.status(400).end();\nres.redirect(next);\n'),
    ("a.js", "const next = req.query.next;\nres.redirect(`/login?next=${encodeURIComponent(next)}`);\n"),
    ("a.js", 'const page = req.query.page;\nres.redirect("/items?page=" + page);\n'),
    ("a.ts", 'const { searchParams, origin } = new URL(request.url);\nconst code = searchParams.get("code");\nreturn NextResponse.redirect(`${origin}/dashboard`);\n'),
    ("a.py", 'return redirect("/home")\n'),
    ("a.py", 'next_url = request.args.get("next")\nif not url_has_allowed_host_and_scheme(next_url, allowed_hosts=None):\n    next_url = "/"\nreturn redirect(next_url)\n'),
    # ---------- pages ----------
    ("a.js", 'const { email } = req.body;\nconst page = "<p>Thanks</p>";\nres.send(page);\n'),
    ("a.js", 'const name = req.query.name;\nres.send("<h1>" + escapeHtml(name) + "</h1>");\n'),
    ("a.js", "const body = req.body;\nres.send(body);\n"),  # an object goes out as JSON
    ("a.py", 'name = request.args.get("name")\nreturn render_template("a.html", name=name)\n'),
    ("a.py", 'name = request.args.get("name")\nreturn jsonify({"name": name})\n'),
    ("a.py", 'name = request.args.get("name")\nreturn {"html": "<b>hello</b>", "name": name}\n'),
    ("a.go", 'name := r.FormValue("n")\nfmt.Fprintf(w, "hello %s", name)\n'),
    ("components/a.js", 'const q = new URLSearchParams(location.search).get("q");\nel.innerHTML = DOMPurify.sanitize(q);\n'),
    ("components/a.js", 'const q = new URLSearchParams(location.search).get("q");\nel.textContent = q;\n'),
    # ---------- scope and clearing ----------
    ("a.js", 'function a(req) {\n  const url = req.body.url;\n  return url.length;\n}\nfunction b() {\n  const url = "https://example.invalid";\n  return fetch(url);\n}\n'),
    ("a.js", 'app.get("/a", (req, res) => {\n  const url = req.query.url;\n  res.json({ url });\n});\napp.get("/b", (req, res) => {\n  const r = fetch(url);\n});\n'),
    ("a.js", 'let url = req.query.url;\nurl = "https://example.invalid/";\nconst r = await fetch(url);\n'),
    ("a.py", 'def a():\n    url = request.args["u"]\n    return url\n\ndef b(url):\n    return requests.get(url)\n'),
    # ---------- things that only look like it ----------
    ("a.js", '// const sql = `SELECT ${req.params.id}`; db.query(sql);\nconst x = 1;\n'),
    ("a.py", '# q = f"SELECT {request.args}"\n# cursor.execute(q)\nx = 1\n'),
    ("a.js", 'const help = "use req.body to read it, then db.query(sql)";\nconst sql = help;\nawait db.query(sql);\n'),
    ("a.js", "const uuidCheck = isUUID(req.params.id);\nres.json({ uuidCheck });\n"),
]


def findings(name: str, code: str) -> set[str]:
    with tempfile.TemporaryDirectory(prefix="ladpock-flow-") as tmp:
        root = Path(tmp)
        path = root / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(code, encoding="utf-8")
        index = FileIndex(root)
        found, errors = run_all(ScanContext(root=root, index=index, stack=set(detect(index))))
        assert errors == [], errors
        return {f.check_id for f in found}


class Flows(unittest.TestCase):
    def test_finds_bugs_spread_over_several_lines(self):
        for check_id, name, code in BUGS:
            with self.subTest(name=name, code=code):
                ids = findings(name, code)
                self.assertTrue(check_id in ids or ALSO[check_id] & ids, f"expected {check_id}, got {sorted(i for i in ids if i.startswith(('LP-INJ', 'LP-FLOW')))}")

    def test_leaves_safe_code_alone(self):
        for name, code in SAFE:
            with self.subTest(name=name, code=code):
                self.assertEqual(sorted(findings(name, code) & ANY_FLOW), [])

    def test_says_where_the_value_came_from(self):
        with tempfile.TemporaryDirectory(prefix="ladpock-flow-") as tmp:
            root = Path(tmp)
            (root / "a.js").write_text("const { id } = req.params;\n\nconst sql = `SELECT * FROM t WHERE id = ${id}`;\nawait db.query(sql);\n", encoding="utf-8")
            index = FileIndex(root)
            found, _ = run_all(ScanContext(root=root, index=index, stack=set()))
            flow = next(f for f in found if f.check_id == SQL)
            self.assertEqual(flow.line, 4)  # the call, where the fix usually goes
            self.assertIn("line 3", flow.message)
            self.assertIn("line 1", flow.message)
            self.assertIn("sql", flow.message)

    def test_thousands_of_variables_dont_slow_a_scan_down(self):
        import time

        from ladpock.checks.flows import _file_flows

        text = "\n".join(f"const v{i} = req.body.x{i};\nconst u{i} = v{i} + v{max(0, i - 1)};" for i in range(9_000))[:390_000]
        started = time.monotonic()
        _file_flows("big.js", text, "js")  # directly: through a project, the size of the file on disk could skip it
        self.assertLess(time.monotonic() - started, 60)

    def test_a_line_another_check_reports_is_only_reported_once(self):
        ids = findings("a.py", 'name = request.json["name"]\nsubprocess.run(f"convert {name}", shell=True)\n')
        self.assertIn("LP-INJ-002", ids)
        self.assertNotIn(SHELL, ids)


if __name__ == "__main__":
    unittest.main()
