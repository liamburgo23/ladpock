# LadPock design

How LadPock is built and why. Written for contributors and for whoever picks up the next milestone.

## Goal

Let people who build software with AI assistants catch the security mistakes a senior developer would catch,
for free, on their own machine. LadPock is a personal tool. It isn't a service for scanning other people's software.

## Principles

1. **Deterministic first, AI last.** Pattern checks, parsers and vulnerability databases do the bulk of the work
   cheaply and repeatably. AI review (planned) only looks at what they flag or can't decide.
2. **Local-first and private.** No account, no telemetry, no code leaves the machine.
3. **Honest about coverage.** Every report says which stacks got deep checks, how confident each finding is, and
   what a human still has to check.
4. **Safe to point at untrusted code.** See [SECURITY.md](../SECURITY.md).
5. **Zero runtime dependencies.** Standard library only, so installing a security tool doesn't add supply-chain risk.

## Pipeline

```text
index files (no symlinks, size caps)
  -> detect stack (package.json, pyproject, supabase/, next.config, workflows ...)
  -> built-in checks (regex rules + structural checks + route matrix)
  -> optional scanners (gitleaks, osv-scanner, opengrep), merged and de-duplicated
  -> dependency inventory from lockfiles (stored per project)
  -> refresh feeds: CISA KEV (conditional GET), OSV live query, EPSS for matched CVEs
  -> registry existence check for declared packages (slopsquatting)
  -> suppressions, scoring, store scan, report
```

## Key modules

| Module | Role |
|---|---|
| `files.py` | One pass over the project, cached reads, test and AI-instruction file detection |
| `checks/` | The check catalog. `base.py` holds the framework (`@check`, `regex_check`, `ScanContext`) |
| `routes.py`, `server_routes.py`, `fullstack_routes.py`, `backend_routes.py` | Route matrix: auth, ownership, validation, rate limit, paid-API use per handler, across frameworks |
| `inventory.py` | Lockfile parsers: npm, yarn, pnpm, bun, pip, poetry, uv, Pipfile, Cargo, Composer, Gemfile, go.mod |
| `feeds/` | OSV, CISA KEV, EPSS, npm/PyPI existence. HTTPS only, size-capped |
| `advisories.py` | Matching, severity (GHSA label, then CVSS v3), fixed versions, "new since" logic |
| `scoring.py` | Category and overall grades. An open critical caps the grade at F, an open high at C+ |
| `masking.py` | Secret patterns and redaction used by every output path |
| `db.py` | SQLite: projects, scans, findings, inventories, advisories, feed state, suppressions |

## "New vulnerabilities in projects you've already scanned"

Each scan stores the project's dependency inventory. `ladpock` (status) re-reads every registered project's
lockfiles, which is fast and runs no code, then queries OSV live. A match whose `first_seen` is after the last
time you opened LadPock is new. An existing match whose CVE was added to CISA KEV since then is also flagged,
because "now actively exploited" is news even if the advisory isn't.

Limits: this covers dependency vulnerabilities only. New *code* checks need a rescan. Databases lag disclosure,
and zero-days aren't in any database.

## Scoring

Weights: critical 40, high 20, medium 8, low 2, halved for low-confidence findings. Category score = 100 minus
weights, floored at 0. Since 0.5.0 it's also floored by the worst severity in the category: 70 (C-) if the worst is
medium, 83 (B) if it's low. A pile of small issues can't fail a category; only critical or high findings can.
Overall = the average of the category scores, limited by the worst finding still open: 59 (F) for critical, 79 (C+)
for high, 89 (B+) for medium, 96 (A) for low. A low-confidence finding limits it one step less (79, 89, 92, 96),
because it may not be real. Averaging over ten categories would otherwise let one real problem barely move the total:
before 0.11.0, one high and one medium could still read as A+. A category with anything open tops out at 96 for the
same reason, so A+ always means nothing is open.

Findings can be hidden with `ladpock suppress` (expiring, with a recorded reason) or a `ladpock-ignore` comment
(optionally `ladpock-ignore: LP-XXX-000`). Hidden findings are always counted in the report, because an AI
assistant "fixing" a finding by adding an ignore comment is exactly the kind of thing LadPock exists to catch.

## Decisions made

- **Python standard library** rather than TypeScript: zero dependencies and an easy `pipx` install.
- **Opengrep with our own rules**, not Semgrep registry rules (their licence restricts redistribution).
- **Optional scanners aren't auto-updated.** Vulnerability *data* refreshes every run; scanner *programs* change
  only deliberately. Tags can be rewritten: the Trivy GitHub Action tags were hijacked in March 2026.
- **Fixtures use placeholders for secrets**, generated at test time, so the repo never contains secret-looking strings.
- **Route analysis is heuristic** and reports `?`/`no` as "go and look", with confidence on each finding.

## Dashboard (built in 0.2.0)

`ladpock ui` runs `ui/server.py`: a standard-library `ThreadingHTTPServer` on 127.0.0.1 serving a single-page app
from `ui/static/` (plain HTML, CSS and JS, no build step) and a JSON API. Scans run in a background thread, and the
page polls `/api/jobs/<id>` for progress. Each request opens its own SQLite connection, and the database uses WAL
mode so the page can read while a scan writes. The security rules are listed in [SECURITY.md](../SECURITY.md) and
tested in `tests/test_ui.py`.

## Tauri pack (built in 0.3.0)

`tauri.py` reads `tauri.conf.json` / `Tauri.toml` (v2 `app.security`, `plugins.updater`; v1 `tauri.allowlist`,
`tauri.security`, `tauri.updater`) and capability files under `capabilities/`. The command matrix finds every
`#[tauri::command]`, drops parameters Tauri injects (`AppHandle`, `State`, `Window`, ...), and follows calls into
helpers in the same file one level deep. It then classifies file access (read/write), path checking
(`dir` = starts_with/strip_prefix against a folder, `ext` = extension only, `none`), process spawning and network
use. Commands missing from `generate_handler!` are marked unregistered. Rust code is scanned with a quote set
that ignores `'`, so lifetimes don't confuse bracket matching.

## Local AI review (built in 0.4.0)

`ai/` holds it. `client.py` talks to Ollama on loopback only (`LADPOCK_OLLAMA_URL` can move the port, not the
host), uses JSON-schema structured output and temperature 0, and sends `think` only to models that support it.

`units.py` splits a project into review units, in priority order:
1. Next.js routes (plus the file's first 25 lines for imports) and registered Tauri commands (plus same-file
   helpers), each with the static facts
2. medium-and-above scanner findings, which get a real / false-alarm / unsure verdict
3. remaining source in 160-line chunks, hot paths first

Every line is redacted and keeps its real line number. `grounding.py` keeps a lead only if its quote matches a line
the model was shown, and pins it to the nearest matching line. `review.py` skips units whose
(content hash, model, prompt version) were already reviewed, saves progress after each unit, and stops cleanly on
a deadline, a stop request, battery or Ctrl+C. It prunes units for code that no longer exists.

Leads are keyed by a fingerprint of category plus quote, so a dismissed lead stays dismissed when the code around
it changes. `system.py` covers Windows power state, keep-awake, below-normal priority, and the Task Scheduler XML:
InteractiveToken, LeastPrivilege, no start on battery, stop on battery, 12-hour limit, optional WakeToRun.

## Scanner installer (built in 0.6.0)

`scanners/pins.json` holds, per tool and platform (windows/linux/darwin × x64/arm64), the release file name, exact
size, SHA-256 and archive layout. The hashes are GitHub's recorded asset digests, cross-checked against the API when
pinned. `scanners/install.py` downloads with an HTTPS-only redirect handler, streams into a temp folder while
hashing, and enforces the exact size and hash. It extracts only the named member (by basename; archive paths are
ignored), and atomically replaces `<data dir>/bin/<tool>`. `scanners.base.which` already prefers that folder.
To update a pin, change pins.json in a reviewed commit after the release has aged two weeks.

## Scan options, grade explanations and the paid online AI review (0.7.0)

**One pipeline, every option a toggle.** `POST /api/projects/{id}/run` takes `{profile, online, scanners, history,
local_ai, online_ai}`. `run_options` validates them and refuses an online AI review on an offline scan. `run_project`
runs the scan, then the local review, then the online review, each as its own job step. `/scan`, `/full-check` and
check-all are thin mappings onto the same path. Each scan's summary records the options it ran with, so the grade
page can tell "scanners weren't installed" apart from "you turned them off".

**Why this grade.** `scoring.explain` returns:
- each category's deductions (points per finding, with the low-confidence halving) and whether the severity floor
  applied
- whether a critical or high finding is capping the overall score, and by how much
- a fix plan: the score and grade after fixing each severity level in turn, worst first

`assessment_payload` adds the gaps in the assessment itself: profile, offline data, missing or disabled scanners,
generic-only stacks, no lockfile, no AI review, and unconfirmed manual checks. The page links every grade to it
(`#/project/{id}/grade[/{category}]`), and each fix-plan step copies a fix prompt for exactly those findings.

**Paid online AI (`ai/online.py`).**
- **SDK and model:** the official `anthropic` SDK, an optional extra so the core stays dependency-free, with
  `claude-opus-5-5`.
- **Request:** streams each request and asks for structured JSON output. `strict_schema` closes objects and drops the
  array limits that structured outputs don't take. `fallbacks: "default"` under `server-side-fallback-2026-07-01`
  lets a declined request be retried on Anthropic's recommended model.
- **Responses:** a refusal is recorded and that part isn't re-sent until its code changes. `max_tokens` and other
  errors are reported. A bad key, an empty account or a connection failure stops the run.
- **Reuse of the local review:**
  - Units, prompts and grounding are shared with the local review.
  - Online reviews are cached in `ai_units` as `online:<unit key>`, so `ai_prune` keeps them while the unit exists.
  - Local leads get an `online_verdict` from the same check prompt.
- **Costs:** every call's usage is priced and stored in `online_usage`. Before each call, the run estimates its cost
  and stops if the month's spend plus the estimate would pass the budget.
- **Key (`ai/keys.py`):** stored in Windows Credential Manager through ctypes. Elsewhere, or if you prefer, the SDK's
  own resolution is used (`ANTHROPIC_API_KEY` or an `ant auth login` profile).

## Wider coverage (0.8.0)

**Route matrix for server frameworks (`server_routes.py`).** Each endpoint becomes the same `Route` record as a
Next.js handler, so the access-control and abuse checks need no per-framework copies.
- **Express, Fastify, Hono and Koa:** reads `x.get('/path', ...middleware, handler)`, `.route('/x').get().post()`
  chains and Fastify `route({...})` objects. Handlers passed by name are followed to their definition. `app.use` and
  `router.use` middleware apply to the routes after them, with path prefixes, but mounted routers aren't counted as
  auth.
- **NestJS:** reads `@Controller` prefixes and method decorators. Guards above or below `@Controller` count, as do
  `@Public()`, global `APP_GUARD`, and typed `@Body()` DTOs with a global `ValidationPipe`.
- **FastAPI, Flask and Django:** decorators, `Depends(...)` and router `dependencies`, `APIRouter` and blueprint
  prefixes, Flask-Limiter. For Django: function views, class-based views, DRF viewsets registered with a router,
  `urls.py` paths and DRF's default permission classes.
- Datastore calls are recognised by their receiver (capitalised models, `db`, `prisma`, repositories, raw SQL), so
  `openai.chat.completions.create()` isn't mistaken for a database write.

**Check modules.** Each new pack has a vulnerable fixture that every check must fire on and a clean twin that must
stay silent.
- `checks/web.py`: one check per mistake, with a pattern per language (deserialisation, raw HTML in templates,
  template injection, XXE, path traversal, NoSQL injection, prototype pollution, mass assignment, CSRF and more).
- `checks/infra.py`: Dockerfiles, Compose, Kubernetes, Terraform and GitHub Actions. Firewall rules are judged by
  their enclosing block, so egress and HTTPS-only rules are left alone.
- `checks/apps.py`: Electron, Android, iOS, React Native and Flutter.
- `checks/languages.py`: Spring, Rails, PHP, ASP.NET and Go framework settings.

The existing SQL-injection, command-injection, CORS, randomness, hashing and TLS checks gained each language's
spelling instead of separate per-language IDs, so a finding means the same thing whatever the stack.

**Secrets.** `masking.SECRET_PATTERNS` covers more than 50 provider formats, and env-style assignments
(`ENV X=...`, `export X=...`) are masked too. Format tests build their samples at runtime from a fixed seed, so no
realistic token is committed.

## Proving it and fitting the workflow (0.9.0)

**Live checks (`probe.py`).** The route matrix is static analysis. `run_probe` asks the running app the same
questions.
- **Requests:** calls each matrix route without credentials. Dynamic segments get placeholder values. GET only unless
  writes are opted into.
- **Reporting:** a route that answers 2xx with a non-HTML body is reported against the route's file and line. The
  message says when the code appeared to check the user, because that means a mismatch between code and behaviour.
- **Other checks:** the home page's headers, CORS and banner; known sensitive paths, judged by content so SPA
  fallbacks don't count; a 20-request failed-login burst; and stack-trace markers in any response.
- **Safety:** targets are resolved and must be loopback, and proxy settings are ignored.
- **Grade:** live findings join the scan and the grade with `source = "live"`.

**Change tracking.** `compare_with_previous` diffs a scan's finding refs against the previous scan. It stores new
refs, fixed findings (compact), the previous grade, and whether the profile matched in the summary. The CLI,
dashboard and MCP tool all read it from there.

**MCP server (`integrations.py`).** Newline-delimited JSON-RPC 2.0 over stdio: `initialize` (negotiating
2024-11-05 to 2025-06-18), `tools/list`, `tools/call` and `ping`. The tools wrap `run_scan`, the stored findings, the
route matrix, `scoring.explain` and `report.fix_prompt`. Scan progress is never written to stdout, which carries the
protocol.

**Pre-commit hook.**
- **What it scans:** `precommit` limits a `FileIndex` to the staged files and runs only the file-local secret
  checks (plus hidden Unicode). It blocks on high or critical findings.
- **The hook script:** calls the same Python interpreter with LadPock's source path, so it also works from a
  source checkout.
- **Other hook managers:** `core.hooksPath` (husky and similar) is detected and left alone.

**More ecosystems.** NuGet, Maven/Gradle (including version catalogs), pub, SwiftPM and Hex parsers feed the same OSV
lookup. XML manifests are read with regular expressions rather than an XML parser.

## Packaging and releases (0.10.0)

LadPock ships as a pure-Python wheel with one console script. `scripts/check_package.py` installs a built wheel
into a fresh virtual environment with `PYTHONPATH` cleared. It then runs `--version`, `checks`, a scan that must
find a planted key without printing it, an MCP handshake, and checks for the dashboard files, rules and scanner
pins. CI runs it on Linux and Windows for every push.

Releasing takes three deliberate steps:
1. **Tag.** Bump the version in `pyproject.toml` and `__init__.py`, add a CHANGELOG section, then push a `vX.Y.Z`
   tag.
2. **Draft.** `release.yml` checks that the tag, version and changelog agree, runs the tests, builds with pinned
   `build` and `setuptools`, runs the package check, and creates a *draft* GitHub release with the built files and
   that version's changelog notes.
3. **Publish.** Publishing the draft triggers `publish.yml`. It uploads those exact files to PyPI with trusted
   publishing (no stored token), but only when the repository variable `PUBLISH_TO_PYPI` is `true` and the `pypi`
   environment allows it.

`ladpock shortcut` writes a launcher that runs `ladpock ui` in a terminal: a Windows `.lnk` (through PowerShell's
WScript.Shell), a macOS `.command` or a Linux `.desktop` entry.

## More route tables and the two-account check (0.11.0)

**Route tables.** `fullstack_routes.py` (SvelteKit, Remix, Nuxt, Astro) and `backend_routes.py` (Spring, Go, Rails,
Laravel, ASP.NET) produce the same `Route` record, so every access-control and abuse check applies to them without
change. `backend_routes.Patterns` holds each framework's spelling of auth, validation and rate limiting.

**Two-account check (`probe._TwoAccounts`).** The route matrix can suspect a missing ownership check; this proves it.
Given session headers for two accounts, it:
1. **Reads lists.** Every GET route without a dynamic segment is requested as A and as B. Record IDs come from JSON
   records, or from links in a server-rendered list. The field follows the route's parameter name, then `ID_FIELDS`.
2. **Decides what's private.** An ID in A's list and not B's is A's. An ID in both means shared data, so it's skipped
   and counted. Under a parent only A has, every child is A's, even if B can list them, because that's the bug.
   `/api/me`-style answers give A's own user ID for routes like `/api/users/[id]`.
3. **Opens the record.** As A (it must answer), with no login (if that also answers it isn't private, and LP-LIVE-001
   covers it), then as B.
4. **Decides it's a leak.** JSON: B's body equals A's, or its ID field is the record's ID. Substring matching isn't used,
   because a small numeric ID appears in almost any body. Pages: the words a person reads must be 90% alike, ignoring
   scripts, meta tags and hidden inputs, with no refusal wording. These are medium confidence.
5. **Rules out answers that aren't records.** Before reporting, it asks for a made-up ID. An answer that doesn't change
   isn't holding a record.

Refusals are recognised beyond status codes: `_answered` treats an empty JSON value, a `200 {"error": ...}` and a page
with a password field as no answer, because these are common in generated code. The check has its own request
allowance, so a large route table can't use it up first, and a note appears if any limit stops a scan early.

Only B's reads of A's records are tried, so an account with a higher role in position A doesn't produce false reports.
The check doesn't try writes: a real ID is a real record, and the rule in SECURITY.md is that placeholder IDs are the
only ones ever written to.

## Function backends, modern mistakes and sharing results (0.12.0)

**Function backends (`function_routes.py`).** Generated apps often have no server to read: the whole backend is tRPC, Convex,
GraphQL resolvers or serverless functions. Each becomes a `Route`, so the existing checks apply.
- **What counts as a login check** differs per platform: a tRPC procedure's name (`protectedProcedure`) or `ctx.session`,
  Convex's `ctx.auth`, `context.auth` in Firebase, an API Gateway authorizer (recorded as `mw`, since it runs outside the code).
- **Supabase Edge Functions:** the platform's JWT check accepts the public anon key, so it isn't a user check. Passing the
  caller's token to the client is, so those functions are `rls`. Using the service role key means owner `no`.
- **Not callable from outside:** Convex `internal*` functions and Vercel `_helpers` aren't routes.
- **Paths without a leading slash** (`convex/orders:list`, `graphql/Query.user`) are skipped by the live checks.

**Test paths.** `app/api/test/route.ts` was invisible, because any folder called `test` counted as test code. File-based
routes under such a folder now count, unless a test folder sits above the route tree (`tests/fixtures/...`).

**More checks (`checks/modern.py`).** Patterns that a senior reviewer would catch, and that apply across languages.
`tests/test_modern_checks.py` pins each to lines it must find and similar lines it must leave alone. LP-AI-003 first
flagged LadPock's own settings endpoint: `model = body.get("model")` stores a choice and checks it's installed, so the Python
pattern now only matches keyword arguments.

**More live probes.** All GET. Reflected input needs a raw `<b>` in an HTML answer. SQL needs a syntax error (SQLSTATE class 42
and similar) for a quote but not for an ordinary value, because a type error from a parameterised query isn't injection.
Redirects are read but never followed. With two accounts these use A's login, because most data is behind one. Cookie
values are never kept, only names and attributes. Supabase's `sb-*` cookie is exempt from the HttpOnly check because its browser
client reads it by design.

**Report (`report_html.py`).** One self-contained file with no scripts. Everything is escaped, and its own
Content-Security-Policy (`default-src 'none'`) means nothing could run even if escaping failed. The folder path is left out
because reports travel.

**GitHub Action (`action.yml`).** A composite action that installs from its own checkout, so tagging a release is enough. Inputs
reach the script through the environment, never by interpolation, which is the injection LP-SUP-006 looks for. CI runs it
against this repository. Annotations carry only check titles, fixes and paths, escaped for workflow commands, never snippets.

## Code and running app agreeing, and slow input (0.13.0)

**Correlation (`probe.correlate`).** Static analysis guesses and live checks observe, so when both have looked at the same route the
live result wins. The join is on the finding's snippet, which for route checks is `METHOD /path`, the key `run_probe` records outcomes
under. Refused with no login: `LP-AUTHZ-001`, `007`, `LP-ABUSE-010`, `LP-API-003` and `004` drop to low confidence, which also relaxes
the grade limit, and say why. Answered: they become high confidence. `LP-AUTHZ-002` takes the same treatment from the two-account check.
Confidence and message aren't part of a finding's ref, so accepted risks and "fixed since last scan" still match.

Findings aren't deleted on a refusal. A 401 could come from a dev-only guard, or a login redirect could hide a bug further in, so it stays
as something to check. Only routes that were actually called change, so a DELETE beside a checked GET keeps its own result.

**Slow input.** A stress test found `trpc_routes` taking 73 seconds on one crafted file, and Spring and Convex not finishing at all: a
regex with `[\s\S]*`, and bracket matching re-run from every match to the end of the file. Three limits, in `jsparse` and `files`:
`FileIndex.sources()` (no huge or minified files), `match_bracket` stopping at `MAX_BLOCK`, and `capped()` on repeated searches.
Whole-file regexes use bounded repeats. `tests/test_slow_input.py` keeps the worst cases as a regression test.

**Supply chain.** These look at how attacks reach you now rather than at known-bad versions. MCP servers run with your credentials and
fetch their newest release on each start, so `npx -y server` with no version is a standing risk (`LP-SUP-011`). `.vscode/tasks.json`
with `runOn: folderOpen`, devcontainer commands and AI tool hooks can run code when a project is opened (`LP-SUP-012`).

## Beyond web apps, and checking against correct code (0.14.0)

**More route tables (`more_routes.py`).** Rust, Elysia, Hapi, Sinatra, Symfony, Ktor, JAX-RS and Micronaut. Each comes down to the
same three questions, with the framework's own spelling of how a route declares its login check: an Axum extractor parameter, a
`route_layer` on the router, `authenticate("jwt") { }` in Ktor, `#[IsGranted]` or `access_control` in Symfony, `@RolesAllowed` on
a class with `@PermitAll` as the exception in JAX-RS. Rocket's `<id>` is rewritten to `{id}` so the other code sees one spelling.

**Other software (`checks/native.py`).** C and C++ are now read at all (`CODE_EXT`), so secrets and generic checks apply to them too.
`LP-SHELL-003` is low confidence because `rm -rf "$DIR"` is usually fine, until `$DIR` is empty.

**Correct code as a test (`tests/fixtures/clean-starters`).** A fixture of idiomatic code in the style of the usual starter templates,
across twelve stacks. It's a stand-in until a study on real repositories: not as good, but it needs no downloads, and it runs on
every commit. It found four false positives on its first run.

## Next milestones

1. **Paid online scanners.** Optional integrations with commercial scanners using your own account, behind the same
   kind of toggle, consent and "never send" rules as the online AI review.
2. **Accuracy study.** Run against real open-source apps and publish false-positive rates per check.
3. **Notifications.** Optional desktop notification when a long task or the nightly review finishes.

## Tasks in the dashboard (0.5.0)

Every background task (scan, full check, check-all, AI review, benchmark) is a `Job` with a title, a list of steps,
the current step, a fraction within that step when known (AI parts done), and start and finish times. `run_scan`
reports its phases through a `step` callback (`SCAN_STEPS`), and `run_review` reports parts through `progress`.

The page polls `/api/jobs` every second while something runs (every 6 seconds otherwise). It drives:
- the top-bar indicator and its panel
- the project's status banner
- the run buttons (disabled while busy)
- the browser tab title
- the "finished" message
Only one task runs per project, "check all projects" runs alone, and only one task at a time uses the local model.
