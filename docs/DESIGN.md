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
| `routes.py` | Next.js route matrix: auth, ownership, validation, rate limit, paid-API use per handler |
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
Overall = the average of the category scores, capped while a critical (F) or high (C+) finding of medium or high
confidence is open, so a leaked key can't hide behind a tidy codebase.

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

## Next milestones

1. **External AI review (optional, your own key).** Separate toggle, budget cap, and a per-project "never send"
   switch. Secrets are redacted before sending. Used to escalate local leads and serious findings.
2. **More packs.** Express/Fastify, FastAPI/Django, SvelteKit, Remix, Electron. Each one adds a route parser, rules and fixtures.
3. **Live probes.** Localhost by default, ownership-verified otherwise. Headers, CORS, exposed paths, a small rate-limit burst.
4. **Notifications.** Optional desktop notification when a long task or the nightly review finishes.

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
