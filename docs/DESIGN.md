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
weights, floored at 0. Overall = the average of the category scores, capped while a critical (F) or high (C+)
finding of medium or high confidence is open, so a leaked key can't hide behind a tidy codebase.

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

## Next milestones

1. **Local dashboard.** A localhost-only web UI over the same engine. Hardening required: bind to 127.0.0.1,
   check the `Host` header (DNS rebinding), use a random per-launch token, no CORS.
2. **Local AI review (overnight).** Ollama or any OpenAI-compatible local endpoint. A resumable job queue in SQLite,
   incremental by file hash, scheduled with the OS (Task Scheduler on Windows), only when plugged in. Local findings
   are "leads" that must quote real lines (grounding check) and can never suppress a finding.
3. **External AI review (optional, your own key).** Separate toggle, budget cap, and a per-project "never send"
   switch. Secrets are redacted before sending. Can be used only to escalate local leads.
4. **More packs.** Express/Fastify, FastAPI/Django, SvelteKit, Remix. Each one adds a route parser, rules and fixtures.
5. **Scanner installer.** Downloads pinned versions by SHA-256 with a cooldown before adopting new releases.
6. **Live probes.** Localhost by default, ownership-verified otherwise. Headers, CORS, exposed paths, a small rate-limit burst.
