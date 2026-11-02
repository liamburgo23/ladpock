# LadPock

**A free, local security checker for vibe-coded projects.** (It's a padlock, slightly rearranged.)

LadPock looks for the mistakes AI-assisted code tends to make, and that a senior developer would spot in review:
admin keys shipped to the browser, API routes that never check who's calling, Supabase tables without Row Level
Security, paid AI endpoints anyone can hit, webhooks that trust any request, packages that don't exist, and more.
It runs on your machine, needs no account, and sends no code anywhere.

```text
  Overall  F   0/100    6 critical  23 high  17 medium  5 low

    Secrets                          F   4 critical  1 high  1 medium
    Authorization                    F   1 critical  6 high  1 medium  1 low
    API abuse and cost               F   1 high  3 medium
    ...

CRITICAL (6)
  LP-SEC-001  Supabase admin key exposed to the browser
    components/Dashboard.tsx:6   confidence high
    > const admin = createClient(process.env.NEXT_PUBLIC_SUPABASE_URL!, process.env.SUPABASE_SERVICE_ROLE_KEY!);
    Why: A Supabase admin key is read in a client component ('use client'). ...
    Fix: Never use the service_role or sb_secret_ key in browser code ...
```

## What it does

- **44 built-in checks** across secrets, sign-in, authorization, API abuse and cost, injection, payments,
  crypto, config, supply chain, and AI-generated code smells. Run `ladpock checks` for the list, or see
  [docs/CHECKS.md](docs/CHECKS.md).
- **A route matrix** for Next.js (App Router, Pages API and server actions). It shows every endpoint with its auth,
  ownership check, validation and rate limiting, and flags the gaps.
- **Live vulnerability data before every run.** Your dependencies are checked against [OSV.dev](https://osv.dev),
  prioritised with CISA's [Known Exploited Vulnerabilities](https://www.cisa.gov/known-exploited-vulnerabilities-catalog)
  list and [EPSS](https://www.first.org/epss/) exploit likelihood.
- **"New since you last looked."** LadPock stores each project's dependency inventory. Every time you open it, it
  re-checks all your projects against fresh data and tells you which ones are affected by newly published or
  newly exploited vulnerabilities, without rescanning the code.
- **Hallucinated package detection.** Declared npm and PyPI packages that don't exist on the registry are flagged,
  because attackers register those names.
- **A fix prompt.** `ladpock fix-prompt` turns the last scan into a paste-ready prompt for Claude Code or another
  AI assistant. Secrets in it are masked.
- **Grades, not just a list**, plus a "needs a human" checklist of things no scanner can verify.
- **CI-friendly**: JSON and SARIF output, and `--fail-on high` to fail a build.

## Install

LadPock needs Python 3.11 or newer and has no other dependencies.

```bash
pipx install git+https://github.com/liamburgo23/ladpock
```

Or from a clone:

```bash
git clone https://github.com/liamburgo23/ladpock
cd ladpock
pip install .
```

## Use

### Dashboard

```bash
ladpock ui
```

This opens LadPock in your browser. You can add projects by picking their folders, run scans with Quick, Standard
or Full profiles, and browse findings by severity with filters and search. Each finding has a copy-fix-prompt button
and an "accept risk" option that needs a reason and expires. There are also tabs for the Next.js route matrix,
vulnerable dependencies (with "actively exploited" flags), the "needs a human" checklist (LadPock remembers what
you've ticked) and scan history. Vulnerability data refreshes every time you open it, and a banner lists anything
new that affects your projects.

The dashboard only listens on `127.0.0.1`, and every request needs a private key that's in the link printed in your
terminal. It changes each time you start it. See [SECURITY.md](SECURITY.md) for the details.

### Command line

```bash
ladpock scan path/to/your-project
```

```bash
ladpock
```

Running `ladpock` on its own refreshes the vulnerability feeds and shows anything new that affects the projects
you've scanned before.

| Command | What it does |
|---|---|
| `ladpock ui` | Open the dashboard (`--port`, `--no-browser`) |
| `ladpock scan [path]` | Scan a project (`--profile quick\|standard\|full`, `--format text\|json\|sarif`, `-o file`) |
| `ladpock` / `ladpock status` | Refresh feeds, show new advisories and your projects' grades |
| `ladpock routes [path]` | Show the Next.js route matrix |
| `ladpock fix-prompt [path]` | Print a prompt for your AI assistant from the last scan |
| `ladpock advisories [path]` | List known vulnerable dependencies |
| `ladpock projects discover <folder>` | Register every project inside a folder |
| `ladpock suppress <ref> --reason "..."` | Accept a finding for 90 days (`--days 0` = forever) |
| `ladpock checks` | List every check |
| `ladpock doctor [path]` | Check your setup and optional scanners |

Add `--offline` to any command to skip the network and use cached data. LadPock will tell you how old it is.

### Optional scanners

LadPock works on its own. If these are installed, it uses them too, and their results are merged and
de-duplicated:

- [Gitleaks](https://github.com/gitleaks/gitleaks#installing) adds more secret patterns, and scans git history
  with `--history` or `--profile full`.
- [OSV-Scanner](https://google.github.io/osv-scanner/installation/) reads more lockfile formats.
- [Opengrep](https://github.com/opengrep/opengrep#installation) (or Semgrep CE) runs LadPock's data-flow rules
  for injection.

Install them from their official releases and verify the published checksums.

### In CI

```yaml
- run: pipx install git+https://github.com/liamburgo23/ladpock
- run: ladpock scan . --format sarif -o ladpock.sarif --fail-on high
```

## Coverage today

| Stack | Depth |
|---|---|
| Next.js, React, Supabase, Firebase, Stripe, GitHub Actions | Framework-aware checks and route matrix |
| Everything else (Python, Express, other frameworks) | Generic checks: secrets, dependencies, injection patterns, config, AI code smells |

Each scan says which stacks got deep checks, so you know how thorough it was. More framework packs are planned.

## Honest limits

LadPock catches common, recognisable mistakes. It doesn't understand your business logic, can't see your
production configuration or dashboard settings, and its route analysis is heuristic: it recognises common
libraries and patterns, and says so when it isn't sure. A good grade means "no obvious problems found", not
"secure". Work through the `--human` checklist too, and get a human review before handling payments or sensitive data.

## Privacy

No telemetry. What leaves your machine:

- package names and versions, sent to OSV.dev and the npm/PyPI registries
- CVE IDs, sent to FIRST's EPSS API
- a download of CISA's public catalog

Your code never leaves your machine. Results live in a local SQLite database: `%LOCALAPPDATA%\LadPock` on Windows,
`~/Library/Application Support/LadPock` on macOS, `~/.local/share/ladpock` on Linux. Set `LADPOCK_HOME` to change
it. Secrets are masked before anything is stored.

## Roadmap

- Local AI review overnight (Ollama), with optional escalation to an external model using your own key
- A Tauri pack (CSP, capabilities, exposed commands) and Rust checks
- More framework packs: Express, FastAPI, SvelteKit, Remix
- Pinned, checksum-verified installer for the optional scanners
- Safe live probes against your own running app (headers, CORS, rate limits)

See [docs/DESIGN.md](docs/DESIGN.md) for the architecture and the decisions behind it.

## Contributing a check

1. Add the check in `src/ladpock/checks/`: a `regex_check(...)` for a pattern, or an `@check` function for anything
   that needs structure.
2. Add an example that must trigger it to `tests/fixtures/vuln-next-supabase`, and make sure
   `tests/fixtures/clean-next-supabase` stays clean.
3. Run the tests:

```bash
PYTHONPATH="src:tests" python -m unittest discover -s tests
```

On Windows, use `src;tests`. The tests fail if a check isn't exercised by the vulnerable fixture.

Fixtures never contain real-looking secrets. Use a placeholder like `{{FAKE_STRIPE_SECRET}}` and add a generated
fake in `tests/helpers.py`.

## Licence

[Apache-2.0](LICENSE).
