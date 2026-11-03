# LadPock

**A free, local security checker for vibe-coded projects.** (It's a padlock, slightly rearranged.)

LadPock looks for the mistakes AI-assisted code tends to make, and that a senior developer would spot in review:
admin keys shipped to the browser, API routes that never check who's calling, Supabase tables without Row Level
Security, paid AI endpoints anyone can hit, webhooks that trust any request, packages that don't exist, containers
that run as root, public storage buckets, Electron windows with Node.js switched on, and more. It covers web apps,
APIs, desktop and mobile apps, and the infrastructure they run on.
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

- **113 built-in checks** across secrets, sign-in, authorization, API abuse and cost, injection, payments,
  crypto, config, supply chain, and AI-generated code smells. Run `ladpock checks` for the list, or see
  [docs/CHECKS.md](docs/CHECKS.md).
- **A route matrix** for Next.js (App Router, Pages API and server actions), Express, Fastify, Hono, Koa, NestJS,
  FastAPI, Flask and Django. It shows every endpoint with its auth, ownership check, validation and rate limiting,
  and flags the gaps: unauthenticated writes, records fetched by ID without an ownership check, auth only in
  middleware, paid AI endpoints without a login or rate limit.
- **Infrastructure checks** for Dockerfiles, Docker Compose, Kubernetes manifests, Terraform and GitHub Actions:
  root containers, baked-in secrets, privileged or host-mounted containers, databases published to the internet,
  public buckets, open firewalls, wildcard IAM policies and workflow script injection.
- **Desktop and mobile checks** for Electron, Android, iOS, React Native/Expo and Flutter: Node.js in the page,
  exposed IPC, missing CSP, cleartext traffic, debuggable builds, exported components, tokens in plain storage,
  risky WebViews and certificate-check bypasses.
- **Many languages:** JavaScript/TypeScript, Python, Go, PHP, Ruby, Java/Kotlin, C#, Rust, Dart and Swift, with each
  language's own spelling of SQL injection, command injection, unsafe deserialisation, weak crypto and more.
- **More than 50 provider secret formats** (cloud, AI, payment, source-control, messaging and observability tokens),
  masked everywhere they appear.
- **A Tauri pack and command matrix.** It checks the Content-Security-Policy, capability files (remote access,
  file-system and shell permissions), the asset protocol and the updater. It also lists every `#[tauri::command]`
  the page can call, with which ones read or write files, whether they check the path is inside an allowed folder,
  and which start programs. Tauri v2 and v1 configs are both supported.
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

This opens LadPock in your browser. Add projects by picking their folders. Each project has one scan panel: pick a
preset or set each option yourself, then press **Scan** at the bottom.

| Option | Cost | Where it runs |
| --- | --- | --- |
| Depth: Quick, Standard or Full | free | this computer |
| Free online vulnerability data (OSV.dev, CISA KEV, EPSS, npm/PyPI). Turn it off for an offline scan | free | sends package names and versions |
| Installed scanners (Gitleaks, OSV-Scanner, Opengrep) | free | this computer |
| Search git history for deleted secrets | free | this computer |
| Local AI review (Ollama) | free | this computer |
| Paid online AI review (Claude, your own API key and budget) | paid | sends code, with secrets masked |
| Paid online scanners (Snyk, Socket ...) | paid | not available yet |

The presets are **Everything free**, **Offline**, **Quick** and **Deepest (paid)**. Before you press Scan, the panel
tells you what the scan will do, what leaves your computer, and what it costs. A greyed-out option says why it
can't run yet, for example a scanner that isn't installed. **Check all projects** on the home page runs a full
check of every project, one after another.

**Click any grade** to see why it isn't A+:
- where every point went, category by category
- whether an open critical or high finding is capping the overall score
- the grade you'd reach after each round of fixes, with a fix prompt for each round
- what would make the assessment itself more complete (missing scanners, offline data, no lockfile, unconfirmed
  manual checks)

While anything runs, the top bar shows what's running and how far along it is (click it for details and a Stop
button). The project page shows a progress banner with the current step. When a task finishes, a message tells you
the result and the page refreshes. A **Help** page explains grades, profiles, the AI review and the data sources.

You can browse findings by severity, with filters and search. Each finding has a copy-fix-prompt button
and an "accept risk" option that needs a reason and expires. There are also tabs for the Next.js route matrix,
vulnerable dependencies (with "actively exploited" flags), the "needs a human" checklist (LadPock remembers what
you've ticked) and scan history. Vulnerability data refreshes every time you open it, and a banner lists anything
new that affects your projects.

The dashboard only listens on `127.0.0.1`, and every request needs a private key that's in the link printed in your
terminal. It changes each time you start it. See [SECURITY.md](SECURITY.md) for the details.

### Local AI review (free, private, overnight)

If [Ollama](https://ollama.com) is running with a model installed, LadPock can have that model read your project to
find logic bugs that patterns can't. Examples are a route that checks login but not ownership, or a command that
trusts a path from the page. Everything runs on your computer.

```bash
ladpock ai status
```

```bash
ladpock ai benchmark path/to/project
```

```bash
ladpock ai review path/to/project
```

```bash
ladpock ai nightly on path/to/project
```

```bash
ladpock ai schedule --at 01:00 --until 07:00
```

These show your models and the one LadPock picked, time the model and estimate a full review, review now, include
a project in the nightly run, and set up the nightly run.

How it works:

- **It reads what matters first.** Next.js routes and Tauri commands come first, each with what the static checks
  found. Then come the scanner's medium-and-above findings, for a second opinion. Then the rest of your source.
- **It's incremental and resumable.** Progress is saved after every part. Stopping (the time limit, battery,
  Ctrl+C, a reboot) loses nothing. After the first run, only code that changed is re-read.
- **Its results are leads, not findings.** The model must quote the exact line it's worried about, and LadPock
  checks that line exists in your code. Leads that fail are dropped. Leads never change your grade, and the AI
  can never hide a scanner finding. You confirm or dismiss each one, and dismissed leads stay dismissed.
  Confirmed leads go into the fix prompt.
- **The nightly task behaves.** It's a Windows scheduled task for your account only. It runs only when plugged in,
  stops on battery and at your stop time, and runs at low priority. It optionally wakes the PC.
  `ladpock ai unschedule` removes it.

On an RTX 3090 with `qwen3.6:35b`, a review takes about 1.5 seconds per part once the model is loaded. A mid-sized
app takes a few minutes. The dashboard has the same controls under **AI settings**.

### Paid online AI review (optional, your own API key)

Claude can review your code too. It's a stronger reviewer than most models that fit on a home computer, and it
also double-checks the local model's leads. It's off until you set it up, and every part of it is your choice:

```bash
python -m pip install anthropic
```

```bash
ladpock ai online key
```

```bash
ladpock ai online set --enable --budget 5
```

```bash
ladpock ai online review path/to/project
```

These install Anthropic's SDK (optional, so LadPock itself keeps zero dependencies), save your API key in Windows
Credential Manager (or set `ANTHROPIC_API_KEY`), allow sending code with a monthly budget, and run a review after
showing the estimated cost. In the dashboard, the same settings are under **AI settings**. Then switch on **Paid
online AI review** in the scan panel.

- **What's sent:** the same parts of your code the local review reads, with secrets masked first. Nothing for a
  project marked "never send this project online".
- **What it costs:** Anthropic bills your own account. LadPock records an estimate of every call and stops before a
  run would go over your monthly budget. Unchanged code isn't sent again.
- **What you get:** leads, like the local review. Quoted code must exist in your project, and leads never change
  the grade.

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
| `ladpock full-check [path]` | Everything: a Full scan, then the local AI review (`--all-projects`, `--no-ai`) |
| `ladpock scan [path]` | Scan a project (`--profile quick\|standard\|full`, `--format text\|json\|sarif`, `-o file`) |
| `ladpock` / `ladpock status` | Refresh feeds, show new advisories and your projects' grades |
| `ladpock routes [path]` | Show the Next.js route matrix |
| `ladpock fix-prompt [path]` | Print a prompt for your AI assistant from the last scan |
| `ladpock advisories [path]` | List known vulnerable dependencies |
| `ladpock projects discover <folder>` | Register every project inside a folder |
| `ladpock suppress <ref> --reason "..."` | Accept a finding for 90 days (`--days 0` = forever) |
| `ladpock ai status\|benchmark\|review\|leads\|nightly\|schedule` | Local AI review (see above) |
| `ladpock scanners [install\|remove] [name]` | List, install or remove the optional scanners (pinned, checksum-verified) |
| `ladpock checks` | List every check |
| `ladpock doctor [path]` | Check your setup and optional scanners |

Add `--offline` to any command to skip the network and use cached data. LadPock will tell you how old it is.

### Optional scanners

LadPock works on its own. If these are installed, it uses them too, and their results are merged and
de-duplicated. The easiest way to install them is the **Scanners** page in the dashboard, or:

```bash
ladpock scanners install
```

LadPock downloads exact pinned versions from each project's GitHub release. It checks every file against a SHA-256
hash built into LadPock before installing it, and installs into its own folder, not your PATH. A file that doesn't
match is deleted.

- [Gitleaks](https://github.com/gitleaks/gitleaks#installing) adds more secret patterns, and scans git history
  with `--history` or `--profile full`.
- [OSV-Scanner](https://google.github.io/osv-scanner/installation/) reads more lockfile formats.
- [Opengrep](https://github.com/opengrep/opengrep#installation) (or Semgrep CE) runs LadPock's data-flow rules
  for injection.

If you install them yourself instead (for example with a package manager), LadPock uses yours and leaves them alone.

### In CI

```yaml
- run: pipx install git+https://github.com/liamburgo23/ladpock
- run: ladpock scan . --format sarif -o ladpock.sarif --fail-on high
```

## Coverage today

| Stack | Depth |
|---|---|
| Next.js, React, Supabase, Firebase, Stripe | Framework-aware checks and route matrix |
| Express, Fastify, Hono, Koa, NestJS | Route matrix (middleware, guards, validation, rate limits) and Node server checks |
| FastAPI, Flask, Django and Django REST Framework | Route matrix (decorators, Depends, permission classes) and settings checks |
| Tauri (v2 and v1) | CSP, capabilities, asset protocol, updater, and the command matrix |
| Electron | Window settings, preload/IPC exposure, navigation, CSP and IPC handlers |
| Android, iOS, React Native/Expo, Flutter | Manifest and ATS settings, storage, WebViews, certificate checks |
| Docker, Compose, Kubernetes, Terraform, GitHub Actions | Infrastructure-as-code checks |
| Go, PHP/Laravel, Ruby/Rails, Java/Spring, .NET, Rust | Language-specific injection, crypto, config and framework-setting checks |
| Anything else | Generic checks: secrets, dependencies, injection patterns, config, AI code smells |

Each scan says which stacks got deep checks, so you know how thorough it was.

## Honest limits

LadPock catches common, recognisable mistakes. It doesn't understand your business logic, can't see your
production configuration or dashboard settings, and its route analysis is heuristic: it recognises common
libraries and patterns, and says so when it isn't sure. A good grade means "no obvious problems found", not
"secure". Work through the `--human` checklist too, and get a human review before handling payments or sensitive data.

## Privacy

No telemetry. The local AI review only talks to a model server on this computer (LadPock refuses any address that
isn't 127.0.0.1 or localhost). What leaves your machine:

- package names and versions, sent to OSV.dev and the npm/PyPI registries (turn off "free online vulnerability
  data" to send nothing)
- CVE IDs, sent to FIRST's EPSS API
- a download of CISA's public catalog
- only if you set up the paid online AI review and switch it on for a scan: parts of your code with secrets masked,
  sent to Anthropic

Otherwise your code never leaves your machine. Results live in a local SQLite database: `%LOCALAPPDATA%\LadPock` on Windows,
`~/Library/Application Support/LadPock` on macOS, `~/.local/share/ladpock` on Linux. Set `LADPOCK_HOME` to change
it. Secrets are masked before anything is stored.

## Roadmap

- Paid online scanners with your own account (for example Snyk or Socket)
- More framework packs: Express, FastAPI, SvelteKit, Remix
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
