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

- **191 built-in checks** across secrets, sign-in, authorization, API abuse and cost, injection, payments,
  crypto, config, supply chain, and AI-generated code smells. Run `ladpock checks` for the list, or see
  [docs/CHECKS.md](docs/CHECKS.md).
- **A route matrix** for Next.js (App Router, Pages API and server actions), SvelteKit, Remix, Nuxt, Astro, Express,
  Fastify, Hono, Koa, NestJS, FastAPI, Flask, Django, Spring, Go (net/http, chi, gin, echo, fiber, gorilla/mux), Rails,
  Laravel and ASP.NET, plus backends with no server of your own: tRPC, Convex, GraphQL resolvers, Firebase Cloud Functions,
  Supabase Edge Functions, and Vercel, Netlify, Cloudflare and AWS Lambda functions. Also Rust (Axum, Actix, Rocket), Elysia,
  Hapi, Sinatra, Symfony, Ktor, JAX-RS (Quarkus, Jersey) and Micronaut. It shows every endpoint with its auth, ownership check, validation and rate limiting,
  and flags the gaps: unauthenticated writes, records fetched by ID without an ownership check, auth only in
  middleware, paid AI endpoints without a login or rate limit.
- **Checks for how apps get built now:** AI keys in the browser, AI replies run as code or queries, user text in system
  prompts, callers choosing the model or token limit, agents with shell tools; uploads saved under the user's file name;
  passwords and tokens in logs; roles, IDs and paid status taken from the request or the browser; every environment
  variable copied into the front end; leftover debug and seed endpoints; and Supabase and Firebase rules that only check
  someone is signed in.
- **Supply-chain checks for how attacks work now:** install scripts that download code, packages from outside the registry,
  AI tool servers with no fixed version, projects that run a command as soon as you open them, and build scripts that pipe a
  download into a shell.
- **Infrastructure checks** for Dockerfiles, Docker Compose, Kubernetes manifests, Terraform and GitHub Actions:
  root containers, baked-in secrets, privileged or host-mounted containers, databases published to the internet,
  public buckets, open firewalls, wildcard IAM policies and workflow script injection.
- **Desktop and mobile checks** for Electron, Android, iOS, React Native/Expo and Flutter: Node.js in the page,
  exposed IPC, missing CSP, cleartext traffic, debuggable builds, exported components, tokens in plain storage,
  risky WebViews and certificate-check bypasses.
- **Many languages:** JavaScript/TypeScript, Python, Go, PHP, Ruby, Java/Kotlin, C#, Rust, Dart, Swift and C/C++, with each
  language's own spelling of SQL injection, command injection, unsafe deserialisation, weak crypto and more.
- **Software that isn't a web app:** buffer overflows, format strings and shell commands in C and C++; `eval`, unsafe
  deletes, turned-off certificate checks and passwords in shell and PowerShell scripts; programs downloaded over plain HTTP;
  and Solidity contracts (reentrancy, `tx.origin`, sensitive functions anyone can call, predictable randomness).
- **More than 50 provider secret formats** (cloud, AI, payment, source-control, messaging and observability tokens),
  masked everywhere they appear.
- **A Tauri pack and command matrix.** It checks the Content-Security-Policy, capability files (remote access,
  file-system and shell permissions), the asset protocol and the updater. It also lists every `#[tauri::command]`
  the page can call, with which ones read or write files, whether they check the path is inside an allowed folder,
  and which start programs. Tauri v2 and v1 configs are both supported.
- **Live checks against your running app.** Point LadPock at your app on this computer (`--live
  http://localhost:3000`, or the toggle in the dashboard) and it confirms which endpoints really answer without a
  login, and checks security headers, cookies, CORS, exposed `.env`/`.git` files, error pages and sign-in rate limits.
  It tries a few harmless probes for reflected input, SQL errors and open redirects. Give it two test accounts and it
  tries to open one account's records as the other, the most common serious web bug. It only ever talks to localhost,
  and only sends requests that change data if you ask.
- **Live vulnerability data before every run.** Your dependencies are checked against [OSV.dev](https://osv.dev),
  prioritised with CISA's [Known Exploited Vulnerabilities](https://www.cisa.gov/known-exploited-vulnerabilities-catalog)
  list and [EPSS](https://www.first.org/epss/) exploit likelihood. Lockfiles and manifests are read for npm, PyPI,
  Cargo, Go, Composer, RubyGems, NuGet (.csproj, packages.lock.json), Maven/Gradle, pub (Flutter), Swift Package
  Manager and Hex.
- **Works inside Claude Code.** `ladpock mcp` lets Claude Code scan while it writes code and check whether its fixes
  worked, and `ladpock hook install` stops commits that add secrets.
- **What changed since the last scan:** new and fixed findings and the grade change, on every scan.
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

LadPock needs Python 3.11 or newer and has no other dependencies. [pipx](https://pipx.pypa.io) installs it in
its own environment and puts the `ladpock` command on your PATH:

```bash
pipx install git+https://github.com/liamburgo23/ladpock
```

Or from a clone (use `pip install -e .` instead if you want to change the code):

```bash
git clone https://github.com/liamburgo23/ladpock
cd ladpock
pip install .
```

Then add a launcher, so you can open the dashboard from the Start Menu, Applications or your app menu:

```bash
ladpock shortcut
```

It opens the dashboard in a terminal window. Close that window to stop LadPock. Add `--desktop` for a desktop icon
too, and `ladpock shortcut remove` takes them away.

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
- which open finding is limiting the overall score (A+ means nothing is open)
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
| `ladpock scan [path]` | Scan a project (`--profile quick\|standard\|full`, `--format text\|json\|sarif\|html`, `-o file`, `--live URL`) |
| `ladpock` / `ladpock status` | Refresh feeds, show new advisories and your projects' grades |
| `ladpock routes [path]` | Show the route matrix |
| `ladpock fix-prompt [path]` | Print a prompt for your AI assistant from the last scan |
| `ladpock advisories [path]` | List known vulnerable dependencies |
| `ladpock projects discover <folder>` | Register every project inside a folder |
| `ladpock suppress <ref> --reason "..."` | Accept a finding for 90 days (`--days 0` = forever) |
| `ladpock ai status\|benchmark\|review\|leads\|nightly\|schedule` | Local AI review (see above) |
| `ladpock scanners [install\|remove] [name]` | List, install or remove the optional scanners (pinned, checksum-verified) |
| `ladpock checks` | List every check |
| `ladpock shortcut [remove] [--desktop]` | Add or remove a launcher for the dashboard |
| `ladpock --version` | Show the installed version |
| `ladpock mcp` | Run as an MCP server for Claude Code and other AI assistants |
| `ladpock hook install\|remove [path]` | Add or remove a git pre-commit hook that stops commits adding secrets |
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

### Live checks against your running app

Start your app, then:

```bash
ladpock scan . --live http://localhost:3000
```

LadPock calls every route the route matrix found without logging in, and reports any that answer with data against
the line of code that defines them. It also checks security headers, session cookies, CORS, server version banners,
files that should never be served (`.env`, `.git`, cloud credentials, private keys, Spring actuator, phpinfo, SQL dumps),
folder listings, public API docs, stack traces in error pages, and whether 20 failed sign-ins in a row get slowed down.

Where the code and the running app disagree, the finding says so. If the code looks unprotected but the app refuses the
request, the finding drops to low confidence and tells you why; if the app answers, it's marked as confirmed.

It also sends a few harmless probes, all GET requests: a marker in the query string to see if it comes back as raw HTML,
a stray quote to see if it causes a database syntax error, and a made-up address in redirect parameters (redirects are
never followed). For the most realistic results, run a production build locally.

It refuses any address that isn't this computer. Routes that change data (POST, PUT, PATCH, DELETE) are skipped
unless you add `--live-writes`, and even then they get placeholder IDs and empty bodies. Only do that against a
development database.

**Can one user read another's data?** Sign in to your app as two ordinary test accounts, each with some data of its
own, and copy each one's `Cookie` or `Authorization` header from your browser's developer tools:

```bash
export LADPOCK_LIVE_USER_A="Cookie: session=..."
export LADPOCK_LIVE_USER_B="Cookie: session=..."
ladpock scan . --live http://localhost:3000
```

Environment variables keep them out of your shell history; `--live-user-a` and `--live-user-b` work too, and the scan
panel has fields for them. LadPock reads account A's lists to find its records (or take them from
`--live-own-url /api/orders/123`), then opens them as account B. It reports the route's line of code when B gets A's
record, and treats records both accounts can list as shared. It also reports admin endpoints that answer both accounts
and answers that need a login but are marked cacheable. This check only reads, even with `--live-writes`. The login values are held in memory, only sent to your app on this
computer, and never logged or saved.

### With Claude Code

```bash
claude mcp add ladpock -- ladpock mcp
```

This gives Claude Code tools to scan a project (optionally reporting only the files it changed), list the last
findings, read the route matrix, explain the grade and get a fix prompt. It can scan after it edits auth, data
access or payment code, and check whether its fix worked, because every scan reports what changed since the
previous one. The server only reads your projects and LadPock's database.

```bash
ladpock hook install
```

This adds a git pre-commit hook that scans the files you're committing and stops the commit if they add a secret. It
won't replace an existing hook unless you pass `--force`; `ladpock hook remove` takes it out again.

### In CI

```yaml
- uses: liamburgo23/ladpock@v0.14.0
  with:
    fail-on: high   # critical, high, medium or low; leave empty to never fail
```

The action marks findings on the changed lines, writes a job summary, and sets `grade`, `score` and `findings` as step
outputs. It also writes `ladpock.sarif`, which you can send to GitHub code scanning with
`github/codeql-action/upload-sarif` (use `if: always()`, so it still runs when the scan fails the job). Pin it to a
commit SHA rather than a tag if you want to be sure what runs. Elsewhere:

```bash
pipx install git+https://github.com/liamburgo23/ladpock
ladpock scan . --format sarif -o ladpock.sarif --fail-on high
```

### A report to keep or pass on

```bash
ladpock scan . --format html -o ladpock-report.html
```

This is one page with the grade, what to fix first, endpoints with gaps and what was checked. The **Download report**
button in the dashboard makes the same page. It holds no scripts and loads nothing from anywhere else, secrets are
masked, and your folder path isn't included. It does contain code snippets, so share it only with people who could see the code.

## Coverage today

| Stack | Depth |
|---|---|
| Next.js, React, Supabase, Firebase, Stripe | Framework-aware checks and route matrix |
| SvelteKit, Remix, Nuxt, Astro | Route matrix (endpoints, loaders, form actions, hooks and middleware) |
| Express, Fastify, Hono, Koa, NestJS | Route matrix (middleware, guards, validation, rate limits) and Node server checks |
| FastAPI, Flask, Django and Django REST Framework | Route matrix (decorators, Depends, permission classes) and settings checks |
| Tauri (v2 and v1) | CSP, capabilities, asset protocol, updater, and the command matrix |
| Electron | Window settings, preload/IPC exposure, navigation, CSP and IPC handlers |
| Android, iOS, React Native/Expo, Flutter | Manifest and ATS settings, storage, WebViews, certificate checks |
| Docker, Compose, Kubernetes, Terraform, GitHub Actions | Infrastructure-as-code checks |
| Spring, Go, Rails, Laravel, ASP.NET | Route matrix (annotations, filters, middleware, authorization attributes) and language checks |
| tRPC, Convex, GraphQL (JavaScript resolvers, NestJS, TypeGraphQL) | Route matrix per procedure, function or resolver |
| Firebase Functions, Supabase Edge, Vercel, Netlify, Cloudflare, AWS Lambda (Serverless Framework, SAM) | Route matrix per function, plus Supabase and Firebase rules |
| Rust (Axum, Actix, Rocket), Elysia, Hapi, Sinatra, Symfony, Ktor, JAX-RS, Micronaut | Route matrix |
| OpenAI, Anthropic, Vercel AI SDK, LangChain | AI key exposure, prompt injection, running AI output, cost abuse |
| C/C++, shell, PowerShell, Solidity | Language-specific checks for memory safety, command injection, unsafe scripts and contract bugs |
| PHP, Ruby, Java, C#, Rust, Go | Language-specific injection, crypto, config and framework-setting checks |
| Anything else | Generic checks: secrets, dependencies, injection patterns, config, AI code smells |

Each scan says which stacks got deep checks, so you know how thorough it was.

## Honest limits

Analysis that reads code's structure skips files over 400 KB and minified files, and stops at 300 routes per file. That's what
keeps a huge bundle or a hostile file from stalling a scan. Line-by-line checks, including secret detection, still read them.

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

Live checks only talk to your app on this computer.

Otherwise your code never leaves your machine. Results live in a local SQLite database: `%LOCALAPPDATA%\LadPock` on Windows,
`~/Library/Application Support/LadPock` on macOS, `~/.local/share/ladpock` on Linux. Set `LADPOCK_HOME` to change
it. Secrets are masked before anything is stored.

## Roadmap

- Paid online scanners with your own account (for example Snyk or Socket)
- An accuracy study against real open-source apps, with false-positive rates published

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
