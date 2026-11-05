# Changelog

All notable changes to LadPock. Versions follow [semantic versioning](https://semver.org/); while LadPock is below
1.0, minor versions can include changes to checks and grades.

## [0.12.0] - 2026-11-05

### Added
- Route matrix for backends with no server of your own: tRPC, Convex, GraphQL resolvers (JavaScript, NestJS, TypeGraphQL),
  Firebase Cloud Functions, Supabase Edge Functions, and Vercel, Netlify, Cloudflare (Pages Functions and Workers) and AWS
  Lambda (Serverless Framework and SAM) functions.
- Checks for AI features: API keys in the browser, AI replies run as code or queries, callers choosing the model or token
  limit, user input in system prompts, agents with shell or code tools.
- Checks for file uploads, passwords and tokens in logs, roles and user IDs taken from the request, admin or paid status
  trusted from the browser, all environment variables sent out or copied into the front end, email account linking,
  hand-built sign-in links with no state, reset links built from the Host header, login tokens set from JavaScript,
  timing-unsafe secret comparison, open image optimisers, paid status from the checkout redirect, archive path traversal,
  sending email or texts to any address, endpoints returning whole tables, leftover debug and seed endpoints, open
  scheduled-job endpoints, and private-looking data readable without a login.
- Supabase and Firebase checks: policies that only check someone is signed in, SECURITY DEFINER functions without a fixed
  search path, views that skip Row Level Security or expose `auth.users`, and open storage.
- More live probes: session cookie flags, input coming back as raw HTML, a stray quote breaking a database query, open
  redirects, private answers marked cacheable, folder listings, public API docs, and more sensitive paths.
- `ladpock scan --format html` and a **Download report** button: a one-page report to keep or pass on, with no scripts.
- A GitHub Action (`uses: liamburgo23/ladpock@v0.12.0`) and `ladpock scan --github`: marks on the changed lines, a job summary
  and the grade as step outputs.

### Changed
- `--format json` now includes the live check results.

### Fixed
- File-based routes in a folder called `test`, `fixtures` or similar were skipped as test code, although they ship.

## [0.11.0] - 2026-11-05

### Added
- Route matrix for SvelteKit, Remix, Nuxt, Astro, Spring, Go (net/http, chi, gin, echo, fiber, gorilla/mux), Rails,
  Laravel and ASP.NET, so the access-control and abuse checks apply to them.
- A live check for the most common serious web bug: give LadPock session headers for two test accounts and it finds
  account A's records and tries to open them as account B. It works with JSON APIs, nested routes and server-rendered
  pages, treats records both accounts can list as shared, and reports the line of code. It only reads.
- A live check for admin endpoints that answer ordinary accounts.
- A Live checks card on the results page with requests, routes, confirmed problems, what the two-account check tried,
  and notes such as a login that has expired.

### Changed
- A+ now means nothing is open, overall and per category. Averaging across categories let one real problem barely
  move the total, so a project with an unconfirmed high and a medium could read as A+. Any open finding now limits the
  grade: at most B+ with a medium and A with a low, and a low-confidence finding limits it one step less. Grades on
  projects with open findings may drop.
- "Make the assessment more complete" now mentions the two-account check when a live scan ran without it.
- Live checks say so when the request limit stopped them early.

### Security
- Live check URLs are now built by joining text onto the checked address, so no path can move a request to another host.

## [0.10.0] - 2026-11-03

### Added
- `ladpock shortcut` adds a double-click launcher: a Start Menu (and optional desktop) shortcut on Windows, a
  `.command` file on macOS, or a menu entry on Linux. It opens the dashboard in a terminal window titled so you
  can see LadPock is running; closing it stops LadPock.
- A release workflow: pushing a version tag tests and builds the package, checks the installed command works, and
  drafts a GitHub release with these notes. Publishing to PyPI is a separate, opt-in step when the release is
  published.
- CI builds the package on Linux and Windows and checks the installed `ladpock` command (scan, MCP server,
  dashboard files, rules and scanner pins), so packaging mistakes are caught before a release.

## [0.9.0] - 2026-11-03

### Added
- Known-vulnerability checks for NuGet (.csproj, packages.lock.json, Directory.Packages.props, packages.config),
  Maven and Gradle (pom.xml, gradle.lockfile, build files, version catalogs), pub (Flutter), Swift Package
  Manager and Hex (Elixir).
- Live checks against your app running on this computer (`--live URL` or the scan panel toggle). Each route is
  called without logging in, and LadPock checks security headers, CORS, exposed `.env`/`.git` and similar files,
  stack traces and sign-in rate limits. Localhost only; requests that change data are only sent if you ask.
- `ladpock mcp`, an MCP server so Claude Code and other AI assistants can scan, read findings and the route table,
  explain the grade and get fix prompts.
- `ladpock hook install`, a git pre-commit hook that stops commits adding secrets.
- What changed since the last scan: new and fixed findings and the grade change, in the CLI, the dashboard and
  the MCP results.
- Six "Needs a human" items for infrastructure, mobile, desktop and APIs.

### Changed
- Express routers mounted with `app.use('/prefix', router)`, Fastify plugin prefixes and Django `include()` now
  show full URLs.
- The local and online AI reviews also read Dockerfiles, Compose, Kubernetes, Terraform and CI workflows.

### Security
- Unquoted YAML values under secret-looking keys (for example a Kubernetes Secret) are now masked before they're
  shown or sent to an AI review.

## [0.8.0] - 2026-11-03

### Added
- Route matrix for Express, Fastify, Hono, Koa, NestJS, FastAPI, Flask and Django, so the access-control and abuse
  checks apply to them.
- Web checks across languages: unsafe deserialisation, raw HTML in templates, template injection, XXE, path
  traversal, NoSQL injection, prototype pollution, mass assignment, CSRF switched off, hardcoded signing keys,
  plain-text passwords, tokens without expiry, weak ciphers, ReDoS, GraphQL limits and more.
- Infrastructure checks for Dockerfiles, Compose, Kubernetes, Terraform and GitHub Actions script injection.
- Desktop and mobile checks for Electron, Android, iOS, React Native/Expo and Flutter.
- Go, PHP, Rails, Spring and .NET spellings of the injection, crypto and config checks.
- 43 more provider secret formats.

## [0.7.0] - 2026-11-03

### Added
- Click any grade to see where the points went, what caps it, the grade after each round of fixes (with a fix
  prompt per round) and what would make the assessment more complete.
- One scan panel with presets and a toggle per option, showing what runs, what leaves your computer and what it
  costs before you press Scan.
- An optional paid online AI review with Claude, using your own Anthropic key (stored in Windows Credential
  Manager), a monthly budget and a per-project "never send" switch.

## [0.6.0] - 2026-11-03

### Added
- A pinned, checksum-verified installer for the optional scanners (Gitleaks, OSV-Scanner, Opengrep).

## [0.5.0] - 2026-11-03

### Added
- The dashboard shows what's running and what finished, with progress, a run-everything button, profile
  explanations and a Help page.

## [0.4.0] - 2026-11-02

### Added
- A local AI review with a model on your own computer (Ollama), incremental and resumable, with an optional
  nightly schedule. Leads must quote real code and never change the grade.

## [0.3.0] - 2026-11-02

### Added
- A Tauri pack and command matrix: CSP, capabilities, asset protocol, updater and every command the page can call.

## [0.2.0] - 2026-11-02

### Added
- The local dashboard (`ladpock ui`), reachable only from this computer with a per-launch token.

## [0.1.0] - 2026-11-02

### Added
- First release: built-in checks for secrets, auth, authorization, API abuse, injection, payments, crypto, config,
  supply chain and AI-generated code smells; a Next.js route matrix; dependency checks against OSV, CISA KEV and
  EPSS with "new since you last looked"; hallucinated-package detection; grades; fix prompts; JSON and SARIF
  output; and support for Gitleaks, OSV-Scanner and Opengrep.

[0.12.0]: https://github.com/liamburgo23/ladpock/compare/v0.11.0...v0.12.0
[0.11.0]: https://github.com/liamburgo23/ladpock/compare/v0.10.0...v0.11.0
[0.10.0]: https://github.com/liamburgo23/ladpock/compare/v0.9.0...v0.10.0
[0.9.0]: https://github.com/liamburgo23/ladpock/compare/v0.8.0...v0.9.0
[0.8.0]: https://github.com/liamburgo23/ladpock/compare/v0.7.0...v0.8.0
[0.7.0]: https://github.com/liamburgo23/ladpock/compare/v0.6.0...v0.7.0
[0.6.0]: https://github.com/liamburgo23/ladpock/compare/v0.5.0...v0.6.0
[0.5.0]: https://github.com/liamburgo23/ladpock/compare/v0.4.0...v0.5.0
[0.4.0]: https://github.com/liamburgo23/ladpock/compare/v0.3.0...v0.4.0
[0.3.0]: https://github.com/liamburgo23/ladpock/compare/v0.2.0...v0.3.0
[0.2.0]: https://github.com/liamburgo23/ladpock/compare/v0.1.0...v0.2.0
[0.1.0]: https://github.com/liamburgo23/ladpock/releases/tag/v0.1.0
