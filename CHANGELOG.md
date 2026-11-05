# Changelog

All notable changes to LadPock. Versions follow [semantic versioning](https://semver.org/); while LadPock is below
1.0, minor versions can include changes to checks and grades.

## [0.16.0] - 2026-11-05

### Added
- Jupyter notebooks are now read, so keys in cells and outputs are found.
- Checks for AI tools open to the network: Ollama on `0.0.0.0`, Gradio `share=True` with no login, Open WebUI with its login off, notebooks with no token.
- Checks for MCP servers you write: tools that run commands or touch files the model chose, and HTTP transports with no login.
- Checks for browser extensions: access to every site, settings that let websites or remote code in. Also a check, for any web code, for messages
  accepted from any site.
- Checks for Arduino and ESP32 sketches: Wi-Fi passwords and device logins in the code, turned-off certificate checks, plain MQTT.
- `unsafe_allow_html=True` in Streamlit is now reported.

### Fixed
- A config file holding the wrong types, such as a `package.json` with `{"dependencies": 5}`, or very deep nesting, could crash a whole scan. Odd files are now skipped, and
  a failure reading one framework's routes no longer loses the others.
- A file with very many blank lines could hang a scan.
- Lines starting with `#` were treated as comments in C and C++ too, so `#define` lines were never checked.

## [0.15.0] - 2026-11-05

### Added
- A baseline, so a project with old problems can start by failing only on new ones: `ladpock scan --write-baseline FILE`, then `--baseline FILE`
  or the action's `baseline` input. Baselined findings still count towards the grade.
- `ladpock.toml` in a project's root: your own login and ownership helpers, routes that are public on purpose, and paths or checks to skip. Whatever
  it hides is still counted in reports.
- `ladpock sbom`: every package version as a CycloneDX bill of materials, read from lockfiles.
- A check for private keys and credentials files in the repository: SSH and TLS private keys, Firebase and Google service account keys, key stores,
  `.git-credentials`, `.npmrc`, `.pypirc` and `.netrc`. These were invisible before, because they aren't files LadPock normally reads.
- The "Needs a human" item about one user reading another's data now shows what the two-account check found.
- A live check for a GraphQL schema open to anyone.

### Changed
- URLs that hold a secret, such as `/invite/{token}`, no longer count as having no login.

## [0.14.0] - 2026-11-05

### Added
- Route matrix for Rust (Axum, Actix, Rocket), Elysia, Hapi, Sinatra, Symfony, Ktor, JAX-RS (Quarkus, Jersey) and Micronaut.
- C and C++ are now scanned: functions with no bounds check, format strings from variables, shell commands the program builds
  itself, and temporary file names that can be guessed.
- Checks for shell and PowerShell scripts: running text as a command, files writable by everyone, deleting a path that could
  be empty, turned-off certificate and host key checks, and passwords on a command line.
- Checks for Solidity contracts: `tx.origin`, reentrancy, sensitive functions anyone can call, predictable randomness, old
  compiler versions, `delegatecall` and `selfdestruct`.
- Checks for programs downloaded over plain HTTP, and shell commands and SQL built with `format!` in Rust.
- The Routes tab shows where each route is defined, can be searched and filtered by kind, and can show only routes with gaps.

### Fixed
- Pasting LadPock's new link into a tab already open on it, after a restart, left the page locked until you reloaded.
- The dashboard no longer scrolls sideways at phone width when a project's folder path is long.

## [0.13.0] - 2026-11-05

### Added
- Findings from the code now use what the running app did. If the code looks unprotected but the app refuses the request, the
  finding drops to low confidence and says why. If the app answers, or one test account opens another's record, it's marked as
  confirmed. Shown as **Confirmed live** and **Refused live** in the dashboard and in reports.
- Supply-chain checks: install scripts that download or run code, packages from outside the registry (URLs, git, plain HTTP,
  extra indexes, `strict-ssl=false`), dependencies that allow any version, AI tool (MCP) servers with no fixed version or over
  plain HTTP, projects that run a command when opened (VS Code tasks, devcontainers, AI tool hooks), and build scripts that pipe a
  download into a shell.
- Checks for code that wipes the database on start or deploy, login that can be switched off with a setting, sites that don't
  insist on HTTPS, database consoles reachable from the web, and web server settings (folder listings, alias path traversal,
  old TLS versions).
- More token checks: .NET's `ValidateLifetime = false` and similar, Go and Java `ParseUnverified`, Laravel's `'secure' => false`.

- The AI reviews now read Supabase policies and Firebase rules, and hosting and web server settings. They're told when a backend
  function can be called straight from the browser, and they don't spend tokens re-checking what the running app has confirmed.

### Changed
- Public read on a Supabase table now depends on its name: fine for `posts`, high severity for `profiles` or `orders`.
- The URL that carries tRPC or GraphQL no longer appears as an endpoint of its own, because each procedure and resolver is listed.

### Fixed
- SHA-256 of a random reset token was reported as weak password hashing.
- tRPC's `.query(` was counted as a database query.
- A very large or deliberately crafted file could stall a scan for minutes or indefinitely. Structural analysis now skips files
  over 400 KB and minified files, and has limits per file. Line-by-line checks still read them.

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

[0.16.0]: https://github.com/liamburgo23/ladpock/compare/v0.15.0...v0.16.0
[0.15.0]: https://github.com/liamburgo23/ladpock/compare/v0.14.0...v0.15.0
[0.14.0]: https://github.com/liamburgo23/ladpock/compare/v0.13.0...v0.14.0
[0.13.0]: https://github.com/liamburgo23/ladpock/compare/v0.12.0...v0.13.0
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
