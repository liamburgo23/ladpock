# Changelog

All notable changes to LadPock. Versions follow [semantic versioning](https://semver.org/); while LadPock is below
1.0, minor versions can include changes to checks and grades.

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
