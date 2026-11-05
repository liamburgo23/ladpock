# Security policy

## Reporting a vulnerability in LadPock

Please don't open a public issue. Use GitHub's private reporting instead:
**Security → Report a vulnerability** on this repository. I'll reply as soon as I can and credit you in the fix
unless you'd rather stay anonymous.

## LadPock's own security model

A tool that reads untrusted code and holds every secret it finds has to be careful. These are the rules the code
follows; a change that breaks one is a security bug.

1. **Never execute the scanned project.** No `npm install`, no build scripts, no tests. Lockfiles and manifests are
   parsed as data.
2. **Don't let the repository run code through git.** Every git call disables `core.fsmonitor`, which a malicious
   `.git/config` could otherwise use to run a command.
3. **Don't follow symlinks.** A repo can't point LadPock at files outside itself.
4. **Mask secrets everywhere.** Snippets go through `masking.redact` before they're stored, printed or exported.
   The local database never holds a usable credential.
5. **Send as little as possible over the network.** By default only package names and versions (to OSV.dev and
   the npm/PyPI registries) and CVE IDs (to FIRST's EPSS API) leave your machine, and an offline scan sends nothing.
   Source code is sent only to the paid online AI review, only after you set it up and switch it on (see 11).
   There's no telemetry.
6. **HTTPS only.** The feed client refuses plain HTTP and caps response sizes.
7. **No third-party runtime dependencies.** LadPock uses only the Python standard library.
8. **The dashboard is reachable only by you.** `ladpock ui` binds to 127.0.0.1. Every API call needs a random
   per-launch token sent in a header (never a cookie). The token is handed over in the URL fragment, which
   browsers don't send to servers. The `Host` header must be 127.0.0.1 or localhost on the right port, which defeats
   DNS rebinding. Requests carrying another site's `Origin` or a cross-site `Sec-Fetch-Site` are refused, and no
   CORS headers are ever sent. Writes must be JSON. Static files are served from an allowlist. The page has a strict
   Content-Security-Policy and builds its DOM with `textContent`, so code from a scanned repository can't inject
   HTML or script. These rules are covered by `tests/test_ui.py`.
9. **Local AI stays local and can't overrule the scanner.** The model client refuses any address that isn't
   loopback. Code is secret-redacted before the model sees it, and the prompt tells the model to treat code as
   untrusted data. A comment saying "this is safe" can still sway a model, so its output is constrained:
   - every lead must quote a line that exists in the code it was shown, or it's dropped
   - leads are capped at high severity
   - leads never affect the grade
   - the AI has no way to suppress or downgrade a scanner finding
   The nightly task is created only after you confirm. It's registered for your account with least privilege,
   and `ladpock ai unschedule` removes it.
10. **Optional scanners are pinned and verified.** Gitleaks, OSV-Scanner and Opengrep run as subprocesses with
   timeouts. When LadPock installs them (`ladpock scanners install` or the Scanners page), the exact version, file
   name, size and SHA-256 come from `scanners/pins.json`, which ships inside LadPock. Nothing about what to install
   is read from the network.
   - Downloads are HTTPS only, including redirects, and stop if they grow past the pinned size.
   - A file whose hash doesn't match is deleted and nothing is installed.
   - Only the one expected program is copied out of an archive. Archive paths are never used, so a crafted archive
     can't write elsewhere.
   - Programs go into LadPock's own folder, never your PATH, with no extra privileges.
   - Pins come from releases at least two weeks old, and change only in a reviewed commit. Moved tags and replaced
     release files are exactly what this defends against.
   - Copies you installed yourself are used as they are and never modified.

11. **The paid online AI review is opt-in at every step.** Nothing is sent unless you:
   - install the optional `anthropic` SDK
   - allow it in AI settings
   - provide an API key
   - switch it on for a scan, after seeing what will be sent and what it should cost

   Projects marked "never send online" are refused before anything else happens. Code goes through the same secret
   redaction as the local review. Leads must quote code that exists, never affect the grade and can't suppress a
   finding.

   The API key is stored in Windows Credential Manager, or taken from `ANTHROPIC_API_KEY`. It's never written to
   LadPock's database or settings, never logged, and never returned by the dashboard API (only `sk-ant-…` and its
   last four characters are shown). Spending is recorded per call, and a run stops before it would exceed your
   monthly budget.

12. **Live checks only touch your own computer.** The target must be localhost, 127.0.0.1, ::1 or a *.localhost
   name that resolves to loopback, proxy settings are ignored, and redirects aren't followed. By default only GET,
   HEAD and OPTIONS requests are sent (plus a short burst of failed sign-ins with a made-up account). Requests that
   could change data need an explicit opt-in and use placeholder IDs and empty bodies. Contents of exposed files are
   masked in the report. URLs are built by joining text onto the checked address, never with a URL resolver, so a
   record ID or path from the app can't move a request to another host.

   The optional two-account check takes session values for two test accounts you create. They're held in memory for
   that one scan and sent only to the checked address. They aren't written to the database, the job record, the log,
   findings or reports, and the dashboard doesn't save them in the browser. Error messages never repeat them. The check
   only sends GET requests, whatever the write option says. Record IDs read from the app only go into a URL if they
   contain nothing that could change the path.

13. **Scanned code can't stall a scan by being large or crafted to be slow.** Structural analysis skips files over 400 KB and
   minified files, bracket matching stops after 100 KB, and repeated searches stop after 300 matches per file. Patterns that
   read across a whole file have bounded repeats, and multi-line patterns never let a line's leading space run across line breaks.
   Files that aren't valid, or that hold the wrong types, are skipped rather than trusted, and a failure reading one kind of route
   can't lose the others. `tests/test_slow_input.py` runs the worst cases we know of against every file LadPock parses.

14. **The MCP server and the git hook only read.** `ladpock mcp` talks JSON-RPC over stdin/stdout to the client
   that started it. Its tools scan, list findings and build fix prompts; none edits code or settings, and results
   are masked like every other report. `ladpock hook install` writes one pre-commit hook. It refuses to overwrite
   an existing hook unless told to, keeps a backup, and restores it on removal.

## Limits

LadPock finds common, recognisable mistakes. It can't prove an application is secure, and it can't see business
logic, runtime configuration or anything outside the code. Treat a good grade as "no obvious problems found",
and work through the `--human` checklist as well.
