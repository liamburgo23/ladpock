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

## Limits

LadPock finds common, recognisable mistakes. It can't prove an application is secure, and it can't see business
logic, runtime configuration or anything outside the code. Treat a good grade as "no obvious problems found",
and work through the `--human` checklist as well.
