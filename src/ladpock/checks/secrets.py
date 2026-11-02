"""Leaked and exposed credentials."""

from __future__ import annotations

import fnmatch
import re
from typing import Iterator

from ..files import JS_EXT, basename, is_env_file, is_env_template
from ..masking import JWT, LOCAL_DB_HOSTS, SECRET_PATTERNS, is_placeholder, jwt_claims
from ..models import Finding, Severity
from .base import CheckInfo, ScanContext, check

PUBLIC_PREFIX = r"(?:NEXT_PUBLIC_|VITE_|REACT_APP_|EXPO_PUBLIC_|NUXT_PUBLIC_|GATSBY_|PUBLIC_)"
SUPABASE_ADMIN_VAR = re.compile(rf"\b{PUBLIC_PREFIX}\w*(?:SERVICE_ROLE|SUPABASE_SECRET)\w*\b")
PUBLIC_SECRET_VAR = re.compile(
    rf"\b({PUBLIC_PREFIX}\w*(?:SECRET|PRIVATE|PASSWORD|PASSWD|ADMIN_KEY|DATABASE_URL|DB_URL|OPENAI|ANTHROPIC|"
    rf"STRIPE_SK|SK_LIVE|WEBHOOK_SECRET|RESEND_API|SENDGRID)\w*)\b"
)
SERVER_SUPABASE_ENV = re.compile(
    r"(?:process\.env|import\.meta\.env)\.(?:SUPABASE_SERVICE_ROLE_KEY|SUPABASE_SECRET_KEY|\w*SERVICE_ROLE\w*)"
)
CLIENT_DIRECTIVE = re.compile(r"""^\s*['"]use client['"]""", re.M)
# Public env prefixes only matter where a bundler can inline them: front-end code, env files and config.
BUNDLED_EXT = JS_EXT | {".json", ".jsonc", ".toml", ".yml", ".yaml", ".html"}
MCP_CONFIG_NAMES = {".mcp.json", "mcp.json", "claude_desktop_config.json"}
MCP_LITERAL = re.compile(r'"(\w*(?:KEY|TOKEN|SECRET|PASSWORD)\w*)"\s*:\s*"([^"$%{][^"]{7,})"', re.I)


def is_client_file(ctx: ScanContext, rel: str) -> bool:
    """Best guess at whether this file ends up in the browser bundle."""
    if not rel.endswith(tuple(JS_EXT)):
        return False
    text = ctx.index.read(rel) or ""
    if CLIENT_DIRECTIVE.search(text[:500]):
        return True
    if "nextjs" not in ctx.stack and ("vite" in ctx.stack or "react" in ctx.stack):
        return rel.startswith("src/") and "/server/" not in rel and "/api/" not in rel
    return False


@check(
    "LP-SEC-001", "Supabase admin key exposed to the browser", "secrets", Severity.CRITICAL,
    why="The service_role / secret key bypasses Row Level Security. Anyone who opens the site can read and change every table.",
    fix="Never use the service_role or sb_secret_ key in browser code or in a NEXT_PUBLIC_/VITE_ variable. Use the publishable "
        "(anon) key in the browser and keep the secret key in server-only code. Rotate the exposed key in the Supabase dashboard.",
    cwe=("CWE-200", "CWE-522"),
)
def supabase_admin_key_exposed(ctx: ScanContext, info: CheckInfo) -> Iterator[Finding]:
    for rel in ctx.index.iter(BUNDLED_EXT, include_env=True):
        client = is_client_file(ctx, rel)
        for i, line in enumerate(ctx.index.lines(rel), 1):
            if SUPABASE_ADMIN_VAR.search(line):
                if is_env_file(basename(rel)) and re.match(r"^\s*\w+\s*=\s*['\"]?\s*['\"]?\s*$", line):
                    continue  # declared but empty
                yield ctx.finding(info, rel, i, line, confidence="high")
            elif client and SERVER_SUPABASE_ENV.search(line):
                yield ctx.finding(info, rel, i, line, confidence="high",
                                  message="A Supabase admin key is read in a client component ('use client'). "
                                          "Either it ships to every visitor or the code only works because the key was made public.")


@check(
    "LP-SEC-002", "Secret exposed through a public environment variable", "secrets", Severity.HIGH,
    why="Variables starting NEXT_PUBLIC_, VITE_, REACT_APP_ or similar are copied into the JavaScript every visitor downloads.",
    fix="Rename the variable without the public prefix and only read it in server code (API routes, server actions, "
        "server components). Rotate the value, because it has already been published with the site.",
    cwe=("CWE-200",),
)
def public_env_secret(ctx: ScanContext, info: CheckInfo) -> Iterator[Finding]:
    seen: set[tuple[str, str]] = set()
    for rel in ctx.index.iter(BUNDLED_EXT, include_env=True):
        env = is_env_file(basename(rel))
        for i, line in enumerate(ctx.index.lines(rel), 1):
            match = PUBLIC_SECRET_VAR.search(line)
            if not match or SUPABASE_ADMIN_VAR.search(line) or (rel, match.group(1)) in seen:
                continue
            if env and re.match(r"^\s*\w+\s*=\s*['\"]?\s*['\"]?\s*$", line):
                continue
            seen.add((rel, match.group(1)))
            yield ctx.finding(info, rel, i, line)


@check(
    "LP-SEC-003", "Hardcoded credential in the code", "secrets", Severity.CRITICAL,
    why="Anything committed to a repository should be treated as public: it lives on in git history, forks and backups.",
    fix="Move the value into an environment variable that isn't committed (.env.local), read it from server code only, "
        "and rotate the credential with the provider, since the old value is already exposed.",
    cwe=("CWE-798",),
)
def hardcoded_credentials(ctx: ScanContext, info: CheckInfo) -> Iterator[Finding]:
    def scannable(rel: str) -> bool:
        name = basename(rel)
        return not is_env_file(name) or is_env_template(name)

    for rel in ctx.index.iter(pred=scannable):
        for i, line in enumerate(ctx.index.lines(rel), 1):
            if len(line) > 4000:
                continue
            hit = _classify_secret(line)
            if hit:
                label, severity = hit
                yield ctx.finding(info, rel, i, line, severity=severity, message=f"{label} found in a committed file. {info.why}",
                                  confidence="high" if severity >= Severity.HIGH else "medium", kind=label)


def _classify_secret(line: str) -> tuple[str, Severity] | None:
    for label, pattern, severity in SECRET_PATTERNS:
        match = pattern.search(line)
        if not match or is_placeholder(match.group(0)):
            continue
        if label == "Database URL with password":
            if match.group(2).lower() in LOCAL_DB_HOSTS or match.group(1).lower() in {"password", "postgres", "root", "secret", "pass"}:
                continue
        return label, severity
    for match in JWT.finditer(line):
        claims = jwt_claims(match.group(0)) or {}
        if claims.get("role") == "service_role":
            return "Supabase service_role key", Severity.CRITICAL
    return None


@check(
    "LP-SEC-004", ".env file committed to git", "secrets", Severity.HIGH,
    why="A committed .env file publishes every secret in it to anyone with access to the repository, including its history.",
    fix="Remove it from git (git rm --cached <file>), add it to .gitignore, and rotate every secret it contained. "
        "Deleting it in a new commit isn't enough: the old values stay in history.",
    cwe=("CWE-538",),
)
def env_committed(ctx: ScanContext, info: CheckInfo) -> Iterator[Finding]:
    if ctx.git_files is None:
        return
    for rel in sorted(ctx.git_files):
        name = basename(rel)
        if is_env_file(name) and not is_env_template(name):
            text = ctx.index.read(rel) or ""
            has_secret = any(_classify_secret(line) for line in text.splitlines())
            yield ctx.finding(info, rel, None, None, severity=Severity.CRITICAL if has_secret else Severity.HIGH,
                              confidence="high")


@check(
    "LP-SEC-005", ".env file not covered by .gitignore", "secrets", Severity.MEDIUM,
    why="One 'git add .' away from publishing your secrets.",
    fix="Add .env and .env*.local to .gitignore. Commit a .env.example with placeholder values instead.",
    cwe=("CWE-538",),
)
def env_not_ignored(ctx: ScanContext, info: CheckInfo) -> Iterator[Finding]:
    env_files = [rel for rel in ctx.index.paths if is_env_file(basename(rel)) and not is_env_template(basename(rel))]
    if not env_files:
        return
    patterns = []
    for line in (ctx.index.read(".gitignore") or "").splitlines():
        line = line.strip()
        if line and not line.startswith(("#", "!")):
            patterns.append(line.lstrip("/"))
    for rel in env_files:
        if ctx.git_files is not None and rel in ctx.git_files:
            continue  # LP-SEC-004 already covers committed files
        name = basename(rel)
        if not any(fnmatch.fnmatch(name, p) or fnmatch.fnmatch(rel, p) for p in patterns):
            yield ctx.finding(info, rel, None, None, confidence="medium")


@check(
    "LP-SEC-006", "Credential written into an AI tool config", "secrets", Severity.HIGH,
    why="MCP and AI assistant config files are often committed or shared, and the keys in them usually have broad access.",
    fix="Reference an environment variable instead of pasting the key (most MCP clients support ${VAR} or an env block "
        "that reads from your shell). Rotate the key.",
    cwe=("CWE-798",),
)
def ai_config_secrets(ctx: ScanContext, info: CheckInfo) -> Iterator[Finding]:
    def is_ai_config(rel: str) -> bool:
        lower = rel.lower()
        in_ai_dir = lower.startswith((".cursor/", ".vscode/mcp", ".claude/", ".windsurf/")) and lower.endswith(".json")
        return basename(lower) in MCP_CONFIG_NAMES or in_ai_dir

    for rel in ctx.index.iter(pred=is_ai_config, include_tests=True):
        tracked = ctx.git_files is None or rel in ctx.git_files
        for i, line in enumerate(ctx.index.lines(rel), 1):
            match = MCP_LITERAL.search(line)
            if match and not is_placeholder(match.group(2)):
                yield ctx.finding(info, rel, i, line, severity=Severity.HIGH if tracked else Severity.MEDIUM)
