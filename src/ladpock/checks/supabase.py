"""Backend-as-a-service rules: Supabase Row Level Security and Firebase rules."""

from __future__ import annotations

import re
from typing import Iterator

from ..files import JS_EXT, basename
from ..models import Finding, Severity
from .base import CheckInfo, ScanContext, check, grep

CREATE_TABLE = re.compile(r"(?im)^[ \t]*create\s+table\s+(?:if\s+not\s+exists\s+)?((?:\"?\w+\"?\.)?\"?\w+\"?)")
ENABLE_RLS = re.compile(
    r"(?is)alter\s+table\s+(?:if\s+exists\s+)?(?:only\s+)?((?:\"?\w+\"?\.)?\"?\w+\"?)\s+enable\s+row\s+level\s+security"
)
POLICY = re.compile(r"(?is)create\s+policy\s+.+?\s+on\s+((?:\"?\w+\"?\.)?\"?\w+\"?)(.*)")
POLICY_TRUE = re.compile(r"(?is)\busing\s*\(\s*true\s*\)|\bwith\s+check\s*\(\s*true\s*\)")
POLICY_CMD = re.compile(r"(?is)\bfor\s+(all|select|insert|update|delete)\b")
ANY_SIGNED_IN = re.compile(r"(?is)auth\.role\(\)\s*=\s*'authenticated'|auth\.uid\(\)\s+is\s+not\s+null|\bto\s+authenticated\b[^;]*\b(?:using|with\s+check)\s*\(\s*true\s*\)")
OWNER_RULE = re.compile(r"(?is)auth\.uid\(\)\s*=|=\s*\(?\s*(?:select\s+)?auth\.uid\(\)|\bowner\b")
FUNCTION_START = re.compile(r"(?is)create\s+(?:or\s+replace\s+)?function\s+((?:\"?\w+\"?\.)?\"?\w+\"?)")
VIEW = re.compile(r"(?is)create\s+(?:or\s+replace\s+)?(?:materialized\s+)?view\s+((?:\"?\w+\"?\.)?\"?\w+\"?)([^;]{0,20000});")
BUCKET_PUBLIC = re.compile(r"(?is)insert\s+into\s+storage\.buckets[^;]{0,2000}\btrue\b|\bcreateBucket\([^)]{0,500}\bpublic\s*:\s*true")
STORAGE_POLICY = re.compile(r"(?is)create\s+policy\s+.{1,300}?\s+on\s+storage\.objects\b(.*)")


def _table(name: str) -> tuple[str, str]:
    parts = name.replace('"', "").lower().split(".")
    return (parts[0], parts[1]) if len(parts) == 2 else ("public", parts[0])


@check(
    "LP-SUPA-001", "Supabase table without Row Level Security", "authz", Severity.HIGH,
    why="Tables in the public schema are reachable with the anon key that ships in your front end. Without RLS, anyone "
        "can read and change every row.",
    fix="Add 'alter table <name> enable row level security;' in a migration and write policies that limit rows to "
        "their owner (for example using (auth.uid() = user_id)). If you enabled RLS in the dashboard instead, add it "
        "to your migrations so it can't be lost.",
    cwe=("CWE-284", "CWE-862"),
    stacks=("supabase",),
)
def tables_without_rls(ctx: ScanContext, info: CheckInfo) -> Iterator[Finding]:
    sql_files = list(ctx.index.iter({".sql"}, include_tests=False))
    enabled = set()
    for rel in sql_files:
        for match in ENABLE_RLS.finditer(ctx.index.read(rel) or ""):
            enabled.add(_table(match.group(1)))
    for rel in sql_files:
        text = ctx.index.read(rel) or ""
        for match in CREATE_TABLE.finditer(text):
            schema, table = _table(match.group(1))
            if schema == "public" and (schema, table) not in enabled:
                lineno = text.count("\n", 0, match.start()) + 1
                yield ctx.finding(info, rel, lineno, match.group(0), confidence="medium",
                                  message=f"Table '{table}' is created without enabling RLS in any migration. {info.why}")


@check(
    "LP-SUPA-002", "Supabase policy lets everyone through", "authz", Severity.HIGH,
    why="A policy of 'using (true)' or 'with check (true)' allows every user, including anonymous visitors, for that operation.",
    fix="Restrict the policy, for example 'using (auth.uid() = user_id)'. Keep 'true' only for data that is genuinely "
        "public and read-only.",
    cwe=("CWE-284",),
    stacks=("supabase",),
)
def permissive_policies(ctx: ScanContext, info: CheckInfo) -> Iterator[Finding]:
    for rel in ctx.index.iter({".sql"}):
        text = ctx.index.read(rel) or ""
        offset = 0
        for statement in text.split(";"):
            start = offset
            offset += len(statement) + 1
            match = POLICY.search(statement)
            if not match or not POLICY_TRUE.search(match.group(2)):
                continue
            cmd_match = POLICY_CMD.search(match.group(2))
            command = cmd_match.group(1).lower() if cmd_match else "all"
            table = _table(match.group(1))[1]
            lineno = text.count("\n", 0, start + match.start()) + 1
            if command == "select":
                yield ctx.finding(info, rel, lineno, f"policy on {table} for select using (true)", severity=Severity.LOW,
                                  message=f"Anyone can read every row of '{table}'. Fine for public content, wrong for user data.")
            else:
                yield ctx.finding(info, rel, lineno, f"policy on {table} for {command} using (true)", confidence="high",
                                  message=f"Anyone can {command} rows in '{table}'. {info.why}")


def _statements(text: str) -> Iterator[tuple[int, str]]:
    offset = 0
    for statement in text.split(";"):
        yield offset, statement
        offset += len(statement) + 1


@check(
    "LP-SUPA-005", "Supabase policy lets any signed-in user through", "authz", Severity.HIGH,
    why="This only checks that someone is signed in, and anyone can sign up. Every account can reach every row, not just its own.",
    fix="Compare the row's owner with the user, for example 'using (auth.uid() = user_id)'. Keep this only for data every "
        "signed-in user should share.",
    cwe=("CWE-284", "CWE-639"),
    stacks=("supabase",),
)
def any_signed_in_policies(ctx: ScanContext, info: CheckInfo) -> Iterator[Finding]:
    for rel in ctx.index.iter({".sql"}):
        text = ctx.index.read(rel) or ""
        for start, statement in _statements(text):
            match = POLICY.search(statement)
            if not match or not ANY_SIGNED_IN.search(match.group(2)) or OWNER_RULE.search(match.group(2)):
                continue
            cmd = POLICY_CMD.search(match.group(2))
            command = cmd.group(1).lower() if cmd else "all"
            table = _table(match.group(1))[1]
            yield ctx.finding(info, rel, text.count("\n", 0, start + match.start()) + 1, f"policy on {table} for {command}",
                              severity=Severity.MEDIUM if command == "select" else Severity.HIGH, confidence="low" if command == "select" else "medium",
                              message=f"Any signed-in user can {command} every row in '{table}'. {info.why}")


@check(
    "LP-SUPA-006", "Database function runs with admin rights and no fixed search path", "authz", Severity.MEDIUM,
    why="A SECURITY DEFINER function runs as its owner and skips Row Level Security. Without a fixed search_path, someone able "
        "to create objects can make it call their code with those rights.",
    fix="Add 'set search_path = \'\'' to the function and use full names like public.orders inside it. Use SECURITY INVOKER "
        "unless the function truly needs to bypass RLS, and check the caller inside it if it does.",
    cwe=("CWE-426", "CWE-269"),
    stacks=("supabase",),
)
def definer_without_search_path(ctx: ScanContext, info: CheckInfo) -> Iterator[Finding]:
    for rel in ctx.index.iter({".sql"}):
        text = ctx.index.read(rel) or ""
        starts = list(FUNCTION_START.finditer(text))
        for i, match in enumerate(starts):
            block = text[match.start(): starts[i + 1].start() if i + 1 < len(starts) else len(text)]
            definer = re.search(r"(?i)\bsecurity\s+definer\b", block)
            if definer and not re.search(r"(?i)\bsearch_path\b", block):
                yield ctx.finding(info, rel, text.count("\n", 0, match.start()) + 1, match.group(0))


@check(
    "LP-SUPA-007", "Database view skips Row Level Security", "authz", Severity.MEDIUM,
    why="A view runs with its creator's rights by default, so Row Level Security on the tables underneath doesn't apply. "
        "Anyone with the public anon key can read everything the view shows.",
    fix="Create it with 'with (security_invoker = true)' (Postgres 15+), or move it out of the public schema. Never expose "
        "auth.users through a view.",
    cwe=("CWE-284", "CWE-200"),
    stacks=("supabase",),
)
def views_skip_rls(ctx: ScanContext, info: CheckInfo) -> Iterator[Finding]:
    for rel in ctx.index.iter({".sql"}):
        text = ctx.index.read(rel) or ""
        for match in VIEW.finditer(text):
            schema, name = _table(match.group(1))
            if schema != "public" or re.search(r"(?i)security_invoker\s*=\s*(?:true|on)", match.group(2)):
                continue
            lineno = text.count("\n", 0, match.start()) + 1
            if re.search(r"(?i)\bauth\.users\b", match.group(2)):
                yield ctx.finding(info, rel, lineno, f"view {name} over auth.users", severity=Severity.CRITICAL, confidence="high",
                                  message=f"The view '{name}' exposes your users table, including email addresses, to anyone with "
                                          "the public anon key.")
            else:
                yield ctx.finding(info, rel, lineno, f"view {name}", confidence="low")


@check(
    "LP-SUPA-008", "Supabase storage open to everyone", "authz", Severity.HIGH,
    why="A storage policy on who can upload, replace or delete files that doesn't check the owner lets people overwrite or delete "
        "each other's files.",
    fix="Add an owner check, for example 'auth.uid() = owner', or put files in a folder named after the user and check that. "
        "Use private buckets with signed URLs for anything that isn't public.",
    cwe=("CWE-284",),
    stacks=("supabase",),
)
def storage_policies(ctx: ScanContext, info: CheckInfo) -> Iterator[Finding]:
    for rel in ctx.index.iter({".sql", ".ts", ".js", ".tsx", ".jsx", ".mjs"}):
        text = ctx.index.read(rel) or ""
        if "storage" not in text and "createBucket" not in text:
            continue
        for match in BUCKET_PUBLIC.finditer(text):
            yield ctx.finding(info, rel, text.count("\n", 0, match.start()) + 1, match.group(0)[:120], severity=Severity.LOW, confidence="low",
                              message="This bucket is public, so anyone with a link can read its files. That's right for public "
                                      "images and wrong for anything users upload privately.")
        if not rel.endswith(".sql"):
            continue
        for start, statement in _statements(text):
            match = STORAGE_POLICY.search(statement)
            if not match:
                continue
            cmd = POLICY_CMD.search(match.group(1))
            command = cmd.group(1).lower() if cmd else "all"
            if command != "select" and not re.search(r"(?i)auth\.uid\(\)|\bowner\b", match.group(1)):
                yield ctx.finding(info, rel, text.count("\n", 0, start + match.start()) + 1, f"storage policy for {command}", confidence="medium")


FIRE_ANY_SIGNED_IN = re.compile(r"allow\s+([\w\s,]+):\s*if\s+request\.auth\s*!=\s*null\s*;")


@check(
    "LP-SUPA-009", "Firebase rules let any signed-in user through", "authz", Severity.HIGH,
    why="This only checks that someone is signed in, and anyone can create an account. Every account can reach every document "
        "under this path, not just its own.",
    fix="Compare the document's owner with the user, for example 'allow read, write: if request.auth.uid == userId;' or "
        "resource.data.ownerId == request.auth.uid.",
    cwe=("CWE-284", "CWE-639"),
)
def firebase_any_signed_in(ctx: ScanContext, info: CheckInfo) -> Iterator[Finding]:
    for rel in ctx.index.iter({".rules"}, include_tests=False):
        lines = ctx.index.lines(rel)
        for i, line in enumerate(lines, 1):
            if FIRE_ANY_SIGNED_IN.search(line):
                wildcard = any("{document=**}" in earlier or "{allPaths=**}" in earlier for earlier in lines[max(0, i - 3): i])
                yield ctx.finding(info, rel, i, line, confidence="medium" if wildcard else "low")


@check(
    "LP-SUPA-003", "Firebase rules open to everyone", "authz", Severity.CRITICAL,
    why="These security rules let anyone on the internet read or write the database or storage bucket.",
    fix="Require authentication and check ownership, for example 'allow read, write: if request.auth != null && "
        "request.auth.uid == userId;'. Test mode rules must never reach production.",
    cwe=("CWE-284",),
)
def firebase_open_rules(ctx: ScanContext, info: CheckInfo) -> Iterator[Finding]:
    open_rule = re.compile(r"allow\s+[\w\s,]+:\s*if\s+true\s*;|allow\s+(?:read|write)[\w\s,]*;\s*$")
    test_mode = re.compile(r"allow\s+[\w\s,]+:\s*if\s+request\.time\s*<")
    rtdb_open = re.compile(r"\"\.(?:read|write)\"\s*:\s*(?:true|\"true\")")
    for rel in ctx.index.iter({".rules"}, names={"database.rules.json"}, include_tests=False):
        rtdb = basename(rel) == "database.rules.json"
        for i, line in enumerate(ctx.index.lines(rel), 1):
            if (rtdb and rtdb_open.search(line)) or (not rtdb and open_rule.search(line)):
                yield ctx.finding(info, rel, i, line, confidence="high")
            elif not rtdb and test_mode.search(line):
                yield ctx.finding(info, rel, i, line, severity=Severity.HIGH,
                                  message="Test-mode rules allow everyone until the date passes, then lock everyone out.")


@check(
    "LP-SUPA-004", "Supabase getSession() trusted on the server", "auth", Severity.MEDIUM,
    why="On the server, getSession() reads the session from cookies without re-validating it, so it can be spoofed. "
        "Supabase recommends getUser() (or getClaims()) for authorization decisions.",
    fix="Use supabase.auth.getUser() in server code that decides what a user may do.",
    cwe=("CWE-287",),
    stacks=("supabase",),
)
def server_get_session(ctx: ScanContext, info: CheckInfo) -> Iterator[Finding]:
    server_path = re.compile(r"(?:^|/)(?:middleware|proxy)\.[jt]s$|/route\.[jt]sx?$|/api/|/server/|actions?\.[jt]sx?$")
    pattern = re.compile(r"\.auth\.getSession\s*\(")
    for rel, lineno, line, _ in grep(ctx, pattern, exts=JS_EXT):
        text = ctx.index.read(rel) or ""
        if server_path.search(rel) or re.search(r"""^\s*['"]use server['"]""", text[:300], re.M):
            yield ctx.finding(info, rel, lineno, line)
