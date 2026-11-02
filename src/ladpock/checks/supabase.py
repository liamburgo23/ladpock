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
