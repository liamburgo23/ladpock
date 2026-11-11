"""LadPock inside your workflow: a Model Context Protocol server so Claude Code
(or any MCP client) can scan while it writes code, and a git pre-commit hook
that stops secrets being committed.

The MCP server speaks JSON-RPC over stdin/stdout using only the standard
library. It never edits code: the assistant does that. Besides reading
projects, it keeps the record of a fix run and of risks the assistant accepted
(see fixloop.py), which the dashboard shows.
"""

from __future__ import annotations

import json
import shutil
import subprocess
import sys
from pathlib import Path
from typing import Callable, TextIO

from . import __version__, fixloop, report, scoring
from .checks import ScanContext, inline_ignored, run_all
from .db import DB
from .files import FileIndex
from .gitutil import safe_env
from .models import Severity, finding_from_dict
from .routes import analyze, gaps
from .scan import PROFILES, run_scan
from .stack import detect

PROTOCOL_VERSIONS = ("2025-06-18", "2025-03-26", "2024-11-05")
SEVERITY_NAMES = [s.label for s in Severity if s > Severity.INFO]

PROMPTS = [
    {"name": "ladpock", "title": "LadPock: what did it find?",
     "description": "Scan the project you're working in and summarise what LadPock found",
     "arguments": []},
    {"name": "fix", "title": "LadPock: fix findings one by one",
     "description": "Work through LadPock's findings one at a time, checking each fix with a re-scan",
     "arguments": [{"name": "which", "description": "critical, high (default), medium, low or all; or what the user asked for in words",
                    "required": False}]},
]


def prompt_text(name: str, args: dict) -> str:
    if name == "ladpock":
        return ("Use LadPock on the project in the folder you're working in. Call ladpock_scan with that folder's absolute path. "
                "Then tell me in a few lines: the grade, the most serious problems (with file and line), and any known risks that "
                "were accepted. Finish by offering to fix them one by one with ladpock_fix_start.")
    if name == "fix":
        which = str(args.get("which") or "").strip() or "high"
        return ("Use LadPock to fix this project's security findings one at a time. Call ladpock_fix_start with the absolute path of "
                f"the folder you're working in and which='{which}' (if that isn't one of critical, high, medium, low or all, pick the "
                "closest, or pass the refs I meant). Then follow LadPock's instructions exactly: fix one finding, call "
                "ladpock_fix_check, commit if it says to, and carry on until it says you're done or says STOP. "
                "When it's finished, tell me what was fixed, what's left for me, and any risks you accepted and why.")
    raise ToolError(f"Unknown prompt {name}")


TOOLS = [
    {
        "name": "ladpock_scan",
        "description": "Scan a project folder for security problems (leaked secrets, missing auth or ownership checks, "
                       "injection, unsafe config, vulnerable dependencies and more) and return its grade and findings "
                       "with file:line locations and fixes. Run it after changing code that touches auth, data access, "
                       "payments, file handling or configuration.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "path": {"type": "string", "description": "Absolute path of the project folder"},
                "profile": {"type": "string", "enum": sorted(PROFILES), "description": "quick, standard (default) or full"},
                "offline": {"type": "boolean", "description": "Skip the online vulnerability data refresh"},
                "files": {"type": "array", "items": {"type": "string"},
                          "description": "Only report findings in these files (paths relative to the project)"},
            },
            "required": ["path"],
        },
    },
    {
        "name": "ladpock_findings",
        "description": "List the findings from the most recent LadPock scan of a project without rescanning.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "path": {"type": "string", "description": "Absolute path of the project folder"},
                "min_severity": {"type": "string", "enum": SEVERITY_NAMES, "description": "Lowest severity to include"},
                "file": {"type": "string", "description": "Only findings in this file (relative path)"},
            },
            "required": ["path"],
        },
    },
    {
        "name": "ladpock_routes",
        "description": "List every API endpoint LadPock found (Next.js, SvelteKit, Remix, Nuxt, Astro, Express, Fastify, Hono, "
                       "Koa, NestJS, FastAPI, Flask, Django, Spring, Go, Rails, Laravel, ASP.NET, tRPC, Convex, GraphQL, Firebase, Supabase Edge, "
                       "Vercel, Netlify, Cloudflare, AWS Lambda) with whether it checks login, "
                       "record ownership, input validation and rate limits.",
        "inputSchema": {"type": "object", "properties": {"path": {"type": "string"}}, "required": ["path"]},
    },
    {
        "name": "ladpock_explain_grade",
        "description": "Explain why a project's last scan didn't get an A+ and what to fix, most serious first, with "
                       "the grade reached after each round of fixes.",
        "inputSchema": {"type": "object", "properties": {"path": {"type": "string"}}, "required": ["path"]},
    },
    {
        "name": "ladpock_fix_start",
        "description": "Start fixing this project's security findings one at a time, worst first. LadPock re-scans, makes the list, and "
                       "gives you the first finding with how to fix it. After each fix call ladpock_fix_check, which confirms the fix "
                       "with a fresh scan and gives you the next one. Use this when the user asks to fix what LadPock found.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "path": {"type": "string", "description": "Absolute path of the project folder (the folder you are working in)"},
                "which": {"type": "string", "enum": list(fixloop.SCOPES),
                          "description": "Lowest severity to include: critical, high (default), medium, low, or all"},
                "refs": {"type": "array", "items": {"type": "string"}, "description": "Only these findings (refs from ladpock_findings)"},
                "notes": {"type": "string", "description": "Anything the user said that should guide every fix"},
            },
            "required": ["path"],
        },
    },
    {
        "name": "ladpock_fix_check",
        "description": "Call after fixing the finding LadPock gave you. LadPock re-scans and says whether it's fixed (and whether the change "
                       "introduced anything new), tells you whether to commit, and gives you the next finding.",
        "inputSchema": {
            "type": "object",
            "properties": {"path": {"type": "string", "description": "Absolute path of the project folder (the folder you are working in)"},
                           "note": {"type": "string", "description": "One line on what you changed, shown to the user"}},
            "required": ["path"],
        },
    },
    {
        "name": "ladpock_fix_next",
        "description": "Show the finding you're working on in the current fix run (or the next one), for example after a break.",
        "inputSchema": {"type": "object", "properties": {"path": {"type": "string", "description": "Absolute path of the project folder (the folder you are working in)"}}, "required": ["path"]},
    },
    {
        "name": "ladpock_fix_skip",
        "description": "Leave the current finding for the user (for example it needs a decision only they can make) and move to the next.",
        "inputSchema": {
            "type": "object",
            "properties": {"path": {"type": "string", "description": "Absolute path of the project folder (the folder you are working in)"},
                           "reason": {"type": "string", "description": "Why, in a sentence the user can act on"},
                           "ref": {"type": "string", "description": "The finding's ref, if not the current one"}},
            "required": ["path", "reason"],
        },
    },
    {
        "name": "ladpock_accept_risk",
        "description": "Accept a finding as a known risk because it isn't a real problem here or is a deliberate choice. It is never hidden: "
                       "it's listed under Known risks with your reason, the grade notes it, and the user can undo it. Not allowed for "
                       "critical findings. Tell the user whenever you do this.",
        "inputSchema": {
            "type": "object",
            "properties": {"path": {"type": "string", "description": "Absolute path of the project folder (the folder you are working in)"},
                           "ref": {"type": "string", "description": "The finding's ref"},
                           "reason": {"type": "string", "description": "Why this is acceptable, in a sentence"},
                           "days": {"type": "integer", "minimum": 1, "maximum": fixloop.MAX_ACCEPT_DAYS,
                                    "description": "How long until it's checked again (default 90)"}},
            "required": ["path", "ref", "reason"],
        },
    },
    {
        "name": "ladpock_fix_stop",
        "description": "Stop the current fix run, for example when the user says to stop. What's done stays done.",
        "inputSchema": {"type": "object", "properties": {"path": {"type": "string", "description": "Absolute path of the project folder (the folder you are working in)"}}, "required": ["path"]},
    },
    {
        "name": "ladpock_fix_prompt",
        "description": "A step-by-step fix list for the last scan's findings (or the given refs), with secrets masked.",
        "inputSchema": {
            "type": "object",
            "properties": {"path": {"type": "string"}, "refs": {"type": "array", "items": {"type": "string"}}},
            "required": ["path"],
        },
    },
]


class ToolError(Exception):
    pass


def _project(db: DB, path: str):
    if not str(path or "").strip() or not Path(path).expanduser().is_absolute():
        raise ToolError("path must be the absolute path of the project folder")
    root = Path(path).expanduser().resolve()
    if not root.is_dir():
        raise ToolError(f"{root} is not a folder")
    return root, db.get_project(root)


def _latest(db: DB, path: str) -> tuple[Path, list[dict], object]:
    root, row = _project(db, path)
    scan = db.latest_scan(row["id"]) if row else None
    if not scan:
        raise ToolError(f"{root.name} hasn't been scanned yet. Call ladpock_scan first.")
    return root, db.scan_findings(scan["id"]), scan


def _format_findings(findings: list[dict], limit: int = 40) -> str:
    if not findings:
        return "No findings."
    order = {s.label: -int(s) for s in Severity}
    lines = []
    for f in sorted(findings, key=lambda f: (order.get(f["severity"], 0), f.get("file") or "", f.get("line") or 0))[:limit]:
        where = f"{f['file']}:{f['line']}" if f.get("file") and f.get("line") else (f.get("file") or "project")
        lines.append(f"- [{f['severity']}] {f['title']} ({f['check_id']}, ref {f['ref']}) at {where}\n"
                     f"  Why: {f.get('message', '')}\n  Fix: {f.get('fix', '')}")
    if len(findings) > limit:
        lines.append(f"...and {len(findings) - limit} more (filter with min_severity or file).")
    return "\n".join(lines)


def _known_risks(scan) -> str:
    """Accepted risks are part of every answer, so an assistant can't quietly make a finding disappear."""
    summary = json.loads(scan["summary"] or "{}") if scan else {}
    accepted = summary.get("accepted") or []
    if not accepted:
        return ""
    lines = [f"\nKnown risks ({len(accepted)}, accepted, not counted in the grade):"]
    for a in accepted:
        who = "an AI assistant" if a.get("by") == "agent" else "the user"
        lines.append(f"- [{a.get('severity')}] {a.get('title')} at {a.get('file') or 'project'} (ref {a.get('ref')}), accepted by {who}: "
                     f"{a.get('reason')}")
    return "\n".join(lines)


CLIENT: dict = {}  # who's connected (from initialize), recorded on fix runs so the dashboard can say which assistant did the work


def call_tool(db: DB, name: str, args: dict) -> str:
    if name == "ladpock_scan":
        profile = args.get("profile") or "standard"
        if profile not in PROFILES:
            raise ToolError("profile must be quick, standard or full")
        root, _ = _project(db, args["path"])
        result = run_scan(root, db, profile=profile, offline=bool(args.get("offline")), log=lambda _m: None)
        findings = [f.to_dict() for f in result.findings]
        wanted = {str(p).replace("\\", "/") for p in args.get("files") or []}
        if wanted:
            findings = [f for f in findings if f.get("file") in wanted]
        card = result.scorecard
        head = (f"{root.name}: grade {card.grade} ({card.overall}/100), {len(result.findings)} finding(s)"
                + (f", {len(findings)} in the requested files" if wanted else "") + ".")
        if result.changes:
            c = result.changes
            head += (f" Since the previous scan: {c['previous_grade']} -> {card.grade}, {c['fixed_count']} fixed, "
                     f"{len(c['new'])} new.")
        return (f"{head}\n{_format_findings(findings)}" + _known_risks(db.latest_scan(result.project_id))
                + "\n\nCall ladpock_explain_grade for the path to A+, or ladpock_fix_start to fix them one by one.")
    if name == "ladpock_findings":
        root, findings, scan = _latest(db, args["path"])
        floor = Severity.parse(args["min_severity"]) if args.get("min_severity") else Severity.INFO
        findings = [f for f in findings if Severity.parse(f["severity"]) >= floor
                    and (not args.get("file") or f.get("file") == str(args["file"]).replace("\\", "/"))]
        return (f"{root.name}: last scanned {scan['finished_at']}, grade {scan['grade']}.\n{_format_findings(findings)}"
                + _known_risks(scan))
    if name == "ladpock_routes":
        root, _ = _project(db, args["path"])
        routes = analyze(FileIndex(root))
        if not routes:
            return ("No HTTP routes found (supported: Next.js, SvelteKit, Remix, Nuxt, Astro, Express, Fastify, Hono, Koa, NestJS, "
                    "FastAPI, Flask, Django, Spring, Go, Rails, Laravel, ASP.NET, tRPC, Convex, GraphQL, Firebase, Supabase Edge, Vercel, Netlify, "
                    "Cloudflare, AWS Lambda).")
        return "\n".join(f"{r.method} {r.path} ({r.file}:{r.line}) auth={r.auth} owner={r.owner} validation={r.validation} "
                         f"rate_limit={r.rate_limit}" + (f" GAPS: {', '.join(gaps(r))}" if gaps(r) else "") for r in routes)
    if name == "ladpock_explain_grade":
        root, findings, scan = _latest(db, args["path"])
        summary = json.loads(scan["summary"] or "{}")
        categories = {c["key"] for c in summary.get("categories", [])} or None
        a = scoring.explain([finding_from_dict(f) for f in findings], categories)
        lines = [f"{root.name}: {a['grade']} ({a['score']}/100)."]
        if a["cap"]:
            lines.append(f"Limited to {a['cap']['limit']} by an open {a['cap']['severity']} finding (categories average {a['average']}).")
        for c in a["categories"]:
            if c["deductions"]:
                lines.append(f"{c['name']}: {c['grade']} ({c['score']}), " + "; ".join(
                    f"-{d['points']} {d['title']} at {d['file'] or 'project'}" for d in c["deductions"][:5]))
        for i, step in enumerate(a["plan"], 1):
            lines.append(f"Step {i}: fix {step['count']} {step['severity']} finding(s) -> {step['grade']} ({step['score']}).")
        return "\n".join(lines)
    if name == "ladpock_fix_start":
        return fixloop.start(db, args["path"], str(args.get("which") or "high"), args.get("refs") or None, str(args.get("notes") or ""),
                             agent=CLIENT.get("name", ""), offline=bool(args.get("offline")))
    if name == "ladpock_fix_check":
        return fixloop.check(db, args["path"], str(args.get("note") or ""), offline=bool(args.get("offline")))
    if name == "ladpock_fix_next":
        return fixloop.next_item(db, args["path"])
    if name == "ladpock_fix_skip":
        return fixloop.skip(db, args["path"], str(args.get("reason") or ""), args.get("ref") or None)
    if name == "ladpock_accept_risk":
        return fixloop.accept_risk(db, args["path"], str(args.get("ref") or ""), str(args.get("reason") or ""), args.get("days", 90))
    if name == "ladpock_fix_stop":
        return fixloop.stop(db, args["path"])
    if name == "ladpock_fix_prompt":
        root, findings, _ = _latest(db, args["path"])
        refs = set(args.get("refs") or [])
        chosen = [f for f in findings if f["ref"] in refs] if refs else findings
        return report.fix_prompt(root.name, chosen) if chosen else "Nothing to fix."
    raise ToolError(f"Unknown tool {name}")


def handle(message: dict, db_factory: Callable[[], DB]) -> dict | None:
    """One JSON-RPC message in, one response out (None for notifications)."""
    method, msg_id = message.get("method"), message.get("id")
    if msg_id is None:
        return None
    if method == "initialize":
        params = message.get("params") or {}
        requested = params.get("protocolVersion")
        info = params.get("clientInfo")
        if isinstance(info, dict) and isinstance(info.get("name"), str):
            CLIENT["name"] = info["name"][:80]
        return {"jsonrpc": "2.0", "id": msg_id, "result": {
            "protocolVersion": requested if requested in PROTOCOL_VERSIONS else PROTOCOL_VERSIONS[0],
            "capabilities": {"tools": {}, "prompts": {}},
            "serverInfo": {"name": "ladpock", "version": __version__},
            "instructions": "LadPock checks the user's own projects for security problems. Scan after changes to "
                            "auth, data access, payments, file handling or config, and fix high and critical findings. "
                            "When the user asks to fix what LadPock found, use ladpock_fix_start and follow its instructions: "
                            "one finding at a time, each confirmed with ladpock_fix_check.",
        }}
    if method == "ping":
        return {"jsonrpc": "2.0", "id": msg_id, "result": {}}
    if method == "tools/list":
        return {"jsonrpc": "2.0", "id": msg_id, "result": {"tools": TOOLS}}
    if method == "prompts/list":
        return {"jsonrpc": "2.0", "id": msg_id, "result": {"prompts": PROMPTS}}
    if method == "prompts/get":
        params = message.get("params") or {}
        try:
            text = prompt_text(str(params.get("name")), params.get("arguments") or {})
        except ToolError as exc:
            return {"jsonrpc": "2.0", "id": msg_id, "error": {"code": -32602, "message": str(exc)}}
        return {"jsonrpc": "2.0", "id": msg_id, "result": {
            "description": next(p["description"] for p in PROMPTS if p["name"] == params.get("name")),
            "messages": [{"role": "user", "content": {"type": "text", "text": text}}]}}
    if method == "tools/call":
        params = message.get("params") or {}
        db = db_factory()
        try:
            text, error = call_tool(db, str(params.get("name")), params.get("arguments") or {}), False
        except (ToolError, fixloop.FixError, FileNotFoundError, KeyError, ValueError) as exc:
            text, error = f"Error: {exc}", True
        finally:
            db.close()
        return {"jsonrpc": "2.0", "id": msg_id, "result": {"content": [{"type": "text", "text": text}], "isError": error}}
    return {"jsonrpc": "2.0", "id": msg_id, "error": {"code": -32601, "message": f"Method not found: {method}"}}


def serve_mcp(stdin: TextIO = sys.stdin, stdout: TextIO = sys.stdout, db_factory: Callable[[], DB] = DB) -> int:
    for line in stdin:
        line = line.strip()
        if not line:
            continue
        try:
            message = json.loads(line)
        except json.JSONDecodeError:
            reply = {"jsonrpc": "2.0", "id": None, "error": {"code": -32700, "message": "Parse error"}}
        else:
            reply = handle(message, db_factory) if isinstance(message, dict) else None
        if reply is not None:
            stdout.write(json.dumps(reply) + "\n")
            stdout.flush()
    return 0


# ---------- git pre-commit hook ----------

HOOK_MARKER = "Added by LadPock"
# File-local checks that are serious enough to stop a commit: leaked credentials and hidden characters.
BLOCKING = {"LP-SEC-001", "LP-SEC-002", "LP-SEC-003", "LP-SEC-004", "LP-SEC-006", "LP-SEC-007", "LP-SUP-004",
            "LP-DOCKER-002", "LP-INFRA-004", "LP-TF-005"}


def _git(root: Path, *args: str) -> subprocess.CompletedProcess | None:
    git = shutil.which("git")
    if not git:
        return None
    try:
        return subprocess.run([git, "-c", "core.fsmonitor=false", "-C", str(root), *args], capture_output=True,
                              timeout=60, env=safe_env())
    except (OSError, subprocess.TimeoutExpired):
        return None


def repo_root(path: Path) -> Path | None:
    proc = _git(path, "rev-parse", "--show-toplevel")
    return Path(proc.stdout.decode().strip()) if proc and proc.returncode == 0 else None


def precommit(path: Path, out: TextIO = sys.stderr) -> int:
    """Scan the files being committed. Returns 1 (block) if they add secrets."""
    root = repo_root(path)
    if not root:
        print("LadPock: not inside a git repository.", file=out)
        return 0
    proc = _git(root, "diff", "--cached", "--name-only", "--diff-filter=ACMR", "-z")
    staged = {p for p in (proc.stdout.decode("utf-8", "replace").split("\0") if proc else []) if p}
    if not staged:
        return 0
    index = FileIndex(root)
    index.paths = [p for p in index.paths if p in staged]
    index._set = set(index.paths)
    ctx = ScanContext(root=root, index=index, stack=set(detect(index)), git_files=staged)
    findings, _ = run_all(ctx, {"secrets", "supply-chain"})
    blocking = [f for f in findings if f.check_id in BLOCKING and f.severity >= Severity.HIGH and not inline_ignored(ctx, f)]
    if not blocking:
        return 0
    print(f"LadPock stopped this commit: {len(blocking)} problem(s) in the staged files.\n", file=out)
    for f in blocking:
        print(f"  [{f.severity.label}] {f.title}\n    {f.location}  {f.snippet or ''}\n    Fix: {f.fix}\n", file=out)
    print("Remove the secret (and rotate it if it was ever pushed), then commit again.\n"
          "If it's a false alarm, add a 'ladpock-ignore' comment on the line, or skip the check once with "
          "git commit --no-verify.", file=out)
    return 1


def _hooks_dir(root: Path) -> tuple[Path, bool]:
    """(hooks folder, managed by another tool such as husky)."""
    proc = _git(root, "config", "--get", "core.hooksPath")
    custom = proc.stdout.decode().strip() if proc and proc.returncode == 0 else ""
    if custom:
        return (root / custom).resolve(), True
    proc = _git(root, "rev-parse", "--git-path", "hooks")
    rel = proc.stdout.decode().strip() if proc and proc.returncode == 0 else ".git/hooks"
    return (root / rel).resolve(), False


def hook_script() -> str:
    python = Path(sys.executable).as_posix()
    src = Path(__file__).resolve().parent.parent.as_posix()
    if "'" in python or "'" in src or '"' in src:
        raise ValueError("LadPock's install path contains quotes, so the hook can't be written safely")
    return (
        "#!/bin/sh\n"
        f"# {HOOK_MARKER}: stops commits that add secrets. Remove with: ladpock hook remove\n"
        "# Skip it once with: git commit --no-verify\n"
        f"exec '{python}' -c 'import sys; sys.path.insert(0, \"{src}\"); "
        "from ladpock.cli import main; sys.exit(main([\"precommit\"]))'\n"
    )


def install_hook(path: Path, force: bool = False) -> str:
    root = repo_root(path)
    if not root:
        raise ToolError(f"{path} isn't inside a git repository")
    hooks, managed = _hooks_dir(root)
    if managed:
        raise ToolError(f"This repository's hooks live in {hooks} (core.hooksPath, often husky). Add this line to its "
                        "pre-commit hook instead: ladpock precommit")
    hook = hooks / "pre-commit"
    if hook.exists() and HOOK_MARKER not in hook.read_text(encoding="utf-8", errors="replace"):
        if not force:
            raise ToolError(f"{hook} already exists. Add 'ladpock precommit' to it yourself, or rerun with --force "
                            "(the existing hook is kept as pre-commit.before-ladpock).")
        hook.replace(hook.with_name("pre-commit.before-ladpock"))
    hooks.mkdir(parents=True, exist_ok=True)
    hook.write_text(hook_script(), encoding="utf-8", newline="\n")
    hook.chmod(0o755)
    return str(hook)


def remove_hook(path: Path) -> bool:
    root = repo_root(path)
    if not root:
        return False
    hooks, _ = _hooks_dir(root)
    hook = hooks / "pre-commit"
    if not hook.exists() or HOOK_MARKER not in hook.read_text(encoding="utf-8", errors="replace"):
        return False
    hook.unlink()
    backup = hook.with_name("pre-commit.before-ladpock")
    if backup.exists():
        backup.replace(hook)
    return True
