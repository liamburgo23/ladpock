"""Command-line interface."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from . import __version__, advisories, report, tauri
from .checks import REGISTRY
from .db import DB
from .feeds import kev
from .files import FileIndex
from .models import CATEGORIES, Severity
from .paths import data_dir, db_path
from .routes import analyze
from .scan import PROFILES, refresh_all_projects, run_scan
from .scanners import gitleaks, opengrep, osv_scanner
from .scanners.base import version_of, which
from .stack import detect
from .timeutil import iso


def _style(args) -> report.Style:
    return report.Style(report.enable_ansi() and not getattr(args, "no_color", False))


def _emit(text: str, output: str | None) -> None:
    if output:
        Path(output).write_text(text + "\n", encoding="utf-8")
        print(f"Wrote {output}", file=sys.stderr)
    else:
        print(text)


def cmd_status(args, db: DB) -> int:
    last_opened = db.get_meta("last_opened_at")
    feeds, problems = refresh_all_projects(db, args.offline)
    hits = advisories.hits(db, kev.load(db))
    new = advisories.new_since(hits, last_opened)
    print(report.render_status(db.list_projects(), hits, new, feeds, problems, last_opened, _style(args)))
    db.set_meta("last_opened_at", iso())
    return 0


def cmd_scan(args, db: DB) -> int:
    result = run_scan(args.path, db, profile=args.profile, offline=args.offline, external=not args.no_external,
                      history=True if args.history else None)
    if args.format == "json":
        _emit(json.dumps(result.to_dict(), indent=2), args.output)
    elif args.format == "sarif":
        _emit(json.dumps(report.to_sarif(result), indent=2), args.output)
    else:
        _emit(report.render_scan(result, _style(args) if not args.output else report.Style(False), args.human), args.output)
    if args.fail_on:
        threshold = Severity.parse(args.fail_on)
        if any(f.severity >= threshold for f in result.findings):
            return 1
    return 0


def cmd_full_check(args, db: DB) -> int:
    from .ai import settings as ai_settings
    from .ai.client import LocalModelError
    from .ai.review import run_review

    if args.all_projects:
        roots = [Path(p["path"]) for p in db.list_projects() if Path(p["path"]).is_dir()]
        if not roots:
            print("No projects yet. Add one with: ladpock projects add <folder>", file=sys.stderr)
            return 2
    else:
        roots = [Path(args.path).resolve()]
    client = None
    if not args.no_ai:
        try:
            client = ai_settings.make_client(db)
        except LocalModelError as exc:
            print(f"Local AI review will be skipped: {exc}", file=sys.stderr)
    style = _style(args)
    for i, root in enumerate(roots, 1):
        print(style.bold(f"[{i}/{len(roots)}] {root.name}: full scan"), file=sys.stderr)
        result = run_scan(root, db, profile="full", offline=args.offline)
        line = f"{root.name}: grade {result.scorecard.grade} ({result.scorecard.overall}/100), {len(result.findings)} findings"
        if client:
            print(style.bold(f"[{i}/{len(roots)}] {root.name}: local AI review with {client.model}"), file=sys.stderr)
            summary = run_review(db, result.project_id, client, log=lambda m: print(m, file=sys.stderr))
            line += f", {summary.leads} new AI lead(s)"
        print(line)
    print("\nDetails: ladpock scan <folder>, ladpock ai leads <folder>, or open the dashboard with: ladpock ui")
    return 0


def cmd_routes(args, db: DB) -> int:
    index = FileIndex(args.path)
    routes = analyze(index)
    commands = tauri.analyze_commands(index) if tauri.is_tauri_project(index) else []
    if args.format == "json":
        print(json.dumps({"routes": [r.to_dict() for r in routes], "commands": [c.to_dict() for c in commands]}, indent=2))
        return 0
    style = _style(args)
    if commands:
        print(report.render_commands(commands, style))
    if routes or not commands:
        if commands:
            print()
        print(report.render_routes(routes, style))
    return 0


def cmd_fix_prompt(args, db: DB) -> int:
    project = db.get_project(Path(args.path))
    scan = db.latest_scan(project["id"]) if project else None
    if not scan:
        print(f"No scan found for {args.path}. Run: ladpock scan \"{args.path}\"", file=sys.stderr)
        return 2
    findings = db.scan_findings(scan["id"])
    if not findings:
        print("The last scan found nothing to fix.")
        return 0
    print(report.fix_prompt(project["name"], findings, args.limit))
    return 0


def cmd_advisories(args, db: DB) -> int:
    project_id = None
    if args.path:
        project = db.get_project(Path(args.path))
        if not project:
            print(f"{args.path} hasn't been scanned yet.", file=sys.stderr)
            return 2
        project_id = project["id"]
    hits = advisories.hits(db, kev.load(db), project_id)
    print(report.render_advisories(hits, _style(args)))
    return 0


def cmd_suppress(args, db: DB) -> int:
    project_id = db.upsert_project(Path(args.path))
    db.add_suppression(project_id, args.ref, args.reason, None if args.days == 0 else args.days)
    until = "permanently" if args.days == 0 else f"for {args.days} days"
    print(f"Suppressed {args.ref} {until}. Reason recorded: {args.reason}")
    return 0


def cmd_projects(args, db: DB) -> int:
    if args.action == "list":
        rows = db.list_projects()
        if not rows:
            print("No projects yet.")
        for p in rows:
            print(f"{(p['last_grade'] or '-').ljust(3)} {p['name'].ljust(28)} {p['path']}")
        return 0
    path = Path(args.path or ".").resolve()
    if args.action == "add":
        if not path.is_dir():
            print(f"{path} is not a folder", file=sys.stderr)
            return 2
        db.upsert_project(path)
        print(f"Added {path}")
    elif args.action == "remove":
        print(f"Removed {path}" if db.remove_project(path) else f"{path} wasn't registered")
    elif args.action == "discover":
        markers = ("package.json", "pyproject.toml", "requirements.txt", "go.mod", "Cargo.lock", ".git")
        found = [p for p in sorted(path.iterdir()) if p.is_dir() and not p.is_symlink() and any((p / m).exists() for m in markers)]
        for p in found:
            db.upsert_project(p)
            print(f"Added {p}")
        if not found:
            print(f"No projects found directly inside {path}")
    return 0


def cmd_checks(args, db: DB) -> int:
    infos = sorted((info for info, _ in REGISTRY.values()), key=lambda i: (list(CATEGORIES).index(i.category), i.id))
    if args.markdown:
        print("# LadPock checks\n")
        print("Generated with `ladpock checks --markdown`.\n")
        current = None
        for info in infos:
            if info.category != current:
                current = info.category
                print(f"\n## {CATEGORIES[current]}\n")
                print("| ID | Check | Default severity | Applies to |")
                print("|---|---|---|---|")
            applies = ", ".join(info.stacks) if info.stacks else "all projects"
            print(f"| `{info.id}` | {info.title} | {info.severity.label} | {applies} |")
        return 0
    for info in infos:
        stacks = f" [{', '.join(info.stacks)}]" if info.stacks else ""
        print(f"{info.id.ljust(15)} {info.severity.label.ljust(9)} {info.title}{stacks}")
    print(f"\n{len(infos)} checks")
    return 0


def cmd_doctor(args, db: DB) -> int:
    print(f"LadPock {__version__} on Python {sys.version.split()[0]}")
    print(f"Data folder   {data_dir()}")
    print(f"Database      {db_path()}")
    print("\nOptional scanners (LadPock works without them; each adds coverage):")
    for name, module, version_args, purpose in (
        ("gitleaks", gitleaks, ("version",), "more secret patterns, plus git history with --history"),
        ("osv-scanner", osv_scanner, ("--version",), "more lockfile formats"),
        ("opengrep", opengrep, ("--version",), "data-flow rules (Semgrep CE also works)"),
    ):
        exe = which(name) or (which("semgrep") if name == "opengrep" else None)
        if exe:
            print(f"  [found]   {name.ljust(12)} {version_of(exe, *version_args) or ''}")
        else:
            print(f"  [missing] {name.ljust(12)} {purpose}. Install: {module.INSTALL}")
    ollama = which("ollama")
    print(f"\nLocal AI      {'Ollama found. See: ladpock ai status' if ollama else 'Ollama not found (https://ollama.com)'}")
    if args.path:
        index = FileIndex(args.path)
        print(f"\nProject       {index.root}")
        print(f"Stack         {', '.join(detect(index)) or 'not recognised'}")
        print(f"Files indexed {len(index.paths)}" + (f" ({index.skipped_large} skipped as too large)" if index.skipped_large else ""))
    return 0


def cmd_ui(args, db: DB) -> int:
    from .ui.server import serve

    db.close()  # the server opens its own connection per request
    return serve(port=args.port, open_browser=not args.no_browser)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="ladpock",
        description="A free, local security checker for vibe-coded projects. Run with no command to refresh "
                    "vulnerability data and see what's new for the projects you've scanned.",
    )
    parser.add_argument("--version", action="version", version=f"ladpock {__version__}")
    parser.add_argument("--offline", action="store_true", help="don't contact any feed; use cached data")
    parser.add_argument("--no-color", action="store_true", help="plain output")
    # The same flags are accepted after the command too ("ladpock scan . --offline").
    common = argparse.ArgumentParser(add_help=False)
    common.add_argument("--offline", action="store_true", default=argparse.SUPPRESS, help=argparse.SUPPRESS)
    common.add_argument("--no-color", action="store_true", default=argparse.SUPPRESS, help=argparse.SUPPRESS)
    sub = parser.add_subparsers(dest="command")
    _add_parser = sub.add_parser
    sub.add_parser = lambda *a, **kw: _add_parser(*a, parents=[common], **kw)  # type: ignore[method-assign]

    sub.add_parser("status", help="refresh feeds and show new advisories for your projects (the default)")

    scan = sub.add_parser(
        "scan", help="scan a project folder",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        description="Profiles:\n"
                    "  quick     leaked keys and passwords, committed .env files, known-vulnerable dependencies. Seconds.\n"
                    "  standard  everything in quick plus every code check (sign-in, access control, routes and\n"
                    "            commands, injection, payments, config, AI code smells), installed scanners, and a\n"
                    "            check that your packages really exist. The default.\n"
                    "  full      everything in standard plus a search of git history for deleted secrets (Gitleaks).\n"
                    "None of them run your code. For everything including the local AI review: ladpock full-check",
    )
    scan.add_argument("path", nargs="?", default=".")
    scan.add_argument("--profile", choices=sorted(PROFILES), default="standard",
                      help="how much to check (see the profiles above; default standard)")
    scan.add_argument("--format", choices=["text", "json", "sarif"], default="text")
    scan.add_argument("--output", "-o", help="write the report to a file")
    scan.add_argument("--no-external", action="store_true", help="only run LadPock's built-in checks")
    scan.add_argument("--history", action="store_true", help="also search git history for secrets (needs gitleaks)")
    scan.add_argument("--human", action="store_true", help="show the 'needs a human' checklist")
    scan.add_argument("--fail-on", choices=[s.label for s in Severity if s > Severity.INFO],
                      help="exit with code 1 if anything at or above this severity is found (for CI)")

    full = sub.add_parser("full-check", help="everything: a full scan, then the local AI review if a model is installed")
    full.add_argument("path", nargs="?", default=".")
    full.add_argument("--all-projects", action="store_true", help="check every project LadPock knows about")
    full.add_argument("--no-ai", action="store_true", help="skip the local AI review")

    routes = sub.add_parser("routes", help="show the route matrix (Next.js) and command matrix (Tauri)")
    routes.add_argument("path", nargs="?", default=".")
    routes.add_argument("--format", choices=["text", "json"], default="text")

    fix = sub.add_parser("fix-prompt", help="print a paste-ready prompt for your AI assistant from the last scan")
    fix.add_argument("path", nargs="?", default=".")
    fix.add_argument("--limit", type=int, default=25)

    adv = sub.add_parser("advisories", help="list known vulnerable dependencies across your projects")
    adv.add_argument("path", nargs="?")

    sup = sub.add_parser("suppress", help="hide a finding you've decided to accept, with a reason")
    sup.add_argument("ref", help="the 'ref' shown under the finding")
    sup.add_argument("--reason", required=True)
    sup.add_argument("--days", type=int, default=90, help="expire after this many days (0 = never; default 90)")
    sup.add_argument("--path", default=".")

    projects = sub.add_parser("projects", help="manage the projects LadPock watches")
    projects.add_argument("action", choices=["list", "add", "remove", "discover"])
    projects.add_argument("path", nargs="?")

    checks = sub.add_parser("checks", help="list every built-in check")
    checks.add_argument("--markdown", action="store_true")

    doctor = sub.add_parser("doctor", help="check your setup and optional scanners")
    doctor.add_argument("path", nargs="?")

    from .ai import cli as ai_cli

    ai_cli.add_parser(sub)

    ui = sub.add_parser("ui", help="open the dashboard in your browser (only reachable from this computer)")
    ui.add_argument("--port", type=int, default=8765, help="preferred port (default 8765; another is used if busy)")
    ui.add_argument("--no-browser", action="store_true", help="print the link instead of opening a browser")
    return parser


COMMANDS = {
    None: cmd_status, "status": cmd_status, "scan": cmd_scan, "full-check": cmd_full_check, "routes": cmd_routes,
    "fix-prompt": cmd_fix_prompt,
    "advisories": cmd_advisories, "suppress": cmd_suppress, "projects": cmd_projects, "checks": cmd_checks,
    "doctor": cmd_doctor, "ui": cmd_ui, "ai": lambda args, db: _ai_run(args, db),
}


def _ai_run(args, db: DB) -> int:
    from .ai import cli as ai_cli

    return ai_cli.run(args, db)


def main(argv: list[str] | None = None) -> int:
    for stream in (sys.stdout, sys.stderr):
        try:
            stream.reconfigure(encoding="utf-8", errors="replace")
        except (AttributeError, ValueError):
            pass
    args = build_parser().parse_args(argv)
    db = DB()
    try:
        return COMMANDS[args.command](args, db)
    except FileNotFoundError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    except KeyboardInterrupt:
        return 130
    finally:
        db.close()
