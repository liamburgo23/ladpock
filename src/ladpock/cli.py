"""Command-line interface."""

from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path

from . import __version__, advisories, github, report, tauri
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
                      history=True if args.history else None, live_url=args.live, live_writes=args.live_writes,
                      live_user_a=args.live_user_a or os.environ.get("LADPOCK_LIVE_USER_A"),
                      live_user_b=args.live_user_b or os.environ.get("LADPOCK_LIVE_USER_B"),
                      live_own_urls=args.live_own_url or ())
    if args.format == "json":
        _emit(json.dumps(result.to_dict(), indent=2), args.output)
    elif args.format == "sarif":
        _emit(json.dumps(report.to_sarif(result), indent=2), args.output)
    elif args.format == "html":
        _emit(report.to_html(result), args.output)
    else:
        _emit(report.render_scan(result, _style(args) if not args.output else report.Style(False), args.human), args.output)
    known = _read_baseline(args.baseline) if args.baseline else frozenset()
    if args.write_baseline:
        _write_baseline(args.write_baseline, result)
    if known or args.baseline:
        fresh = sum(1 for f in result.findings if f.fingerprint not in known)
        current = {f.fingerprint for f in result.findings}
        print(f"Baseline: {fresh} new, {len(result.findings) - fresh} already known, {len(known - current)} from the baseline now fixed.", file=sys.stderr)
    if args.github:
        _github_outputs(result, known)
    if args.fail_on:
        threshold = Severity.parse(args.fail_on)
        if any(f.severity >= threshold and f.fingerprint not in known for f in result.findings):
            return 1
    return 0


def _read_baseline(path: str) -> frozenset[str]:
    try:
        data = json.loads(Path(path).read_text(encoding="utf-8"))
        return frozenset(data["findings"])
    except FileNotFoundError:
        print(f"warning: no baseline at {path}, so every finding counts as new", file=sys.stderr)
    except (ValueError, KeyError, TypeError, OSError) as exc:
        print(f"warning: couldn't read the baseline at {path} ({exc}), so every finding counts as new", file=sys.stderr)
    return frozenset()


def _write_baseline(path: str, result) -> None:
    """Refs ignore line numbers, so the file stays valid as code moves around. Titles are only there for whoever reads the diff."""
    findings = {f.fingerprint: f"{f.severity.label}: {f.title}" + (f" ({f.file})" if f.file else "") for f in result.findings}
    Path(path).write_text(json.dumps({"tool": f"ladpock {__version__}", "findings": dict(sorted(findings.items()))}, indent=2) + "\n", encoding="utf-8")
    print(f"Wrote {len(findings)} finding(s) to {path}. Only new ones will fail a scan run with --baseline {path}.", file=sys.stderr)


def cmd_sbom(args, db: DB) -> int:
    from . import sbom

    document, warnings = sbom.build(args.path)
    for warning in warnings:
        print(f"warning: {warning}", file=sys.stderr)
    _emit(json.dumps(document, indent=2), args.output)
    print(f"{len(document['components'])} packages listed. Lockfiles give the exact versions, so commit yours.", file=sys.stderr)
    return 0


def _github_outputs(result, known: frozenset[str] = frozenset()) -> None:
    """For GitHub Actions: marks on the changed lines, a job summary, and the grade as step outputs."""
    for line in report.github_annotations(result, known):
        print(line, file=sys.stderr)
    summary, outputs = os.environ.get("GITHUB_STEP_SUMMARY"), os.environ.get("GITHUB_OUTPUT")
    if summary:
        with open(summary, "a", encoding="utf-8") as handle:
            handle.write(report.github_summary(result, known))
    if outputs:
        with open(outputs, "a", encoding="utf-8") as handle:
            fresh = sum(1 for f in result.findings if f.fingerprint not in known)
            handle.write(f"grade={result.scorecard.grade}\nscore={result.scorecard.overall}\nfindings={len(result.findings)}\nnew={fresh}\n")


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


def cmd_github(args, db: DB) -> int:
    """Add repositories from GitHub by link, and scan them."""
    try:
        owner, repo = github.parse_link(args.link)
        repos, via = github.list_repos(owner, repo)
    except github.GitHubError as exc:
        print(str(exc), file=sys.stderr)
        return 2
    if via == "api":
        print("Only public repositories are visible. For private ones, install the GitHub CLI (gh) and run 'gh auth login'.", file=sys.stderr)
    if not repo:
        skipped = [r for r in repos if r.archived or r.empty or (r.fork and not args.include_forks)]
        repos = [r for r in repos if r not in skipped]
        if skipped:
            print(f"Skipping {len(skipped)} archived, empty or forked repositories" + ("" if args.include_forks else " (--include-forks adds forks)"),
                  file=sys.stderr)
    if args.list:
        for r in repos:
            print(f"{r.full_name.ljust(40)} {'private' if r.private else 'public '}  {(r.language or '-').ljust(12)} {r.pushed_at[:10]}")
        return 0
    if not repos:
        print("Nothing to add.", file=sys.stderr)
        return 0
    failed = 0
    for i, r in enumerate(repos, 1):
        print(f"[{i}/{len(repos)}] {r.full_name}", file=sys.stderr)
        try:
            folder = github.fetch(r.full_name, lambda line: print(f"  {line}", file=sys.stderr))
        except github.GitHubError as exc:
            print(f"  {exc}", file=sys.stderr)
            failed += 1
            continue
        db.upsert_project(folder, name=r.full_name)
        if args.no_scan:
            print(f"Added {r.full_name}")
            continue
        result = run_scan(folder, db, profile=args.profile, offline=args.offline, log=lambda line: print(f"  {line}", file=sys.stderr))
        print(f"{r.full_name}: grade {result.scorecard.grade} ({result.scorecard.overall}/100), {len(result.findings)} findings")
    if failed:
        print(f"{failed} of {len(repos)} couldn't be copied (see above).", file=sys.stderr)
    return 1 if failed == len(repos) else 0


def cmd_projects(args, db: DB) -> int:
    if args.action == "list":
        rows = db.list_projects()
        if not rows:
            print("No projects yet.")
        for p in rows:
            print(f"{(p['last_grade'] or '-').ljust(3)} {p['name'].ljust(28)} {p['path']}")
        return 0
    path = Path(args.path or ".").resolve()
    if args.action == "remove" and args.path and not path.is_dir():
        # A GitHub project can be named the way the list shows it: owner/repo.
        named = next((p for p in db.list_projects() if p["name"] == args.path), None)
        path = Path(named["path"]) if named else path
    if args.action == "add":
        if not path.is_dir():
            print(f"{path} is not a folder", file=sys.stderr)
            return 2
        db.upsert_project(path)
        print(f"Added {path}")
    elif args.action == "remove":
        if not db.remove_project(path):
            print(f"{path} wasn't registered")
        elif github.managed_name(path) and github.remove_copy(path):
            print(f"Removed {github.managed_name(path) or path} and LadPock's copy of it")
        else:
            print(f"Removed {path}")
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
            print(f"  [missing] {name.ljust(12)} {purpose}. Install: ladpock scanners install {name}")
    ollama = which("ollama")
    print(f"\nLocal AI      {'Ollama found. See: ladpock ai status' if ollama else 'Ollama not found (https://ollama.com)'}")
    if args.path:
        index = FileIndex(args.path)
        print(f"\nProject       {index.root}")
        print(f"Stack         {', '.join(detect(index)) or 'not recognised'}")
        print(f"Files indexed {len(index.paths)}" + (f" ({index.skipped_large} skipped as too large)" if index.skipped_large else ""))
    return 0


def ask_yes(prompt: str) -> bool:
    """True only for an explicit yes; no keyboard (EOF) or Ctrl+C means no."""
    try:
        return input(prompt).strip().lower() in ("y", "yes")
    except (EOFError, KeyboardInterrupt):
        print()
        return False


def cmd_scanners(args, db: DB) -> int:
    from .scanners import install as installer

    tools = installer.status()
    if args.action == "list":
        print(f"Optional scanners (this computer: {installer.platform_key() or 'unsupported platform'}):")
        for t in tools:
            if t.installed:
                where = "installed by LadPock" if t.managed else f"found at {t.path}"
                state = f"{t.installed_version or 'installed'} ({where})" + ("" if t.up_to_date or not t.managed else ", update available")
            else:
                state = "not installed"
            print(f"  {t.name:<12} pinned {t.version:<8} {state}")
            print(f"  {'':<12} {t.adds}")
        print("\nInstall: ladpock scanners install [name ...]  (downloads are checked against pinned SHA-256 hashes)")
        return 0
    if args.action == "remove":
        for name in args.names or []:
            print(f"Removed {name}" if installer.remove(name) else f"{name} wasn't installed by LadPock")
        return 0
    wanted = args.names or [t.name for t in tools if t.supported and not (t.managed and t.up_to_date)
                            and not (t.installed and not t.managed)]
    chosen = [t for t in tools if t.name in wanted]
    unknown = set(wanted) - {t.name for t in chosen}
    if unknown:
        print(f"Unknown scanner(s): {', '.join(sorted(unknown))}", file=sys.stderr)
        return 2
    if not chosen:
        print("Everything is already installed and up to date.")
        return 0
    total = sum(t.download_size or 0 for t in chosen)
    print("LadPock will download and install:")
    for t in chosen:
        print(f"  {t.file}  ({(t.download_size or 0) / 1e6:.1f} MB) from github.com/{t.repo}, {t.license} licence")
    print(f"Total {total / 1e6:.1f} MB into {installer.bin_dir()}. Each file is checked against its pinned SHA-256 first.")
    if not args.yes and not ask_yes("Continue? [y/N] "):
        print("Cancelled.")
        return 1
    failed = 0
    for t in chosen:
        try:
            installer.install(t.name)
        except installer.InstallError as exc:
            failed += 1
            print(f"{t.name}: {exc}", file=sys.stderr)
    return 1 if failed else 0


def cmd_ui(args, db: DB) -> int:
    from .ui.server import serve

    db.close()  # the server opens its own connection per request
    if sys.platform == "win32":
        try:
            import ctypes

            ctypes.windll.kernel32.SetConsoleTitleW("LadPock dashboard (close this window to stop it)")
        except (AttributeError, OSError):
            pass
    return serve(port=args.port, open_browser=not args.no_browser)


def cmd_shortcut(args, db: DB) -> int:
    from . import launcher

    if args.action == "remove":
        removed = launcher.remove()
        print("\n".join(f"Removed {p}" for p in removed) or "No LadPock shortcuts found.")
        return 0
    try:
        made = launcher.install(desktop=args.desktop)
    except OSError as exc:
        print(exc, file=sys.stderr)
        return 2
    for path in made:
        print(f"Created {path}")
    print("It opens the dashboard in a terminal window; close that window to stop LadPock.")
    return 0


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
    scan.add_argument("--format", choices=["text", "json", "sarif", "html"], default="text",
                      help="html is a one-page report you can keep or pass on")
    scan.add_argument("--baseline", metavar="FILE",
                      help="findings listed in this file don't count for --fail-on or GitHub marks, so a project with old problems can "
                           "start by failing only on new ones. They still count towards the grade")
    scan.add_argument("--write-baseline", metavar="FILE", help="record today's findings, for use with --baseline")
    scan.add_argument("--github", action="store_true",
                      help="in GitHub Actions, also mark findings on the changed lines and write a job summary and step outputs")
    scan.add_argument("--output", "-o", help="write the report to a file")
    scan.add_argument("--no-external", action="store_true", help="only run LadPock's built-in checks")
    scan.add_argument("--history", action="store_true", help="also search git history for secrets (needs gitleaks)")
    scan.add_argument("--human", action="store_true", help="show the 'needs a human' checklist")
    scan.add_argument("--live", metavar="URL",
                      help="also check your app running on this computer, e.g. http://localhost:3000 (localhost only)")
    scan.add_argument("--live-writes", action="store_true",
                      help="with --live, also call POST/PUT/PATCH/DELETE routes (use a development database)")
    scan.add_argument("--live-user-a", metavar="LOGIN",
                      help="with --live, a test account's session, e.g. 'Cookie: session=...' or 'Bearer ...'. Checks whether "
                           "this account's records can be read by --live-user-b. Prefer the LADPOCK_LIVE_USER_A environment "
                           "variable so it doesn't end up in your shell history")
    scan.add_argument("--live-user-b", metavar="LOGIN", help="the second test account (or LADPOCK_LIVE_USER_B)")
    scan.add_argument("--live-own-url", metavar="PATH", action="append",
                      help="a record that belongs to account A, e.g. /api/orders/123, if LadPock can't find them itself "
                           "(can be repeated)")
    scan.add_argument("--fail-on", choices=[s.label for s in Severity if s > Severity.INFO],
                      help="exit with code 1 if anything at or above this severity is found (for CI)")

    full = sub.add_parser("full-check", help="everything: a full scan, then the local AI review if a model is installed")
    full.add_argument("path", nargs="?", default=".")
    full.add_argument("--all-projects", action="store_true", help="check every project LadPock knows about")
    full.add_argument("--no-ai", action="store_true", help="skip the local AI review")

    sbom_parser = sub.add_parser("sbom", help="list every package version this project uses, as a CycloneDX bill of materials")
    sbom_parser.add_argument("path", nargs="?", default=".")
    sbom_parser.add_argument("--output", "-o", help="write it to a file")

    routes = sub.add_parser("routes", help="show the route matrix and the command matrix (Tauri)")
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

    gh = sub.add_parser("github", help="add (and scan) repositories from GitHub by link: your profile for all of them, or one repository")
    gh.add_argument("link", help="e.g. https://github.com/you, https://github.com/you/your-app or you/your-app")
    gh.add_argument("--list", action="store_true", help="only list what's there")
    gh.add_argument("--no-scan", action="store_true", help="add them without scanning")
    gh.add_argument("--include-forks", action="store_true", help="with a profile link, also add forks")
    gh.add_argument("--profile", choices=sorted(PROFILES), default="standard", help="how much to check (default standard)")

    projects = sub.add_parser("projects", help="manage the projects LadPock watches")
    projects.add_argument("action", choices=["list", "add", "remove", "discover"])
    projects.add_argument("path", nargs="?")

    checks = sub.add_parser("checks", help="list every built-in check")
    checks.add_argument("--markdown", action="store_true")

    scanners = sub.add_parser("scanners", help="list, install or remove the optional scanners (pinned and checksum-verified)")
    scanners.add_argument("action", nargs="?", choices=["list", "install", "remove"], default="list")
    scanners.add_argument("names", nargs="*", help="gitleaks, osv-scanner, opengrep (default: all missing)")
    scanners.add_argument("--yes", action="store_true", help="don't ask before downloading")

    doctor = sub.add_parser("doctor", help="check your setup and optional scanners")
    doctor.add_argument("path", nargs="?")

    from .ai import cli as ai_cli

    ai_cli.add_parser(sub)

    sub.add_parser("mcp", help="run as an MCP server so Claude Code can scan while it writes code "
                              "(claude mcp add ladpock -- ladpock mcp)")
    sub.add_parser("precommit", help="scan the staged files and block the commit if they add secrets (used by the hook)")
    hook = sub.add_parser("hook", help="install or remove LadPock's git pre-commit hook in a repository")
    hook.add_argument("action", choices=["install", "remove"])
    hook.add_argument("path", nargs="?", default=".")
    hook.add_argument("--force", action="store_true", help="replace an existing pre-commit hook (it's kept as a backup)")

    shortcut = sub.add_parser("shortcut", help="add a LadPock launcher to the Start Menu / Applications / app menu")
    shortcut.add_argument("action", nargs="?", choices=["install", "remove"], default="install")
    shortcut.add_argument("--desktop", action="store_true", help="also put one on the desktop")

    ui = sub.add_parser("ui", help="open the dashboard in your browser (only reachable from this computer)")
    ui.add_argument("--port", type=int, default=8765, help="preferred port (default 8765; another is used if busy)")
    ui.add_argument("--no-browser", action="store_true", help="print the link instead of opening a browser")
    return parser


COMMANDS = {
    None: cmd_status, "status": cmd_status, "scan": cmd_scan, "full-check": cmd_full_check, "routes": cmd_routes, "sbom": cmd_sbom,
    "fix-prompt": cmd_fix_prompt,
    "advisories": cmd_advisories, "suppress": cmd_suppress, "projects": cmd_projects, "github": cmd_github, "checks": cmd_checks,
    "doctor": cmd_doctor, "ui": cmd_ui, "scanners": cmd_scanners, "ai": lambda args, db: _ai_run(args, db),
    "shortcut": cmd_shortcut, "mcp": lambda args, db: _mcp(), "precommit": lambda args, db: _precommit(), "hook": lambda args, db: _hook(args),
}


def _mcp() -> int:
    from .integrations import serve_mcp

    return serve_mcp()


def _precommit() -> int:
    from .integrations import precommit

    return precommit(Path.cwd())


def _hook(args) -> int:
    from .integrations import ToolError, install_hook, remove_hook

    try:
        if args.action == "install":
            where = install_hook(Path(args.path), force=args.force)
            print(f"Installed {where}. Commits that add secrets will be stopped (skip once with git commit --no-verify).")
        else:
            print("Removed LadPock's pre-commit hook." if remove_hook(Path(args.path)) else "No LadPock hook found.")
    except ToolError as exc:
        print(exc, file=sys.stderr)
        return 2
    return 0


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
