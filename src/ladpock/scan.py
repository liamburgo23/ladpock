"""The scan pipeline: built-in checks, optional scanners, live advisory data, scoring."""

from __future__ import annotations

import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable

from . import advisories, inventory, probe, scoring
from .checks import REGISTRY, ScanContext, inline_ignored, run_all
from .db import DB
from .feeds import epss, kev, registry
from .feeds.http import FeedError
from .files import FileIndex
from .gitutil import tracked_files
from .human import items_for
from .models import CATEGORIES, Component, Finding, Severity
from .routes import Route
from .scanners import gitleaks, opengrep, osv_scanner
from .scanners.base import ScannerResult
from .stack import coverage, detect
from .timeutil import iso

SCAN_STEPS = ["Reading files", "Built-in checks", "Installed scanners", "Vulnerability data",
              "Package registry", "Scoring"]

PROFILES = {
    "quick": {"categories": {"secrets", "supply-chain"}, "scanners": False, "history": False, "registry": False},
    "standard": {"categories": None, "scanners": True, "history": False, "registry": True},
    "full": {"categories": None, "scanners": True, "history": True, "registry": True},
}


def profile_summary(stack: list[str]) -> dict[str, dict]:
    """What each profile would run on a project with this stack, for explaining the choice."""
    out = {}
    for name, settings in PROFILES.items():
        infos = [info for info, _ in REGISTRY.values()
                 if (settings["categories"] is None or info.category in settings["categories"])
                 and (not info.stacks or set(info.stacks) & set(stack))]
        out[name] = {"checks": len(infos), "scanners": settings["scanners"], "history": settings["history"],
                     "registry": settings["registry"], "categories": sorted({i.category for i in infos})}
    return out


@dataclass
class FeedStatus:
    name: str
    ok: bool
    detail: str


@dataclass
class ScanResult:
    root: Path
    project_id: int
    stack: list[str]
    profile: str
    findings: list[Finding]
    suppressed: list[Finding]
    routes: list[Route]
    advisory_hits: list[advisories.AdvisoryHit]
    scorecard: scoring.Scorecard
    scanners: list[ScannerResult]
    feeds: list[FeedStatus]
    components: int
    errors: list[str] = field(default_factory=list)
    human: list[tuple[str, str]] = field(default_factory=list)
    started: str = ""
    checks_run: int = 0
    changes: dict | None = None
    live: dict | None = None

    def to_dict(self) -> dict:
        deep, generic = coverage(self.stack)
        return {
            "project": str(self.root),
            "profile": self.profile,
            "started": self.started,
            "stack": self.stack,
            "coverage": {"deep": deep, "generic": generic},
            "score": self.scorecard.overall,
            "grade": self.scorecard.grade,
            "categories": [
                {"key": c.key, "name": c.name, "score": c.score, "grade": c.grade, "counts": c.counts}
                for c in self.scorecard.categories
            ],
            "findings": [f.to_dict() for f in self.findings],
            "suppressed": [f.fingerprint for f in self.suppressed],
            "routes": [r.to_dict() for r in self.routes],
            "dependencies_checked": self.components,
            "feeds": [vars(s) for s in self.feeds],
            "scanners": [{"name": s.name, "available": s.available, "version": s.version, "ran": s.ran,
                          "error": s.error} for s in self.scanners],
            "needs_a_human": [{"id": i, "text": t} for i, t in self.human],
            "live": self.live,
            "errors": self.errors,
        }


def _log(message: str) -> None:
    print(message, file=sys.stderr, flush=True)


def refresh_feeds(db: DB, offline: bool, log: Callable[[str], None] = _log) -> list[FeedStatus]:
    """Update shared feeds before a run. Failures are reported loudly, never silently ignored."""
    from .timeutil import ago

    def cached_copy() -> str:
        row = db.get_feed(kev.NAME)
        return f"using copy from {ago(row['fetched_at'])}" if row and row["fetched_at"] else "no cached copy yet"

    statuses = []
    if offline:
        statuses.append(FeedStatus("CISA KEV", False, f"offline, {cached_copy()}"))
        statuses.append(FeedStatus("OSV", False, "offline, using results from the last online run"))
        return statuses
    try:
        kev.refresh(db)
        statuses.append(FeedStatus("CISA KEV", True, "updated just now"))
    except FeedError as exc:
        log(f"warning: couldn't update CISA KEV ({exc})")
        statuses.append(FeedStatus("CISA KEV", False, f"update failed, {cached_copy()}"))
    return statuses


def advisory_findings(hits: list[advisories.AdvisoryHit], info) -> list[Finding]:
    """One finding per vulnerable package version, listing every advisory that applies."""
    grouped: dict[tuple[str, str, str], list[advisories.AdvisoryHit]] = {}
    for hit in hits:
        grouped.setdefault((hit.ecosystem, hit.name, hit.version), []).append(hit)
    findings = []
    for (_, name, version), group in grouped.items():
        group.sort(key=lambda h: h.priority(), reverse=True)
        top = group[0]
        fixes = sorted({h.fixed for h in group if h.fixed}, key=advisories.version_key)
        target = fixes[-1] if fixes else None
        ids = ", ".join(h.cves[0] if h.cves else h.advisory_id for h in group[:5])
        more = f" and {len(group) - 5} more" if len(group) > 5 else ""
        notes = []
        if any(h.kev_added for h in group):
            notes.append("At least one is on CISA's list of vulnerabilities being actively exploited.")
        if top.epss is not None:
            notes.append(f"Exploit likelihood (EPSS): {top.epss:.0%} in the next 30 days.")
        message = f"{len(group)} known advisor{'y' if len(group) == 1 else 'ies'}: {ids}{more}. Most serious: {top.summary}"
        findings.append(Finding(
            check_id=info.id, title=f"Vulnerable dependency: {name} {version}", severity=top.effective_severity,
            category=info.category, message=" ".join([message, *notes]),
            fix=(f"Upgrade {name} to {target} or later, then update the lockfile and re-scan." if target else info.fix),
            file=top.source, snippet=f"{name}@{version}", confidence="high", source="osv", cwe=info.cwe,
            extra={"advisories": [h.advisory_id for h in group], "kev": any(h.kev_added for h in group), "fixed": target},
        ))
    return findings


def _dedupe(findings: list[Finding]) -> list[Finding]:
    """Same secret reported by two tools, or the same issue twice: keep one, note both sources."""
    out: dict[tuple, Finding] = {}
    for f in findings:
        key = (f.category, f.file, f.line) if f.category == "secrets" and f.line else (f.check_id, f.fingerprint)
        existing = out.get(key)
        if existing is None:
            out[key] = f
            continue
        keep, other = (f, existing) if f.severity > existing.severity else (existing, f)
        if other.source not in keep.source:
            keep.source = f"{keep.source}+{other.source}"
        out[key] = keep
    return list(out.values())


def run_scan(path: str | Path, db: DB, *, profile: str = "standard", offline: bool = False,
             external: bool = True, history: bool | None = None, log: Callable[[str], None] = _log,
             step: Callable[[str], None] = lambda _name: None, live_url: str | None = None,
             live_writes: bool = False, should_stop: Callable[[], bool] = lambda: False,
             live_user_a: str | None = None, live_user_b: str | None = None,
             live_own_urls: list[str] | tuple[str, ...] = ()) -> ScanResult:
    """Scan a project. ``step`` is called with each name in SCAN_STEPS as the scan reaches it."""
    root = Path(path).resolve()
    if not root.is_dir():
        raise FileNotFoundError(f"{root} is not a folder")
    settings = PROFILES[profile]
    started = iso()
    project_id = db.upsert_project(root)

    step(SCAN_STEPS[0])
    log(f"Indexing {root} ...")
    index = FileIndex(root)
    stack = detect(index)
    ctx = ScanContext(root=root, index=index, stack=set(stack), git_files=tracked_files(root))
    errors: list[str] = []
    if index.truncated:
        errors.append("Stopped indexing at 50,000 files; some files weren't checked.")

    step(SCAN_STEPS[1])
    log(f"Running built-in checks ({', '.join(stack) or 'generic'}) ...")
    findings, check_errors = run_all(ctx, settings["categories"])
    errors.extend(check_errors)
    routes = ctx.routes if settings["categories"] is None else []
    checks_run = sum(1 for info, _ in REGISTRY.values()
                     if (settings["categories"] is None or info.category in settings["categories"])
                     and (not info.stacks or set(info.stacks) & ctx.stack))

    components, warnings = inventory.collect(index)
    errors.extend(warnings)
    scanners: list[ScannerResult] = []
    step(SCAN_STEPS[2])
    if external and settings["scanners"]:
        for name, runner in (("gitleaks", lambda: gitleaks.scan(root, history if history is not None else settings["history"])),
                             ("osv-scanner", lambda: osv_scanner.scan(root)),
                             ("opengrep", lambda: opengrep.scan(root))):
            result = runner()
            if result.available:
                log(f"Running {result.name} ...")
            scanners.append(result)
            findings.extend(result.findings)
            if result.error:
                errors.append(f"{result.name}: {result.error}")
            known = set(components)
            components.extend(c for c in result.components if c not in known)
    db.replace_components(project_id, components)

    step(SCAN_STEPS[3])
    feeds = refresh_feeds(db, offline, log)
    if not offline and components:
        log(f"Checking {len(components)} dependencies against OSV ...")
        try:
            advisories.refresh_project(db, project_id, components)
            feeds.append(FeedStatus("OSV", True, "queried live"))
        except FeedError as exc:
            log(f"warning: couldn't reach OSV ({exc}); using results from the last online run")
            feeds.append(FeedStatus("OSV", False, "unreachable, using results from the last online run"))
    elif not offline:
        feeds.append(FeedStatus("OSV", True, "no lockfiles found, nothing to check"))
    kev_map = kev.load(db)
    hits = advisories.hits(db, kev_map, project_id)
    if not offline and hits:
        try:
            epss.refresh(db, sorted({c for h in hits for c in h.cves}))
            hits = advisories.hits(db, kev_map, project_id)
            feeds.append(FeedStatus("EPSS", True, "updated"))
        except FeedError:
            feeds.append(FeedStatus("EPSS", False, "unreachable, exploit likelihood may be missing"))
    findings.extend(advisory_findings(hits, REGISTRY["LP-DEP-001"][0]))

    step(SCAN_STEPS[4])
    if not offline and settings["registry"]:
        deps = inventory.direct_dependencies(index)
        if deps:
            log(f"Checking {len(deps)} declared packages exist on their registry ...")
            info = REGISTRY["LP-SUP-005"][0]
            for eco, name, src in registry.missing_packages(db, deps):
                findings.append(ctx.finding(info, src, None, f"{name} ({eco})", confidence="high",
                                            message=f"'{name}' isn't on the public {eco} registry. {info.why}"))

    live = None
    if live_url:
        step("Live checks")
        try:
            probed = probe.run_probe(live_url, ctx.routes, include_writes=live_writes, log=log, should_stop=should_stop,
                                     user_a=live_user_a, user_b=live_user_b, own_urls=live_own_urls)
            probe.correlate(findings, probed)
            findings.extend(probed.findings)
            live = {"url": probed.base, "requests": probed.requests, "routes": probed.checked_routes,
                    "confirmed": len(probed.findings), "skipped_writes": probed.skipped_writes, "notes": probed.notes,
                    "accounts": probed.accounts}
        except probe.ProbeError as exc:
            errors.append(f"Live checks: {exc}")
            live = {"url": live_url, "error": str(exc)}

    step(SCAN_STEPS[5])
    findings = _dedupe(findings)
    suppressions = db.active_suppressions(project_id)
    hidden = {id(f) for f in findings if f.fingerprint in suppressions or inline_ignored(ctx, f)}
    suppressed = [f for f in findings if id(f) in hidden]
    findings = [f for f in findings if id(f) not in hidden]
    findings.sort(key=lambda f: (-f.severity, f.category, f.file or "", f.line or 0))

    categories = settings["categories"] if settings["categories"] is not None else set(CATEGORIES)
    card = scoring.score(findings, categories)
    deep, generic = coverage(stack)
    summary = {
        "counts": card.counts,
        "categories": [{"key": c.key, "name": c.name, "score": c.score, "grade": c.grade, "counts": c.counts}
                       for c in card.categories],
        "routes": len(routes),
        "dependencies": len(components),
        "checks_run": checks_run,
        "suppressed": len(suppressed),
        "coverage": {"deep": deep, "generic": generic},
        "feeds": [vars(f) for f in feeds],
        "scanners": [{"name": s.name, "available": s.available, "ran": s.ran, "error": s.error} for s in scanners],
        "errors": errors[:20],
        "live": live,
        "options": {"offline": offline, "scanners": bool(external and settings["scanners"]),
                    "history": bool(external and settings["scanners"]
                                    and (history if history is not None else settings["history"]))},
    }
    summary["changes"] = changes = compare_with_previous(db, project_id, findings, profile)
    db.save_scan(project_id, started, profile, card.overall, card.grade, stack, findings, summary)
    return ScanResult(
        root=root, project_id=project_id, stack=stack, profile=profile, findings=findings, suppressed=suppressed,
        routes=routes, advisory_hits=hits, scorecard=card, scanners=scanners, feeds=feeds, components=len(components),
        errors=errors, human=items_for(set(stack)), started=started, checks_run=checks_run, changes=changes, live=live,
    )


def compare_with_previous(db: DB, project_id: int, findings: list[Finding], profile: str) -> dict | None:
    """What's new and what's fixed since this project's previous scan (findings match by their stable ref)."""
    previous = db.latest_scan(project_id)
    if not previous:
        return None
    before = {f["ref"]: f for f in db.scan_findings(previous["id"])}
    now = {f.fingerprint for f in findings}
    fixed = [{k: f.get(k) for k in ("ref", "title", "severity", "category", "file", "line")}
             for ref, f in before.items() if ref not in now]
    return {
        "previous_at": previous["finished_at"], "previous_grade": previous["grade"], "previous_score": previous["score"],
        "previous_profile": previous["profile"], "same_profile": previous["profile"] == profile,
        "new": sorted(ref for ref in now if ref not in before), "fixed": fixed[:200], "fixed_count": len(fixed),
    }


def refresh_all_projects(db: DB, offline: bool, log: Callable[[str], None] = _log) -> tuple[list[FeedStatus], dict[int, str]]:
    """Re-read every registered project's lockfiles and re-match them against live advisories."""
    feeds = refresh_feeds(db, offline, log)
    problems: dict[int, str] = {}
    osv_ok = True
    for project in db.list_projects():
        root = Path(project["path"])
        if not root.is_dir():
            problems[project["id"]] = "folder not found"
            continue
        components: list[Component]
        components, _ = inventory.collect(FileIndex(root))
        db.replace_components(project["id"], components)
        if offline or not components:
            continue
        try:
            advisories.refresh_project(db, project["id"], components)
        except FeedError as exc:
            osv_ok = False
            problems[project["id"]] = f"couldn't reach OSV ({exc})"
    if not offline:
        feeds.append(FeedStatus("OSV", osv_ok, "queried live" if osv_ok else "some projects couldn't be checked"))
        hits = advisories.hits(db, kev.load(db))
        cves = sorted({c for h in hits for c in h.cves})
        if cves:
            try:
                epss.refresh(db, cves)
                feeds.append(FeedStatus("EPSS", True, "updated"))
            except FeedError:
                feeds.append(FeedStatus("EPSS", False, "unreachable"))
    return feeds, problems


def worst(findings: list[Finding]) -> Severity | None:
    return max((f.severity for f in findings), default=None)
