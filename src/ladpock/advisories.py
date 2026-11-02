"""Matches a project's dependency inventory against live advisory data.

Because each project's inventory is stored, LadPock can re-check every
project you've scanned whenever the feeds change, without rescanning code.
That's what powers the "new advisories affect your projects" banner.
"""

from __future__ import annotations

import json
from dataclasses import dataclass

from . import cvss
from .db import DB
from .feeds import osv
from .models import Component, Severity
from .timeutil import iso, parse_iso

_GHSA_SEVERITY = {"LOW": Severity.LOW, "MODERATE": Severity.MEDIUM, "MEDIUM": Severity.MEDIUM,
                  "HIGH": Severity.HIGH, "CRITICAL": Severity.CRITICAL}


@dataclass
class AdvisoryHit:
    advisory_id: str
    project_id: int
    project_name: str
    ecosystem: str
    name: str
    version: str
    source: str | None
    fixed: str | None
    summary: str
    aliases: list[str]
    severity: Severity
    cvss: float | None
    first_seen: str
    kev_added: str | None = None
    epss: float | None = None

    @property
    def cves(self) -> list[str]:
        ids = [self.advisory_id, *self.aliases]
        return sorted({i for i in ids if i.startswith("CVE-")})

    @property
    def effective_severity(self) -> Severity:
        return Severity.CRITICAL if self.kev_added else self.severity

    def priority(self) -> tuple:
        return (self.kev_added is not None, self.effective_severity, self.epss or 0.0)


def severity_of(vuln: dict) -> tuple[Severity, float | None]:
    if vuln.get("id", "").startswith("MAL-"):
        return Severity.CRITICAL, None
    score = None
    for entry in vuln.get("severity") or []:
        if str(entry.get("type", "")).startswith("CVSS_V3"):
            score = cvss.base_score(str(entry.get("score", "")))
            if score is not None:
                break
    label = str((vuln.get("database_specific") or {}).get("severity", "")).upper()
    if label in _GHSA_SEVERITY:
        return _GHSA_SEVERITY[label], score
    if score is not None:
        return cvss.severity_for(score), score
    return Severity.MEDIUM, None


def _trim_affected(vuln: dict) -> list[dict]:
    out = []
    for entry in vuln.get("affected") or []:
        pkg = entry.get("package") or {}
        fixed = [ev["fixed"] for r in entry.get("ranges") or [] for ev in r.get("events") or [] if "fixed" in ev]
        out.append({"ecosystem": pkg.get("ecosystem"), "name": pkg.get("name"), "fixed": fixed})
    return out


def version_key(version: str) -> tuple:
    parts = []
    for piece in version.replace("-", ".").split("."):
        parts.append((0, int(piece), "") if piece.isdigit() else (1, 0, piece))
    return tuple(parts)


def fixed_version(affected: list[dict], comp: Component) -> str | None:
    """Lowest fixed version above the installed one, if the advisory lists one."""
    candidates = []
    for entry in affected:
        if entry.get("name") == comp.name and str(entry.get("ecosystem", "")).split(":")[0] == comp.ecosystem:
            candidates.extend(entry.get("fixed") or [])
    if not candidates:
        return None
    try:
        current = version_key(comp.version or "0")
        above = [c for c in candidates if version_key(c) > current]
        return min(above or candidates, key=version_key)
    except (TypeError, ValueError):
        return candidates[0]


def refresh_project(db: DB, project_id: int, components: list[Component]) -> None:
    """Query OSV for the project's components and record matches (raises FeedError if offline)."""
    matches = osv.query_batch(components)
    wanted: dict[str, str] = {}
    for pairs in matches.values():
        for vuln_id, modified in pairs:
            row = db.get_advisory(vuln_id)
            if row is None or (modified and row["modified"] != modified):
                wanted[vuln_id] = modified
    for vuln_id, vuln in osv.get_vulns(sorted(wanted)).items():
        severity, score = severity_of(vuln)
        aliases = sorted(set(vuln.get("aliases") or []) | set(vuln.get("upstream") or []))
        db.upsert_advisory(vuln_id, vuln.get("modified", ""), (vuln.get("summary") or vuln.get("details") or "")[:300],
                           aliases, int(severity), score, _trim_affected(vuln))
    db.conn.commit()

    rows: list[tuple[str, Component, str | None]] = []
    for comp, pairs in matches.items():
        for vuln_id, _ in pairs:
            row = db.get_advisory(vuln_id)
            if row is None:
                continue  # detail fetch failed this time; it will be retried next run
            rows.append((vuln_id, comp, fixed_version(json.loads(row["affected"] or "[]"), comp)))
    db.sync_project_advisories(project_id, rows)
    db.set_meta("osv_checked_at", iso())


def hits(db: DB, kev: dict[str, str], project_id: int | None = None) -> list[AdvisoryHit]:
    out = []
    for row in db.project_advisories(project_id):
        hit = AdvisoryHit(
            advisory_id=row["advisory_id"], project_id=row["project_id"], project_name=row["project_name"],
            ecosystem=row["ecosystem"], name=row["name"], version=row["version"], source=row["source"],
            fixed=row["fixed"], summary=row["summary"] or "", aliases=json.loads(row["aliases"] or "[]"),
            severity=Severity(row["severity"]), cvss=row["cvss"], first_seen=row["first_seen"],
        )
        for cve in hit.cves:
            if cve in kev:
                hit.kev_added = kev[cve]
                break
        out.append(hit)
    epss = db.epss_scores(sorted({c for h in out for c in h.cves}))
    for hit in out:
        scores = [epss[c]["score"] for c in hit.cves if c in epss]
        hit.epss = max(scores) if scores else None
    out.sort(key=lambda h: h.priority(), reverse=True)
    return out


def new_since(all_hits: list[AdvisoryHit], since: str | None) -> list[AdvisoryHit]:
    """Advisories first matched, or newly marked as actively exploited, after ``since``."""
    cutoff = parse_iso(since)
    if cutoff is None:
        return []
    out = []
    for hit in all_hits:
        first_seen = parse_iso(hit.first_seen)
        kev_date = parse_iso(hit.kev_added) if hit.kev_added else None
        if (first_seen and first_seen > cutoff) or (kev_date and kev_date.date() >= cutoff.date()):
            out.append(hit)
    return out
