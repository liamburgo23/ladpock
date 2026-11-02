"""Local SQLite store: projects, scan history, inventories and advisory state."""

from __future__ import annotations

import json
import os
import sqlite3
from datetime import timedelta
from pathlib import Path

from .models import Component, Finding
from .paths import db_path
from .timeutil import iso, now

SCHEMA = """
CREATE TABLE IF NOT EXISTS meta (key TEXT PRIMARY KEY, value TEXT);
CREATE TABLE IF NOT EXISTS projects (
    id INTEGER PRIMARY KEY,
    path TEXT NOT NULL,
    path_key TEXT NOT NULL UNIQUE,
    name TEXT NOT NULL,
    added_at TEXT NOT NULL,
    last_scan_at TEXT,
    last_score INTEGER,
    last_grade TEXT,
    stack TEXT
);
CREATE TABLE IF NOT EXISTS scans (
    id INTEGER PRIMARY KEY,
    project_id INTEGER NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
    started_at TEXT NOT NULL,
    finished_at TEXT,
    profile TEXT,
    score INTEGER,
    grade TEXT,
    summary TEXT
);
CREATE TABLE IF NOT EXISTS findings (
    id INTEGER PRIMARY KEY,
    scan_id INTEGER NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
    data TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS components (
    project_id INTEGER NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
    ecosystem TEXT NOT NULL,
    name TEXT NOT NULL,
    version TEXT NOT NULL,
    source TEXT NOT NULL,
    PRIMARY KEY (project_id, ecosystem, name, version, source)
);
CREATE TABLE IF NOT EXISTS advisories (
    id TEXT PRIMARY KEY,
    modified TEXT,
    summary TEXT,
    aliases TEXT,
    severity INTEGER,
    cvss REAL,
    affected TEXT,
    fetched_at TEXT
);
CREATE TABLE IF NOT EXISTS project_advisories (
    project_id INTEGER NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
    advisory_id TEXT NOT NULL,
    ecosystem TEXT NOT NULL,
    name TEXT NOT NULL,
    version TEXT NOT NULL,
    source TEXT,
    fixed TEXT,
    first_seen TEXT NOT NULL,
    PRIMARY KEY (project_id, advisory_id, ecosystem, name, version)
);
CREATE TABLE IF NOT EXISTS feeds (
    name TEXT PRIMARY KEY,
    fetched_at TEXT,
    checked_at TEXT,
    etag TEXT,
    last_modified TEXT,
    data TEXT,
    error TEXT
);
CREATE TABLE IF NOT EXISTS epss (cve TEXT PRIMARY KEY, score REAL, percentile REAL, fetched_at TEXT);
CREATE TABLE IF NOT EXISTS registry_cache (
    ecosystem TEXT NOT NULL,
    name TEXT NOT NULL,
    found INTEGER NOT NULL,
    checked_at TEXT NOT NULL,
    PRIMARY KEY (ecosystem, name)
);
CREATE TABLE IF NOT EXISTS ai_runs (
    id INTEGER PRIMARY KEY,
    project_id INTEGER NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
    started_at TEXT NOT NULL,
    finished_at TEXT,
    status TEXT NOT NULL,
    model TEXT,
    trigger TEXT,
    total INTEGER DEFAULT 0,
    done INTEGER DEFAULT 0,
    cached INTEGER DEFAULT 0,
    leads INTEGER DEFAULT 0,
    dropped INTEGER DEFAULT 0,
    errors INTEGER DEFAULT 0,
    message TEXT
);
CREATE TABLE IF NOT EXISTS ai_units (
    project_id INTEGER NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
    unit_key TEXT NOT NULL,
    content_hash TEXT NOT NULL,
    model TEXT NOT NULL,
    prompt_version INTEGER NOT NULL,
    reviewed_at TEXT NOT NULL,
    PRIMARY KEY (project_id, unit_key)
);
CREATE TABLE IF NOT EXISTS ai_leads (
    id INTEGER PRIMARY KEY,
    project_id INTEGER NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
    unit_key TEXT NOT NULL,
    fingerprint TEXT NOT NULL,
    file TEXT,
    line INTEGER,
    title TEXT,
    severity TEXT,
    category TEXT,
    quote TEXT,
    explanation TEXT,
    fix TEXT,
    model TEXT,
    created_at TEXT,
    status TEXT NOT NULL DEFAULT 'new',
    UNIQUE (project_id, fingerprint)
);
CREATE TABLE IF NOT EXISTS ai_verdicts (
    project_id INTEGER NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
    finding_ref TEXT NOT NULL,
    verdict TEXT,
    reason TEXT,
    model TEXT,
    created_at TEXT,
    PRIMARY KEY (project_id, finding_ref)
);
CREATE TABLE IF NOT EXISTS human_checks (
    project_id INTEGER NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
    item_id TEXT NOT NULL,
    checked_at TEXT NOT NULL,
    PRIMARY KEY (project_id, item_id)
);
CREATE TABLE IF NOT EXISTS suppressions (
    project_id INTEGER NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
    ref TEXT NOT NULL,
    reason TEXT NOT NULL,
    created_at TEXT NOT NULL,
    expires_at TEXT,
    PRIMARY KEY (project_id, ref)
);
"""


def path_key(path: Path) -> str:
    return os.path.normcase(str(path.resolve()))


class DB:
    def __init__(self, path: str | Path | None = None):
        # The dashboard reads while a scan writes from another thread, so wait for locks and use WAL.
        self.conn = sqlite3.connect(str(path or db_path()), timeout=30)
        self.conn.row_factory = sqlite3.Row
        self.conn.execute("PRAGMA foreign_keys = ON")
        self.conn.execute("PRAGMA journal_mode = WAL")
        self.conn.executescript(SCHEMA)
        self._migrate()
        self.conn.commit()

    def _migrate(self) -> None:
        """Add columns introduced after a database was first created."""
        columns = {r["name"] for r in self.conn.execute("PRAGMA table_info(projects)")}
        if "ai_nightly" not in columns:
            self.conn.execute("ALTER TABLE projects ADD COLUMN ai_nightly INTEGER NOT NULL DEFAULT 0")
        columns = {r["name"] for r in self.conn.execute("PRAGMA table_info(ai_runs)")}
        if "rejected" not in columns:
            self.conn.execute("ALTER TABLE ai_runs ADD COLUMN rejected INTEGER DEFAULT 0")

    def close(self) -> None:
        self.conn.close()

    # meta
    def get_meta(self, key: str) -> str | None:
        row = self.conn.execute("SELECT value FROM meta WHERE key = ?", (key,)).fetchone()
        return row["value"] if row else None

    def set_meta(self, key: str, value: str) -> None:
        self.conn.execute("INSERT INTO meta (key, value) VALUES (?, ?) ON CONFLICT(key) DO UPDATE SET value = excluded.value", (key, value))
        self.conn.commit()

    # projects
    def upsert_project(self, path: Path) -> int:
        resolved = path.resolve()
        key = path_key(resolved)
        row = self.conn.execute("SELECT id FROM projects WHERE path_key = ?", (key,)).fetchone()
        if row:
            return row["id"]
        cur = self.conn.execute(
            "INSERT INTO projects (path, path_key, name, added_at) VALUES (?, ?, ?, ?)",
            (str(resolved), key, resolved.name, iso()),
        )
        self.conn.commit()
        return int(cur.lastrowid)

    def get_project(self, path: Path) -> sqlite3.Row | None:
        return self.conn.execute("SELECT * FROM projects WHERE path_key = ?", (path_key(path),)).fetchone()

    def list_projects(self) -> list[sqlite3.Row]:
        return self.conn.execute("SELECT * FROM projects ORDER BY name COLLATE NOCASE").fetchall()

    def remove_project(self, path: Path) -> bool:
        cur = self.conn.execute("DELETE FROM projects WHERE path_key = ?", (path_key(path),))
        self.conn.commit()
        return cur.rowcount > 0

    # scans
    def save_scan(self, project_id: int, started: str, profile: str, score: int, grade: str,
                  stack: list[str], findings: list[Finding], summary: dict) -> int:
        cur = self.conn.execute(
            "INSERT INTO scans (project_id, started_at, finished_at, profile, score, grade, summary) VALUES (?, ?, ?, ?, ?, ?, ?)",
            (project_id, started, iso(), profile, score, grade, json.dumps(summary)),
        )
        scan_id = int(cur.lastrowid)
        self.conn.executemany(
            "INSERT INTO findings (scan_id, data) VALUES (?, ?)",
            [(scan_id, json.dumps(f.to_dict())) for f in findings],
        )
        self.conn.execute(
            "UPDATE projects SET last_scan_at = ?, last_score = ?, last_grade = ?, stack = ? WHERE id = ?",
            (iso(), score, grade, json.dumps(stack), project_id),
        )
        self.conn.commit()
        return scan_id

    def latest_scan(self, project_id: int) -> sqlite3.Row | None:
        return self.conn.execute(
            "SELECT * FROM scans WHERE project_id = ? ORDER BY id DESC LIMIT 1", (project_id,)
        ).fetchone()

    def scan_findings(self, scan_id: int) -> list[dict]:
        rows = self.conn.execute("SELECT data FROM findings WHERE scan_id = ? ORDER BY id", (scan_id,)).fetchall()
        return [json.loads(r["data"]) for r in rows]

    def scan_history(self, project_id: int, limit: int = 10) -> list[sqlite3.Row]:
        return self.conn.execute(
            "SELECT * FROM scans WHERE project_id = ? ORDER BY id DESC LIMIT ?", (project_id, limit)
        ).fetchall()

    # inventory
    def replace_components(self, project_id: int, components: list[Component]) -> None:
        self.conn.execute("DELETE FROM components WHERE project_id = ?", (project_id,))
        self.conn.executemany(
            "INSERT OR IGNORE INTO components (project_id, ecosystem, name, version, source) VALUES (?, ?, ?, ?, ?)",
            [(project_id, c.ecosystem, c.name, c.version, c.source) for c in components if c.version],
        )
        self.conn.commit()

    def components(self, project_id: int) -> list[Component]:
        rows = self.conn.execute(
            "SELECT ecosystem, name, version, source FROM components WHERE project_id = ?", (project_id,)
        ).fetchall()
        return [Component(r["ecosystem"], r["name"], r["version"], r["source"]) for r in rows]

    # advisories
    def get_advisory(self, advisory_id: str) -> sqlite3.Row | None:
        return self.conn.execute("SELECT * FROM advisories WHERE id = ?", (advisory_id,)).fetchone()

    def upsert_advisory(self, advisory_id: str, modified: str, summary: str, aliases: list[str],
                        severity: int, cvss: float | None, affected: list) -> None:
        self.conn.execute(
            """INSERT INTO advisories (id, modified, summary, aliases, severity, cvss, affected, fetched_at)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?)
               ON CONFLICT(id) DO UPDATE SET modified = excluded.modified, summary = excluded.summary,
                 aliases = excluded.aliases, severity = excluded.severity, cvss = excluded.cvss,
                 affected = excluded.affected, fetched_at = excluded.fetched_at""",
            (advisory_id, modified, summary, json.dumps(aliases), severity, cvss, json.dumps(affected), iso()),
        )

    def sync_project_advisories(self, project_id: int, rows: list[tuple[str, Component, str | None]]) -> None:
        """Record current matches. New ones get first_seen = now; resolved ones are removed."""
        stamp = iso()
        current = set()
        for advisory_id, comp, fixed in rows:
            current.add((advisory_id, comp.ecosystem, comp.name, comp.version))
            self.conn.execute(
                """INSERT INTO project_advisories (project_id, advisory_id, ecosystem, name, version, source, fixed, first_seen)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                   ON CONFLICT(project_id, advisory_id, ecosystem, name, version)
                   DO UPDATE SET fixed = excluded.fixed, source = excluded.source""",
                (project_id, advisory_id, comp.ecosystem, comp.name, comp.version, comp.source, fixed, stamp),
            )
        existing = self.conn.execute(
            "SELECT advisory_id, ecosystem, name, version FROM project_advisories WHERE project_id = ?", (project_id,)
        ).fetchall()
        for r in existing:
            key = (r["advisory_id"], r["ecosystem"], r["name"], r["version"])
            if key not in current:
                self.conn.execute(
                    "DELETE FROM project_advisories WHERE project_id = ? AND advisory_id = ? AND ecosystem = ? AND name = ? AND version = ?",
                    (project_id, *key),
                )
        self.conn.commit()

    def project_advisories(self, project_id: int | None = None) -> list[sqlite3.Row]:
        sql = """SELECT pa.*, a.summary, a.aliases, a.severity, a.cvss, p.name AS project_name, p.path AS project_path
                 FROM project_advisories pa
                 JOIN advisories a ON a.id = pa.advisory_id
                 JOIN projects p ON p.id = pa.project_id"""
        if project_id is None:
            return self.conn.execute(sql).fetchall()
        return self.conn.execute(sql + " WHERE pa.project_id = ?", (project_id,)).fetchall()

    # feeds
    def get_feed(self, name: str) -> sqlite3.Row | None:
        return self.conn.execute("SELECT * FROM feeds WHERE name = ?", (name,)).fetchone()

    def save_feed(self, name: str, *, data: str | None = None, etag: str | None = None,
                  last_modified: str | None = None, error: str | None = None, fetched: bool = False) -> None:
        stamp = iso()
        self.conn.execute("INSERT OR IGNORE INTO feeds (name) VALUES (?)", (name,))
        self.conn.execute("UPDATE feeds SET checked_at = ?, error = ? WHERE name = ?", (stamp, error, name))
        if fetched:
            self.conn.execute("UPDATE feeds SET fetched_at = ? WHERE name = ?", (stamp, name))
        if data is not None:
            self.conn.execute(
                "UPDATE feeds SET data = ?, etag = ?, last_modified = ? WHERE name = ?",
                (data, etag, last_modified, name),
            )
        self.conn.commit()

    # epss
    def epss_scores(self, cves: list[str]) -> dict[str, sqlite3.Row]:
        out = {}
        for cve in cves:
            row = self.conn.execute("SELECT * FROM epss WHERE cve = ?", (cve,)).fetchone()
            if row:
                out[cve] = row
        return out

    def save_epss(self, rows: list[tuple[str, float, float]]) -> None:
        stamp = iso()
        self.conn.executemany(
            "INSERT INTO epss (cve, score, percentile, fetched_at) VALUES (?, ?, ?, ?) "
            "ON CONFLICT(cve) DO UPDATE SET score = excluded.score, percentile = excluded.percentile, fetched_at = excluded.fetched_at",
            [(cve, score, pct, stamp) for cve, score, pct in rows],
        )
        self.conn.commit()

    # registry existence cache
    def registry_lookup(self, ecosystem: str, name: str, max_age_days: int = 7) -> bool | None:
        row = self.conn.execute(
            "SELECT found, checked_at FROM registry_cache WHERE ecosystem = ? AND name = ?", (ecosystem, name)
        ).fetchone()
        if not row or row["checked_at"] < iso(now() - timedelta(days=max_age_days)):
            return None
        return bool(row["found"])

    def registry_save(self, ecosystem: str, name: str, found: bool) -> None:
        self.conn.execute(
            "INSERT INTO registry_cache (ecosystem, name, found, checked_at) VALUES (?, ?, ?, ?) "
            "ON CONFLICT(ecosystem, name) DO UPDATE SET found = excluded.found, checked_at = excluded.checked_at",
            (ecosystem, name, int(found), iso()),
        )
        self.conn.commit()

    def get_project_by_id(self, project_id: int) -> sqlite3.Row | None:
        return self.conn.execute("SELECT * FROM projects WHERE id = ?", (project_id,)).fetchone()

    def remove_project_by_id(self, project_id: int) -> bool:
        cur = self.conn.execute("DELETE FROM projects WHERE id = ?", (project_id,))
        self.conn.commit()
        return cur.rowcount > 0

    # local AI review

    def set_ai_nightly(self, project_id: int, enabled: bool) -> None:
        self.conn.execute("UPDATE projects SET ai_nightly = ? WHERE id = ?", (int(enabled), project_id))
        self.conn.commit()

    def ai_nightly_projects(self) -> list[sqlite3.Row]:
        return self.conn.execute("SELECT * FROM projects WHERE ai_nightly = 1 ORDER BY name COLLATE NOCASE").fetchall()

    def ai_reviewed_units(self, project_id: int) -> dict[str, tuple[str, str, int]]:
        rows = self.conn.execute(
            "SELECT unit_key, content_hash, model, prompt_version FROM ai_units WHERE project_id = ?", (project_id,)
        ).fetchall()
        return {r["unit_key"]: (r["content_hash"], r["model"], r["prompt_version"]) for r in rows}

    def ai_mark_reviewed(self, project_id: int, unit_key: str, content_hash: str, model: str, version: int) -> None:
        self.conn.execute(
            "INSERT OR REPLACE INTO ai_units (project_id, unit_key, content_hash, model, prompt_version, reviewed_at) "
            "VALUES (?, ?, ?, ?, ?, ?)",
            (project_id, unit_key, content_hash, model, version, iso()),
        )
        self.conn.commit()

    def ai_save_leads(self, project_id: int, unit_key: str, file: str, leads: list, model: str) -> int:
        """Replace this unit's open leads. Leads you dismissed or confirmed keep that status."""
        keep = {lead.fingerprint for lead in leads}
        stale = self.conn.execute(
            "SELECT id, fingerprint FROM ai_leads WHERE project_id = ? AND unit_key = ? AND status = 'new'",
            (project_id, unit_key),
        ).fetchall()
        for row in stale:
            if row["fingerprint"] not in keep:
                self.conn.execute("DELETE FROM ai_leads WHERE id = ?", (row["id"],))
        existing = {r["fingerprint"] for r in self.conn.execute(
            "SELECT fingerprint FROM ai_leads WHERE project_id = ?", (project_id,)).fetchall()}
        added = sum(1 for lead in leads if lead.fingerprint not in existing)
        for lead in leads:
            self.conn.execute(
                """INSERT INTO ai_leads (project_id, unit_key, fingerprint, file, line, title, severity, category, quote,
                                         explanation, fix, model, created_at)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                   ON CONFLICT(project_id, fingerprint) DO UPDATE SET unit_key = excluded.unit_key, file = excluded.file,
                     line = excluded.line, title = excluded.title, severity = excluded.severity,
                     explanation = excluded.explanation, fix = excluded.fix, model = excluded.model""",
                (project_id, unit_key, lead.fingerprint, file, lead.line, lead.title, lead.severity, lead.category,
                 lead.quote, lead.explanation, lead.fix, model, iso()),
            )
        self.conn.commit()
        return added

    def ai_prune(self, project_id: int, current_keys: set[str]) -> None:
        """Forget units (and their open leads) for code that no longer exists."""
        for row in self.conn.execute("SELECT unit_key FROM ai_units WHERE project_id = ?", (project_id,)).fetchall():
            if row["unit_key"] not in current_keys:
                self.conn.execute("DELETE FROM ai_units WHERE project_id = ? AND unit_key = ?", (project_id, row["unit_key"]))
                self.conn.execute("DELETE FROM ai_leads WHERE project_id = ? AND unit_key = ? AND status = 'new'",
                                  (project_id, row["unit_key"]))
        self.conn.commit()

    def ai_leads(self, project_id: int) -> list[sqlite3.Row]:
        return self.conn.execute(
            "SELECT * FROM ai_leads WHERE project_id = ? ORDER BY status = 'dismissed', "
            "CASE severity WHEN 'high' THEN 0 WHEN 'medium' THEN 1 ELSE 2 END, file, line",
            (project_id,),
        ).fetchall()

    def ai_set_lead_status(self, project_id: int, lead_id: int, status: str) -> bool:
        cur = self.conn.execute("UPDATE ai_leads SET status = ? WHERE id = ? AND project_id = ?", (status, lead_id, project_id))
        self.conn.commit()
        return cur.rowcount > 0

    def ai_save_verdict(self, project_id: int, ref: str, verdict: str, reason: str, model: str) -> None:
        self.conn.execute(
            "INSERT OR REPLACE INTO ai_verdicts (project_id, finding_ref, verdict, reason, model, created_at) "
            "VALUES (?, ?, ?, ?, ?, ?)",
            (project_id, ref, verdict, reason, model, iso()),
        )
        self.conn.commit()

    def ai_verdicts(self, project_id: int) -> dict[str, sqlite3.Row]:
        rows = self.conn.execute("SELECT * FROM ai_verdicts WHERE project_id = ?", (project_id,)).fetchall()
        return {r["finding_ref"]: r for r in rows}

    def ai_run_start(self, project_id: int, model: str, trigger: str, total: int, cached: int) -> int:
        cur = self.conn.execute(
            "INSERT INTO ai_runs (project_id, started_at, status, model, trigger, total, cached) VALUES (?, ?, 'running', ?, ?, ?, ?)",
            (project_id, iso(), model, trigger, total, cached),
        )
        self.conn.commit()
        return int(cur.lastrowid)

    _AI_RUN_UPDATES = {
        "status": "UPDATE ai_runs SET status = ? WHERE id = ?",
        "done": "UPDATE ai_runs SET done = ? WHERE id = ?",
        "leads": "UPDATE ai_runs SET leads = ? WHERE id = ?",
        "dropped": "UPDATE ai_runs SET dropped = ? WHERE id = ?",
        "rejected": "UPDATE ai_runs SET rejected = ? WHERE id = ?",
        "errors": "UPDATE ai_runs SET errors = ? WHERE id = ?",
        "message": "UPDATE ai_runs SET message = ? WHERE id = ?",
        "finished_at": "UPDATE ai_runs SET finished_at = ? WHERE id = ?",
    }

    def ai_run_update(self, run_id: int, **fields) -> None:
        for key, value in fields.items():
            self.conn.execute(self._AI_RUN_UPDATES[key], (value, run_id))
        self.conn.commit()

    def ai_last_run(self, project_id: int) -> sqlite3.Row | None:
        return self.conn.execute(
            "SELECT * FROM ai_runs WHERE project_id = ? ORDER BY id DESC LIMIT 1", (project_id,)
        ).fetchone()

    # "needs a human" checklist
    def human_checks(self, project_id: int) -> dict[str, str]:
        rows = self.conn.execute("SELECT item_id, checked_at FROM human_checks WHERE project_id = ?", (project_id,)).fetchall()
        return {r["item_id"]: r["checked_at"] for r in rows}

    def set_human_check(self, project_id: int, item_id: str, checked: bool) -> None:
        if checked:
            self.conn.execute(
                "INSERT OR REPLACE INTO human_checks (project_id, item_id, checked_at) VALUES (?, ?, ?)",
                (project_id, item_id, iso()),
            )
        else:
            self.conn.execute("DELETE FROM human_checks WHERE project_id = ? AND item_id = ?", (project_id, item_id))
        self.conn.commit()

    # suppressions
    def add_suppression(self, project_id: int, ref: str, reason: str, days: int | None) -> None:
        expires = iso(now() + timedelta(days=days)) if days else None
        self.conn.execute(
            "INSERT INTO suppressions (project_id, ref, reason, created_at, expires_at) VALUES (?, ?, ?, ?, ?) "
            "ON CONFLICT(project_id, ref) DO UPDATE SET reason = excluded.reason, created_at = excluded.created_at, expires_at = excluded.expires_at",
            (project_id, ref, reason, iso(), expires),
        )
        self.conn.commit()

    def active_suppressions(self, project_id: int) -> dict[str, str]:
        rows = self.conn.execute(
            "SELECT ref, reason FROM suppressions WHERE project_id = ? AND (expires_at IS NULL OR expires_at > ?)",
            (project_id, iso()),
        ).fetchall()
        return {r["ref"]: r["reason"] for r in rows}
