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
        self.conn.commit()

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
