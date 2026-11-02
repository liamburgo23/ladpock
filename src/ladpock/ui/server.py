"""Local dashboard server.

A dashboard that can read your scan results is itself a target: any website
you visit can send requests to localhost. So:

- it listens on 127.0.0.1 only
- every API call must carry a random per-launch token in a header. It's never
  a cookie, so other sites can't ride on it, and it's handed over in the URL
  fragment, which browsers don't send to servers or put in Referer headers
- the Host header must be 127.0.0.1/localhost on our port (defeats DNS rebinding)
- requests from other origins are refused, and no CORS headers are ever sent
- a strict Content-Security-Policy, and the page builds its DOM with
  textContent, so code from a scanned repo can't inject HTML or script
"""

from __future__ import annotations

import http.server
import json
import os
import re
import secrets
import string
import threading
import uuid
import webbrowser
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable
from urllib.parse import parse_qs, urlsplit

from .. import __version__, advisories, report, tauri
from ..checks import REGISTRY
from ..db import DB
from ..feeds import epss, kev
from ..files import FileIndex
from ..human import items_for
from ..models import CATEGORIES
from ..routes import analyze, gaps
from ..scan import PROFILES, refresh_all_projects, run_scan
from ..stack import coverage
from ..timeutil import iso

STATIC = Path(__file__).resolve().parent / "static"
CONTENT_TYPES = {".html": "text/html; charset=utf-8", ".js": "text/javascript; charset=utf-8",
                 ".css": "text/css; charset=utf-8", ".svg": "image/svg+xml"}
SECURITY_HEADERS = {
    "Content-Security-Policy": "default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self' data:; "
                               "connect-src 'self'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'",
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
    "Referrer-Policy": "no-referrer",
    "Cross-Origin-Opener-Policy": "same-origin",
    "Cross-Origin-Resource-Policy": "same-origin",
    "Cache-Control": "no-store",
}
MAX_BODY = 1_000_000
PROJECT_MARKERS = ("package.json", "pyproject.toml", "requirements.txt", "go.mod", "Cargo.toml", ".git")


class ApiError(Exception):
    def __init__(self, status: int, message: str):
        super().__init__(message)
        self.status = status


@dataclass
class Job:
    id: str
    project_id: int | None
    status: str = "running"  # running | done | error
    log: list[str] = field(default_factory=list)
    error: str | None = None
    result: dict | None = None


class App:
    """State shared by request threads. Each request opens its own DB connection."""

    def __init__(self, port: int, token: str, db_factory: Callable[[], DB] = DB):
        self.port = port
        self.token = token
        self.db_factory = db_factory
        self.jobs: dict[str, Job] = {}
        self.jobs_lock = threading.Lock()
        self.refresh_lock = threading.Lock()
        self.static_files = {p.name for p in STATIC.iterdir() if p.is_file()}

    @property
    def allowed_hosts(self) -> set[str]:
        return {f"127.0.0.1:{self.port}", f"localhost:{self.port}"}

    @property
    def allowed_origins(self) -> set[str]:
        return {f"http://{h}" for h in self.allowed_hosts}

    # jobs

    def start_scan(self, project_id: int, path: str, options: dict) -> Job:
        with self.jobs_lock:
            for job in self.jobs.values():
                if job.project_id == project_id and job.status == "running":
                    return job
            job = Job(uuid.uuid4().hex, project_id)
            self.jobs[job.id] = job

        def work() -> None:
            db = self.db_factory()
            try:
                result = run_scan(path, db, log=job.log.append, **options)
                job.result = {"project_id": result.project_id, "grade": result.scorecard.grade,
                              "score": result.scorecard.overall, "findings": len(result.findings)}
                job.status = "done"
            except Exception as exc:  # reported to the page, never swallowed
                job.error = f"{type(exc).__name__}: {exc}"
                job.status = "error"
            finally:
                db.close()

        threading.Thread(target=work, name=f"ladpock-scan-{job.id[:8]}", daemon=True).start()
        return job

    def running_job(self, project_id: int) -> Job | None:
        with self.jobs_lock:
            return next((j for j in self.jobs.values() if j.project_id == project_id and j.status == "running"), None)


# payload builders


def _hit_dict(hit: advisories.AdvisoryHit) -> dict:
    return {
        "id": hit.advisory_id, "cves": hit.cves, "project_id": hit.project_id, "project": hit.project_name,
        "package": hit.name, "version": hit.version, "ecosystem": hit.ecosystem, "fixed": hit.fixed,
        "summary": hit.summary, "severity": hit.effective_severity.label, "kev": hit.kev_added is not None,
        "epss": hit.epss, "first_seen": hit.first_seen,
    }


def _feed_status(db: DB) -> list[dict]:
    def row(name: str):
        return db.get_feed(name)

    kev_row, epss_row = row(kev.NAME), row(epss.NAME)
    return [
        {"name": "OSV", "updated": db.get_meta("osv_checked_at"), "error": None},
        {"name": "CISA KEV", "updated": kev_row["fetched_at"] if kev_row else None, "error": kev_row["error"] if kev_row else None},
        {"name": "EPSS", "updated": epss_row["fetched_at"] if epss_row else None, "error": epss_row["error"] if epss_row else None},
    ]


def _project_summary(db: DB, row, vulnerable: dict[int, set]) -> dict:
    stack = json.loads(row["stack"] or "[]")
    deep, generic = coverage(stack)
    return {
        "id": row["id"], "name": row["name"], "path": row["path"], "exists": Path(row["path"]).is_dir(),
        "grade": row["last_grade"], "score": row["last_score"], "last_scan_at": row["last_scan_at"],
        "stack": deep + generic, "vulnerable_deps": len(vulnerable.get(row["id"], ())),
    }


def status_payload(db: DB) -> dict:
    hits = advisories.hits(db, kev.load(db))
    vulnerable: dict[int, set] = {}
    for hit in hits:
        vulnerable.setdefault(hit.project_id, set()).add((hit.name, hit.version))
    last_opened = db.get_meta("last_opened_at")
    return {
        "version": __version__,
        "last_opened": last_opened,
        "feeds": _feed_status(db),
        "projects": [_project_summary(db, p, vulnerable) for p in db.list_projects()],
        "new": [_hit_dict(h) for h in advisories.new_since(hits, last_opened)][:50],
    }


def project_payload(app: App, db: DB, project_id: int) -> dict:
    row = db.get_project_by_id(project_id)
    if not row:
        raise ApiError(404, "Project not found")
    stack = json.loads(row["stack"] or "[]")
    scan = db.latest_scan(project_id)
    findings = db.scan_findings(scan["id"]) if scan else []
    summary = json.loads(scan["summary"] or "{}") if scan else {}
    checked = db.human_checks(project_id)
    job = app.running_job(project_id)
    return {
        "project": _project_summary(db, row, {}),
        "scan": None if not scan else {
            "id": scan["id"], "started_at": scan["started_at"], "finished_at": scan["finished_at"],
            "profile": scan["profile"], "score": scan["score"], "grade": scan["grade"], "summary": summary,
        },
        "findings": findings,
        "history": [{"started_at": s["started_at"], "grade": s["grade"], "score": s["score"], "profile": s["profile"]}
                    for s in db.scan_history(project_id, 20)],
        "human": [{"id": i, "text": t, "checked_at": checked.get(i)} for i, t in items_for(set(stack))],
        "job": job.id if job else None,
        "profiles": sorted(PROFILES),
        "categories": CATEGORIES,
    }


def browse(path: str) -> dict:
    """List sub-folders, for the 'add project' picker. Folder names only, never file contents."""
    if not path:
        if os.name == "nt":
            drives = [f"{d}:\\" for d in string.ascii_uppercase if os.path.isdir(f"{d}:\\")]
            return {"path": "", "parent": None, "dirs": [{"name": d, "path": d, "project": False} for d in drives]}
        path = str(Path.home())
    target = Path(path).expanduser()
    if not target.is_absolute() or not target.is_dir():
        raise ApiError(400, "That folder doesn't exist")
    target = target.resolve()
    dirs = []
    try:
        entries = sorted(os.scandir(target), key=lambda e: e.name.lower())
    except OSError as exc:
        raise ApiError(400, f"Can't open that folder: {exc.strerror}") from exc
    for entry in entries:
        try:
            if not entry.is_dir(follow_symlinks=False) or entry.name.startswith((".", "$")):
                continue
        except OSError:
            continue
        full = Path(entry.path)
        is_project = any((full / m).exists() for m in PROJECT_MARKERS)
        dirs.append({"name": entry.name, "path": str(full), "project": is_project})
        if len(dirs) >= 500:
            break
    parent = str(target.parent) if target.parent != target else ""
    is_project = any((target / m).exists() for m in PROJECT_MARKERS)
    return {"path": str(target), "parent": parent, "dirs": dirs, "project": is_project,
            "projects_inside": sum(1 for d in dirs if d["project"])}


def _bool(body: dict, key: str, default: bool = False) -> bool:
    value = body.get(key, default)
    if not isinstance(value, bool):
        raise ApiError(400, f"'{key}' must be true or false")
    return value


def _project_id(match: re.Match[str]) -> int:
    return int(match.group(1))


# request handling


class Handler(http.server.BaseHTTPRequestHandler):
    server_version = "LadPock"
    sys_version = ""
    protocol_version = "HTTP/1.1"

    @property
    def app(self) -> App:
        return self.server.app  # type: ignore[attr-defined]

    def log_message(self, format: str, *args) -> None:  # keep the terminal quiet
        pass

    def do_GET(self) -> None:
        self._handle("GET")

    def do_POST(self) -> None:
        self._handle("POST")

    def do_DELETE(self) -> None:
        self._handle("DELETE")

    def _send(self, status: int, body: bytes, content_type: str) -> None:
        self.send_response(status)
        for key, value in SECURITY_HEADERS.items():
            self.send_header(key, value)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(body)

    def _json(self, status: int, payload: object) -> None:
        self._send(status, json.dumps(payload).encode("utf-8"), "application/json; charset=utf-8")

    def _origin_ok(self) -> bool:
        if self.headers.get("Host", "") not in self.app.allowed_hosts:
            return False
        origin = self.headers.get("Origin")
        if origin is not None and origin not in self.app.allowed_origins:
            return False
        return self.headers.get("Sec-Fetch-Site", "same-origin") in ("same-origin", "none")

    def _handle(self, method: str) -> None:
        if not self._origin_ok():
            self._json(403, {"error": "Requests are only accepted from the LadPock page itself."})
            return
        url = urlsplit(self.path)
        if not url.path.startswith("/api/"):
            if method != "GET":
                self._json(405, {"error": "Method not allowed"})
                return
            self._static(url.path)
            return
        token = self.headers.get("X-LadPock-Token", "")
        if not secrets.compare_digest(token.encode(), self.app.token.encode()):
            self._json(401, {"error": "Missing or wrong token. Open LadPock with the link printed in your terminal."})
            return
        try:
            body = self._read_body() if method == "POST" else {}
            status, payload = self._route(method, url.path, parse_qs(url.query), body)
        except ApiError as exc:
            status, payload = exc.status, {"error": str(exc)}
        except Exception as exc:  # report, don't crash the server thread
            status, payload = 500, {"error": f"{type(exc).__name__}: {exc}"}
        self._json(status, payload)

    def _read_body(self) -> dict:
        if not self.headers.get("Content-Type", "").startswith("application/json"):
            raise ApiError(415, "Send JSON")
        length = int(self.headers.get("Content-Length") or 0)
        if length > MAX_BODY:
            raise ApiError(413, "Request too large")
        raw = self.rfile.read(length) if length else b"{}"
        try:
            body = json.loads(raw or b"{}")
        except ValueError as exc:
            raise ApiError(400, "Invalid JSON") from exc
        if not isinstance(body, dict):
            raise ApiError(400, "Expected a JSON object")
        return body

    def _static(self, path: str) -> None:
        name = "index.html" if path in ("/", "/index.html") else path.lstrip("/")
        if name not in self.app.static_files:  # allowlist, so no path traversal
            self._json(404, {"error": "Not found"})
            return
        file = STATIC / name
        self._send(200, file.read_bytes(), CONTENT_TYPES.get(file.suffix, "application/octet-stream"))

    def _route(self, method: str, path: str, query: dict, body: dict) -> tuple[int, object]:
        for route_method, pattern, handler in ROUTES:
            match = pattern.fullmatch(path)
            if match and route_method == method:
                db = self.app.db_factory()
                try:
                    return handler(self.app, db, match, query, body)
                finally:
                    db.close()
        raise ApiError(404, "Unknown API endpoint")


# endpoints: (app, db, match, query, body) -> (status, payload)


def api_status(app, db, match, query, body):
    return 200, status_payload(db)


def api_refresh(app, db, match, query, body):
    if not app.refresh_lock.acquire(blocking=False):
        return 409, {"error": "Already refreshing"}
    try:
        _, problems = refresh_all_projects(db, offline=False, log=lambda _: None)
    finally:
        app.refresh_lock.release()
    payload = status_payload(db)
    payload["problems"] = {str(k): v for k, v in problems.items()}
    return 200, payload


def api_ack(app, db, match, query, body):
    db.set_meta("last_opened_at", iso())
    return 200, {"ok": True}


def api_add_project(app, db, match, query, body):
    path = Path(str(body.get("path", ""))).expanduser()
    if not path.is_absolute() or not path.is_dir():
        raise ApiError(400, "Choose an existing folder")
    project_id = db.upsert_project(path)
    return 200, {"id": project_id}


def api_discover(app, db, match, query, body):
    folder = Path(str(body.get("path", ""))).expanduser()
    if not folder.is_absolute() or not folder.is_dir():
        raise ApiError(400, "Choose an existing folder")
    added = []
    for child in sorted(folder.iterdir()):
        if child.is_dir() and not child.is_symlink() and any((child / m).exists() for m in PROJECT_MARKERS):
            added.append(db.upsert_project(child))
    return 200, {"added": len(added)}


def api_project(app, db, match, query, body):
    return 200, project_payload(app, db, _project_id(match))


def api_remove_project(app, db, match, query, body):
    if not db.remove_project_by_id(_project_id(match)):
        raise ApiError(404, "Project not found")
    return 200, {"ok": True}


def api_scan(app, db, match, query, body):
    row = db.get_project_by_id(_project_id(match))
    if not row:
        raise ApiError(404, "Project not found")
    if not Path(row["path"]).is_dir():
        raise ApiError(400, "That project's folder no longer exists")
    profile = body.get("profile", "standard")
    if profile not in PROFILES:
        raise ApiError(400, "Unknown profile")
    options = {"profile": profile, "offline": _bool(body, "offline"), "external": _bool(body, "external", True),
               "history": True if _bool(body, "history") else None}
    job = app.start_scan(row["id"], row["path"], options)
    return 202, {"job": job.id}


def api_job(app, db, match, query, body):
    job = app.jobs.get(match.group(1))
    if not job:
        raise ApiError(404, "Unknown job")
    return 200, {"id": job.id, "status": job.status, "log": job.log[-50:], "error": job.error, "result": job.result}


def api_routes(app, db, match, query, body):
    row = db.get_project_by_id(_project_id(match))
    if not row or not Path(row["path"]).is_dir():
        raise ApiError(404, "Project folder not found")
    index = FileIndex(row["path"])
    routes = analyze(index)
    commands = tauri.analyze_commands(index) if tauri.is_tauri_project(index) else []
    return 200, {"routes": [{**r.to_dict(), "gaps": gaps(r)} for r in routes],
                 "commands": [{**c.to_dict(), "gaps": tauri.command_gaps(c)} for c in commands]}


def api_advisories(app, db, match, query, body):
    return 200, {"advisories": [_hit_dict(h) for h in advisories.hits(db, kev.load(db), _project_id(match))]}


def api_fix_prompt(app, db, match, query, body):
    row = db.get_project_by_id(_project_id(match))
    scan = db.latest_scan(row["id"]) if row else None
    if not scan:
        raise ApiError(404, "Scan this project first")
    findings = db.scan_findings(scan["id"])
    refs = query.get("ref")
    if refs:
        findings = [f for f in findings if f["ref"] in refs]
    return 200, {"prompt": report.fix_prompt(row["name"], findings) if findings else ""}


def api_suppress(app, db, match, query, body):
    project_id = _project_id(match)
    ref, reason = str(body.get("ref", "")), str(body.get("reason", "")).strip()
    days = body.get("days", 90)
    if not re.fullmatch(r"[0-9a-f]{10}", ref):
        raise ApiError(400, "Unknown finding reference")
    if not reason:
        raise ApiError(400, "Give a reason, so future-you knows why this was accepted")
    if not isinstance(days, int) or days < 0 or days > 3650:
        raise ApiError(400, "Days must be between 0 and 3650")
    db.add_suppression(project_id, ref, reason[:500], None if days == 0 else days)
    return 200, {"ok": True}


def api_human(app, db, match, query, body):
    item = str(body.get("item", ""))
    if not re.fullmatch(r"H-\d{2}", item):
        raise ApiError(400, "Unknown checklist item")
    db.set_human_check(_project_id(match), item, _bool(body, "checked"))
    return 200, {"ok": True}


def api_browse(app, db, match, query, body):
    return 200, browse((query.get("path") or [""])[0])


def api_checks(app, db, match, query, body):
    infos = sorted((info for info, _ in REGISTRY.values()), key=lambda i: i.id)
    return 200, {"checks": [{"id": i.id, "title": i.title, "category": i.category, "severity": i.severity.label,
                             "stacks": list(i.stacks)} for i in infos]}


ROUTES: list[tuple[str, re.Pattern[str], Callable]] = [
    ("GET", re.compile(r"/api/status"), api_status),
    ("POST", re.compile(r"/api/refresh"), api_refresh),
    ("POST", re.compile(r"/api/ack"), api_ack),
    ("POST", re.compile(r"/api/projects"), api_add_project),
    ("POST", re.compile(r"/api/discover"), api_discover),
    ("GET", re.compile(r"/api/projects/(\d+)"), api_project),
    ("DELETE", re.compile(r"/api/projects/(\d+)"), api_remove_project),
    ("POST", re.compile(r"/api/projects/(\d+)/scan"), api_scan),
    ("GET", re.compile(r"/api/projects/(\d+)/routes"), api_routes),
    ("GET", re.compile(r"/api/projects/(\d+)/advisories"), api_advisories),
    ("GET", re.compile(r"/api/projects/(\d+)/fix-prompt"), api_fix_prompt),
    ("POST", re.compile(r"/api/projects/(\d+)/suppress"), api_suppress),
    ("POST", re.compile(r"/api/projects/(\d+)/human"), api_human),
    ("GET", re.compile(r"/api/jobs/([0-9a-f]{32})"), api_job),
    ("GET", re.compile(r"/api/browse"), api_browse),
    ("GET", re.compile(r"/api/checks"), api_checks),
]


class Server(http.server.ThreadingHTTPServer):
    daemon_threads = True

    def __init__(self, app_factory: Callable[[int], App], port: int = 0):
        super().__init__(("127.0.0.1", port), Handler)
        self.app = app_factory(self.server_address[1])


def make_server(port: int = 0, token: str | None = None, db_factory: Callable[[], DB] = DB) -> Server:
    token = token or secrets.token_urlsafe(32)
    return Server(lambda p: App(p, token, db_factory), port)


def serve(port: int = 8765, open_browser: bool = True) -> int:
    try:
        server = make_server(port)
    except OSError:
        server = make_server(0)  # preferred port busy: let the OS pick one
    url = f"http://127.0.0.1:{server.app.port}/#token={server.app.token}"
    print(f"LadPock {__version__} dashboard running at:\n\n  {url}\n")
    print("Only this computer can reach it. Keep the link private; it changes every time you start LadPock.")
    print("Press Ctrl+C to stop.")
    if open_browser:
        webbrowser.open(url)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()
    return 0
