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

from .. import __version__, advisories, probe, report, scoring, tauri
from ..ai import keys as ai_keys
from ..ai import online as ai_online
from ..ai import review as ai_review
from ..ai import settings as ai_settings
from ..ai import system as ai_system
from ..ai.client import LocalModelError
from ..scanners import install as scanner_install
from ..scanners.base import which
from ..checks import REGISTRY
from ..db import DB
from ..feeds import epss, kev
from ..files import FileIndex
from ..human import items_for
from ..models import CATEGORIES, finding_from_dict
from ..routes import analyze, gaps
from ..scan import PROFILES, SCAN_STEPS, profile_summary, refresh_all_projects, run_scan
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


AI_KINDS = {"ai", "full", "full-all", "benchmark"}  # these use the GPU, so only one runs at a time


@dataclass
class Job:
    id: str
    project_id: int | None
    kind: str = "scan"  # scan | ai | benchmark | full | full-all
    title: str = ""
    steps: list[str] = field(default_factory=list)
    step: int = 0  # index into steps
    fraction: float | None = None  # progress within the current step, when known
    status: str = "running"  # running | done | error
    log: list[str] = field(default_factory=list)
    error: str | None = None
    result: dict | None = None
    started_at: str = field(default_factory=iso)
    finished_at: str | None = None
    stop: threading.Event = field(default_factory=threading.Event)

    def enter(self, name: str) -> None:
        """Move to the named step (adding it if this job didn't plan for it)."""
        if name not in self.steps:
            self.steps.append(name)
        self.step = self.steps.index(name)
        self.fraction = None

    def to_dict(self) -> dict:
        return {
            "id": self.id, "kind": self.kind, "project_id": self.project_id, "title": self.title,
            "steps": self.steps, "step": self.step, "fraction": self.fraction, "status": self.status,
            "log": self.log[-50:], "error": self.error, "result": self.result, "started_at": self.started_at,
            "finished_at": self.finished_at, "stopping": self.stop.is_set(),
        }


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

    def start_job(self, kind: str, project_id: int | None, title: str, steps: list[str],
                  work: Callable[[DB, Job], dict]) -> Job:
        """Run work(db, job) on a background thread.

        One job per project at a time (a scan and an AI review of the same code would trip over each other),
        and one GPU job at a time across all projects.
        """
        with self.jobs_lock:
            running = [j for j in self.jobs.values() if j.status == "running"]
            for job in running:
                if job.kind == kind and job.project_id == project_id:
                    return job  # pressing the button twice just shows the same job
            for job in running:
                if (project_id is not None and job.project_id == project_id) or "full-all" in (kind, job.kind):
                    raise ApiError(409, f"Wait for \"{job.title}\" to finish first")
                if kind in AI_KINDS and job.kind in AI_KINDS:
                    raise ApiError(409, f"The local model is busy with \"{job.title}\". Try again when it finishes")
            job = Job(uuid.uuid4().hex, project_id, kind, title, list(steps))
            self.jobs[job.id] = job

        def run() -> None:
            db = self.db_factory()
            try:
                job.result = work(db, job)
                job.status = "done"
            except Exception as exc:  # reported to the page, never swallowed
                job.error = f"{type(exc).__name__}: {exc}"
                job.status = "error"
            finally:
                job.finished_at = iso()
                db.close()

        threading.Thread(target=run, name=f"ladpock-{kind}-{job.id[:8]}", daemon=True).start()
        return job

    def start_run(self, project_id: int, name: str, options: dict) -> Job:
        """Scan one project with the chosen options (see run_options)."""
        kind = "full" if options["local_ai"] else "scan"
        return self.start_job(kind, project_id, f"{run_title(options)} of {name}", run_steps(options),
                              lambda db, job: run_project(db, job, project_id, options))

    def running_job(self, project_id: int, kind: str | None = None) -> Job | None:
        with self.jobs_lock:
            return next((j for j in self.jobs.values() if j.project_id == project_id and j.status == "running"
                         and (kind is None or j.kind == kind)), None)

    def recent_jobs(self, limit: int = 20) -> list[Job]:
        with self.jobs_lock:
            jobs = sorted(self.jobs.values(), key=lambda j: j.started_at, reverse=True)
        return jobs[:limit]


def _scan_result(result) -> dict:
    return {"project_id": result.project_id, "grade": result.scorecard.grade, "score": result.scorecard.overall,
            "findings": len(result.findings)}


def run_options(body: dict, **defaults) -> dict:
    """The scan panel's choices. Each one is a separate toggle so you decide what runs and what leaves your computer."""
    merged = {"profile": "standard", "online": True, "scanners": True, "history": None, "local_ai": False,
              "online_ai": False, "live": False, "live_writes": False, **defaults}
    profile = body.get("profile", merged["profile"])
    if profile not in PROFILES:
        raise ApiError(400, "Unknown profile")
    options = {"profile": profile}
    for key in ("online", "scanners", "local_ai", "online_ai", "live", "live_writes"):
        options[key] = _bool(body, key, merged[key])
    options["live_url"] = None
    if options["live"]:
        try:
            options["live_url"] = probe.check_target(str(body.get("live_url") or "http://localhost:3000"))
        except probe.ProbeError as exc:
            raise ApiError(400, str(exc)) from exc
    history = body.get("history", merged["history"])
    options["history"] = PROFILES[profile]["history"] if history is None else _bool(body, "history", history)
    if options["online_ai"] and not options["online"]:
        raise ApiError(400, "The paid online AI review needs the internet. Turn on online data, or turn off the "
                            "online AI review.")
    return options


def run_steps(options: dict) -> list[str]:
    scan = list(SCAN_STEPS[:-1]) + (["Live checks"] if options.get("live") else []) + [SCAN_STEPS[-1]]
    return (scan + (["Local AI review"] if options["local_ai"] else [])
            + (["Online AI review"] if options["online_ai"] else []))


def run_title(options: dict) -> str:
    extras = [name for key, name in (("local_ai", "local AI"), ("online_ai", "online AI")) if options[key]]
    return f"{options['profile'].capitalize()} scan" + (f" + {' + '.join(extras)}" if extras else "")


def run_project(db: DB, job: Job, project_id: int, options: dict, prefix: str = "") -> dict:
    """One project, with whatever the scan panel turned on: the scan, then the local and online AI reviews."""
    row = db.get_project_by_id(project_id)
    label = (lambda name: f"{prefix}{name}") if prefix else (lambda name: name)
    result = run_scan(row["path"], db, profile=options["profile"], offline=not options["online"],
                      external=options["scanners"], history=options["history"], log=job.log.append,
                      step=lambda name: job.enter(label(name)), live_url=options.get("live_url"),
                      live_writes=options.get("live_writes", False), should_stop=job.stop.is_set)
    out = {"project_id": project_id, "name": row["name"], **_scan_result(result)}

    def progress(done: int, total: int) -> None:
        job.fraction = done / total if total else 1.0

    if options["local_ai"]:
        out["ai"] = "skipped"
        if not job.stop.is_set():
            job.enter(label("Local AI review"))
            try:
                client = ai_settings.make_client(db)
                summary = ai_review.run_review(db, project_id, client, should_stop=job.stop.is_set,
                                               log=job.log.append, progress=progress)
                out.update(ai=summary.status, leads=summary.leads)
            except LocalModelError as exc:
                job.log.append(f"Local AI review skipped: {exc}")
                out["ai"] = "unavailable"
    if options["online_ai"]:
        out["online_ai"] = "skipped"
        if not job.stop.is_set():
            job.enter(label("Online AI review"))
            if not ai_online.enabled(db):
                job.log.append("Online AI review skipped: it isn't set up yet (AI settings, Paid online AI)")
                out["online_ai"] = "not set up"
                return out
            try:
                client = ai_online.OnlineClient(effort=ai_online.effort(db))
                summary = ai_online.run_online_review(db, project_id, client, should_stop=job.stop.is_set,
                                                      log=job.log.append, progress=progress)
                out.update(online_ai=summary.status, online_leads=summary.leads, online_cost=round(summary.cost, 2))
                if summary.message:
                    job.log.append(summary.message)
            except ai_online.OnlineAIError as exc:
                job.log.append(f"Online AI review skipped: {exc}")
                out["online_ai"] = "unavailable"
    return out


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
    epss_note = None
    if not (epss_row and epss_row["fetched_at"]):
        # EPSS is only looked up for CVEs your dependencies actually have; none means nothing to fetch.
        has_cves = any(h.cves for h in advisories.hits(db, {}))
        epss_note = None if has_cves else "nothing to look up"
    return [
        {"name": "OSV", "updated": db.get_meta("osv_checked_at"), "error": None,
         "about": "Known vulnerabilities in open-source packages, matched against your lockfiles."},
        {"name": "CISA KEV", "updated": kev_row["fetched_at"] if kev_row else None, "error": kev_row["error"] if kev_row else None,
         "about": "The US government's list of vulnerabilities attackers are actively exploiting."},
        {"name": "EPSS", "updated": epss_row["fetched_at"] if epss_row else None, "error": epss_row["error"] if epss_row else None,
         "note": epss_note, "about": "The chance a vulnerability gets exploited in the next 30 days."},
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
    human = [{"id": i, "text": t, "checked_at": checked.get(i)} for i, t in items_for(set(stack))]
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
        "human": human,
        "job": job.to_dict() if job else None,
        "profiles": profile_summary(stack),
        "categories": CATEGORIES,
        "ai": ai_payload(app, db, project_id, row),
        "assessment": assessment_payload(db, project_id, scan, findings, summary, human),
    }


def assessment_payload(db: DB, project_id: int, scan, findings: list[dict], summary: dict,
                       human: list[dict]) -> dict | None:
    """Why the project got its grade, the path to A+, and what would make the assessment itself more complete."""
    if not scan:
        return None
    categories = {c["key"] for c in summary.get("categories", [])} or None
    explanation = scoring.explain([finding_from_dict(f) for f in findings], categories)

    gaps_ = []
    if scan["profile"] != "full":
        gaps_.append({"id": "profile", "title": f"The last scan was {scan['profile'].capitalize()}, not Full",
                      "detail": "A full check also searches git history for deleted secrets"
                      + (" and runs every code check" if scan["profile"] == "quick" else "") + ".",
                      "fix": "Run a full check", "href": f"#/project/{project_id}"})
    failed = [f["name"] for f in summary.get("feeds", []) if not f.get("ok")]
    if failed:
        gaps_.append({"id": "offline", "title": "Vulnerability data wasn't refreshed",
                      "detail": f"{', '.join(failed)} couldn't be reached (or the scan was offline), so newly published "
                                "vulnerabilities in your dependencies may be missing.",
                      "fix": "Scan again with online vulnerability data on", "href": f"#/project/{project_id}"})
    missing = [name for name, info in scanner_install.load_pins().items() if not which(info["binary"])]
    if missing:
        gaps_.append({"id": "scanners", "title": f"Not installed: {', '.join(missing)}",
                      "detail": "These free scanners find things LadPock's own checks don't: more secret types, "
                                "secrets in git history, more lockfile formats, and data-flow bugs.",
                      "fix": "Install from the Scanners page", "href": "#/scanners"})
    generic = (summary.get("coverage") or {}).get("generic") or []
    if generic:
        gaps_.append({"id": "coverage", "title": f"Generic checks only for {', '.join(generic)}",
                      "detail": "LadPock doesn't have a framework-aware pack for these yet, so framework-specific "
                                "mistakes in them may be missed. The AI review helps fill this gap.",
                      "fix": "Run the local AI review", "href": f"#/project/{project_id}"})
    if not summary.get("dependencies"):
        gaps_.append({"id": "lockfile", "title": "No dependencies were checked",
                      "detail": "No lockfile was found, so LadPock couldn't match exact package versions "
                                "against known vulnerabilities.",
                      "fix": "Commit your lockfile (package-lock.json, pnpm-lock.yaml, poetry.lock, Cargo.lock ...)",
                      "href": None})
    live = summary.get("live") or {}
    if not live or live.get("error"):
        gaps_.append({"id": "live", "title": "Only the code was checked, not the running app" if not live
                      else "Live checks couldn't reach your app",
                      "detail": "Live checks call your app on this computer without logging in, to confirm which "
                                "endpoints really answer, and check headers, CORS and exposed files."
                                + (f" Last attempt: {live['error']}" if live.get("error") else ""),
                      "fix": "Start your app, then scan with Live checks on", "href": f"#/project/{project_id}"})
    used = summary.get("options") or {}
    if used.get("scanners") is False and scan["profile"] != "quick":
        gaps_.append({"id": "scanners-off", "title": "Installed scanners were turned off for the last scan",
                      "detail": "gitleaks, osv-scanner and opengrep add checks LadPock doesn't have built in.",
                      "fix": "Scan again with Installed scanners on", "href": f"#/project/{project_id}"})
    if not db.ai_last_run(project_id) and not db.ai_last_run(project_id, online=True):
        gaps_.append({"id": "ai", "title": "No AI review yet",
                      "detail": "Pattern checks can't follow logic. An AI review reads your routes, commands and code "
                                "for things like missing ownership checks.",
                      "fix": "Turn on the local AI review and scan", "href": f"#/project/{project_id}"})
    unticked = [i for i in human if not i["checked_at"]]
    if unticked:
        gaps_.append({"id": "human", "title": f"{len(unticked)} of {len(human)} manual checks not confirmed",
                      "detail": "Some of the most important protections can't be seen in code: two-factor login, "
                                "tested backups, spending limits, and testing one user can't see another's data.",
                      "fix": "Work through Needs a human", "href": f"#/project/{project_id}/human"})
    explanation["gaps"] = gaps_
    return explanation


def ai_payload(app: App, db: DB, project_id: int, row) -> dict:
    last = db.ai_last_run(project_id)
    last_online = db.ai_last_run(project_id, online=True)
    ai_job = app.running_job(project_id, "ai")
    return {
        "nightly": bool(row["ai_nightly"]),
        "never_online": bool(row["online_never"]),
        "job": ai_job.id if ai_job else None,
        "last_run": dict(last) if last else None,
        "last_online_run": dict(last_online) if last_online else None,
        "leads": [dict(lead) for lead in db.ai_leads(project_id)],
        "verdicts": {ref: {"verdict": v["verdict"], "reason": v["reason"], "model": v["model"]}
                     for ref, v in db.ai_verdicts(project_id).items()},
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
            try:
                self.wfile.write(body)
            except (BrokenPipeError, ConnectionAbortedError, ConnectionResetError):
                pass  # the browser navigated away mid-response; nothing to report

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
        except LocalModelError as exc:
            status, payload = 503, {"error": str(exc)}
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


def _runnable(db: DB, match: re.Match[str]):
    row = db.get_project_by_id(_project_id(match))
    if not row:
        raise ApiError(404, "Project not found")
    if not Path(row["path"]).is_dir():
        raise ApiError(400, "That project's folder no longer exists")
    return row


def api_run(app, db, match, query, body):
    """The scan panel: every option is a toggle, then one Scan button."""
    row = _runnable(db, match)
    job = app.start_run(row["id"], row["name"], run_options(body))
    return 202, {"job": job.id}


def api_scan(app, db, match, query, body):
    """Older form of /run, kept for scripts: offline/external instead of online/scanners."""
    row = _runnable(db, match)
    legacy = {"profile": body.get("profile", "standard"), "online": not _bool(body, "offline"),
              "scanners": _bool(body, "external", True)}
    if _bool(body, "history"):
        legacy["history"] = True
    job = app.start_run(row["id"], row["name"], run_options(legacy))
    return 202, {"job": job.id}


def api_job(app, db, match, query, body):
    job = app.jobs.get(match.group(1))
    if not job:
        raise ApiError(404, "Unknown job")
    return 200, job.to_dict()


def api_jobs(app, db, match, query, body):
    """Running and recent jobs, for the activity indicator."""
    jobs = []
    for job in app.recent_jobs():
        item = job.to_dict()
        item["log"] = item["log"][-3:]
        jobs.append(item)
    return 200, {"jobs": jobs}


def _full_options(body: dict) -> dict:
    """Run-everything defaults: a full scan plus the local AI review. Accepts the scan panel's options too."""
    legacy = {k: v for k, v in body.items() if k in ("profile", "online", "scanners", "history", "local_ai", "online_ai")}
    if "ai" in body:
        legacy["local_ai"] = body["ai"]
    if "offline" in body:
        legacy["online"] = not _bool(body, "offline")
    return run_options(legacy, profile="full", local_ai=True)


def api_full_check(app, db, match, query, body):
    row = _runnable(db, match)
    job = app.start_run(row["id"], row["name"], _full_options(body))
    return 202, {"job": job.id}


def api_full_check_all(app, db, match, query, body):
    projects = [p for p in db.list_projects() if Path(p["path"]).is_dir()]
    if not projects:
        raise ApiError(400, "Add a project first")
    options = _full_options(body)
    steps = [f"{p['name']}: {s}" for p in projects for s in run_steps(options)]

    def work(db: DB, job: Job) -> dict:
        results = []
        for i, project in enumerate(projects):
            if job.stop.is_set():
                break
            job.log.append(f"== {project['name']} ({i + 1} of {len(projects)})")
            results.append(run_project(db, job, project["id"], options, prefix=f"{project['name']}: "))
        return {"projects": results}

    job = app.start_job("full-all", None, f"{run_title(options)} of all {len(projects)} projects", steps, work)
    return 202, {"job": job.id}


def api_scanners(app, db, match, query, body):
    return 200, {"platform": scanner_install.platform_key(), "bin_dir": str(scanner_install.bin_dir()),
                 "tools": [s.to_dict() for s in scanner_install.status()]}


def api_scanners_install(app, db, match, query, body):
    names = body.get("names")
    pins = scanner_install.load_pins()
    if not isinstance(names, list) or not names or any(n not in pins for n in names):
        raise ApiError(400, f"Choose scanners from: {', '.join(pins)}")

    def work(db: DB, job: Job) -> dict:
        installed, failed = [], {}
        for name in names:
            job.enter(f"Download and verify {name} {pins[name]['version']}")

            def progress(fraction: float) -> None:
                job.fraction = fraction

            try:
                scanner_install.install(name, progress=progress, log=job.log.append)
                installed.append(name)
            except scanner_install.InstallError as exc:
                job.log.append(f"{name}: {exc}")
                failed[name] = str(exc)
        if failed and not installed:
            raise scanner_install.InstallError("; ".join(f"{k}: {v}" for k, v in failed.items()))
        return {"installed": installed, "failed": failed}

    steps = [f"Download and verify {n} {pins[n]['version']}" for n in names]
    job = app.start_job("install", None, f"Installing {', '.join(names)}", steps, work)
    return 202, {"job": job.id}


def api_scanners_remove(app, db, match, query, body):
    name = str(body.get("name", ""))
    try:
        removed = scanner_install.remove(name)
    except scanner_install.InstallError as exc:
        raise ApiError(400, str(exc)) from exc
    return 200, {"removed": removed}


def api_job_stop(app, db, match, query, body):
    job = app.jobs.get(match.group(1))
    if not job:
        raise ApiError(404, "Unknown job")
    job.stop.set()  # the AI review checks this between parts
    return 200, {"ok": True}


# local AI

TIME = re.compile(r"(?:[01]\d|2[0-3]):[0-5]\d")


def api_ai_status(app, db, match, query, body):
    info = ai_settings.status(db)
    info["schedule"] = ai_system.schedule_status()
    return 200, info


def api_ai_settings(app, db, match, query, body):
    model = body.get("model")
    if model is not None:
        ai_settings.make_client(db, model=str(model))  # refuses models that aren't installed
    ai_settings.save(db, model=str(model) if model is not None else None,
                     think=_bool(body, "think") if "think" in body else None)
    return 200, ai_settings.status(db)


def api_ai_benchmark(app, db, match, query, body):
    project_id = body.get("project_id")

    def work(db: DB, job: Job) -> dict:
        client = ai_settings.make_client(db)
        job.log.append(f"Loading {client.model} and timing a sample review ...")
        result = ai_review.benchmark(client)
        if isinstance(project_id, int) and db.get_project_by_id(project_id):
            units, todo = ai_review.pending_units(db, project_id, client.model)
            result["parts"], result["todo"] = len(units), len(todo)
            result["estimate_seconds"] = round(ai_review.estimate_seconds(todo, result["prompt_rate"],
                                                                          result["output_rate"], client.think))
        return result

    job = app.start_job("benchmark", project_id if isinstance(project_id, int) else None, "Timing the local model",
                        ["Loading the model and timing a sample"], work)
    return 202, {"job": job.id}


def api_ai_run(app, db, match, query, body):
    project_id = _project_id(match)
    row = db.get_project_by_id(project_id)
    if not row or not Path(row["path"]).is_dir():
        raise ApiError(404, "Project folder not found")
    max_minutes = body.get("max_minutes")
    if max_minutes is not None and (not isinstance(max_minutes, int) or not 1 <= max_minutes <= 1440):
        raise ApiError(400, "max_minutes must be between 1 and 1440")

    def work(db: DB, job: Job) -> dict:
        client = ai_settings.make_client(db)

        def progress(done: int, total: int) -> None:
            job.fraction = done / total if total else 1.0

        summary = ai_review.run_review(db, project_id, client, deadline=ai_system.deadline_from(None, max_minutes),
                                       should_stop=job.stop.is_set, log=job.log.append, progress=progress)
        return {k: getattr(summary, k) for k in ("status", "total", "cached", "done", "leads", "dropped", "rejected",
                                                 "errors", "message")}

    job = app.start_job("ai", project_id, f"Local AI review of {row['name']}", ["Local AI review"], work)
    return 202, {"job": job.id}


def api_ai_nightly(app, db, match, query, body):
    project_id = _project_id(match)
    if not db.get_project_by_id(project_id):
        raise ApiError(404, "Project not found")
    db.set_ai_nightly(project_id, _bool(body, "enabled"))
    return 200, {"ok": True}


def api_ai_lead(app, db, match, query, body):
    status = body.get("status")
    if status not in ("new", "confirmed", "dismissed"):
        raise ApiError(400, "Status must be new, confirmed or dismissed")
    if not db.ai_set_lead_status(_project_id(match), int(match.group(2)), status):
        raise ApiError(404, "Lead not found")
    return 200, {"ok": True}


def api_ai_schedule(app, db, match, query, body):
    at, until = str(body.get("at", "01:00")), str(body.get("until", "07:00"))
    if not TIME.fullmatch(at) or not TIME.fullmatch(until):
        raise ApiError(400, "Times must look like 01:00")
    try:
        ai_system.schedule(at, until, _bool(body, "wake"))
    except RuntimeError as exc:
        raise ApiError(400, str(exc)) from exc
    return 200, ai_system.schedule_status()


def api_ai_unschedule(app, db, match, query, body):
    try:
        ai_system.unschedule()
    except RuntimeError as exc:
        raise ApiError(400, str(exc)) from exc
    return 200, ai_system.schedule_status()


# paid online AI


def api_online_status(app, db, match, query, body):
    return 200, ai_online.status(db)


def api_online_settings(app, db, match, query, body):
    budget = body.get("budget")
    if budget is not None and (isinstance(budget, bool) or not isinstance(budget, (int, float))):
        raise ApiError(400, "budget must be a number of dollars")
    effort = body.get("effort")
    try:
        ai_online.save(db, enabled_=_bool(body, "enabled") if "enabled" in body else None,
                       budget_=float(budget) if budget is not None else None,
                       effort_=str(effort) if effort is not None else None)
    except ValueError as exc:
        raise ApiError(400, str(exc)) from exc
    return 200, ai_online.status(db)


def api_online_key(app, db, match, query, body):
    """Store the key in Windows Credential Manager. It's never returned, logged or written to LadPock's database."""
    key = body.get("key")
    if not isinstance(key, str) or len(key) > 400:
        raise ApiError(400, "Paste your Anthropic API key")
    try:
        ai_keys.store(key)
    except ai_keys.KeyError_ as exc:
        raise ApiError(400, str(exc)) from exc
    return 200, ai_online.status(db)


def api_online_forget_key(app, db, match, query, body):
    ai_keys.delete()
    return 200, ai_online.status(db)


def api_online_plan(app, db, match, query, body):
    row = db.get_project_by_id(_project_id(match))
    if not row:
        raise ApiError(404, "Project not found")
    return 200, {**ai_online.status(db), **ai_online.plan(db, row["id"])}


def api_online_never(app, db, match, query, body):
    project_id = _project_id(match)
    if not db.get_project_by_id(project_id):
        raise ApiError(404, "Project not found")
    db.set_online_never(project_id, _bool(body, "never"))
    return 200, {"ok": True}


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
    # Leads you confirmed belong in the fix list; unreviewed AI leads don't.
    leads = [_lead_as_finding(lead) for lead in db.ai_leads(row["id"]) if lead["status"] == "confirmed"]
    refs, lead_ids = query.get("ref"), query.get("lead")
    if refs or lead_ids:
        findings = [f for f in findings if f["ref"] in (refs or [])]
        leads = [_lead_as_finding(lead) for lead in db.ai_leads(row["id"]) if str(lead["id"]) in (lead_ids or [])]
    items = findings + leads
    return 200, {"prompt": report.fix_prompt(row["name"], items) if items else ""}


def _lead_as_finding(lead) -> dict:
    return {"severity": lead["severity"], "title": f"{lead['title']} (found by local AI review)", "file": lead["file"],
            "line": lead["line"], "message": lead["explanation"], "fix": lead["fix"]}


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
    ("POST", re.compile(r"/api/projects/(\d+)/run"), api_run),
    ("GET", re.compile(r"/api/projects/(\d+)/routes"), api_routes),
    ("GET", re.compile(r"/api/projects/(\d+)/advisories"), api_advisories),
    ("GET", re.compile(r"/api/projects/(\d+)/fix-prompt"), api_fix_prompt),
    ("POST", re.compile(r"/api/projects/(\d+)/suppress"), api_suppress),
    ("POST", re.compile(r"/api/projects/(\d+)/human"), api_human),
    ("GET", re.compile(r"/api/jobs/([0-9a-f]{32})"), api_job),
    ("GET", re.compile(r"/api/browse"), api_browse),
    ("GET", re.compile(r"/api/checks"), api_checks),
    ("POST", re.compile(r"/api/jobs/([0-9a-f]{32})/stop"), api_job_stop),
    ("GET", re.compile(r"/api/jobs"), api_jobs),
    ("GET", re.compile(r"/api/scanners"), api_scanners),
    ("POST", re.compile(r"/api/scanners/install"), api_scanners_install),
    ("POST", re.compile(r"/api/scanners/remove"), api_scanners_remove),
    ("POST", re.compile(r"/api/projects/(\d+)/full-check"), api_full_check),
    ("POST", re.compile(r"/api/full-check"), api_full_check_all),
    ("GET", re.compile(r"/api/ai"), api_ai_status),
    ("POST", re.compile(r"/api/ai/settings"), api_ai_settings),
    ("POST", re.compile(r"/api/ai/benchmark"), api_ai_benchmark),
    ("POST", re.compile(r"/api/ai/schedule"), api_ai_schedule),
    ("DELETE", re.compile(r"/api/ai/schedule"), api_ai_unschedule),
    ("POST", re.compile(r"/api/projects/(\d+)/ai/run"), api_ai_run),
    ("POST", re.compile(r"/api/projects/(\d+)/ai/nightly"), api_ai_nightly),
    ("POST", re.compile(r"/api/projects/(\d+)/ai/leads/(\d+)"), api_ai_lead),
    ("GET", re.compile(r"/api/online"), api_online_status),
    ("POST", re.compile(r"/api/online/settings"), api_online_settings),
    ("POST", re.compile(r"/api/online/key"), api_online_key),
    ("DELETE", re.compile(r"/api/online/key"), api_online_forget_key),
    ("GET", re.compile(r"/api/projects/(\d+)/online/plan"), api_online_plan),
    ("POST", re.compile(r"/api/projects/(\d+)/online/never"), api_online_never),
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
