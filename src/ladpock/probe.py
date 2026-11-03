"""Live checks against your own app running on this computer.

The route matrix says what the code *looks* like it does; these checks ask
the running app. They only ever talk to localhost, so LadPock can't be pointed
at someone else's site, and by default they only send requests that can't
change data:

- every route the matrix found is called without logging in (GET by default;
  POST/PUT/PATCH/DELETE only with include_writes, using placeholder IDs and an
  empty body)
- the home page's security headers, CORS answer and server banner
- well-known files that should never be served (.env, .git, actuator, phpinfo)
- a short burst of failed sign-ins, to see whether anything slows it down
- every response is checked for stack traces
"""

from __future__ import annotations

import ipaddress
import json
import re
import socket
import time
import urllib.error
import urllib.request
from dataclasses import dataclass, field
from typing import Callable
from urllib.parse import urljoin, urlsplit

from .checks.base import describe
from .models import Finding, Severity
from .routes import AUTH_FLOW, Route

MAX_REQUESTS = 250
MAX_BODY = 200_000
TIMEOUT = 6
LOGIN_BURST = 20
EVIL_ORIGIN = "https://ladpock-probe.invalid"

UNAUTHENTICATED = describe(
    "LP-LIVE-001", "Endpoint answered without logging in", "authz", Severity.HIGH,
    why="LadPock called this endpoint on your running app with no login and it returned data. Anyone who finds the "
        "URL can do the same.",
    fix="Check the user at the top of the handler and return 401 when there isn't one. If the endpoint is meant to "
        "be public, make sure it returns nothing private.",
    cwe=("CWE-306", "CWE-862"),
)
HEADERS = describe(
    "LP-LIVE-002", "Security headers missing from responses", "config", Severity.LOW,
    why="The running app doesn't send headers that browsers use to block clickjacking, MIME sniffing and injected "
        "scripts.",
    fix="Send Content-Security-Policy, X-Content-Type-Options: nosniff, a frame-ancestors rule (or X-Frame-Options) "
        "and Referrer-Policy. helmet, Next.js headers() or your framework's security middleware can add them.",
    cwe=("CWE-693",),
)
CORS = describe(
    "LP-LIVE-003", "App lets any website read its responses (CORS)", "config", Severity.MEDIUM,
    why="LadPock sent a request from a made-up website and the app said yes. With credentials allowed too, any site "
        "a user visits can read their data from your API while they're logged in.",
    fix="Only allow your own origins, and never reflect the request's Origin header back while allowing credentials.",
    cwe=("CWE-942",),
)
EXPOSED_FILE = describe(
    "LP-LIVE-004", "Private file served to anyone", "secrets", Severity.CRITICAL,
    why="The running app serves a file that should never be public, such as your .env secrets, git metadata (which "
        "can rebuild your source code) or a diagnostics endpoint.",
    fix="Serve only your public/static folder, block dotfiles at the web server, and turn off diagnostic endpoints "
        "in production. Rotate any secrets the file contained.",
    cwe=("CWE-538", "CWE-200"),
)
NO_LOGIN_LIMIT = describe(
    "LP-LIVE-005", "Sign-in allows unlimited attempts", "auth", Severity.MEDIUM,
    why=f"LadPock sent {LOGIN_BURST} failed sign-ins in a row and none were slowed down or refused, so password "
        "guessing runs at full speed.",
    fix="Rate limit sign-in by IP and by account (for example 5 attempts a minute) and return 429 when it's hit.",
    cwe=("CWE-307",),
)
STACK_TRACE = describe(
    "LP-LIVE-006", "Error page shows a stack trace", "config", Severity.MEDIUM,
    why="An error response from the running app included a stack trace, which reveals file paths, libraries and code "
        "structure.",
    fix="Show a generic error in production and log the details on the server. Make sure debug mode is off.",
    cwe=("CWE-209",),
)
BANNER = describe(
    "LP-LIVE-007", "Server announces its software version", "config", Severity.LOW,
    why="Server and X-Powered-By headers with version numbers tell attackers exactly which known vulnerabilities to "
        "try.",
    fix="Remove X-Powered-By (app.disable('x-powered-by'), poweredByHeader: false) and hide version numbers in the "
        "Server header.",
    cwe=("CWE-200",),
)

SENSITIVE_PATHS = [
    ("/.env", re.compile(r"(?m)^[A-Z][A-Z0-9_]*\s*=")),
    ("/.env.local", re.compile(r"(?m)^[A-Z][A-Z0-9_]*\s*=")),
    ("/.env.production", re.compile(r"(?m)^[A-Z][A-Z0-9_]*\s*=")),
    ("/.git/HEAD", re.compile(r"^ref:\s*refs/")),
    ("/.git/config", re.compile(r"\[core\]")),
    ("/actuator/env", re.compile(r"propertySources|activeProfiles")),
    ("/actuator/heapdump", None),
    ("/phpinfo.php", re.compile(r"PHP Version|phpinfo\(\)")),
    ("/server-status", re.compile(r"Apache Server Status")),
    ("/.DS_Store", re.compile(r"Bud1")),
    ("/backup.sql", re.compile(r"(?i)CREATE TABLE|INSERT INTO")),
    ("/dump.sql", re.compile(r"(?i)CREATE TABLE|INSERT INTO")),
    ("/db.sqlite3", re.compile(r"^SQLite format 3")),
]
STACK_MARKERS = re.compile(
    r"Traceback \(most recent call last\)|\bat [\w$.<>]+ \((?:file://)?/?[\w./\\:-]+\.(?:js|ts|mjs|cjs):\d+:\d+\)|"
    r"Werkzeug Debugger|django\.core\.exceptions|Whitelabel Error Page.*Exception|java\.lang\.\w+Exception|"
    r"System\.\w+Exception:|SQLSTATE\[|PHP (?:Fatal|Parse) error|ActiveRecord::\w+Error|NoMethodError|"
    r"Microsoft\.AspNetCore\.Diagnostics", re.S)
VERSIONED = re.compile(r"\d+\.\d+")


class ProbeError(Exception):
    """The target isn't allowed or can't be reached."""


@dataclass
class Response:
    status: int
    headers: dict[str, str]
    body: str


@dataclass
class ProbeResult:
    base: str
    findings: list[Finding] = field(default_factory=list)
    requests: int = 0
    checked_routes: int = 0
    skipped_writes: int = 0
    notes: list[str] = field(default_factory=list)


def check_target(url: str) -> str:
    """Normalise the URL and refuse anything that isn't this computer."""
    parts = urlsplit(url.strip() if "://" in url else f"http://{url.strip()}")
    if parts.scheme not in ("http", "https") or not parts.hostname:
        raise ProbeError("Use an address like http://localhost:3000")
    host = parts.hostname.lower()
    if host not in ("localhost", "127.0.0.1", "::1") and not host.endswith(".localhost"):
        raise ProbeError("Live checks only run against your own computer (localhost / 127.0.0.1), never other sites")
    try:
        addresses = {info[4][0] for info in socket.getaddrinfo(host, parts.port or 80)}
    except socket.gaierror as exc:
        raise ProbeError(f"Can't resolve {host}: {exc}") from exc
    if not addresses or not all(ipaddress.ip_address(a.split("%")[0]).is_loopback for a in addresses):
        raise ProbeError(f"{host} doesn't resolve to this computer")
    return f"{parts.scheme}://{parts.netloc}"


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None  # a redirect to /login is an answer in itself


class Client:
    def __init__(self, base: str, result: ProbeResult, should_stop: Callable[[], bool]):
        self.base = base
        self.result = result
        self.should_stop = should_stop
        # Loopback only: ignore any proxy settings so requests can't leave the machine.
        self.opener = urllib.request.build_opener(_NoRedirect, urllib.request.ProxyHandler({}))

    def send(self, method: str, path: str, headers: dict[str, str] | None = None, body: bytes | None = None) -> Response | None:
        if self.result.requests >= MAX_REQUESTS or self.should_stop():
            return None
        self.result.requests += 1
        request = urllib.request.Request(urljoin(self.base + "/", path.lstrip("/")), data=body, method=method,
                                         headers={"User-Agent": "LadPock live check", **(headers or {})})
        try:
            with self.opener.open(request, timeout=TIMEOUT) as resp:
                return Response(resp.status, {k.lower(): v for k, v in resp.headers.items()},
                                resp.read(MAX_BODY).decode("utf-8", "replace"))
        except urllib.error.HTTPError as err:
            try:
                text = err.read(MAX_BODY).decode("utf-8", "replace")
            except OSError:
                text = ""
            return Response(err.code, {k.lower(): v for k, v in (err.headers or {}).items()}, text)
        except (urllib.error.URLError, OSError, ValueError):
            return None


def _looks_like_page(resp: Response) -> bool:
    return "html" in resp.headers.get("content-type", "") or resp.body.lstrip()[:15].lower().startswith(("<!doctype", "<html"))


def _route_path(route: Route) -> str | None:
    """A concrete URL for a route pattern, with placeholder values in dynamic segments."""
    if route.kind == "action" or not route.path.startswith("/") or " " in route.path:
        return None
    path = route.path
    path = re.sub(r"\[\[?\.\.\.[^\]]+\]?\]", "x", path)  # Next.js catch-all
    path = re.sub(r"\[[^\]]+\]|:\w+\??|\{[^}]+\}|<(?:\w+:)?\w+>", "1", path)
    path = re.sub(r"\(\?P<\w+>[^)]*\)|[\^$]", "", path)
    return path if "*" not in path else None


def _finding(info, route: Route | None, url: str, message: str | None = None, severity: Severity | None = None,
             snippet: str | None = None) -> Finding:
    return Finding(check_id=info.id, title=info.title, severity=severity or info.severity, category=info.category,
                   message=message or info.why, fix=info.fix, file=route.file if route else None,
                   line=route.line if route else None, snippet=(snippet or url)[:220], confidence="high",
                   source="live", cwe=info.cwe, extra={"url": url})


def run_probe(url: str, routes: list[Route], *, include_writes: bool = False, log: Callable[[str], None] = print,
              should_stop: Callable[[], bool] = lambda: False) -> ProbeResult:
    base = check_target(url)
    result = ProbeResult(base)
    client = Client(base, result, should_stop)
    home = client.send("GET", "/")
    if home is None:
        raise ProbeError(f"Nothing answered at {base}. Start your app (for example npm run dev) and try again.")
    log(f"Live checks against {base} ...")
    responses: list[tuple[str, Response, Route | None]] = [("/", home, None)]

    _headers(result, base, home)
    _banner(result, base, home)
    _cors(client, result, base)
    _sensitive_files(client, result, base)

    for route in routes:
        path = _route_path(route)
        if path is None:
            continue
        method = "GET" if route.method in ("GET", "HEAD", "ANY") else route.method
        if method not in ("GET",) and not include_writes:
            if not AUTH_FLOW.search(route.path):  # sign-in routes get the failed-login burst below instead
                result.skipped_writes += 1
            continue
        body = b"{}" if method in ("POST", "PUT", "PATCH") else None
        resp = client.send(method, path, {"Content-Type": "application/json", "Accept": "application/json"}, body)
        if resp is None:
            continue
        result.checked_routes += 1
        responses.append((path, resp, route))
        protected = resp.status in (401, 403) or (300 <= resp.status < 400 and "login" in resp.headers.get("location", "").lower())
        public = route.public_path or route.webhook or route.public
        if 200 <= resp.status < 300 and not protected and not public and not _looks_like_page(resp) and resp.body.strip():
            expected = route.auth in ("yes", "mw", "sig")
            message = (f"{route.method} {route.path} returned {resp.status} with data and no login. "
                       + ("The code appears to check the user, but the running app didn't stop the request. "
                          if expected else "")
                       + UNAUTHENTICATED.why)
            result.findings.append(_finding(UNAUTHENTICATED, route, base + path, message,
                                            snippet=f"{method} {path} -> {resp.status}"))

    for route in routes:
        if AUTH_FLOW.search(route.path) and route.method in ("POST", "ANY") and _route_path(route):
            _login_burst(client, result, base, route)
            break

    marker = client.send("GET", "/ladpock-probe-%ZZ")
    if marker is not None:
        responses.append(("/ladpock-probe-%ZZ", marker, None))
    for path, resp, route in responses:
        if resp.status >= 400 or resp.status == 200:
            match = STACK_MARKERS.search(resp.body)
            if match:
                result.findings.append(_finding(STACK_TRACE, route, base + path, snippet=match.group(0)[:160]))
                break
    if result.skipped_writes:
        result.notes.append(f"Skipped {result.skipped_writes} route(s) that change data (POST/PUT/PATCH/DELETE). "
                            "Turn on 'include writes' to call them too, against a development database.")
    log(f"Live checks: {result.requests} requests, {len(result.findings)} problem(s) confirmed.")
    return result


def _headers(result: ProbeResult, base: str, home: Response) -> None:
    h = home.headers
    missing = []
    csp = h.get("content-security-policy", "")
    if not csp:
        missing.append("Content-Security-Policy")
    if h.get("x-content-type-options", "").lower() != "nosniff":
        missing.append("X-Content-Type-Options")
    if "frame-ancestors" not in csp and not h.get("x-frame-options"):
        missing.append("X-Frame-Options or frame-ancestors")
    if not h.get("referrer-policy"):
        missing.append("Referrer-Policy")
    if base.startswith("https://") and not h.get("strict-transport-security"):
        missing.append("Strict-Transport-Security")
    if missing:
        result.findings.append(_finding(HEADERS, None, base + "/", f"Missing: {', '.join(missing)}. {HEADERS.why}",
                                        snippet=f"GET / -> missing {', '.join(missing)}"))


def _banner(result: ProbeResult, base: str, home: Response) -> None:
    leaks = [f"{name}: {home.headers[name]}" for name in ("x-powered-by", "server", "x-aspnet-version", "x-aspnetmvc-version")
             if name in home.headers and (name == "x-powered-by" or VERSIONED.search(home.headers[name]))]
    if leaks:
        result.findings.append(_finding(BANNER, None, base + "/", snippet="; ".join(leaks)))


def _cors(client: Client, result: ProbeResult, base: str) -> None:
    resp = client.send("GET", "/", {"Origin": EVIL_ORIGIN})
    if resp is None:
        return
    allow = resp.headers.get("access-control-allow-origin", "")
    credentials = resp.headers.get("access-control-allow-credentials", "").lower() == "true"
    if allow == EVIL_ORIGIN or (allow == "*" and credentials):
        severity = Severity.HIGH if credentials else Severity.MEDIUM
        result.findings.append(_finding(CORS, None, base + "/", severity=severity,
                                        snippet=f"Origin: {EVIL_ORIGIN} -> Access-Control-Allow-Origin: {allow}"
                                                + (", credentials allowed" if credentials else "")))


def _sensitive_files(client: Client, result: ProbeResult, base: str) -> None:
    for path, signature in SENSITIVE_PATHS:
        resp = client.send("HEAD" if signature is None else "GET", path)
        if resp is None or resp.status != 200 or _looks_like_page(resp):
            continue
        if signature is None or signature.search(resp.body):
            preview = resp.body.splitlines()[0][:40] if resp.body else ""
            if path.startswith("/.env") and "=" in preview:
                preview = preview.split("=", 1)[0] + "=****"
            result.findings.append(_finding(EXPOSED_FILE, None, base + path, snippet=f"GET {path} -> 200 {preview}"))


def _login_burst(client: Client, result: ProbeResult, base: str, route: Route) -> None:
    path = _route_path(route)
    body = json.dumps({"email": "ladpock-probe@example.invalid", "username": "ladpock-probe",
                       "password": "not-the-password"}).encode()
    statuses = []
    started = time.monotonic()
    for _ in range(LOGIN_BURST):
        resp = client.send("POST", path, {"Content-Type": "application/json"}, body)
        if resp is None:
            return
        statuses.append(resp.status)
        if resp.status == 429 or "retry-after" in resp.headers:
            return
    if time.monotonic() - started > LOGIN_BURST * 1.5:
        return  # responses slowed right down: some kind of throttling is happening
    if all(s in (400, 401, 403, 404, 422) or 200 <= s < 300 for s in statuses) and not all(s == 404 for s in statuses):
        result.findings.append(_finding(NO_LOGIN_LIMIT, route, base + path,
                                        snippet=f"{LOGIN_BURST} x POST {path} -> {sorted(set(statuses))}, never 429"))
