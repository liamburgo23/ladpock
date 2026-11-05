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
- with two test accounts: can one account open the other's records? Only GET
  requests are used for this, whatever include_writes says, and the login
  values are held in memory, sent only to localhost and never stored or logged
"""

from __future__ import annotations

import difflib
import http.client
import ipaddress
import json
import re
import socket
import time
import urllib.error
import urllib.request
from dataclasses import dataclass, field
from typing import Callable
from urllib.parse import urlsplit

from .checks.base import describe
from .models import Finding, Severity
from .routes import AUTH_FLOW, Route

MAX_REQUESTS = 250
MAX_ACCOUNT_REQUESTS = 400  # the two-account check has its own allowance, so a big app can't use it all up first
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

CROSS_ACCOUNT = describe(
    "LP-LIVE-008", "One user can read another user's data", "authz", Severity.CRITICAL,
    why="Signed in as one test account, LadPock opened a record belonging to the other account. Any user can do the same "
        "by changing the ID in the URL, which is how most real data breaches of this kind happen.",
    fix="Load records through the signed-in user (for example where: { id, userId: user.id }) and return 404 when the "
        "record isn't theirs. Check the routes that update and delete these records too: they usually share the bug.",
    cwe=("CWE-639", "CWE-862"),
)
ADMIN_REACHABLE = describe(
    "LP-LIVE-009", "Ordinary account reached an admin endpoint", "authz", Severity.HIGH,
    why="This admin endpoint refused anonymous requests but answered both test accounts. Checking that someone is logged "
        "in isn't the same as checking they're an admin.",
    fix="Check the user's role on every admin route (not just that they're logged in), and put that check somewhere "
        "shared so a new route can't forget it. If either test account really is an admin, use ordinary accounts instead.",
    cwe=("CWE-285", "CWE-269"),
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
DYNAMIC_SEGMENT = re.compile(r"\(\?P<\w+>[^)]*\)|\[\[?(?:\.\.\.)?[^\]]+\]?\]|:\w+\??|\{[^}]+\}|<(?:\w+:)?\w+>")
ID_FIELDS = ("id", "_id", "uuid", "slug", "key", "pk")
IDENTITY_FIELDS = ("userId", "user_id", "sub")
SAFE_ID = re.compile(r"^[\w.~@+-]{1,128}$")
ERROR_KEYS = {"error", "errors", "message", "detail", "status", "code", "success", "ok"}
ACCEPT_ANY = {"Accept": "application/json, text/html;q=0.9, */*;q=0.1"}
SIGN_IN_FORM = re.compile(r"""(?i)type=["']?password""")
DENIED_PAGE = re.compile(r"(?i)access denied|forbidden|not authori[sz]ed|unauthori[sz]ed|not allowed|permission|not found|"
                         r"doesn't exist|does not exist")
VOLATILE_HTML = re.compile(r"""(?is)<script\b.*?</script>|<style\b.*?</style>|<!--.*?-->|<meta\b[^>]*>|"""
                           r"""<input\b[^>]*type=["']?hidden[^>]*>""")
MIN_PAGE_WORDS = 8
NO_SUCH_RECORD = "ladpock-no-such-record"
ADMIN_PATH = re.compile(r"(?i)/admin(?:/|$|[-_])")
IDENTITY_PATH = re.compile(r"(?i)/(?:me|whoami|current[-_]?user|profile|account|session|user)$")
USER_RESOURCE = re.compile(r"(?i)/(?:users?|profiles?|accounts?|members?|customers?)$")


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
    accounts: dict | None = None  # counts from the two-account check, when it ran
    stopped_early: bool = False  # hit the request limit


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
        self.limit = MAX_REQUESTS
        # Loopback only: ignore any proxy settings so requests can't leave the machine.
        self.opener = urllib.request.build_opener(_NoRedirect, urllib.request.ProxyHandler({}))

    def send(self, method: str, path: str, headers: dict[str, str] | None = None, body: bytes | None = None) -> Response | None:
        if self.should_stop():
            return None
        if self.result.requests >= self.limit:
            self.result.stopped_early = True
            return None
        self.result.requests += 1
        # Joined as text, not with urljoin: a path like /http://other.site must never move a request off this computer,
        # and some of these requests carry a login.
        request = urllib.request.Request(f"{self.base}/{path.lstrip('/')}", data=body, method=method,
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
        except (urllib.error.URLError, http.client.HTTPException, OSError, ValueError):
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
             snippet: str | None = None, confidence: str = "high") -> Finding:
    return Finding(check_id=info.id, title=info.title, severity=severity or info.severity, category=info.category,
                   message=message or info.why, fix=info.fix, file=route.file if route else None,
                   line=route.line if route else None, snippet=(snippet or url)[:220], confidence=confidence,
                   source="live", cwe=info.cwe, extra={"url": url})


def parse_login(text: str, label: str) -> dict[str, str]:
    """A session as a request header: 'Cookie: a=b', 'Authorization: Bearer x', 'Bearer x' or a bare 'a=b' cookie."""
    text = (text or "").strip()
    bad = f"{label}'s login isn't in a form LadPock understands. Use 'Cookie: name=value' or 'Authorization: Bearer ...'."
    if not text or "\n" in text or "\r" in text:
        raise ProbeError(bad)
    if text.lower().startswith("bearer "):
        return {"Authorization": text}
    named = re.match(r"^([A-Za-z][A-Za-z0-9-]*):\s*(\S.*)$", text)
    if named:
        return {named.group(1): named.group(2)}
    if "=" in text:
        return {"Cookie": text}
    raise ProbeError(bad)


def own_url_path(url: str, base: str) -> str:
    """A path on the app being checked. Anything pointing at another host is refused."""
    url = url.strip()
    bad = ProbeError(f"Record addresses must be on {base}, for example /api/orders/123")
    if re.search(r"\s", url):
        raise bad
    if url.startswith("/") and not url.startswith("//"):
        return url
    parts = urlsplit(url)
    if parts.scheme and f"{parts.scheme}://{parts.netloc}" == base:
        return (parts.path or "/") + (f"?{parts.query}" if parts.query else "")
    raise bad


def run_probe(url: str, routes: list[Route], *, include_writes: bool = False, log: Callable[[str], None] = print,
              should_stop: Callable[[], bool] = lambda: False, user_a: str | None = None, user_b: str | None = None,
              own_urls: list[str] | tuple[str, ...] = ()) -> ProbeResult:
    base = check_target(url)
    logins = None
    if user_a or user_b:
        if not (user_a and user_b):
            raise ProbeError("The two-account check needs a login for both account A and account B")
        logins = (parse_login(user_a, "Account A"), parse_login(user_b, "Account B"))
    own_paths = [own_url_path(u, base) for u in own_urls if u.strip()]
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

    if logins:
        client.limit = result.requests + MAX_ACCOUNT_REQUESTS
        _TwoAccounts(client, result, base, routes, logins[0], logins[1], own_paths).run()

    marker = client.send("GET", "/ladpock-probe-%ZZ")
    if marker is not None:
        responses.append(("/ladpock-probe-%ZZ", marker, None))
    for path, resp, route in responses:
        if resp.status >= 400 or resp.status == 200:
            match = STACK_MARKERS.search(resp.body)
            if match:
                result.findings.append(_finding(STACK_TRACE, route, base + path, snippet=match.group(0)[:160]))
                break
    if result.stopped_early:
        result.notes.append(f"Stopped after {result.requests} requests, so some routes weren't called.")
    if result.skipped_writes:
        result.notes.append(f"Skipped {result.skipped_writes} route(s) that change data (POST/PUT/PATCH/DELETE). "
                            "Turn on 'include writes' to call them too, against a development database.")
    for note in result.notes:
        log(f"Live checks: {note}")
    log(f"Live checks: {result.requests} requests, {len(result.findings)} problem(s) confirmed.")
    return result


def _answered(resp: Response | None) -> bool:
    """Did the app hand something over? Not an error, an empty answer, a '200 {error: ...}' or a sign-in page."""
    if not resp or not 200 <= resp.status < 300 or not resp.body.strip():
        return False
    if _looks_like_page(resp):
        return not SIGN_IN_FORM.search(resp.body)
    try:
        data = json.loads(resp.body)
    except ValueError:
        return True
    if isinstance(data, dict):
        return any(data.values()) and not set(data) <= ERROR_KEYS
    return bool(data)


def _page_words(body: str) -> list[str]:
    """What a person reads on a page. Scripts, tokens and nonces change on every request, so they don't count."""
    return re.sub(r"<[^>]+>", " ", VOLATILE_HTML.sub(" ", body[:MAX_BODY])).split()[:5000]


def _same_page(one: Response, two: Response) -> bool:
    words_one, words_two = _page_words(one.body), _page_words(two.body)
    if len(words_one) < MIN_PAGE_WORDS or len(words_two) < MIN_PAGE_WORDS:
        return False
    return words_one == words_two or difflib.SequenceMatcher(None, words_one, words_two, autojunk=False).ratio() >= 0.9


def _same_answer(one: Response, two: Response) -> bool:
    return one.body == two.body or (_looks_like_page(one) and _looks_like_page(two) and _same_page(one, two))


def _json_items(body: str) -> list[dict]:
    """The records in a JSON list answer: a top-level list, or the first list inside an object, one level down at most."""
    try:
        data = json.loads(body)
    except ValueError:
        return []
    for _ in range(3):
        if isinstance(data, dict):
            found = next((v for v in data.values() if isinstance(v, list)), None)
            data = found if found is not None else next((v for v in data.values() if isinstance(v, dict)), None)
    return [item for item in data if isinstance(item, dict)][:100] if isinstance(data, list) else []


def _id_of(item: dict, fields: tuple[str, ...]) -> str | None:
    for name in fields:
        value = item.get(name)
        if isinstance(value, (str, int)) and not isinstance(value, bool):
            value = str(value)
            if SAFE_ID.match(value) and value.strip("."):  # it goes into a URL, so nothing that could change the path
                return value
    return None


def _record_ids(resp: Response | None, source: str, param: str) -> list[str]:
    """Record IDs in a list answer: JSON records, or links like /orders/123 on a server-rendered page."""
    if not resp or not 200 <= resp.status < 300:
        return []
    if _looks_like_page(resp):
        links = re.findall(rf"""href=["']{re.escape(source.rstrip("/"))}/([\w.~@+-]+)/?(?:["'?#])""", resp.body)
        return list(dict.fromkeys(i for i in links if i.strip(".")))[:100]
    fields = (param, *ID_FIELDS)
    return list(dict.fromkeys(i for i in (_id_of(item, fields) for item in _json_items(resp.body)) if i))


def _object_of(body: str) -> list[dict]:
    """The object in a single-record answer, and any object directly inside it ({"user": {...}})."""
    try:
        data = json.loads(body)
    except ValueError:
        return []
    if isinstance(data, list) and len(data) == 1:
        data = data[0]
    return [data, *(v for v in data.values() if isinstance(v, dict))] if isinstance(data, dict) else []


def _holds_record(body: str, record: str, param: str) -> bool:
    fields = (param, *ID_FIELDS)
    return any(str(obj[name]) == record for obj in _object_of(body) for name in fields if name in obj)


def _param_name(slot: str) -> str:
    """'orderId' from [orderId], :orderId, {orderId} or <int:orderId>."""
    return (re.findall(r"\w+", slot) or [""])[-1]


def _route_regex(pattern: str) -> re.Pattern:
    return re.compile("[^/]+".join(re.escape(part) for part in DYNAMIC_SEGMENT.split(pattern.strip("^$"))) + "/?")


class _TwoAccounts:
    """Can account B open account A's records? Reads only: nothing here ever changes data."""

    def __init__(self, client: Client, result: ProbeResult, base: str, routes: list[Route], a: dict, b: dict, own_paths: list[str]):
        self.client, self.result, self.base = client, result, base
        self.a, self.b = {**ACCEPT_ANY, **a}, {**ACCEPT_ANY, **b}
        self.own_paths = own_paths
        self.gets = [r for r in routes if r.method in ("GET", "ANY") and _route_path(r) and not r.public_path and not r.webhook]
        self.stats = {"records_checked": 0, "protected": 0, "exposed": 0, "shared_skipped": 0, "routes_without_ids": 0,
                      "admin_exposed": 0}
        self.listings: dict[str, tuple[Response | None, Response | None]] = {}
        self.known: dict[str, str] = {}
        self.identity: str | None = None
        self.identity_source = ""
        self.signed_in = False
        self.opened: set[str] = set()
        self.exposed_routes: set[tuple[str, str]] = set()
        result.accounts = self.stats

    def get(self, path: str, login: dict | None = None) -> Response | None:
        return self.client.send("GET", path, login or ACCEPT_ANY)

    def listing(self, path: str) -> tuple[Response | None, Response | None]:
        if path not in self.listings:
            self.listings[path] = (self.get(path, self.a), self.get(path, self.b))
        return self.listings[path]

    def run(self) -> None:
        for route in self.gets:
            if not DYNAMIC_SEGMENT.search(route.path):
                self.read_list(_route_path(route))
        for route in self.gets:
            slots = list(DYNAMIC_SEGMENT.finditer(route.path))
            if len(slots) == 1:
                self.one_id(route, slots[0])
            elif len(slots) == 2:
                self.two_ids(route, slots)
            elif slots:
                self.stats["routes_without_ids"] += 1
        for path in self.own_paths:
            route = next((r for r in self.gets if _route_regex(r.path).fullmatch(path)), None)
            self.open_record(route, path, None, "", path.rsplit("/", 1)[0] + "/" + NO_SUCH_RECORD,
                             "You listed this as one of account A's private records, and account B opened it.")
        for route in self.gets:
            if ADMIN_PATH.search(route.path) and not DYNAMIC_SEGMENT.search(route.path):
                self.admin(route)
        self.add_notes()

    def read_list(self, path: str) -> None:
        self.known[path.rstrip("/")] = path
        as_a, as_b = self.listing(path)
        if not _answered(as_a):
            return
        if not _answered(self.get(path)):
            self.signed_in = True
        if IDENTITY_PATH.search(path.rstrip("/")) and _answered(as_b):
            fields = (*IDENTITY_FIELDS, *ID_FIELDS)
            mine = next((i for i in (_id_of(o, fields) for o in _object_of(as_a.body)) if i), None)
            theirs = next((i for i in (_id_of(o, fields) for o in _object_of(as_b.body)) if i), None)
            if mine and theirs and mine != theirs:
                self.identity, self.identity_source = mine, path

    def source_for(self, head: str) -> str:
        """The list that names these records: its own parent path, or a list with the same name (/orders/[id] and /api/orders)."""
        head = head.rstrip("/")
        if head in self.known:
            return self.known[head]
        name = head.rsplit("/", 1)[-1]
        return next((p for k, p in self.known.items() if name and k.rsplit("/", 1)[-1] == name), head)

    def records(self, source: str, param: str) -> tuple[list[str], list[str]]:
        if not source:
            return [], []
        as_a, as_b = self.listing(source)
        return _record_ids(as_a, source, param), _record_ids(as_b, source, param)

    def one_id(self, route: Route, slot: re.Match) -> None:
        head, param = route.path[: slot.start()].rstrip("/"), _param_name(slot.group(0))
        source = self.source_for(head)
        mine, theirs = self.records(source, param)
        private = [i for i in mine if i not in theirs]
        evidence = (f"The record is in account A's list at {source} but not in account B's, yet account B opened it. "
                    "If records like this are meant to be visible to every signed-in user, you can ignore this.")
        tests = [(i, evidence) for i in private[:3]]
        if self.identity and USER_RESOURCE.search(head) and self.identity not in theirs and self.identity not in private[:3]:
            tests.insert(0, (self.identity, f"This is account A's own user record (its ID comes from {self.identity_source}), "
                                            "and account B opened it."))
        if not tests:
            self.stats["shared_skipped" if mine else "routes_without_ids"] += 1  # the same lists means meant to be shared
            return
        filled = lambda value: DYNAMIC_SEGMENT.sub(value, route.path)
        for record, why in tests:
            if self.open_record(route, filled(record), record, param, filled(NO_SUCH_RECORD), why) == "exposed":
                break

    def two_ids(self, route: Route, slots: list[re.Match]) -> None:
        """/api/projects/[id]/tasks/[taskId]: take one of A's projects, list its tasks, then try one as B."""
        first, second = slots
        parents, others = self.records(self.source_for(route.path[: first.start()]), _param_name(first.group(0)))
        param = _param_name(second.group(0))
        tested = shared = False
        for parent in parents[:2]:
            inner = DYNAMIC_SEGMENT.sub(parent, route.path[: second.start()]).rstrip("/")
            mine, theirs = self.records(inner, param)
            shared = shared or bool(mine)
            # Under a parent only A has, everything is A's: B seeing the same list here is the problem, not a sign it's shared.
            for record in [i for i in mine if parent not in others or i not in theirs][:2]:
                tested = True
                path = DYNAMIC_SEGMENT.sub(parent, route.path[: second.start()]) + record + route.path[second.end():]
                absent = DYNAMIC_SEGMENT.sub(parent, route.path[: second.start()]) + NO_SUCH_RECORD + route.path[second.end():]
                why = (f"The record is in account A's list at {inner} but not in account B's, yet account B opened it. "
                       "If records like this are meant to be visible to every signed-in user, you can ignore this.")
                if self.open_record(route, path, record, param, absent, why) == "exposed":
                    return
        if not tested:
            self.stats["shared_skipped" if shared else "routes_without_ids"] += 1

    def open_record(self, route: Route | None, path: str, record: str | None, param: str, absent: str, evidence: str) -> str:
        if path in self.opened or (route and (route.method, route.path) in self.exposed_routes):
            return "skipped"
        self.opened.add(path)
        own = self.get(path, self.a)
        if not _answered(own):
            return "skipped"
        page = _looks_like_page(own)
        if page and len(_page_words(own.body)) < MIN_PAGE_WORDS:
            return "skipped"  # a single-page app's empty shell: the data comes later, so there's nothing to compare
        anon = self.get(path)
        if _answered(anon) and (not page or _same_answer(anon, own)):
            return "skipped"  # anyone can read it, so it isn't private (the no-login check covers that)
        self.signed_in = True
        self.stats["records_checked"] += 1
        other = self.get(path, self.b)
        if _answered(other) and page and DENIED_PAGE.search(" ".join(_page_words(other.body))):
            exposed = False
        elif _answered(other):
            exposed = _same_answer(other, own) or (record is not None and not page and _holds_record(other.body, record, param))
        else:
            exposed = False
        if exposed:
            # An address that answers the same whatever the ID isn't holding a record: it's a page or a fixed answer.
            baseline = self.get(absent, self.b)
            exposed = not (_answered(baseline) and _same_answer(baseline, own))
        if not exposed:
            self.stats["protected"] += 1
            return "protected"
        self.stats["exposed"] += 1
        if route:
            self.exposed_routes.add((route.method, route.path))
        self.result.findings.append(_finding(
            CROSS_ACCOUNT, route, self.base + path, f"{evidence} {CROSS_ACCOUNT.why}",
            snippet=f"GET {path} as account B -> {other.status}, account A's record", confidence="medium" if page else "high"))
        return "exposed"

    def admin(self, route: Route) -> None:
        path = _route_path(route)
        anon = self.get(path)
        if anon is None or _answered(anon):
            return
        if _answered(self.get(path, self.a)) and _answered(self.get(path, self.b)):
            self.signed_in = True
            self.stats["admin_exposed"] += 1
            self.result.findings.append(_finding(ADMIN_REACHABLE, route, self.base + path, confidence="medium",
                                                 snippet=f"GET {path} -> refused without a login, answered both test accounts"))

    def add_notes(self) -> None:
        notes, stats = self.result.notes, self.stats
        if not self.signed_in:
            notes.append("Neither test account seemed to be signed in: nothing answered differently from a request with no "
                         "login. Check the login values and that they haven't expired.")
            return
        if stats["shared_skipped"] and not stats["records_checked"]:
            notes.append("Both test accounts see the same records, so nothing could be tested for leaks between them. Use "
                         "two accounts that each have data of their own.")
        elif stats["routes_without_ids"] and not stats["records_checked"]:
            notes.append("Couldn't find any of account A's record IDs to try. Add some directly, for example /api/orders/123, "
                         "to the list of account A's records.")
        if stats["records_checked"]:
            notes.append("The two-account check only reads. It doesn't try to change or delete another account's records, so "
                         "check those routes as well, especially for any record it could read.")


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
