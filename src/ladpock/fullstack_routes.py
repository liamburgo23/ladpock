"""The route matrix for full-stack JavaScript frameworks with file-based routing:
SvelteKit, Remix / React Router, Nuxt (Nitro) and Astro.

Files decide the URLs and exports decide the methods, so every framework here
comes down to the same steps: turn a file path into a URL, split the module
into its exported handlers, and assess each one like a Next.js handler.
"""

from __future__ import annotations

import re
from typing import Iterator

from .files import JS_EXT, FileIndex
from .jsparse import capped, line_of, match_bracket, split_args, strip_comments
from .routes import (AUTH, DB, METHODS, MUTATING, MUTATION, OWNER, PAID_API, RATE_LIMIT, RLS_CLIENT, SERVICE_ROLE, SIGNATURE,
                     VALIDATION, Middleware, Route, _auth_names, _calls_any)
from .server_routes import PAID_CALL

CODE = frozenset(JS_EXT - {".vue", ".svelte"})
EXPORT = re.compile(r"(?m)^export\s+(?:async\s+)?(?:function|const|let|var)\s+(\w+)\b")

FW_AUTH = re.compile(
    r"\blocals\??\.(?:user|session|auth|account|getSession|safeGetSession|pb\.authStore)\b|\bevent\.context\.(?:user|auth|session)\b|"
    r"\b(?:requireUserSession|getUserSession|serverSupabaseUser|getServerSession|requireUserId|getUserId|requireUser|"
    r"safeGetSession|requireAuth|requireLogin|getAuthenticatedUser)\s*\(|\bauthenticator\.\w+\(|\bisAuthenticated\b|"
    r"\buser\s*=\s*await\s+\w*[Aa]uth"
)
FW_OWNER = re.compile(
    r"\blocals\??\.user\??\.(?:id|sub)\b|\bcontext\.user\??\.(?:id|sub)\b|\bsession\??\.user\??\.(?:id|sub)\b|"
    r"\bwhere\s*:\s*\{[^}]*\b(?:userId|ownerId|authorId|user_id|owner_id)\b|\b(?:userId|ownerId|authorId)\s*(?:,|\})"
)
FW_RLS = re.compile(r"\blocals\??\.supabase\b|\bserverSupabaseClient\s*\(|\bcreateServerClient\s*\(")
FW_VALIDATION = re.compile(r"\breadValidatedBody\s*\(|\bgetValidatedQuery\s*\(|\bgetValidatedRouterParams\s*\(|\bsuperValidate\s*\(|"
                           r"\bparseWithZod\s*\(|\bzfd\.|\binput\s*:\s*z\.")
READS_BODY = re.compile(r"\.json\(\)|\.formData\(\)|\breadBody\s*\(|\breadFormData\s*\(|\breadMultipartFormData\s*\(|\bformData\b|"
                        r"\brequest\.body\b|\bbody\b|\binput\b")
GUARDED_PREFIX = re.compile(r"(!?)[\w.()]*(?:pathname|\.path|\.url)\.startsWith\(\s*['\"`](/[^'\"`]*)['\"`]")
DYNAMIC = re.compile(r"\[|/:\w")


def _assess(route: Route, body: str, module: str, auth_names: set[str], mw: Middleware) -> Route:
    if SIGNATURE.search(body) or SIGNATURE.search(module):
        route.auth = "sig"
    elif AUTH.search(body) or FW_AUTH.search(body) or _calls_any(body, auth_names):
        route.auth = "yes"
    elif mw.auth and mw.covers(route.path):
        route.auth = "mw"
    route.db = bool(DB.search(body))
    route.mutates = route.db and bool(MUTATION.search(body))
    route.paid_api = bool(PAID_API.search(module) and PAID_CALL.search(body))
    route.dynamic = bool(DYNAMIC.search(route.path))
    if route.db and (route.dynamic or route.method in MUTATING):
        if OWNER.search(body) or FW_OWNER.search(body):
            route.owner = "yes"
        elif (RLS_CLIENT.search(module) or FW_RLS.search(module)) and not SERVICE_ROLE.search(module):
            route.owner = "rls"
        else:
            route.owner = "no"
    if route.method in MUTATING:
        validated = VALIDATION.search(body) or VALIDATION.search(module) or FW_VALIDATION.search(body)
        route.validation = ("yes" if validated else "no") if READS_BODY.search(body) else "n/a"
    if RATE_LIMIT.search(body):
        route.rate_limit = "yes"
    elif mw.rate_limit and mw.covers(route.path):
        route.rate_limit = "mw"
    return route


def _guard(index: FileIndex, pattern: re.Pattern[str]) -> Middleware:
    """A framework's app-wide hook (hooks.server.ts, src/middleware.ts, server/middleware/*), treated like Next.js middleware."""
    files = [rel for rel in index.sources(CODE) if pattern.search(rel)]
    if not files:
        return Middleware()
    text = "\n".join(strip_comments(index.read(rel) or "") for rel in files)
    prefixes = GUARDED_PREFIX.findall(text)
    # A guard like `if (!pathname.startsWith('/public')) requireLogin()` protects everything else, so treat it as global.
    matchers = None if not prefixes or any(neg for neg, _ in prefixes) else [re.compile("^" + re.escape(p)) for _, p in prefixes]
    return Middleware(file=files[0], auth=bool(AUTH.search(text) or FW_AUTH.search(text) or "redirect" in text and "session" in text),
                      rate_limit=bool(RATE_LIMIT.search(text)), matchers=matchers)


def _sections(code: str) -> Iterator[tuple[str, int, str]]:
    """(export name, offset, text up to the next export) for each top-level export."""
    matches = list(EXPORT.finditer(code))
    for i, match in enumerate(matches):
        end = matches[i + 1].start() if i + 1 < len(matches) else len(code)
        yield match.group(1), match.start(), code[match.start(): end]


# ---------- SvelteKit ----------

SK_SERVER = re.compile(r"(?:^|/)src/routes/((?:.*/)?)\+server\.(?:ts|js)$")
SK_PAGE = re.compile(r"(?:^|/)src/routes/((?:.*/)?)\+page\.server\.(?:ts|js)$")
SK_ACTIONS = re.compile(r"(?m)^export\s+const\s+actions\b[^=]*=\s*\{")


def _sk_path(segment: str) -> str:
    parts = [p for p in segment.strip("/").split("/") if p and not (p.startswith("(") and p.endswith(")"))]
    parts = [re.sub(r"=\w+\]", "]", re.sub(r"^\[\[(.+)\]\]$", r"[\1]", p)) for p in parts]
    return "/" + "/".join(parts)


def sveltekit_routes(index: FileIndex) -> list[Route]:
    mw = _guard(index, re.compile(r"(?:^|/)src/hooks\.server(?:/index)?\.(?:ts|js)$"))
    routes = []
    for rel in index.sources(CODE):
        server, page = SK_SERVER.search(rel), SK_PAGE.search(rel)
        if not (server or page):
            continue
        code = strip_comments(index.read(rel) or "")
        names = _auth_names(code)
        path = _sk_path((server or page).group(1))
        for name, offset, text in _sections(code):
            if server and name in (*METHODS, "fallback"):
                method = "ANY" if name == "fallback" else name
                routes.append(_assess(Route(method, path, rel, line_of(code, offset), "sveltekit"), text, code, names, mw))
            elif page and name == "load" and DB.search(text):
                routes.append(_assess(Route("GET", path, rel, line_of(code, offset), "sveltekit"), text, code, names, mw))
        match = SK_ACTIONS.search(code) if page else None
        if match:
            open_idx = match.end() - 1
            close = match_bracket(code, open_idx)
            for arg in split_args(code, open_idx, close) if close > 0 else []:
                key = re.match(r"\s*(?:async\s+)?(\w+)", arg)
                if not key or not arg.strip():
                    continue
                action = key.group(1)
                url = path if action == "default" else f"{path}?/{action}"
                routes.append(_assess(Route("ACTION", url, rel, line_of(code, code.find(arg, open_idx)), "sveltekit"),
                                      arg, code, names, mw))
    return routes


# ---------- Remix / React Router ----------

REMIX_FILE = re.compile(r"(?:^|/)app/routes/(.+)\.(?:tsx|ts|jsx|js)$")
RR_CONFIG = re.compile(r"\broute\(\s*['\"`]([^'\"`]*)['\"`]\s*,\s*['\"`]([^'\"`]+)['\"`]|\bindex\(\s*['\"`]([^'\"`]+)['\"`]")


def _remix_path(name: str) -> str:
    name = re.sub(r"/(?:route|index)$", "", name).replace("[.]", "\0")
    parts = []
    for part in re.split(r"[./]", name):
        if not part or part == "_index" or part.startswith("_"):
            continue
        part = part.rstrip("_").replace("(", "").replace(")", "")
        if part == "$":
            part = "*"
        elif part.startswith("$"):
            part = ":" + part[1:]
        parts.append(re.sub(r"\[(.+?)\]", r"\1", part).replace("\0", "."))
    return "/" + "/".join(parts)


def remix_routes(index: FileIndex) -> list[Route]:
    configured: dict[str, str] = {}
    for rel in ("app/routes.ts", "src/routes.ts"):
        if index.exists(rel):
            base = rel.rsplit("/", 1)[0]
            for m in capped(RR_CONFIG.finditer(strip_comments(index.read(rel) or ""))):
                configured[f"{base}/{m.group(2) or m.group(3)}"] = "/" + (m.group(1) or "").strip("/")
    routes = []
    mw = Middleware()
    for rel in index.sources(CODE):
        flat = REMIX_FILE.search(rel)
        if not (flat or rel in configured):
            continue
        code = strip_comments(index.read(rel) or "")
        names = _auth_names(code)
        path = configured.get(rel) or _remix_path(flat.group(1))
        for name, offset, text in _sections(code):
            if name == "action":
                routes.append(_assess(Route("POST", path, rel, line_of(code, offset), "remix"), text, code, names, mw))
            elif name == "loader" and DB.search(text):
                routes.append(_assess(Route("GET", path, rel, line_of(code, offset), "remix"), text, code, names, mw))
    return routes


# ---------- Nuxt / Nitro ----------

NUXT_FILE = re.compile(r"(?:^|/)server/(api|routes)/(.+)\.(?:ts|js|mjs|mts|cts)$")
NUXT_HANDLER = re.compile(r"\b(?:defineEventHandler|eventHandler|defineCachedEventHandler|defineEventHandlerWithAuth)\s*\(")


def nuxt_routes(index: FileIndex) -> list[Route]:
    mw = _guard(index, re.compile(r"(?:^|/)server/middleware/[^/]+\.(?:ts|js|mjs|mts)$"))
    security_module = any("nuxt-security" in (index.read(rel) or "") for rel in index.iter(names={"package.json"}))
    routes = []
    for rel in index.sources(CODE):
        match = NUXT_FILE.search(rel)
        if not match:
            continue
        code = strip_comments(index.read(rel) or "")
        handler = NUXT_HANDLER.search(code)
        if not handler:
            continue
        rest = match.group(2)
        verb = re.search(r"\.(get|post|put|patch|delete|head|options)$", rest)
        rest = rest[: verb.start()] if verb else rest
        rest = re.sub(r"(?:^|/)index$", "", rest)
        path = ("/api/" if match.group(1) == "api" else "/") + rest
        route = Route(verb.group(1).upper() if verb else "ANY", path.rstrip("/") or "/", rel, line_of(code, handler.start()), "nuxt")
        route = _assess(route, code, code, _auth_names(code), mw)
        if route.rate_limit == "no" and security_module:
            route.rate_limit = "mw"  # nuxt-security's rate limiter is on by default
        routes.append(route)
    return routes


# ---------- Astro ----------

ASTRO_ENDPOINT = re.compile(r"(?:^|/)src/pages/(.+)\.(?:ts|js|mjs)$")
ASTRO_PAGE = re.compile(r"(?:^|/)src/pages/(.+)\.astro$")
ASTRO_ACTIONS = re.compile(r"(?:^|/)src/actions/[^/]+\.(?:ts|js|mjs)$")
ASTRO_ACTION = re.compile(r"\b(\w+)\s*:\s*defineAction\s*\(")


def _astro_path(name: str) -> str:
    return "/" + re.sub(r"(?:^|/)index$", "", name)


def astro_routes(index: FileIndex) -> list[Route]:
    mw = _guard(index, re.compile(r"(?:^|/)src/middleware(?:/index)?\.(?:ts|js|mjs)$"))
    routes = []
    for rel in index.sources(CODE):
        endpoint, page = ASTRO_ENDPOINT.search(rel), ASTRO_PAGE.search(rel)
        if endpoint:
            code = strip_comments(index.read(rel) or "")
            static = re.search(r"\bexport\s+const\s+prerender\s*=\s*true", code)
            for name, offset, text in _sections(code):
                if name in (*METHODS, "ALL"):
                    route = Route("ANY" if name == "ALL" else name, _astro_path(endpoint.group(1)), rel,
                                  line_of(code, offset), "astro")
                    route.public = bool(static)  # built ahead of time, so it can't see who's asking
                    routes.append(_assess(route, text, code, _auth_names(code), mw))
        elif page:
            text = index.read(rel) or ""
            front = re.match(r"\s*---\r?\n(.*?)\r?\n---", text, re.S)
            if front and re.search(r"Astro\.request\.method\s*===?\s*['\"]POST['\"]", front.group(1)):
                code = strip_comments(front.group(1))
                routes.append(_assess(Route("POST", _astro_path(page.group(1)), rel, 2, "astro"), code, code,
                                      _auth_names(code), mw))
        elif ASTRO_ACTIONS.search(rel):
            code = strip_comments(index.read(rel) or "")
            for match in capped(ASTRO_ACTION.finditer(code)):
                open_idx = match.end() - 1
                close = match_bracket(code, open_idx)
                body = code[open_idx: close + 1] if close > 0 else code[open_idx:]
                routes.append(_assess(Route("ACTION", f"action {match.group(1)}()", rel, line_of(code, match.start()), "astro"),
                                      body, code, _auth_names(code), mw))
    return routes


def analyze_fullstack(index: FileIndex) -> list[Route]:
    return sveltekit_routes(index) + remix_routes(index) + nuxt_routes(index) + astro_routes(index)
