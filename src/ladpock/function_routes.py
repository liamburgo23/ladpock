"""The route matrix for backends that aren't a web server you run: tRPC, Convex,
GraphQL resolvers, Firebase Cloud Functions, Supabase Edge Functions, Vercel,
Netlify and Cloudflare functions, and AWS Lambda.

A lot of generated apps have no Express or Next.js route to read, because their
whole backend is one of these. Each function still becomes a Route, so the
access-control and abuse checks apply. Functions reached through a client library
rather than a URL path on your app (tRPC aside) get a path without a leading
slash, like convex/orders:list, which the live checks skip.
"""

from __future__ import annotations

import re
from functools import lru_cache
from itertools import islice
from typing import Iterator

from .files import FileIndex, basename
from .jsparse import line_of, match_bracket, strip_comments
from .routes import AUTH, DB, MUTATION, OWNER, PAID_API, RATE_LIMIT, SERVICE_ROLE, SIGNATURE, VALIDATION, Route, _auth_names, _calls_any
from .server_routes import PAID_CALL

JS = frozenset({".ts", ".js", ".mjs", ".cjs", ".tsx", ".jsx", ".mts"})
ID_INPUT = re.compile(r"\b(?:input|args|data|params|event\.pathParameters)\??\.\w*(?:[iI]d|ID|slug|uuid)\b|"
                      r"\{\s*(?:\w+\s*,\s*)*\w*[iI]d\s*(?:,\s*\w+\s*)*\}")
READS_INPUT = re.compile(r"\b(?:input|args|request\.data|data|req\.body|event\.body|\.json\(\)|\.formData\(\))")
WRITE_WORDS = re.compile(r"\.(?:set|add|patch|replace|push|commit|run)\s*\(")
FIREBASE_DB = re.compile(r"\.collection\(|\.doc\(|\.ref\(|\bfirestore\(\)|\bgetFirestore\(")
D1 = re.compile(r"\benv\.\w+\.(?:prepare|exec|batch|put|delete)\(|\bcontext\.env\.\w+\.(?:prepare|exec|batch|put|delete)\(")
SQL_WRITE = re.compile(r"(?i)\b(?:INSERT\s+INTO|UPDATE\s+\w+\s+SET|DELETE\s+FROM)\b")
PRIVATE_KEY = re.compile(r"\.auth\.(?:getUser|getClaims)\(|\bverifyIdToken\(|\bjwtVerify\(|\bjwt\.verify\(|\bverifyToken\(|\bgetAuth\(")
OWNER_MORE = re.compile(r"\b(?:ctx|context|request|req)\.(?:session\??\.)?(?:user|auth)\??\.(?:id|uid|sub|userId)\b|\bctx\.userId\b|"
                        r"\bidentity\??\.(?:subject|tokenIdentifier)\b|\buid\b|\buserId\b(?!\s*:\s*(?:input|args|data))")


# Limits, because scanned code can be huge or crafted to be slow. See jsparse.MAX_BLOCK.
MAX_FUNCTIONS_PER_FILE = 200
MAX_BODY = 60_000


def _sources(index: FileIndex, *needles: str, exts=JS) -> Iterator[tuple[str, str]]:
    """(file, text) for files worth reading: written by a person, and mentioning what this analyzer looks for."""
    for rel in index.sources(exts):
        raw = index.read(rel) or ""
        if not needles or any(needle in raw for needle in needles):
            yield rel, raw


def _closing(code: str, open_idx: int) -> int:
    """match_bracket, but it won't read more than a function's worth of text. -1 if it isn't closed by then."""
    close = match_bracket(code[open_idx: open_idx + MAX_BODY], 0)
    return open_idx + close if close != -1 else -1


@lru_cache(maxsize=4)
def _names_in(module: str) -> frozenset[str]:
    return frozenset(_auth_names(module))


@lru_cache(maxsize=4)
def _uses_paid_api(module: str) -> bool:
    return bool(PAID_API.search(module))


def _assess(route: Route, body: str, module: str, *, authed: bool = False, validated: bool = False) -> Route:
    """The common questions, once a function's body has been found."""
    names = _names_in(module)
    if SIGNATURE.search(body):
        route.auth = "sig"
    elif authed or AUTH.search(body) or PRIVATE_KEY.search(body) or _calls_any(body, names):
        route.auth = "yes"
    route.db = bool(DB.search(body) or FIREBASE_DB.search(body) or D1.search(body))
    route.mutates = route.db and bool(MUTATION.search(body) or SQL_WRITE.search(body)
                                      or (FIREBASE_DB.search(body) and WRITE_WORDS.search(body)))
    route.paid_api = bool(_uses_paid_api(module) and PAID_CALL.search(body))
    route.dynamic = route.dynamic or bool(ID_INPUT.search(body))
    if route.db and (route.dynamic or route.mutates):
        route.owner = "yes" if OWNER.search(body) or OWNER_MORE.search(body) else "no"
    if route.mutates or route.method == "POST":
        route.validation = ("yes" if validated or VALIDATION.search(body) else "no") if READS_INPUT.search(body) else "n/a"
    if RATE_LIMIT.search(body):
        route.rate_limit = "yes"
    return route


# ---------- tRPC ----------

PROCEDURE = re.compile(r"(?m)^[ \t]*(\w+)\s*:\s*((?:\w+\.)*\w*[Pp]rocedure)\b")
TRPC_CALL = re.compile(r"\.(?:query|mutation)\s*\(")
ROUTER_VAR = re.compile(r"(?:const|let|var)\s+(\w+)\s*=\s*(?:createTRPCRouter|router|t\.router|createRouter)\s*\(")
ROUTER_ENTRY = re.compile(r"(?m)^[ \t]*(\w+)\s*:\s*(\w+)\s*,?\s*$|^[ \t]*(\w+)\s*,\s*$")
AUTHED_PROCEDURE = re.compile(r"(?i)protected|auth|user|admin|private|member|staff|owner|logged|session|org|team|tenant|paid|premium")
PROCEDURE_GUARD = re.compile(r"\.use\(\s*\w*(?:[aA]uth|[sS]ession|[pP]rotect|[lL]ogin)")
TRPC_LIMITED = re.compile(r"(?i)rate_?limit|throttle")
TRPC_AUTH = re.compile(r"\bctx\.(?:session|user|auth|userId)\b")


def trpc_routes(index: FileIndex) -> list[Route]:
    modules = {}
    for rel, raw in _sources(index, "rocedure", "trpc", "TRPC"):
        code = strip_comments(raw)
        if ("rocedure" in code and TRPC_CALL.search(code)) or (ROUTER_VAR.search(code) and "trpc" in code.lower()):
            modules[rel] = code
    prefixes: dict[str, str] = {}
    for code in modules.values():  # appRouter = router({ order: orderRouter }) gives order.* its URL prefix
        for match in islice(ROUTER_VAR.finditer(code), MAX_FUNCTIONS_PER_FILE):
            open_idx = code.find("{", match.end(), match.end() + 200)
            close = _closing(code, open_idx) if open_idx != -1 else -1
            if close == -1:
                continue
            for entry in ROUTER_ENTRY.finditer(code[open_idx: close]):
                key, value = entry.group(1) or entry.group(3), entry.group(2) or entry.group(3)
                if key and "rocedure" not in value:
                    prefixes[value] = key
    routes = []
    for rel, code in modules.items():
        owners = [(m.start(), m.group(1)) for m in islice(ROUTER_VAR.finditer(code), MAX_FUNCTIONS_PER_FILE)]
        procedures = list(islice(PROCEDURE.finditer(code), MAX_FUNCTIONS_PER_FILE))
        for i, match in enumerate(procedures):
            end = procedures[i + 1].start() if i + 1 < len(procedures) else len(code)
            body = code[match.start(): min(end, match.start() + MAX_BODY)]
            kind = re.search(r"\.(query|mutation|subscription)\s*\(", body)
            if not kind or kind.group(1) == "subscription":
                continue
            router = next((name for start, name in reversed(owners) if start < match.start()), None)
            prefix = prefixes.get(router or "", "")
            path = f"/api/trpc/{prefix + '.' if prefix else ''}{match.group(1)}"
            base = match.group(2).rsplit(".", 1)[-1]
            route = Route("GET" if kind.group(1) == "query" else "POST", path, rel, line_of(code, match.start()), "trpc")
            authed = bool(AUTHED_PROCEDURE.search(base) or PROCEDURE_GUARD.search(body) or TRPC_AUTH.search(body))
            # Without tRPC's own .query( call, which would otherwise read as a database query.
            handler = body[:kind.start()] + body[kind.end() - 1:]
            routes.append(_assess(route, handler, code, authed=authed, validated=".input(" in body))
            if TRPC_LIMITED.search(base):
                routes[-1].rate_limit = "yes"
    return routes


# ---------- Convex ----------

CONVEX_FN = re.compile(r"(?m)^export\s+const\s+(\w+)\s*=\s*(\w*)\s*\(")
CONVEX_KINDS = re.compile(r"(?i)(query|mutation|action|httpaction)$")
CONVEX_AUTH = re.compile(r"\bctx\.auth\.getUserIdentity\(|\bgetAuthUserId\(|\bctx\.auth\b|\brequire\w*\(\s*ctx\b|\bget\w*User\w*\(\s*ctx\b|\bauth\w*\(\s*ctx\b")
CONVEX_DB = re.compile(r"\bctx\.db\.")
CONVEX_WRITE = re.compile(r"\bctx\.db\.(?:insert|patch|replace|delete)\(")
CONVEX_OWNER = re.compile(r"\bidentity\b|\buserId\b|\bsubject\b|\btokenIdentifier\b|\bwithIndex\(\s*['\"]by_?[uU]ser")
CONVEX_ID_ARG = re.compile(r"\bv\.id\(")


def convex_routes(index: FileIndex) -> list[Route]:
    routes = []
    for rel, raw in _sources(index):
        if not re.search(r"(?:^|/)convex/", rel) or "/_generated/" in rel or basename(rel).startswith("schema."):
            continue
        code = strip_comments(raw)
        name = rel.split("convex/", 1)[-1].rsplit(".", 1)[0]
        wrappers = set(re.findall(r"(?:const|let)\s+(\w+)\s*=\s*custom(?:Query|Mutation|Action)\(", code))
        for match in islice(CONVEX_FN.finditer(code), MAX_FUNCTIONS_PER_FILE):
            builder = match.group(2)
            kind = CONVEX_KINDS.search(builder)
            if not kind or builder.lower().startswith("internal"):
                continue  # internal functions can't be called from outside
            close = _closing(code, match.end() - 1)
            body = code[match.end(): close] if close != -1 else code[match.end(): match.end() + MAX_BODY]
            route = Route("GET" if kind.group(1).lower() == "query" else "POST", f"convex/{name}:{match.group(1)}", rel,
                          line_of(code, match.start()), "convex")
            # Wrappers like authedQuery or customQuery are how Convex apps usually add a login check.
            if CONVEX_AUTH.search(body) or builder in wrappers or re.match(r"(?i)^(?:authed|protected|auth|user|private|admin)", builder):
                route.auth = "yes"
            if SIGNATURE.search(body):
                route.auth = "sig"
            route.db = bool(CONVEX_DB.search(body) or re.search(r"\bctx\.run(?:Query|Mutation)\(", body))
            route.mutates = bool(CONVEX_WRITE.search(body) or "runMutation" in body)
            route.dynamic = bool(CONVEX_ID_ARG.search(body))
            route.paid_api = bool(_uses_paid_api(code) and PAID_CALL.search(body))
            if route.db and (route.dynamic or route.mutates):
                route.owner = "yes" if CONVEX_OWNER.search(body) else "no"
            if route.mutates:
                route.validation = "yes" if re.search(r"\bargs\s*:", body) else "no"
            if RATE_LIMIT.search(body):
                route.rate_limit = "yes"
            routes.append(route)
    return routes


# ---------- GraphQL resolvers ----------

RESOLVER_SECTION = re.compile(r"(?m)\b(Query|Mutation)\s*:\s*\{")
RESOLVER_FN = re.compile(r"(?m)^[ \t]*(?:async\s+)?(\w+)\s*(?::\s*(?:async\s*)?(?:\(|function\b|\w+\s*=>)|\()")
GQL_AUTH = re.compile(r"\b(?:ctx|context|contextValue)\.(?:user|session|auth|userId|currentUser|viewer)\b|AuthenticationError|"
                      r"\brequire\w*\(\s*(?:ctx|context)\b|\bauthenticated\(|\bisAuthenticated\b|\bcurrentUser\b|\{\s*(?:\w+\s*,\s*)*(?:user|session|currentUser)\s*[,}]")
GQL_FILE = re.compile(r"(?i)resolver|apollo|graphql|yoga|mercurius|typeDefs")
SKIP_RESOLVER_NAMES = {"if", "for", "while", "switch", "return", "catch", "function"}
DECORATED = re.compile(r"(?m)^[ \t]*@(Query|Mutation)\s*\(")
DECORATED_METHOD = re.compile(r"\s*(?:@\w+(?:\([^)\n]{0,200}\))?\s*){0,5}(?:public\s+)?(?:async\s+)?(\w+)\s*\(")
GUARD_DECORATOR = re.compile(r"@UseGuards\(|@Authorized\(|@Auth\w*\(")
CLASS_GUARD = re.compile(r"@(?:UseGuards|Authorized|Auth\w*)\([^)\n]{0,200}\)\s*(?:@\w+\([^)\n]{0,200}\)\s*){0,5}(?:export\s+)?class\b")


def graphql_routes(index: FileIndex) -> list[Route]:
    routes = []
    for rel, raw in _sources(index, "Query", "Mutation"):
        if not (GQL_FILE.search(rel) or GQL_FILE.search(raw[:3000])):
            continue
        code = strip_comments(raw)
        for section in islice(RESOLVER_SECTION.finditer(code), 10):
            open_idx = section.end() - 1
            close = _closing(code, open_idx)
            if close == -1:
                continue
            block = code[open_idx + 1: close]
            names = []
            depth = 0
            for line_start, line in _lines(block):
                if depth == 0:
                    match = RESOLVER_FN.match(line)
                    if match and match.group(1) not in SKIP_RESOLVER_NAMES:
                        names.append((match.group(1), line_start))
                depth += sum(line.count(c) for c in "{(") - sum(line.count(c) for c in "})")
            for i, (name, start) in enumerate(names):
                end = names[i + 1][1] if i + 1 < len(names) else len(block)
                body = block[start: end]
                route = Route("GET" if section.group(1) == "Query" else "POST", f"graphql/{section.group(1)}.{name}", rel,
                              line_of(code, open_idx + 1 + start), "graphql")
                routes.append(_assess(route, body, code, authed=bool(GQL_AUTH.search(body))))
        class_guarded = bool(CLASS_GUARD.search(code))
        for match in islice(DECORATED.finditer(code), MAX_FUNCTIONS_PER_FILE):  # NestJS GraphQL and TypeGraphQL
            args_end = _closing(code, match.end() - 1)
            method = DECORATED_METHOD.match(code, args_end + 1) if args_end != -1 else None
            if not method:
                continue
            params_end = _closing(code, method.end() - 1)
            brace = code.find("{", params_end, params_end + 300) if params_end != -1 else -1
            close = _closing(code, brace) if brace != -1 else -1
            body = code[brace: close] if close != -1 else ""
            # Decorators on this method: from the end of the previous one down to the method's name.
            above = code[max(code.rfind("}", max(0, match.start() - 2000), match.start()), match.start() - 2000, 0): method.end()]
            guarded = class_guarded or bool(GUARD_DECORATOR.search(above))
            route = Route("GET" if match.group(1) == "Query" else "POST", f"graphql/{match.group(1)}.{method.group(1)}", rel,
                          line_of(code, match.start()), "graphql")
            routes.append(_assess(route, body, code, authed=guarded or bool(GQL_AUTH.search(body))))
    return routes


def _lines(block: str) -> list[tuple[int, str]]:
    out, offset = [], 0
    for line in block.split("\n"):
        out.append((offset, line))
        offset += len(line) + 1
    return out


# ---------- Firebase Cloud Functions ----------

FIREBASE_FN = re.compile(r"(?m)^(?:exports\.(\w+)|export\s+const\s+(\w+))\s*=\s*[^=\n]*?\b(onCall|onRequest)\s*\(")
FIREBASE_AUTH = re.compile(r"\b(?:context|request|req)\.auth\b|\bverifyIdToken\(|\.auth\(\)\.verify")
FIREBASE_OWNER = re.compile(r"\b(?:context|request|req)\.auth\??\.uid\b|\buid\b")
PY_FIREBASE = re.compile(r"(?m)^[ \t]*@(?:\w+\.)?(on_call|on_request)\b[^\n]*\n(?:[ \t]*@[^\n]*\n)*[ \t]*def\s+(\w+)\s*\(")


def firebase_routes(index: FileIndex) -> list[Route]:
    routes = []
    for rel, raw in _sources(index, "onCall", "onRequest", "on_call", "on_request", exts=JS | {".py"}):
        if rel.endswith(".py"):
            code = raw
            matches = [(m.group(2), m.start(), m.group(1) == "on_call", m.end()) for m in islice(PY_FIREBASE.finditer(code), MAX_FUNCTIONS_PER_FILE)]
        else:
            code = strip_comments(raw)
            matches = [(m.group(1) or m.group(2), m.start(), m.group(3) == "onCall", m.end())
                       for m in islice(FIREBASE_FN.finditer(code), MAX_FUNCTIONS_PER_FILE)]
        for i, (name, start, callable_fn, body_start) in enumerate(matches):
            end = matches[i + 1][1] if i + 1 < len(matches) else len(code)
            body = code[body_start: min(end, body_start + MAX_BODY)]
            route = Route("POST" if callable_fn else "ANY", f"functions/{name}", rel, line_of(code, start), "firebase-fn")
            routes.append(_assess(route, body, code, authed=bool(FIREBASE_AUTH.search(body))))
            if routes[-1].db and (routes[-1].dynamic or routes[-1].mutates):
                routes[-1].owner = "yes" if FIREBASE_OWNER.search(body) else "no"
    return routes


# ---------- Supabase Edge Functions ----------

EDGE = re.compile(r"(?:^|/)supabase/functions/([\w-]+)/index\.(?:ts|js)$")
FORWARDS_TOKEN = re.compile(r"""headers\s*:\s*\{[^}]*Authorization\s*:[^}]*req(?:uest)?\.headers\.get\(\s*['"]Authorization""", re.I)


def supabase_edge_routes(index: FileIndex) -> list[Route]:
    routes = []
    config = (index.read("supabase/config.toml") or "") if index.exists("supabase/config.toml") else ""
    for rel, raw in _sources(index):
        match = EDGE.search(rel)
        if not match or match.group(1).startswith("_"):
            continue
        code = strip_comments(raw)
        name = match.group(1)
        route = _assess(Route("ANY", f"/functions/v1/{name}", rel, 1, "supabase-edge"), code, code)
        # The platform's own JWT check accepts the public anon key, so it isn't a user check. Passing the caller's token
        # to the Supabase client is: every query then runs as them, under Row Level Security.
        admin = bool(SERVICE_ROLE.search(code))
        if FORWARDS_TOKEN.search(code) and not admin:
            route.auth = "yes" if route.auth == "no" else route.auth
            if route.owner == "no":
                route.owner = "rls"
        elif admin and route.db and route.owner == "n/a":
            route.owner, route.dynamic = "no", True  # the admin key reads every row, so it needs the same check as a lookup by ID
        if re.search(rf"(?ms)^\[functions\.{re.escape(name)}\][^\[]*^verify_jwt\s*=\s*false", config):
            route.notes.append("verify_jwt is off, so the function runs even with no token")
        routes.append(route)
    return routes


# ---------- Vercel functions (outside Next.js) ----------

VERCEL_FILE = re.compile(r"^(?:(?:apps|packages)/[\w.-]+/)?api/(.*?)(?:/index)?\.(?:ts|js|mjs|cjs|mts)$")
VERCEL_DEFAULT = re.compile(r"export\s+default\s+(?:async\s+)?(?:function\s*\w*\s*)?\(?\s*(?:req|request|_req)\b|"
                            r"module\.exports\s*=\s*(?:async\s*)?(?:function\s*\w*\s*)?\(?\s*(?:req|request|_req)\b")
VERCEL_NAMED = re.compile(r"(?m)^export\s+(?:async\s+)?(?:function|const)\s+(GET|POST|PUT|PATCH|DELETE)\b")
METHOD_BRANCH = re.compile(r"(?:method\s*===?\s*|case\s+)['\"](GET|POST|PUT|PATCH|DELETE)['\"]")


def _vercel_path(segment: str) -> str:
    return "/api/" + segment if segment else "/api"


def vercel_routes(index: FileIndex) -> list[Route]:
    routes = []
    for rel, raw in _sources(index):
        match = VERCEL_FILE.search(rel)
        if not match or any(part.startswith("_") for part in match.group(1).split("/")):
            continue  # Vercel doesn't deploy _helpers as functions
        code = strip_comments(raw)
        path = _vercel_path(match.group(1))
        dynamic = "[" in path
        named = list(islice(VERCEL_NAMED.finditer(code), 10))
        if named:
            for i, fn in enumerate(named):
                end = named[i + 1].start() if i + 1 < len(named) else len(code)
                route = Route(fn.group(1), path, rel, line_of(code, fn.start()), "vercel", dynamic=dynamic)
                routes.append(_assess(route, code[fn.start(): end], code))
        elif (default := VERCEL_DEFAULT.search(code)):
            methods = sorted(set(METHOD_BRANCH.findall(code))) or ["ANY"]
            for method in methods:
                route = Route(method, path, rel, line_of(code, default.start()), "vercel", dynamic=dynamic)
                routes.append(_assess(route, code, code))
    return routes


# ---------- Netlify functions ----------

NETLIFY = re.compile(r"(?:^|/)netlify/(?:edge-)?functions/((?:[\w.-]+/)?[\w.-]+)\.(?:ts|js|mjs|cjs|mts)$")
NETLIFY_HANDLER = re.compile(r"(?:exports\.handler|export\s+(?:const|async\s+function|function)\s+handler|module\.exports\.handler)\b|"
                             r"export\s+default\b")
NETLIFY_AUTH = re.compile(r"\bcontext\.clientContext\??\.user\b|\bclientContext\b|\bverifyIdToken\(|\bjwtVerify\(|\bgetUser\(|\bcontext\.identity\b")


def netlify_routes(index: FileIndex) -> list[Route]:
    routes = []
    for rel, raw in _sources(index):
        match = NETLIFY.search(rel)
        if not match:
            continue
        name = match.group(1).split("/")[0]
        if "/" in match.group(1) and match.group(1).split("/")[-1] not in (name, "index"):
            continue  # a helper file inside the function's own folder
        code = strip_comments(raw)
        handler = NETLIFY_HANDLER.search(code)
        if not handler:
            continue
        methods = sorted(set(re.findall(r"httpMethod\s*[!=]==?\s*['\"](GET|POST|PUT|PATCH|DELETE)['\"]", code))) or ["ANY"]
        for method in methods:
            route = Route(method, f"/.netlify/functions/{name}", rel, line_of(code, handler.start()), "netlify")
            routes.append(_assess(route, code, code, authed=bool(NETLIFY_AUTH.search(code))))
    return routes


# ---------- Cloudflare: Pages Functions and Workers ----------

PAGES_FN = re.compile(r"(?:^|/)functions/(.*?)(?:/index)?\.(?:ts|js|mjs)$")
ON_REQUEST = re.compile(r"(?m)^export\s+(?:const|async\s+function|function)\s+onRequest(Get|Post|Put|Patch|Delete|Head|Options)?\b")
WORKER_DEFAULT = re.compile(r"export\s+default\s*\{")
WORKER_METHOD = re.compile(r"\bfetch\s*(?::\s*(?:async\s*)?(?:function\s*)?)?\(")
WORKER_LISTENER = re.compile(r"addEventListener\(\s*['\"]fetch['\"]")
WORKER_PATH = re.compile(r"(?:pathname|\.path)\s*===?\s*['\"](/[^'\"]*)['\"]")
METHOD_CHECK = re.compile(r"method\s*===?\s*['\"](GET|POST|PUT|PATCH|DELETE)['\"]")
CF_AUTH = re.compile(r"\bcontext\.data\.(?:user|auth|session)\b|\bCf-Access|\bjwtVerify\(|\bverifyToken\(|\bgetUser\(|\brequireAuth\(|\bauthorize\(|"
                     r"\bAuthorization\b[\s\S]{0,200}(?:verify|compare|===)")


def _worker_start(code: str) -> int | None:
    """Where a Worker's fetch handler starts, if this module has one."""
    default = WORKER_DEFAULT.search(code)
    if default and WORKER_METHOD.search(code, default.end(), default.end() + 5000):
        return default.start()
    listener = WORKER_LISTENER.search(code)
    return listener.start() if listener else None


def _pages_path(segment: str) -> str:
    parts = [re.sub(r"^\[\[(.+)\]\]$", r"[\1]", p) for p in segment.split("/") if p]
    return "/" + "/".join(parts)


def cloudflare_routes(index: FileIndex) -> list[Route]:
    routes = []
    has_wrangler = any(index.exists(name) for name in ("wrangler.toml", "wrangler.json", "wrangler.jsonc"))
    for rel, raw in _sources(index, "onRequest", *(("fetch",) if has_wrangler else ())):
        code = strip_comments(raw)
        pages = PAGES_FN.search(rel)
        handlers = list(islice(ON_REQUEST.finditer(code), 10)) if pages else []
        if handlers:
            path = _pages_path(pages.group(1))
            for i, handler in enumerate(handlers):
                end = handlers[i + 1].start() if i + 1 < len(handlers) else len(code)
                method = (handler.group(1) or "ANY").upper()
                route = Route(method, path, rel, line_of(code, handler.start()), "cloudflare", dynamic="[" in path)
                routes.append(_assess(route, code[handler.start(): end], code, authed=bool(CF_AUTH.search(code[handler.start(): end]))))
            continue
        offset = _worker_start(code) if has_wrangler else None
        if offset is None:
            continue
        paths = sorted(set(islice((m.group(1) for m in WORKER_PATH.finditer(code)), MAX_FUNCTIONS_PER_FILE)))
        if not paths:
            routes.append(_assess(Route("ANY", "/", rel, line_of(code, offset), "cloudflare"), code, code, authed=bool(CF_AUTH.search(code))))
        for path in paths:
            at = code.find(path)
            end = min((p for p in (code.find(other, at + 1) for other in paths if other != path) if p > at), default=len(code))
            body = code[at: end]
            method = METHOD_CHECK.search(code, at, min(end, at + 120)) or METHOD_CHECK.search(code, max(0, at - 80), at)
            route = Route(method.group(1) if method else "ANY", path, rel, line_of(code, at), "cloudflare")
            routes.append(_assess(route, body, code, authed=bool(CF_AUTH.search(code[:at]) or CF_AUTH.search(body))))
    return routes


# ---------- AWS Lambda: Serverless Framework and SAM ----------

def _indent(line: str) -> int:
    return len(line) - len(line.lstrip(" "))


def _value(line: str) -> str:
    return line.split(":", 1)[1].split(" #")[0].strip().strip("'\"") if ":" in line else ""


def _handler_body(index: FileIndex, handler: str, code_uri: str = "") -> tuple[str | None, str, str, int]:
    """(file, function body, whole module, line) for a handler like src/orders.create."""
    base, _, export = handler.rpartition(".")
    if not base:
        return None, "", "", 1
    base = f"{code_uri.rstrip('/')}/{base}".lstrip("./") if code_uri else base.lstrip("./")
    for ext in (".ts", ".js", ".mjs", ".cjs", ".py"):
        rel = base + ext
        if index.exists(rel):
            raw = index.read(rel) or ""
            code = raw if ext == ".py" else strip_comments(raw)
            found = re.search(rf"(?m)^(?:export\s+(?:async\s+)?(?:const|function)\s+|exports\.|module\.exports\.|(?:async\s+)?def\s+|(?:async\s+)?function\s+|const\s+){re.escape(export)}\b", code)
            if not found:
                return rel, code, code, 1
            following = re.compile(r"(?m)^(?:export\s|exports\.|module\.exports\.|def\s|async\s+def\s)").search(code, found.end())
            return rel, code[found.start(): following.start() if following else len(code)], code, line_of(code, found.start())
    return None, "", "", 1


def _lambda_route(index: FileIndex, config: str, config_line: int, method: str, path: str, handler: str, code_uri: str,
                  authorizer: bool) -> Route:
    path = "/" + path.strip("/").strip()
    rel, body, module, line = _handler_body(index, handler, code_uri)
    route = Route(method.upper().replace("$DEFAULT", "ANY") if method != "*" else "ANY", path, rel or config, line if rel else config_line,
                  "lambda", dynamic="{" in path)
    route = _assess(route, body, module)
    if authorizer and route.auth == "no":
        route.auth = "mw"  # API Gateway checks the caller before the function runs
    return route


def serverless_framework_routes(index: FileIndex) -> list[Route]:
    routes = []
    for rel in ("serverless.yml", "serverless.yaml"):
        text = index.read(rel) if index.exists(rel) else None
        if not text:
            continue
        lines = text.splitlines()
        start = next((i for i, line in enumerate(lines) if re.match(r"^functions:\s*$", line)), None)
        if start is None:
            continue
        i = start + 1
        handler = ""
        while i < len(lines):
            line = lines[i]
            if line.strip() and _indent(line) == 0:
                break
            stripped = line.strip()
            if stripped.startswith("handler:"):
                handler = _value(line)
            event = re.match(r"-\s*(httpApi|http)\s*:\s*(.*)$", stripped)
            if event:
                inline = event.group(2).strip().strip("'\"")
                shape = re.match(r"^(\*|GET|POST|PUT|PATCH|DELETE|ANY|get|post|put|patch|delete|any)\s+(\S+)$", inline)
                method, path, authorizer = (shape.group(1), shape.group(2), False) if shape else ("", "", False)
                if inline == "*":
                    method, path = "ANY", "{proxy+}"
                block = re.findall(r"(method|path|authorizer)\s*:\s*([^,}]+)", inline) if inline.startswith("{") else []
                for key, value in block:
                    if key == "method":
                        method = value.strip().strip("'\"")
                    elif key == "path":
                        path = value.strip().strip("'\"")
                    else:
                        authorizer = True
                depth = _indent(line)
                j = i + 1
                while j < len(lines) and (not lines[j].strip() or _indent(lines[j]) > depth):
                    inner = lines[j].strip()
                    if inner.startswith("method:"):
                        method = _value(lines[j])
                    elif inner.startswith("path:"):
                        path = _value(lines[j])
                    elif inner.startswith("authorizer:"):
                        authorizer = True
                    j += 1
                if method and path:
                    routes.append(_lambda_route(index, rel, i + 1, method, path, handler, "", authorizer))
                i = j
                continue
            i += 1
    return routes


def sam_routes(index: FileIndex) -> list[Route]:
    routes = []
    for rel in ("template.yaml", "template.yml", "sam.yaml", "sam.yml"):
        text = index.read(rel) if index.exists(rel) else None
        if not text or "AWS::Serverless::Function" not in text:
            continue
        lines = text.splitlines()
        global_auth = bool(re.search(r"(?m)^\s+DefaultAuthorizer:", text))
        for i, line in enumerate(lines):
            if "AWS::Serverless::Function" not in line:
                continue
            top = _indent(line)
            handler = code_uri = ""
            j = i + 1
            events: list[tuple[int, str, str, bool]] = []
            while j < len(lines) and (not lines[j].strip() or _indent(lines[j]) >= top):
                stripped = lines[j].strip()
                if stripped.startswith("Handler:"):
                    handler = _value(lines[j])
                elif stripped.startswith("CodeUri:"):
                    code_uri = _value(lines[j])
                elif re.match(r"Type:\s*(?:Http)?Api\b", stripped):
                    depth = _indent(lines[j])
                    path, method, auth = "", "", False
                    k = j + 1
                    while k < len(lines) and (not lines[k].strip() or _indent(lines[k]) >= depth):
                        inner = lines[k].strip()
                        if inner.startswith("Path:"):
                            path = _value(lines[k])
                        elif inner.startswith("Method:"):
                            method = _value(lines[k])
                        elif inner.startswith("Authorizer:") and _value(lines[k]) != "NONE":
                            auth = True
                        elif inner.startswith("Type:"):
                            break
                        k += 1
                    events.append((j + 1, method, path, auth))
                j += 1
            for line_no, method, path, auth in events:
                if path and method:
                    routes.append(_lambda_route(index, rel, line_no, method, path, handler, code_uri, auth or global_auth))
    return routes


def analyze_functions(index: FileIndex) -> list[Route]:
    return (trpc_routes(index) + convex_routes(index) + graphql_routes(index) + firebase_routes(index)
            + supabase_edge_routes(index) + vercel_routes(index) + netlify_routes(index) + cloudflare_routes(index)
            + serverless_framework_routes(index) + sam_routes(index))
