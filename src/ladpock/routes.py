"""The route matrix: every endpoint and which protections it has (auth,
ownership check, validation, rate limiting). Next.js handlers and server
actions are read here; Express, Fastify, Hono, NestJS, FastAPI, Flask and
Django come from server_routes; SvelteKit, Remix, Nuxt and Astro from
fullstack_routes; Spring, Go, Rails, Laravel and ASP.NET from backend_routes;
tRPC, Convex, GraphQL, Firebase, Supabase Edge, Vercel, Netlify, Cloudflare and
AWS Lambda functions from function_routes; Rust, Elysia, Hapi, Sinatra, Symfony,
Ktor, JAX-RS and Micronaut from more_routes.

This is heuristic. It recognises common libraries and patterns, and says "?"
when it can't tell rather than guessing.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field

from .files import FileIndex
from .jsparse import capped, line_of, strip_comments

METHODS = ("GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS")
MUTATING = {"POST", "PUT", "PATCH", "DELETE", "ACTION", "ANY"}

APP_ROUTE = re.compile(r"(?:^|/)app/((?:.*/)?)route\.(?:ts|js|tsx|jsx|mjs)$")
PAGES_API = re.compile(r"(?:^|/)pages/(api/.*?)(?:/index)?\.(?:ts|js|tsx|jsx|mjs)$")
HANDLER = re.compile(
    r"export\s+(?:async\s+)?function\s+(GET|POST|PUT|PATCH|DELETE|HEAD|OPTIONS)\b|"
    r"export\s+const\s+(GET|POST|PUT|PATCH|DELETE|HEAD|OPTIONS)\s*=|"
    r"export\s+const\s*\{([^}]*)\}\s*=|export\s*\{([^}]*)\}"
)
ACTION = re.compile(r"export\s+(?:default\s+)?(?:async\s+function\s+(\w+)|const\s+(\w+)\s*=\s*async)")
USE_SERVER = re.compile(r"""^\s*['"]use server['"]""", re.M)

AUTH = re.compile(
    r"\b(?:auth|getServerSession|getSession|currentUser|getUser|getAuth|requireAuth|requireUser|requireSession|"
    r"requireAdmin|requireRole|verifyToken|verifyJwt|verifyIdToken|validateSession|validateRequest|getCurrentUser|"
    r"getUserFromRequest|getServerUser|getLoggedInUser|getToken|withAuth|withApiAuth|authenticate|isAuthenticated|"
    r"ensureAuth|checkAuth|getKindeServerSession|getClaims)\s*\(|jwt\.verify\s*\(|auth\.protect\s*\(|auth\.api\.getSession"
)
AUTH_IMPORT = re.compile(r"import\s*\{([^}]*)\}\s*from\s*['\"]([^'\"]*(?:auth|session|clerk|kinde|lucia)[^'\"]*)['\"]", re.I)
SIGNATURE = re.compile(
    r"constructEvent(?:Async)?\s*\(|verifyHeader|new\s+Webhook\s*\(|verifySignature|verifyWebhook|timingSafeEqual|"
    r"createHmac|webhooks\.verify|CRON_SECRET"
)
OWNER = re.compile(
    r"\b(?:user|session\??\.user|currentUser|me|viewer|claims)\??\.(?:id|sub)\b|\buserId\s*:\s*(?:user|session|currentUser)|"
    r"\.eq\(\s*['\"](?:user_id|owner_id|author_id|created_by|profile_id|account_id)['\"]|auth\.uid\(\)|"
    r"\b(?:owner|author|user)_?[iI]d\s*(?:===|!==|==|!=)"
)
RLS_CLIENT = re.compile(
    r"createServerClient|createRouteHandlerClient|createServerComponentClient|createServerActionClient|"
    r"from\s+['\"][^'\"]*supabase/server['\"]"
)
SERVICE_ROLE = re.compile(r"SERVICE_ROLE|SUPABASE_SECRET_KEY|sb_secret_")
VALIDATION = re.compile(
    r"(?<!JSON)(?<!Date)\.(?:safeParse|parse|parseAsync|safeParseAsync|validate|validateSync)\s*\(|\bz\.\w+\(|\byup\.|"
    r"\bJoi\.|\bv\.(?:parse|safeParse)\(|\bajv\b|\btypia\.|class-validator|valibot"
)
RATE_LIMIT = re.compile(r"(?i)rate_?limit|ratelimit|\blimiter\b|slowdown|throttle|arcjet|\baj\.protect|upstash")
PAID_API = re.compile(
    r"(?i)['\"]openai['\"]|@anthropic-ai|\bnew\s+(?:OpenAI|Anthropic)\b|@ai-sdk/|\bgenerateText\(|\bstreamText\(|"
    r"\bgenerateObject\(|\bstreamObject\(|chat\.completions|messages\.create|images\.generate|['\"]resend['\"]|"
    r"['\"]twilio['\"]|@sendgrid|['\"]replicate['\"]|elevenlabs|maps\.googleapis|@google/generative-ai|@google/genai|groq-sdk"
)
DB = re.compile(
    r"(?<!Array)\.from\(\s*['\"`]|\bprisma\.\w+\.|\bdb\.\w+|\.(?:findUnique|findFirst|findMany|insert|update|upsert|delete|select)\(|"
    r"\bsql`|\bquery\(|\.execute\(|\.collection\(|\.rpc\("
)
MUTATION = re.compile(
    r"\.(?:insert|update|upsert|delete|create|createMany|updateMany|deleteMany|destroy|remove|insertOne|insertMany|"
    r"updateOne|deleteOne)\s*\(|\b(?:INSERT\s+INTO|UPDATE\s+\w+\s+SET|DELETE\s+FROM)\b"
)
PUBLIC_PATH = re.compile(
    r"(?i)/(?:auth|login|logout|signin|sign-in|signup|sign-up|register|forgot\w*|reset\w*|callback|verify|magic\w*|otp|"
    r"confirm|health|healthz|status|og|sitemap|robots|public|webhooks?|cron)(?:/|$|-)"
)
# SvelteKit names actions in the URL (/settings?/reset). A sign-in word there counts, but a bare "reset" action
# usually resets something else, so that one has to be a real path segment.
AUTH_FLOW = re.compile(r"(?i)/(?:login|signin|sign-in|signup|sign-up|register|forgot\w*|otp|magic\w*|password|reset-?password)"
                       r"(?:/|$|-|\?)|(?<!\?)/reset\w*(?:/|$|-|\?)")
WEBHOOK = re.compile(r"(?i)webhook")
CRON_PATH = re.compile(r"(?i)/(?:cron|crons|cron-?jobs?|scheduled|schedule/run|jobs/run|tasks/run)(?:/|$|-)")


# Frameworks whose app-wide guard decides by path, so a missed path is wide open. Router-level middleware elsewhere
# (Express router.use, Rails before_action, Spring Security) is the normal, robust way to protect routes.
PATH_MATCHED_MIDDLEWARE = {"route", "pages-api", "sveltekit", "nuxt", "astro"}


@dataclass
class Route:
    method: str
    path: str
    file: str
    line: int
    kind: str  # route | pages-api | action, or the framework's name for the others
    auth: str = "no"  # yes | mw (middleware only) | sig (signature) | no
    owner: str = "n/a"  # yes | rls | no | n/a
    validation: str = "n/a"  # yes | no | n/a
    rate_limit: str = "no"  # yes | mw | no
    paid_api: bool = False
    mutates: bool = False
    db: bool = False
    dynamic: bool = False
    public: bool = False  # explicitly marked public (@Public(), AllowAny)
    notes: list[str] = field(default_factory=list)

    @property
    def public_path(self) -> bool:
        # Only the path itself says a route is public: /settings?/confirm is still the settings page.
        return self.public or bool(PUBLIC_PATH.search(self.path.split("?")[0])) or bool(AUTH_FLOW.search(self.path))

    @property
    def webhook(self) -> bool:
        return bool(WEBHOOK.search(self.path))

    def to_dict(self) -> dict:
        return {k: getattr(self, k) for k in (
            "method", "path", "file", "line", "kind", "auth", "owner", "validation", "rate_limit",
            "paid_api", "mutates", "db", "dynamic", "public", "notes")}


@dataclass
class Middleware:
    file: str | None = None
    auth: bool = False
    rate_limit: bool = False
    matchers: list[re.Pattern[str]] | None = None  # None = applies to every path

    def covers(self, path: str) -> bool:
        if not self.file:
            return False
        if self.matchers is None:
            return True
        sample = re.sub(r"\[\[?\.\.\.[^\]]+\]?\]|\[[^\]]+\]", "x", path)
        return any(m.match(sample) for m in self.matchers)


def _matcher_regex(pattern: str) -> re.Pattern[str] | None:
    if "(" in pattern and ":" not in pattern:
        source = pattern
    else:
        source = re.sub(r"/:\w+\*", "(?:/.*)?", pattern)
        source = re.sub(r"/:\w+\+", "/.+", source)
        source = re.sub(r":\w+", "[^/]+", source)
    try:
        return re.compile(f"^{source}$")
    except re.error:
        return None


def _middleware(index: FileIndex) -> Middleware:
    for rel in ("middleware.ts", "middleware.js", "src/middleware.ts", "src/middleware.js",
                "proxy.ts", "proxy.js", "src/proxy.ts", "src/proxy.js"):
        if not index.exists(rel):
            continue
        text = strip_comments(index.read(rel) or "")
        mw = Middleware(
            file=rel,
            auth=bool(AUTH.search(text) or re.search(r"clerkMiddleware|authMiddleware|withAuth|NextAuth\(", text)),
            rate_limit=bool(RATE_LIMIT.search(text)),
        )
        match = re.search(r"matcher\s*:\s*(\[[^\]]*\]|['\"][^'\"]+['\"])", text)
        if match:
            compiled = [_matcher_regex(s) for s in re.findall(r"['\"]([^'\"]+)['\"]", match.group(1))]
            mw.matchers = None if any(c is None for c in compiled) else [c for c in compiled if c]
        return mw
    return Middleware()


def _auth_names(code: str) -> set[str]:
    """Local helpers whose bodies authenticate, plus functions imported from auth modules."""
    names = set()
    for match in capped(AUTH_IMPORT.finditer(code)):
        for part in match.group(1).split(","):
            name = part.split(" as ")[-1].strip()
            if name:
                names.add(name)
    for match in capped(re.finditer(r"(?:async\s+)?function\s+(\w+)\s*\(|const\s+(\w+)\s*=\s*(?:async\s*)?\(", code)):
        name = match.group(1) or match.group(2)
        if name in METHODS:
            continue
        body = code[match.end(): match.end() + 1500]
        if AUTH.search(body):
            names.add(name)
    return names


def _calls_any(code: str, names: set[str]) -> bool:
    return any(re.search(rf"\b{re.escape(n)}\s*\(", code) for n in names)


def _url(rel: str, segment: str, prefix: str = "/") -> str:
    parts = [p for p in segment.strip("/").split("/") if p and not (p.startswith("(") and p.endswith(")")) and not p.startswith("@")]
    return prefix + "/".join(parts) if parts else prefix.rstrip("/") or "/"


def _assess(route: Route, body: str, module: str, auth_names: set[str], mw: Middleware) -> Route:
    has_auth = bool(AUTH.search(body)) or _calls_any(body, auth_names)
    if SIGNATURE.search(body) or SIGNATURE.search(module):
        route.auth = "sig"
    elif has_auth:
        route.auth = "yes"
    elif mw.auth and mw.covers(route.path):
        route.auth = "mw"
    route.db = bool(DB.search(body))
    # Only count writes that touch a datastore, so e.g. openai.chat.completions.create() isn't a "mutation".
    route.mutates = route.db and bool(MUTATION.search(body))
    route.paid_api = bool(PAID_API.search(module))
    route.dynamic = "[" in route.path

    if route.db and (route.dynamic or route.method in MUTATING):
        if OWNER.search(body):
            route.owner = "yes"
        elif RLS_CLIENT.search(module) and not SERVICE_ROLE.search(module):
            route.owner = "rls"
        else:
            route.owner = "no"

    if route.method in MUTATING:
        reads_body = re.search(r"\.json\(\)|\.formData\(\)|req\.body|formData\.get|\bbody\b", body) or route.kind == "action"
        route.validation = ("yes" if VALIDATION.search(body) or VALIDATION.search(module) else "no") if reads_body else "n/a"

    if RATE_LIMIT.search(body):
        route.rate_limit = "yes"
    elif mw.rate_limit and mw.covers(route.path):
        route.rate_limit = "mw"
    return route


def analyze(index: FileIndex) -> list[Route]:
    mw = _middleware(index)
    routes: list[Route] = []
    for rel in index.sources({".ts", ".js", ".tsx", ".jsx", ".mjs"}):
        app = APP_ROUTE.search(rel)
        pages = PAGES_API.search(rel)
        text = index.read(rel) or ""
        if not (app or pages or USE_SERVER.search(text[:500])):
            continue
        code = strip_comments(text)
        auth_names = _auth_names(code)
        if pages and not re.search(r"export\s+default|module\.exports", code):
            continue  # Next.js API routes have a default export; Astro's src/pages/api files don't

        if app:
            path = _url(rel, app.group(1))
            inline: list[tuple[str, int]] = []
            for match in capped(HANDLER.finditer(code)):
                if match.group(1) or match.group(2):
                    inline.append((match.group(1) or match.group(2), match.start()))
                    continue
                # export { handler as GET } / export const { GET, POST } = handlers:
                # the implementation lives elsewhere in the module, so assess all of it.
                listed = match.group(3) or match.group(4) or ""
                for method in METHODS:
                    if re.search(rf"\b{method}\b", listed):
                        route = Route(method, path, rel, line_of(code, match.start()), "route")
                        routes.append(_assess(route, code, code, auth_names, mw))
            inline.sort(key=lambda item: item[1])
            for i, (method, start) in enumerate(inline):
                end = inline[i + 1][1] if i + 1 < len(inline) else len(code)
                route = Route(method, path, rel, line_of(code, start), "route")
                routes.append(_assess(route, code[start:end], code, auth_names, mw))
        elif pages:
            path = _url(rel, pages.group(1))
            methods = sorted(set(re.findall(r"(?:method\s*===?\s*|case\s+)['\"](GET|POST|PUT|PATCH|DELETE)['\"]", code))) or ["ANY"]
            for method in methods:
                route = Route(method, path, rel, 1, "pages-api")
                routes.append(_assess(route, code, code, auth_names, mw))
        else:
            for match in capped(ACTION.finditer(code)):
                name = match.group(1) or match.group(2)
                end = len(code)
                nxt = ACTION.search(code, match.end())
                if nxt:
                    end = nxt.start()
                route = Route("ACTION", f"action {name}()", rel, line_of(code, match.start()), "action")
                route = _assess(route, code[match.start():end], code, auth_names, Middleware())
                routes.append(route)
    from .backend_routes import analyze_backends
    from .fullstack_routes import analyze_fullstack
    from .function_routes import analyze_functions
    from .more_routes import analyze_more
    from .server_routes import analyze_servers

    routes.extend(analyze_servers(index, Route))
    routes.extend(analyze_fullstack(index))
    routes.extend(analyze_backends(index))
    routes.extend(analyze_functions(index))
    routes.extend(analyze_more(index))
    # The generic JavaScript reader also sees app.get(...) in these frameworks' files. The specific reader knows better.
    specific = {r.file for r in routes if r.kind in ("elysia", "hapi")}
    routes = [r for r in routes if r.file not in specific or r.kind in ("elysia", "hapi")]
    # The URL that carries tRPC or GraphQL isn't an endpoint of its own: each procedure and resolver is listed instead.
    if any(r.kind == "trpc" for r in routes):
        routes = [r for r in routes if r.kind == "trpc" or not re.search(r"/trpc(?:/|$)", r.path)]
    if any(r.kind == "graphql" for r in routes):
        routes = [r for r in routes if r.kind == "graphql" or not re.search(r"/graphql/?$", r.path)]
    routes.sort(key=lambda r: (r.kind == "action", r.path, METHODS.index(r.method) if r.method in METHODS else 99))
    return routes


def gaps(route: Route) -> list[str]:
    """Short labels for what a route is missing, used in reports."""
    out = []
    needs_auth = not route.public_path and (route.method in MUTATING or route.db or route.paid_api)
    if needs_auth and route.auth == "no" and not route.webhook:
        out.append("no auth")
    if route.owner == "no" and route.auth in ("yes", "mw"):
        out.append("no ownership check")
    if route.auth == "mw" and (route.db or route.mutates) and route.kind in PATH_MATCHED_MIDDLEWARE:
        out.append("auth only in middleware")
    if route.paid_api and route.rate_limit == "no":
        out.append("paid API without rate limit")
    if AUTH_FLOW.search(route.path) and route.method in MUTATING and route.rate_limit == "no":
        out.append("sign-in flow without rate limit")
    if route.webhook and route.auth != "sig":
        out.append("webhook not verified")
    if CRON_PATH.search(route.path) and route.auth == "no":
        out.append("job endpoint with no secret")
    return out
