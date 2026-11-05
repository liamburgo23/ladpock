"""The route matrix for server frameworks: Express, Fastify, Hono and Koa
routers, NestJS controllers, FastAPI, Flask and Django.

Each endpoint becomes a routes.Route with the same columns as a Next.js
handler (auth, ownership check, validation, rate limit), so the same access
control and abuse checks apply to every framework. Like the Next.js matrix,
this is heuristic: it recognises common libraries and conventions and leans
towards "go and look" rather than certainty.
"""

from __future__ import annotations

import posixpath
import re
from dataclasses import dataclass, field

from .files import JS_EXT, PY_EXT, FileIndex
from .jsparse import capped, line_of, match_bracket, split_args, strip_comments

# ---------- shared ----------

DYNAMIC = re.compile(r":\w+|\{[^}]+\}|<[^>]+>|\[[^\]]+\]|\(\?P<")
PY_QUOTES = "'\""

# ---------- JavaScript servers (Express, Fastify, Hono, Koa, NestJS) ----------

JS_SERVER_IMPORT = re.compile(
    r"""(?:require\(\s*|from\s+)['"](?:express|fastify|hono|koa|@koa/router|koa-router|restify|polka|"""
    r"""@hapi/hapi|h3|elysia)(?:/[\w-]+)?['"]"""
)
JS_ROUTE = re.compile(r"\b(\w+)\.(get|post|put|patch|delete|del|all)\s*\(\s*(['\"`])(/[^'\"`]*)\3")
JS_ROUTE_CHAIN = re.compile(r"\b(\w+)\.route\(\s*(['\"`])(/[^'\"`]*)\2\s*\)")
JS_ROUTE_OBJECT = re.compile(r"\b(\w+)\.route\(\s*\{")
JS_USE = re.compile(r"\b(\w+)\.(?:use|register|addHook)\s*\(")
JS_AUTH_NAME = re.compile(
    r"(?i)\b(?:\w*auth\w*|require\w*(?:user|login|session|admin|role)\w*|ensure\w*(?:logged|auth)\w*|is\w*(?:logged|auth)\w*|"
    r"protect\w*|verify\w*(?:token|jwt|user|session)\w*|check\w*(?:jwt|auth|token)\w*|\w*jwt\w*|passport\.authenticate|"
    r"\w*guard\w*|clerk\w*|requireAuth|withAuth|bearerAuth|basicAuth|session\w*Required)\b"
)
JS_RATE = re.compile(r"(?i)rate_?limit|ratelimit|\blimiter\b|slow_?down|throttl|@fastify/rate-limit|hono-rate-limiter")
JS_VALIDATION = re.compile(
    r"\.(?:safeParse|parse|parseAsync|validate|validateAsync|validateSync)\s*\(|\bz\.\w+\(|\byup\.|\bJoi\.|celebrate|"
    r"express-validator|\bbody\(\s*['\"]|validationResult|\bschema\s*:\s*\{|zValidator|typebox|\bTypebox\b|\bajv\b"
)
# A datastore call: an ORM model (capitalised), a db/prisma/knex handle, a repository or raw SQL. Lower-case
# receivers like openai.chat.completions.create() aren't counted.
JS_DB = re.compile(
    r"\bprisma\.\w+\.|\bdb\.\w+|\bknex\b|\bsequelize\b|\b[A-Z]\w*\.(?:find\w*|create|insert\w*|update\w*|delete\w*|destroy|"
    r"upsert|count\w*|aggregate|bulkCreate|exists)\(|\bsql`|\.from\(\s*['\"`]|\b(?:pool|client|conn|connection|tx)\.query\(|"
    r"getRepository|\.collection\(|\w+(?:Repository|repo)\.\w+\(|\bthis\.\w+(?:Model|Repository)\.\w+\(|\benv\.\w+\.prepare\("
)
JS_MUTATION = re.compile(
    r"\.(?:insert|insertOne|insertMany|update|updateOne|updateMany|upsert|delete|deleteOne|deleteMany|destroy|create|"
    r"createMany|save|remove|findByIdAndUpdate|findByIdAndDelete|findOneAndUpdate|findOneAndDelete)\s*\(|"
    r"\b(?:INSERT\s+INTO|UPDATE\s+\w+\s+SET|DELETE\s+FROM)\b"
)
JS_OWNER = re.compile(
    r"\breq\.(?:user|auth|session(?:\.user)?)\??\.(?:id|_id|sub|userId)\b|\brequest\.user\??\.(?:id|sub)\b|"
    r"\b(?:user|owner|author)_?[iI]d\s*(?:===|!==|==|!=|:)\s*(?:req|request|user|session|ctx)\b|\buser\??\.(?:id|_id|sub)\b|"
    r"\bctx\.state\.user|@CurrentUser|@User\(|\bc\.get\(\s*['\"](?:user|jwtPayload)['\"]\)"
)
JS_AUTH_BODY = re.compile(
    r"\breq\.(?:user|auth|isAuthenticated\(\))|\bjwt\.verify\s*\(|\bverifyToken\s*\(|\bgetAuth\s*\(|\bauth\(\)|"
    r"\bctx\.state\.user|\bc\.get\(\s*['\"](?:user|jwtPayload)['\"]\)|\brequest\.user\b|\bgetSession\s*\(|\bgetUser\s*\("
)
JS_SIGNATURE = re.compile(r"constructEvent(?:Async)?\s*\(|verifyHeader|new\s+Webhook\s*\(|verifySignature|verifyWebhook|timingSafeEqual|createHmac")
JS_PAID = re.compile(
    r"(?i)['\"]openai['\"]|@anthropic-ai|\bnew\s+(?:OpenAI|Anthropic)\b|@ai-sdk/|\bgenerateText\(|\bstreamText\(|chat\.completions|"
    r"messages\.create|images\.generate|['\"]resend['\"]|['\"]twilio['\"]|@sendgrid|['\"]replicate['\"]|elevenlabs|"
    r"@google/generative-ai|@google/genai|groq-sdk|@mistralai|cohere-ai"
)
FN_DEF = re.compile(
    r"(?:async\s+)?function\s+(\w+)\s*\(|(?:const|let|var)\s+(\w+)\s*=\s*(?:async\s*)?(?:\([^)]*\)|\w+)\s*=>|"
    r"(?:exports|module\.exports)\.(\w+)\s*=\s*(?:async\s*)?(?:function\b|\([^)]*\)\s*=>|\w+\s*=>)|"
    r"^\s*(?:async\s+)?(\w+)\s*\(\s*(?:req|request|ctx|c)\b[^)]*\)\s*\{|\b(\w+)\s*:\s*(?:async\s*)?(?:function\b|\([^)]*\)\s*=>)",
    re.M,
)

NEST_CONTROLLER = re.compile(r"@Controller\(\s*(?:['\"`]([^'\"`]*)['\"`]|\{[^}]*path\s*:\s*['\"`]([^'\"`]*)['\"`][^}]*\})?\s*\)")
NEST_METHOD = re.compile(r"@(Get|Post|Put|Patch|Delete|All)\(\s*(?:['\"`]([^'\"`]*)['\"`])?\s*\)")
NEST_AUTH = re.compile(r"@UseGuards\([^)]*(?:Auth|Jwt|Session|Role|Clerk|Firebase|Supabase|Permission|Admin|Api[Kk]ey)\w*")
NEST_PUBLIC = re.compile(r"@(?:Public|AllowAnonymous|SkipAuth|IsPublic)\(\)")
NEST_RATE = re.compile(r"@Throttle\(|ThrottlerGuard|@UseGuards\([^)]*Throttl")


@dataclass
class JsHandler:
    file: str
    line: int
    body: str


def _js_server_files(index: FileIndex) -> dict[str, str]:
    """Comment-stripped code of the files that set up a JS server, a router or a Nest controller."""
    out = {}
    for rel in index.sources(JS_EXT - {".vue", ".svelte", ".astro"}):
        if re.search(r"(?:^|/)app/(?:.*/)?route\.\w+$|(?:^|/)pages/api/", rel):
            continue  # Next.js handlers have their own analyser
        text = index.read(rel) or ""
        if JS_SERVER_IMPORT.search(text) or "@Controller(" in text or "@nestjs/" in text or re.search(r"\bRouter\(\)", text):
            out[rel] = strip_comments(text)
    return out


def _js_functions(files: dict[str, str]) -> dict[str, JsHandler]:
    """Named functions in server files, so `router.post('/x', controller.create)` can be followed to its body."""
    found: dict[str, JsHandler] = {}
    for rel, code in files.items():
        for match in capped(FN_DEF.finditer(code)):
            name = next(g for g in match.groups() if g)
            if name in ("if", "for", "while", "switch", "catch", "function"):
                continue
            brace = code.find("{", match.end() - 1)
            if brace < 0 or brace - match.end() > 200:
                continue
            end = match_bracket(code, brace)
            if end > 0:
                found.setdefault(name, JsHandler(rel, line_of(code, match.start()), code[match.start(): end + 1]))
    return found


@dataclass
class _Scope:
    auth: list[tuple[str, int]] = field(default_factory=list)  # (path prefix, offset where it applies from)
    rate: list[tuple[str, int]] = field(default_factory=list)

    def covers(self, items: list[tuple[str, int]], path: str, offset: int) -> bool:
        return any(offset > at and (not prefix or path.startswith(prefix.rstrip("*").rstrip("/"))) for prefix, at in items)


def _js_scope(code: str) -> _Scope:
    """App- or router-wide middleware: app.use(auth), fastify.register(rateLimit), app.use('/api/*', jwt(...))."""
    scope = _Scope()
    for match in capped(JS_USE.finditer(code)):
        open_idx = match.end() - 1
        close = match_bracket(code, open_idx)
        if close < 0:
            continue
        args = split_args(code, open_idx, close)
        prefix = ""
        if args and re.match(r"\s*['\"`](/[^'\"`]*)['\"`]\s*$", args[0]):
            prefix = re.match(r"\s*['\"`](/[^'\"`]*)['\"`]", args[0]).group(1)
            args = args[1:]
        text = ",".join(args)
        mounts_router = re.search(r"(?i)\w*(?:router|routes)\b|require\(\s*['\"]\./", text)
        if JS_AUTH_NAME.search(text) and not JS_RATE.search(text) and not mounts_router:
            scope.auth.append((prefix, match.start()))
        if JS_RATE.search(text):
            scope.rate.append((prefix, match.start()))
    return scope


def _join(prefix: str, path: str) -> str:
    if not prefix:
        return path or "/"
    joined = "/" + "/".join(p for p in (prefix.strip("/"), path.strip("/")) if p)
    return joined


def _js_route(route_cls, method: str, path: str, rel: str, line: int, kind: str, middleware: str, body: str,
              module: str, scope: _Scope, offset: int):
    route = route_cls(method, path, rel, line, kind)
    everything = middleware + "\n" + body
    if JS_SIGNATURE.search(everything):
        route.auth = "sig"
    elif JS_AUTH_NAME.search(middleware) or JS_AUTH_BODY.search(body):
        route.auth = "yes"
    elif scope.covers(scope.auth, path, offset):
        route.auth = "mw"
    route.db = bool(JS_DB.search(body))
    route.mutates = route.db and bool(JS_MUTATION.search(body))
    route.paid_api = bool(JS_PAID.search(module) and PAID_CALL.search(body))
    route.dynamic = bool(DYNAMIC.search(path))
    if route.db and (route.dynamic or route.method in MUTATING_JS):
        route.owner = "yes" if JS_OWNER.search(everything) else "no"
    if route.method in MUTATING_JS:
        reads = re.search(r"\b(?:req|request)\.body\b|\bc\.req\.(?:json|parseBody|valid)\(|ctx\.request\.body|@Body\(", everything)
        route.validation = ("yes" if JS_VALIDATION.search(everything) else "no") if reads else "n/a"
    if JS_RATE.search(middleware) or JS_RATE.search(body):
        route.rate_limit = "yes"
    elif scope.covers(scope.rate, path, offset):
        route.rate_limit = "mw"
    return route


MUTATING_JS = {"POST", "PUT", "PATCH", "DELETE", "ANY"}
PAID_CALL = re.compile(
    r"(?i)\bopenai\b|\banthropic\b|completions|messages\.create|generateText|streamText|generateObject|images\.generate|"
    r"\bresend\.|\btwilio\b|sgMail|sendgrid|replicate\.|elevenlabs|\bgenai\b|\bgroq\b|\bllm\b|model\.generate"
)


def _resolve_module(files: dict[str, str], importer: str, spec: str) -> str | None:
    if not spec.startswith("."):
        return None
    base = posixpath.normpath(posixpath.join(posixpath.dirname(importer), spec))
    for candidate in (base, *(base + e for e in (".js", ".ts", ".mjs", ".cjs")),
                      *(f"{base}/index{e}" for e in (".js", ".ts", ".mjs"))):
        if candidate in files:
            return candidate
    return None


def _js_mounts(files: dict[str, str]) -> dict[str, tuple[str, bool]]:
    """Router file -> (URL prefix, auth middleware on the mount), from app.use('/api/x', [auth,] router) and
    fastify.register(plugin, { prefix: '/api' })."""
    mounts: dict[str, tuple[str, bool]] = {}
    for rel, code in files.items():
        scope = _js_scope(code)
        for match in capped(re.finditer(r"\b\w+\.(use|register|route)\s*\(", code)):
            open_idx = match.end() - 1
            close = match_bracket(code, open_idx)
            if close < 0:
                continue
            args = [a.strip() for a in split_args(code, open_idx, close)]
            if len(args) < 2:
                continue
            if match.group(1) == "register":
                prefix = re.search(r"prefix\s*:\s*['\"`](/[^'\"`]*)['\"`]", args[1])
                target, middle, path = args[0], "", prefix.group(1) if prefix else None
            else:
                first = re.fullmatch(r"['\"`](/[^'\"`]*)['\"`]", args[0])
                target, middle, path = args[-1], ",".join(args[1:-1]), first.group(1) if first else None
            if not path:
                continue
            inline = re.fullmatch(r"require\(\s*['\"]([^'\"]+)['\"]\s*\)(?:\.\w+)?", target)
            spec = inline.group(1) if inline else None
            if not spec and re.fullmatch(r"\w+", target):
                imported = re.search(rf"(?:const|let|var)\s+{target}\s*=\s*require\(\s*['\"]([^'\"]+)['\"]|"
                                     rf"import\s+{target}\s+from\s+['\"]([^'\"]+)['\"]|"
                                     rf"import\s*\{{[^}}]*\b{target}\b[^}}]*\}}\s*from\s*['\"]([^'\"]+)['\"]", code)
                spec = next((g for g in imported.groups() if g), None) if imported else None
            module = _resolve_module(files, rel, spec) if spec else None
            if module and module != rel:
                auth = bool(JS_AUTH_NAME.search(middle)) or scope.covers(scope.auth, path, match.start())
                mounts[module] = (path, auth)
    return mounts


def js_routes(index: FileIndex, route_cls) -> list:
    files = _js_server_files(index)
    if not files:
        return []
    functions = _js_functions(files)
    mounts = _js_mounts(files)
    global_auth = any(re.search(r"APP_GUARD|useGlobalGuards\(", code) and re.search(r"(?i)auth|jwt|clerk|session", code)
                      for code in files.values())
    global_validation = any("ValidationPipe" in code for code in files.values())
    global_rate = any(re.search(r"ThrottlerGuard|ThrottlerModule", code) for code in files.values())
    routes = []
    for rel, code in files.items():
        scope = _js_scope(code)
        before = len(routes)
        if "@Controller(" in code:
            routes.extend(_nest_routes(route_cls, rel, code, global_auth, global_validation, global_rate))
            continue

        def handler_parts(args: list[str]) -> tuple[str, str]:
            middleware = ",".join(args[:-1])
            last = args[-1].strip() if args else ""
            if re.fullmatch(r"[\w.]+", last):
                target = functions.get(last.rsplit(".", 1)[-1])
                return middleware, target.body if target else ""
            # Fastify: app.post('/x', { preHandler: [auth], schema }, handler)
            return middleware, last

        for match in capped(JS_ROUTE.finditer(code)):
            receiver, method, path = match.group(1), match.group(2), match.group(4)
            if receiver in ("axios", "http", "https", "fetch", "got", "ky", "superagent", "request", "api", "client", "$http"):
                continue
            open_idx = code.index("(", match.start() + len(receiver) + 1)
            close = match_bracket(code, open_idx)
            if close < 0:
                continue
            args = split_args(code, open_idx, close)[1:]
            if not args:
                continue
            middleware, body = handler_parts(args)
            method = {"del": "DELETE", "all": "ANY"}.get(method, method.upper())
            kind = "fastify" if "fastify" in code[:2000] else "hono" if "hono" in code[:2000] else "express"
            routes.append(_js_route(route_cls, method, path, rel, line_of(code, match.start()), kind, middleware, body,
                                    code, scope, match.start()))
        for match in capped(JS_ROUTE_CHAIN.finditer(code)):
            path = match.group(3)
            pos = match.end()
            while True:
                nxt = re.match(r"\s*\.(get|post|put|patch|delete|all)\s*\(", code[pos:])
                if not nxt:
                    break
                open_idx = pos + nxt.end() - 1
                close = match_bracket(code, open_idx)
                if close < 0:
                    break
                args = split_args(code, open_idx, close)
                middleware, body = handler_parts(args)
                method = "ANY" if nxt.group(1) == "all" else nxt.group(1).upper()
                routes.append(_js_route(route_cls, method, path, rel, line_of(code, match.start()), "express", middleware,
                                        body, code, scope, match.start()))
                pos = close + 1
        for match in capped(JS_ROUTE_OBJECT.finditer(code)):
            open_idx = match.end() - 1
            close = match_bracket(code, open_idx)
            if close < 0:
                continue
            obj = code[open_idx: close + 1]
            url = re.search(r"\burl\s*:\s*['\"`](/[^'\"`]*)['\"`]", obj)
            methods = re.findall(r"['\"](GET|POST|PUT|PATCH|DELETE)['\"]", obj.split("handler")[0]) if url else []
            for method in methods or (["ANY"] if url else []):
                routes.append(_js_route(route_cls, method, url.group(1), rel, line_of(code, match.start()), "fastify",
                                        obj, obj, code, scope, match.start()))
        if rel in mounts:
            prefix, mount_auth = mounts[rel]
            for route in routes[before:]:
                route.path = _join(prefix, route.path)
                route.dynamic = route.dynamic or bool(DYNAMIC.search(route.path))
                if mount_auth and route.auth == "no":
                    route.auth = "mw"
    return routes


def _nest_routes(route_cls, rel: str, code: str, global_auth: bool, global_validation: bool, global_rate: bool) -> list:
    routes = []
    for ctrl in capped(NEST_CONTROLLER.finditer(code)):
        prefix = ctrl.group(1) or ctrl.group(2) or ""
        class_at = code.find("class ", ctrl.end())
        brace = code.find("{", class_at)
        if class_at < 0 or brace < 0:
            continue
        class_end = match_bracket(code, brace)
        # Class decorators can sit above or below @Controller; take everything since the previous statement.
        head = code[max(code.rfind(";", 0, ctrl.start()), code.rfind("}", 0, ctrl.start())) + 1: brace]
        body = code[brace: class_end + 1 if class_end > 0 else len(code)]
        class_auth = bool(NEST_AUTH.search(head))
        class_public = bool(NEST_PUBLIC.search(head))
        class_rate = bool(NEST_RATE.search(head))
        previous = 0
        for match in capped(NEST_METHOD.finditer(body)):
            name = re.search(r"(?<![@\w.])(?:async\s+)?(\w+)\s*\(", body[match.end():])
            if not name:
                continue
            sig_open = match.end() + name.end() - 1
            sig_close = match_bracket(body, sig_open)
            open_brace = body.find("{", sig_close)
            close_brace = match_bracket(body, open_brace) if open_brace > 0 else -1
            if sig_close < 0 or close_brace < 0:
                continue
            decorators = body[previous: match.end() + name.start()]
            # Only the decorators directly above this method count, not the previous method's.
            decorators = decorators[decorators.rfind("}") + 1:] if "}" in decorators else decorators
            method_body = body[match.start(): close_brace + 1]
            previous = close_brace + 1
            path = _join(prefix, match.group(2) or "")
            route = route_cls("ANY" if match.group(1) == "All" else match.group(1).upper(), path, rel,
                              line_of(code, brace + match.start()), "nest")
            public = class_public or bool(NEST_PUBLIC.search(decorators))
            if public:
                route.public = True
            if JS_SIGNATURE.search(method_body):
                route.auth = "sig"
            elif NEST_AUTH.search(decorators) or class_auth or JS_AUTH_BODY.search(method_body):
                route.auth = "yes"
            elif global_auth and not public:
                route.auth = "mw"
            route.db = bool(JS_DB.search(method_body))
            route.mutates = route.db and bool(JS_MUTATION.search(method_body))
            route.paid_api = bool(JS_PAID.search(code))
            route.dynamic = bool(DYNAMIC.search(path))
            if route.db and (route.dynamic or route.method in MUTATING_JS):
                route.owner = "yes" if JS_OWNER.search(method_body) else "no"
            body_param = re.search(r"@Body\(\)\s*\w+\s*:\s*(\w+)", method_body)
            if body_param:
                typed = body_param.group(1) not in ("any", "unknown", "object", "Record")
                route.validation = "yes" if typed and global_validation or "ValidationPipe" in decorators else "no"
            if class_rate or NEST_RATE.search(decorators):
                route.rate_limit = "yes"
            elif global_rate:
                route.rate_limit = "mw"
            routes.append(route)
    return routes


# ---------- Python servers (FastAPI, Flask, Django) ----------

PY_ROUTE_DECORATOR = re.compile(
    r"@(\w+)\.(get|post|put|patch|delete|api_route|route|websocket)\(\s*(?:path\s*=\s*)?(?:rule\s*=\s*)?[rf]?(['\"])([^'\"]*)\3"
)
PY_METHODS_ARG = re.compile(r"methods\s*=\s*[\[(]([^\])]*)[\])]")
PY_AUTH = re.compile(
    r"@(?:\w+\.)*(?:login_required|jwt_required|fresh_jwt_required|token_required|auth_required|requires_auth|require_auth|"
    r"authenticated|permission_required|roles_required|roles_accepted|admin_required|user_required|staff_member_required|"
    r"user_passes_test|superuser_required|api_key_required|protected)\b|"
    r"Depends\(\s*(?:\w+\.)*\w*(?:user|auth|token|verify|current|login|admin|session|principal|jwt|api_key|apikey|"
    r"oauth2|bearer|permission|role)\w*|Security\(|"
    r"current_user\.is_authenticated|request\.user\.is_authenticated|get_jwt_identity\(|verify_jwt_in_request\(|"
    r"LoginRequiredMixin|PermissionRequiredMixin|UserPassesTestMixin|IsAuthenticated|IsAdminUser|DjangoModelPermissions|"
    r"login_required|\bg\.user\b|session\[['\"]user"
)
PY_PUBLIC = re.compile(r"\bAllowAny\b|@public\b")
PY_DB = re.compile(
    r"\.objects\.|\bsession\.(?:query|execute|add|get|delete|scalars?|merge)\(|\bdb\.(?:session|query|execute|add|get|delete|"
    r"collection|table)\b|cursor\.execute|\.query\(|\bselect\(\s*\w|get_object_or_404|get_list_or_404|\.get_or_404\(|"
    r"\.first_or_404\(|\.filter(?:_by)?\(|\.find_one\(|\.find\(|\.insert_one\(|\.update_one\(|\.delete_one\(|"
    r"supabase\.table\(|\.table\(\s*['\"]|\bconn\.execute|\bawait\s+\w+\.(?:fetch|fetchrow|execute)\(|serializer\.save\(|"
    r"\bModelViewSet\b|\bqueryset\b"
)
PY_MUTATION = re.compile(
    r"\.save\(|\.delete\(\)|\.objects\.(?:create|update|bulk_create|get_or_create|update_or_create)\(|\bsession\.(?:add|delete|merge)\(|"
    r"\bdb\.session\.(?:add|delete|commit)\(|\.commit\(\)|\.insert_one\(|\.insert_many\(|\.update_one\(|\.update_many\(|"
    r"\.delete_one\(|\.delete_many\(|\.insert\(|\.upsert\(|\.update\(\s*\{|\.update\(\w+\s*=|"
    r"\b(?:INSERT\s+INTO|UPDATE\s+\w+\s+SET|DELETE\s+FROM)\b|\bModelViewSet\b|\b(?:Create|Update|Destroy)(?:API)?View\b"
)
PY_OWNER = re.compile(
    r"\b(?:current_user|request\.user|user|g\.user)\.id\b|\brequest\.user\b(?!\.is_authenticated)|"
    r"\b(?:user|owner|author)(?:_id)?\s*=\s*(?:current_user|request\.user|user|g\.user)\b|"
    r"\b(?:user|owner|author)_id\s*(?:==|!=)\s*|\.(?:user|owner|author)(?:_id)?\s*(?:==|!=)\s*"
)
PY_VALIDATION = re.compile(
    r"\bBaseModel\b|\.model_validate\(|\.parse_obj\(|\bSchema\(\)\.load\(|\w*[Ss]chema\w*(?:\(\))?\.load\(|\.is_valid\(|"
    r"validate_on_submit\(|\bForm\(\s*request|\bjsonschema\.validate\(|\bmarshmallow\b|\bpydantic\b|\bCerberus\b|"
    r"serializer_class|Serializer\(\s*data="
)
PY_RATE = re.compile(r"(?i)@limiter\.|limiter\.limit|slowapi|RateLimiter|throttle_classes|@ratelimit|ratelimit\(|flask_limiter|Throttl")
PY_PAID = re.compile(
    r"(?i)^\s*(?:from|import)\s+(?:openai|anthropic|twilio|sendgrid|resend|replicate|elevenlabs|groq|mistralai|cohere|"
    r"google\.generativeai|google\.genai|litellm)\b|boto3\.client\(\s*['\"](?:ses|sns|bedrock-runtime)['\"]",
    re.M,
)
PY_SIGNATURE = re.compile(r"construct_event|verify_header|hmac\.compare_digest|Webhook\(|verify_signature|validate_signature")
PY_FASTAPI_PARAM = re.compile(r"(\w+)\s*:\s*(?:Annotated\[\s*)?([A-Z]\w*)")
NOT_A_MODEL = {"Request", "Response", "Session", "AsyncSession", "BackgroundTasks", "UploadFile", "WebSocket", "Depends",
               "Optional", "List", "Dict", "Any", "Union", "HTTPAuthorizationCredentials", "Query", "Path", "Header",
               "Cookie", "Form", "File", "Body", "Annotated", "User", "JSONResponse", "HTMLResponse"}


@dataclass
class PyFunc:
    name: str
    line: int  # 1-based line of the def
    indent: int
    decorators: str
    signature: str
    body: str
    cls: str | None = None
    cls_head: str = ""


def _indent(line: str) -> int:
    return len(line) - len(line.lstrip(" \t"))


def py_functions(code: str) -> list[PyFunc]:
    """Every def with its decorators, signature and body (by indentation), and the class it sits in."""
    lines = code.splitlines()
    out: list[PyFunc] = []
    classes: list[tuple[int, str, str]] = []  # (indent, name, header incl. decorators and bases)
    for i, line in enumerate(lines):
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        ind = _indent(line)
        classes = [c for c in classes if c[0] < ind]
        cls = re.match(r"class\s+(\w+)\s*(\([^)]*\))?", stripped)
        fn = re.match(r"(?:async\s+)?def\s+(\w+)\s*\(", stripped)
        if not (cls or fn):
            continue
        k = i - 1
        while k >= 0:
            prev = lines[k]
            if not prev.strip():
                break
            if (_indent(prev) == ind and prev.strip().startswith("@")) or _indent(prev) > ind or prev.strip().startswith((")", "]")):
                k -= 1
                continue
            break
        block = lines[k + 1: i]
        while block and not (_indent(block[0]) == ind and block[0].strip().startswith("@")):
            block = block[1:]
        decorators = "\n".join(block)
        if cls:
            classes.append((ind, cls.group(1), decorators + "\n" + stripped))
            continue
        sig_end = i
        depth = 0
        for j in range(i, min(len(lines), i + 40)):
            depth += lines[j].count("(") + lines[j].count("[") - lines[j].count(")") - lines[j].count("]")
            if depth <= 0 and lines[j].rstrip().endswith(":"):
                sig_end = j
                break
        body_end = sig_end + 1
        while body_end < len(lines):
            nxt = lines[body_end]
            if nxt.strip() and not nxt.strip().startswith("#") and _indent(nxt) <= ind:
                break
            body_end += 1
        owner = classes[-1] if classes else None
        out.append(PyFunc(fn.group(1), i + 1, ind, decorators, "\n".join(lines[i: sig_end + 1]),
                          "\n".join(lines[sig_end + 1: body_end]), owner[1] if owner else None, owner[2] if owner else ""))
    return out


def _py_assess(route, everything: str, body: str, module: str, mw_auth: bool, mw_rate: bool, validated: bool | None):
    if PY_SIGNATURE.search(everything):
        route.auth = "sig"
    elif PY_PUBLIC.search(everything):
        route.public = True
    elif PY_AUTH.search(everything):
        route.auth = "yes"
    elif mw_auth:
        route.auth = "mw"
    route.db = bool(PY_DB.search(everything))
    route.mutates = route.db and bool(PY_MUTATION.search(everything))
    route.paid_api = bool(PY_PAID.search(module) and PAID_CALL.search(body))
    route.dynamic = bool(DYNAMIC.search(route.path)) or route.kind == "django" and bool(re.search(r"\bpk\b|_id\b", everything[:400]))
    if route.db and (route.dynamic or route.method in MUTATING_PY):
        route.owner = "yes" if PY_OWNER.search(everything) else "no"
    if route.method in MUTATING_PY:
        reads = re.search(r"request\.(?:json|get_json|form|data|POST|body)|await\s+request\.json\(\)|\bserializer\b", everything)
        if validated is not None:
            route.validation = "yes" if validated or PY_VALIDATION.search(body) else ("no" if reads else "n/a")
        else:
            route.validation = ("yes" if PY_VALIDATION.search(everything) else "no") if reads else "n/a"
    if PY_RATE.search(everything):
        route.rate_limit = "yes"
    elif mw_rate:
        route.rate_limit = "mw"
    return route


MUTATING_PY = {"POST", "PUT", "PATCH", "DELETE", "ANY"}


def _py_strip(code: str) -> str:
    return re.sub(r"(?m)^(\s*)#.*$", r"\1", code)


def python_routes(index: FileIndex, route_cls) -> list:
    files = {}
    for rel in index.sources(PY_EXT):
        text = index.read(rel) or ""
        if re.search(r"^\s*(?:from|import)\s+(?:fastapi|flask|django|rest_framework|starlette|quart|sanic)\b", text, re.M):
            files[rel] = _py_strip(text)
    if not files:
        return []
    everything = "\n".join(files.values())
    drf_default_auth = bool(re.search(r"DEFAULT_PERMISSION_CLASSES[^\]]*IsAuthenticated", everything, re.S))
    django_urls = _django_urls(files)
    routes = []
    for rel, code in files.items():
        prefixes = {m.group(1): m.group(3) for m in re.finditer(
            r"(\w+)\s*=\s*(?:APIRouter|Blueprint)\((?:[^)]*?)(?:prefix|url_prefix)\s*=\s*(['\"])([^'\"]*)\2", code, re.S)}
        router_auth = {m.group(1) for m in re.finditer(r"(\w+)\s*=\s*(?:APIRouter|FastAPI)\([^)]*dependencies\s*=\s*\[[^\]]*Depends", code, re.S)
                       if PY_AUTH.search(code[m.start(): m.start() + 400])}
        before_request_auth = bool(re.search(r"@\w+\.before_(?:app_)?request[\s\S]{0,600}?(?:login|auth|current_user|session|abort\(401)", code))
        limiter_default = bool(re.search(r"Limiter\([^)]*default_limits", code, re.S))
        kind = "fastapi" if re.search(r"^\s*from\s+fastapi\b|^\s*import\s+fastapi\b", code, re.M) else "flask"
        for fn in py_functions(code):
            decorators = fn.decorators
            matched = False
            for deco in capped(PY_ROUTE_DECORATOR.finditer(decorators)):
                matched = True
                receiver, verb, path = deco.group(1), deco.group(2), deco.group(4)
                if verb == "route":
                    listed = PY_METHODS_ARG.search(decorators[deco.start(): deco.start() + 300])
                    methods = re.findall(r"['\"](\w+)['\"]", listed.group(1)) if listed else ["GET"]
                elif verb in ("api_route", "websocket"):
                    listed = PY_METHODS_ARG.search(decorators[deco.start(): deco.start() + 300])
                    methods = re.findall(r"['\"](\w+)['\"]", listed.group(1)) if listed else ["ANY"]
                else:
                    methods = [verb]
                full_path = _join(prefixes.get(receiver, ""), path)
                validated = None
                if kind == "fastapi":
                    validated = any(t not in NOT_A_MODEL for _, t in PY_FASTAPI_PARAM.findall(fn.signature))
                for method in methods:
                    route = route_cls(method.upper(), full_path, rel, fn.line, kind)
                    route = _py_assess(route, decorators + "\n" + fn.signature + "\n" + fn.body, fn.body, code,
                                       receiver in router_auth or before_request_auth, limiter_default, validated)
                    routes.append(route)
            if matched or not re.search(r"^\s*from\s+(?:django|rest_framework)\b", code, re.M):
                continue
            routes.extend(_django_view(route_cls, rel, fn, code, django_urls, drf_default_auth))
        for viewset in capped(re.finditer(r"(?m)^class\s+(\w+)\(([^)]*ModelViewSet[^)]*)\):", code)):
            # Router-registered viewsets expose list/create/update/delete without any method being written out.
            body = _class_body(code, viewset.group(1), full=True)
            if re.search(r"(?m)^\s+def\s+(?:create|update|partial_update|destroy)\(", body):
                continue
            route = route_cls("ANY", django_urls.get(viewset.group(1), f"viewset {viewset.group(1)}"), rel,
                              line_of(code, viewset.start()), "django")
            route.dynamic = True
            routes.append(_py_assess(route, viewset.group(0) + "\n" + body, body, code, drf_default_auth, False, None))
    return _dedupe_django(routes)


def _django_urls(files: dict[str, str]) -> dict[str, str]:
    """View name -> URL pattern, from every urls.py, with include() prefixes (one level) applied."""
    url_files = [rel for rel in files if rel.endswith("urls.py")]
    prefixes: dict[str, str] = {}  # urls.py -> prefix it's included under
    router_prefix: dict[str, str] = {}  # urls.py -> prefix for include(router.urls) in that file
    for rel in url_files:
        for m in re.finditer(r"(?:re_)?path\(\s*r?['\"]([^'\"]*)['\"]\s*,\s*include\(\s*(?:['\"]([\w.]+)['\"]|(\w+)\.urls)",
                             files[rel]):
            prefix = m.group(1).lstrip("^").rstrip("$")
            if m.group(3):
                router_prefix[rel] = prefix
                continue
            target = m.group(2).replace(".", "/") + ".py"
            for other in url_files:
                if other == target or other.endswith("/" + target):
                    prefixes[other] = prefix

    def join(*parts: str) -> str:
        return "/" + "".join(p for p in parts if p)

    mapping: dict[str, str] = {}
    for rel in url_files:
        code = files[rel]
        for m in capped(re.finditer(r"(?:re_)?path\(\s*r?['\"]([^'\"]*)['\"]\s*,\s*([\w.]+)", code)):
            view = m.group(2).rsplit(".", 1)[-1]
            if view not in ("include",):
                mapping.setdefault(view, join(prefixes.get(rel, ""), m.group(1).lstrip("^").rstrip("$")))
        for m in capped(re.finditer(r"register\(\s*r?['\"]([^'\"]*)['\"]\s*,\s*([\w.]+)", code)):
            mapping.setdefault(m.group(2).rsplit(".", 1)[-1],
                               join(prefixes.get(rel, ""), router_prefix.get(rel, ""), m.group(1) + "/"))
    return mapping


def _django_view(route_cls, rel: str, fn: PyFunc, code: str, urls: dict[str, str], drf_default_auth: bool) -> list:
    if not (rel.endswith("views.py") or "/views/" in rel or "api" in rel.rsplit("/", 1)[-1]):
        return []
    routes = []
    if fn.cls is None:
        if not re.search(r"\(\s*request\b", fn.signature):
            return []
        methods = []
        api_view = re.search(r"@api_view\(\s*\[([^\]]*)\]", fn.decorators)
        if api_view:
            methods = [m.upper() for m in re.findall(r"['\"](\w+)['\"]", api_view.group(1))]
        elif re.search(r"@require_POST", fn.decorators):
            methods = ["POST"]
        elif re.search(r"@require_http_methods\(\s*\[([^\]]*)\]", fn.decorators):
            methods = [m.upper() for m in re.findall(r"['\"](\w+)['\"]", re.search(r"@require_http_methods\(\s*\[([^\]]*)\]", fn.decorators).group(1))]
        elif re.search(r"request\.method\s*==\s*['\"]POST['\"]", fn.body):
            methods = ["ANY"]  # one view answering GET and POST
        else:
            methods = ["ANY"] if PY_MUTATION.search(fn.body) else ["GET"]
        path = urls.get(fn.name, f"view {fn.name}()")
        drf = bool(api_view)
        for method in methods:
            route = route_cls(method, path, rel, fn.line, "django")
            routes.append(_py_assess(route, fn.decorators + "\n" + fn.signature + "\n" + fn.body, fn.body, code,
                                     drf and drf_default_auth, False, None))
        return routes
    head = fn.cls_head
    if not re.search(r"View|ViewSet|Mixin", head):
        return []
    drf = bool(re.search(r"APIView|ViewSet|GenericAPIView|ListAPIView|CreateAPIView|RetrieveAPIView|UpdateAPIView|DestroyAPIView", head))
    class_text = _class_body(code, fn.cls)
    verb = fn.name.upper() if fn.name in ("get", "post", "put", "patch", "delete") else None
    if verb is None and not (fn.name in ("create", "update", "partial_update", "destroy", "perform_create") and drf):
        return []
    method = verb or {"create": "POST", "perform_create": "POST", "update": "PUT", "partial_update": "PATCH",
                      "destroy": "DELETE"}[fn.name]
    path = urls.get(fn.cls, f"view {fn.cls}")
    route = route_cls(method, path, rel, fn.line, "django")
    return [_py_assess(route, head + "\n" + class_text + "\n" + fn.decorators + "\n" + fn.body, fn.body, code,
                       drf and drf_default_auth, False, None)]


def _class_body(code: str, name: str, full: bool = False) -> str:
    match = re.search(rf"(?m)^([ \t]*)class\s+{re.escape(name)}\b.*$", code)
    if not match:
        return ""
    ind = len(match.group(1))
    lines = code[match.end():].splitlines()
    body = []
    for line in lines[1:]:
        if line.strip() and _indent(line) <= ind:
            break
        body.append(line)
    if full:
        return "\n".join(body)
    # Class attributes only (permission_classes, queryset ...), not other methods' bodies.
    return "\n".join(l for l in body if _indent(l) <= ind + 4 or not l.strip())


def _dedupe_django(routes: list) -> list:
    seen = set()
    out = []
    for r in routes:
        key = (r.method, r.path, r.file, r.line)
        if key not in seen:
            seen.add(key)
            out.append(r)
    return out


def analyze_servers(index: FileIndex, route_cls) -> list:
    return js_routes(index, route_cls) + python_routes(index, route_cls)
