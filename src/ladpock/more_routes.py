"""The route matrix for the remaining popular frameworks: Rust (Axum, Actix, Rocket),
Elysia, Hapi, Sinatra, Symfony, Ktor, and JAX-RS (Quarkus, Jersey) and Micronaut.
"""

from __future__ import annotations

import re

from .backend_routes import Patterns, SPRING, _assess, _join
from .files import FileIndex
from .function_routes import _assess as _assess_js
from .jsparse import capped, line_of, match_bracket, strip_comments
from .routes import Route

# ---------- Rust: Axum, Actix, Rocket ----------

RUST = Patterns(
    db=re.compile(r"\bsqlx::|\bquery(?:_as|_scalar)?!?\(|\.fetch_(?:one|all|optional)\(|\.execute\(|\bdiesel::|\.load::<|\.get_result\(|::find(?:_by_id)?\(|"
                  r"\.first::<|\bcollection\.\w+\(|\bdb\.\w+\(|\brepo\.\w+\("),
    mutation=re.compile(r"(?i)\bINSERT\s+INTO\b|\bUPDATE\s+\w+\s+SET\b|\bDELETE\s+FROM\b|\.insert_one\(|\.delete_one\(|\.update_one\(|\bdiesel::(?:insert_into|update|delete)\b|"
                        r"\.save\(|\.delete\(|\.insert\("),
    owner=re.compile(r"\b(?:user|claims|auth|session|identity|current_user|principal)\w*\.(?:0\.)?(?:id|sub|user_id)\b|\buser_id\b|\bowner_id\b"),
    validation=re.compile(r"\.validate\(\)|\bValidated\w*\s*<|\bValidJson\b|\bGarde\b|#\[validate"),
    reads=re.compile(r"\bJson<|\bForm<|\bweb::Json\b|\bweb::Form\b|\bJson\(\w+\)|\bdata\s*:"),
    rate=re.compile(r"(?i)governor|ratelimit|rate_limit|throttle"),
)
RUST_FN = re.compile(r"(?:pub(?:\([^)]*\))?\s+)?(?:async\s+)?fn\s+(\w+)\b")
RUST_ATTR_ROUTE = re.compile(r"#\[\s*(get|post|put|patch|delete)\s*\(\s*\"([^\"]+)\"[^\]]*\]")
RUST_AUTH_PARAM = re.compile(r"(?i)\b_?\w*(?:user|claims|auth|session|identity|principal|admin|token|account)\w*\s*:\s*|\bExtension\(\s*\w*(?:user|claims)|:\s*\w*(?:Auth|User|Claims|Session)\w*\b")
RUST_AUTH_ATTR = re.compile(r"#\[\s*(?:protect|has_permissions|has_roles|has_any_role|authorize|require_auth|login_required)\b")
AXUM_ROUTE = re.compile(r"\.route\(\s*\"([^\"]+)\"\s*,")
AXUM_METHOD = re.compile(r"\b(get|post|put|patch|delete)\(\s*([\w:]+)\s*\)")
ACTIX_METHOD = re.compile(r"\bweb::(get|post|put|patch|delete)\(\)\s*\.\s*to\(\s*([\w:]+)\s*\)")
AXUM_NEST = re.compile(r"\.nest\(\s*\"([^\"]+)\"\s*,\s*([\w:]+)\(")
AUTH_LAYER = re.compile(r"(?i)\.(?:route_)?layer\([^\n]{0,200}(?:auth|jwt|session|login|require_user)|\.wrap\([^\n]{0,200}(?:auth|jwt|session|bearer|identity)")
RATE_LAYER = re.compile(r"(?i)\.(?:route_)?layer\([^\n]{0,200}(?:governor|ratelimit|rate_limit|throttle)|\.wrap\([^\n]{0,200}(?:governor|ratelimit)")
ROCKET_MOUNT = re.compile(r"\.mount\(\s*\"([^\"]*)\"\s*,\s*routes!\[([^\]]*)\]")
ACTIX_SCOPE = re.compile(r"web::scope\(\s*\"([^\"]*)\"\s*\)")
ACTIX_SERVICE = re.compile(r"\.service\(\s*([\w:]+)\s*\)")


def _rust_function(code: str, name_end: int) -> tuple[str, str]:
    """(signature, body) of the function whose name ends at name_end."""
    open_paren = code.find("(", name_end, name_end + 300)
    close_paren = match_bracket(code, open_paren, quotes='"') if open_paren != -1 else -1
    if close_paren == -1:
        return "", ""
    brace = code.find("{", close_paren, close_paren + 300)
    close = match_bracket(code, brace, quotes='"') if brace != -1 else -1
    return code[open_paren: close_paren + 1], code[brace: close + 1] if close != -1 else ""


def _braces_path(path: str) -> str:
    """Rocket's <id> and <id..> as {id}, so every framework's parameters look alike."""
    return re.sub(r"<(\w+)(?:\.\.)?>", r"{\1}", path)


def rust_routes(index: FileIndex) -> list[Route]:
    files = {rel: strip_comments(index.read(rel) or "", quotes='"') for rel in index.sources({".rs"})}
    files = {rel: code for rel, code in files.items() if re.search(r"\b(?:axum|actix_web|rocket)\b", code)}
    functions: dict[str, tuple[str, int]] = {}
    prefix_of: dict[str, str] = {}  # handler or router-building function -> URL prefix
    for rel, code in files.items():
        for match in capped(RUST_FN.finditer(code)):
            functions.setdefault(match.group(1), (rel, match.end()))
        for match in capped(AXUM_NEST.finditer(code)):
            prefix_of[match.group(2).rsplit("::", 1)[-1]] = match.group(1)
        for match in capped(ROCKET_MOUNT.finditer(code)):
            for name in match.group(2).split(","):
                if name.strip():
                    prefix_of[name.strip().rsplit("::", 1)[-1]] = match.group(1)
        for match in capped(ACTIX_SCOPE.finditer(code)):
            for service in capped(ACTIX_SERVICE.finditer(code, match.end(), match.end() + 1500)):
                prefix_of.setdefault(service.group(1).rsplit("::", 1)[-1], match.group(1))

    routes = []

    def add(method: str, path: str, kind: str, handler: str, mw_auth: bool, mw_rate: bool, fallback: tuple[str, int]) -> None:
        name = handler.rsplit("::", 1)[-1]
        rel, name_end = functions.get(name, (None, 0))
        signature, body = _rust_function(files[rel], name_end) if rel else ("", "")
        where = rel or fallback[0]
        line = line_of(files[rel], name_end) if rel else fallback[1]
        above = files[rel][max(0, name_end - 300): name_end] if rel else ""
        full = _join(prefix_of.get(name, ""), _braces_path(path))
        route = Route(method.upper(), full, where, line, kind)
        routes.append(_assess(route, RUST, signature + body, auth=bool(RUST_AUTH_PARAM.search(signature) or RUST_AUTH_ATTR.search(above)),
                              mw_auth=mw_auth, mw_rate=mw_rate))

    for rel, code in files.items():
        for match in capped(RUST_ATTR_ROUTE.finditer(code)):
            fn = RUST_FN.search(code, match.end(), match.end() + 500)
            if fn:
                add(match.group(1), match.group(2), "rocket" if "rocket" in code else "actix", fn.group(1), False, False, (rel, line_of(code, match.start())))
        for match in capped(AXUM_ROUTE.finditer(code)):
            close = match_bracket(code, match.end() - len(match.group(0)) + match.group(0).index("("), quotes='"')
            handlers = code[match.end(): close] if close != -1 else ""
            builder = next((f for f in reversed(list(capped(RUST_FN.finditer(code, 0, match.start())))) if f), None)
            scope_end = code.find("\nfn ", match.end())
            scope = code[builder.end() if builder else 0: scope_end if scope_end != -1 else len(code)]
            mw_auth, mw_rate = bool(AUTH_LAYER.search(scope)), bool(RATE_LAYER.search(scope))
            base = prefix_of.get(builder.group(1), "") if builder else ""
            found = [(m.group(1), m.group(2)) for m in AXUM_METHOD.finditer(handlers)] or [(m.group(1), m.group(2)) for m in ACTIX_METHOD.finditer(handlers)]
            for method, handler in found:
                add(method, _join(base, match.group(1)), "axum" if "axum" in code else "actix", handler, mw_auth, mw_rate, (rel, line_of(code, match.start())))
    return routes


# ---------- Elysia and Hapi ----------

ELYSIA_ROUTE = re.compile(r"\.(get|post|put|patch|delete)\(\s*(['\"`])(/[^'\"`]*)\2\s*,")
ELYSIA_AUTH = re.compile(r"\b(?:jwt|bearer|session|user|auth)\b\s*[,}]|\.use\(\s*\w*(?:auth|jwt|bearer|session)|\bbeforeHandle\b|\bverify\(|\bderive\b[^\n]{0,80}(?:user|auth)")
ELYSIA_GROUP = re.compile(r"\.group\(\s*(['\"`])(/[^'\"`]*)\1\s*,")
HAPI_ROUTE = re.compile(r"\.route\(\s*(\{|\[)")
HAPI_ENTRY_METHOD = re.compile(r"\bmethod\s*:\s*\[?\s*['\"`](\w+)['\"`]")
HAPI_ENTRY_PATH = re.compile(r"\bpath\s*:\s*['\"`](/[^'\"`]*)['\"`]")
HAPI_AUTH_OFF = re.compile(r"\bauth\s*:\s*false\b")
HAPI_AUTH = re.compile(r"\bauth\s*:\s*(?!false\b)|\brequest\.auth\.credentials\b")
HAPI_DEFAULT_AUTH = re.compile(r"\bauth\.default\(")


def js_framework_routes(index: FileIndex) -> list[Route]:
    routes = []
    for rel in index.sources({".ts", ".js", ".mjs", ".mts", ".cjs"}):
        raw = index.read(rel) or ""
        if "elysia" in raw:
            code = strip_comments(raw)
            spans = []
            for group in capped(ELYSIA_GROUP.finditer(code)):
                open_idx = code.find("(", group.start())
                close = match_bracket(code, open_idx)
                if close != -1:
                    spans.append((open_idx, close, group.group(2)))
            matches = list(capped(ELYSIA_ROUTE.finditer(code)))
            for i, match in enumerate(matches):
                end = matches[i + 1].start() if i + 1 < len(matches) else len(code)
                body = code[match.start(): min(end, match.start() + 60_000)]
                prefix = "".join(p for start, stop, p in spans if start < match.start() < stop)
                route = Route(match.group(1).upper(), prefix + match.group(3), rel, line_of(code, match.start()), "elysia",
                              dynamic=":" in match.group(3))
                head = code[:match.start()]
                routes.append(_assess_js(route, body, code, authed=bool(ELYSIA_AUTH.search(body) or re.search(r"\.use\(\s*\w*(?:auth|protect|guard)", head)),
                                         validated=bool(re.search(r"\bbody\s*:\s*t\.", body))))
        elif "@hapi/hapi" in raw or "hapi" in raw and "server.route" in raw:
            code = strip_comments(raw)
            default_auth = bool(HAPI_DEFAULT_AUTH.search(code))
            for call in capped(HAPI_ROUTE.finditer(code)):
                open_idx = call.end() - 1
                close = match_bracket(code, open_idx)
                if close == -1:
                    continue
                block = code[open_idx: close + 1]
                entries = re.split(r"(?=\bmethod\s*:)", block)
                for entry in entries[1:]:
                    method, path = HAPI_ENTRY_METHOD.search(entry), HAPI_ENTRY_PATH.search(entry)
                    if not (method and path):
                        continue
                    authed = (default_auth and not HAPI_AUTH_OFF.search(entry)) or bool(HAPI_AUTH.search(entry) and not HAPI_AUTH_OFF.search(entry))
                    route = Route(method.group(1).upper(), path.group(1), rel, line_of(code, open_idx + block.find(entry)), "hapi", dynamic="{" in path.group(1))
                    routes.append(_assess_js(route, entry, code, authed=authed, validated=bool(re.search(r"\bvalidate\s*:", entry))))
    return routes


# ---------- Sinatra ----------

SINATRA = Patterns(
    db=re.compile(r"\b[A-Z]\w*\.(?:find\w*|where|all|first|last|create!?|new|update\w*|delete\w*|destroy\w*|count|exists\?)\b|@\w+\.(?:save|update|destroy|delete)\b|"
                  r"\bDB\[|\bsettings\.db\b|\bdb\.(?:execute|query)\b"),
    mutation=re.compile(r"\.(?:create|save|update\w*|destroy\w*|delete\w*|insert\w*)\b|(?i:\bINSERT\s+INTO\b|\bDELETE\s+FROM\b|\bUPDATE\s+\w+\s+SET\b)"),
    owner=re.compile(r"\bcurrent_user\.\w+|\bsession\[:user_id\]|\buser_id:\s*(?:current_user|session)"),
    validation=re.compile(r"\bparam\s+:|\bcontract\b|\bdry-validation\b|\.validate\b"),
    reads=re.compile(r"\bparams\b|\brequest\.body\b"),
    rate=re.compile(r"\bRack::Attack\b|\bthrottle\b"),
)
SINATRA_VERB = re.compile(r"(?m)^([ \t]*)(get|post|put|patch|delete)\s+['\"](/[^'\"]*)['\"][^\n]*\bdo\b")
SINATRA_AUTH = re.compile(r"(?i)\bauthenticate\w*!?|\bprotected!|\brequire_(?:login|user|auth)\b|\bhalt\s+40[13]\b|\bcurrent_user\b|\bsession\[:user_id\]|\blogged_in\?|\bauthorized\?")
SINATRA_BEFORE = re.compile(r"(?m)^[ \t]*before\s*(?:['\"]([^'\"]*)['\"])?\s*do\b[\s\S]{0,600}?^[ \t]*end\b")


def sinatra_routes(index: FileIndex) -> list[Route]:
    routes = []
    for rel in index.sources({".rb"}):
        code = index.read(rel) or ""
        if "sinatra" not in code.lower() or rel.endswith("config/routes.rb"):
            continue
        guards = [m for m in capped(SINATRA_BEFORE.finditer(code)) if SINATRA_AUTH.search(m.group(0))]
        for match in capped(SINATRA_VERB.finditer(code)):
            indent = match.group(1)
            end = re.compile(rf"(?m)^{indent}end\b").search(code, match.end(), match.end() + 60_000)
            body = code[match.end(): end.start() if end else match.end() + 5000]
            path = match.group(3)
            guarded = any(not g.group(1) or path.startswith(g.group(1).rstrip("*").rstrip("/")) for g in guards)
            route = Route(match.group(2).upper(), path, rel, line_of(code, match.start()), "sinatra")
            routes.append(_assess(route, SINATRA, body, auth=bool(SINATRA_AUTH.search(body)), mw_auth=guarded))
    return routes


# ---------- Symfony ----------

SYMFONY = Patterns(
    db=re.compile(r"\$(?:em|entityManager|\w*[Rr]epository)\b|->(?:find|findBy|findOneBy|findAll|persist|remove|flush|createQueryBuilder)\("),
    mutation=re.compile(r"->(?:persist|remove|flush)\("),
    owner=re.compile(r"->getUser\(\)|denyAccessUnlessGranted\(\s*['\"]\w+['\"]\s*,|#\[IsGranted\([^)]*subject"),
    validation=re.compile(r"#\[MapRequestPayload|->validate\(|#\[Assert|ValidatorInterface"),
    reads=re.compile(r"\$request->|->getContent\(\)|#\[MapRequestPayload"),
    rate=re.compile(r"RateLimiterFactory|->consume\("),
)
SYMFONY_ROUTE = re.compile(r"#\[Route\(\s*(?:path\s*:\s*)?['\"]([^'\"]*)['\"]([^\]]*)\]|@Route\(\s*\"([^\"]*)\"([^)\n]*)\)")
SYMFONY_METHOD = re.compile(r"(?:public\s+)?function\s+(\w+)\s*\(")
SYMFONY_AUTH = re.compile(r"#\[IsGranted\b|@IsGranted\b|#\[Security\b|@Security\b|denyAccessUnlessGranted\(|->getUser\(\)|isGranted\(")
ACCESS_RULE = re.compile(r"\{\s*path\s*:\s*['\"]?([^,'\"\s]+)['\"]?\s*,\s*roles?\s*:\s*\[?\s*['\"]?(\w+)")


def symfony_routes(index: FileIndex) -> list[Route]:
    rules = []
    for rel in index.iter({".yaml", ".yml"}, pred=lambda r: r.endswith("security.yaml")):
        for pattern, role in ACCESS_RULE.findall(index.read(rel) or ""):
            try:
                rules.append((re.compile(pattern), role))
            except re.error:
                continue

    def firewall(path: str) -> bool:
        for pattern, role in rules:
            if pattern.search(path):
                return role not in ("PUBLIC_ACCESS", "IS_AUTHENTICATED_ANONYMOUSLY")
        return False

    routes = []
    for rel in index.sources({".php"}):
        raw = index.read(rel) or ""
        if "Route" not in raw or "Symfony" not in raw:
            continue
        code = strip_comments(raw, quotes="'\"")
        klass = re.search(r"\bclass\s+\w+[^{]*\{", code)
        if not klass:
            continue
        head = code[: klass.start()]
        class_route = SYMFONY_ROUTE.search(head[-500:])
        prefix = (class_route.group(1) or class_route.group(3) or "") if class_route else ""
        class_auth = bool(SYMFONY_AUTH.search(head[-500:]))
        for match in capped(SYMFONY_ROUTE.finditer(code, klass.end())):
            fn = SYMFONY_METHOD.search(code, match.end(), match.end() + 600)
            if not fn:
                continue
            params_end = match_bracket(code, fn.end() - 1, quotes="'\"")
            brace = code.find("{", params_end, params_end + 200) if params_end != -1 else -1
            close = match_bracket(code, brace, quotes="'\"") if brace != -1 else -1
            # Attributes can sit above #[Route] as well as below it.
            above = code[code.rfind("}", max(klass.end(), match.start() - 600), match.start()) + 1: match.start()]
            body = above + code[match.start(): close] if close != -1 else ""
            path = _join(prefix, match.group(1) or match.group(3) or "")
            options = match.group(2) or match.group(4) or ""
            methods = re.findall(r"['\"](GET|POST|PUT|PATCH|DELETE)['\"]", options) or ["GET" if not re.search(r"methods", options) else "ANY"]
            for method in methods:
                route = Route(method, path, rel, line_of(code, match.start()), "symfony")
                routes.append(_assess(route, SYMFONY, body, auth=class_auth or bool(SYMFONY_AUTH.search(body)), mw_auth=firewall(path)))
    return routes


# ---------- Ktor ----------

KTOR = Patterns(
    db=re.compile(r"\btransaction\s*\{|\bdbQuery\b|\.selectAll\(|\.select\s*[{(]|\.insert\s*[{(]|\.update\s*[({]|\.deleteWhere\b|\b\w*[Rr]epo(?:sitory)?\.\w+\(|\b\w*(?:Dao|Service)\.\w+\("),
    mutation=re.compile(r"\.insert\s*[{(]|\.update\s*[({]|\.deleteWhere\b|\.(?:save|create|delete|remove|update|insert)\w*\("),
    owner=re.compile(r"\bcall\.principal\b|\bprincipal\b|\buserId\b"),
    validation=re.compile(r"\bvalidate\(|\bRequestValidation\b"),
    reads=re.compile(r"\bcall\.receive\b"),
    rate=re.compile(r"\brateLimit\s*[({]|\bRateLimit\b"),
)
KTOR_VERB = re.compile(r"\b(get|post|put|patch|delete)\(\s*\"([^\"]*)\"\s*\)\s*\{")
KTOR_ROUTE = re.compile(r"\broute\(\s*\"([^\"]*)\"\s*\)\s*\{")
KTOR_AUTH = re.compile(r"\bauthenticate\b[^{\n]{0,120}\{")


def ktor_routes(index: FileIndex) -> list[Route]:
    routes = []
    for rel in index.sources({".kt"}):
        raw = index.read(rel) or ""
        if "routing" not in raw and "Route." not in raw:
            continue
        code = strip_comments(raw, quotes='"')
        spans: list[tuple[int, int, str]] = []
        guards: list[tuple[int, int]] = []
        for match in capped(KTOR_ROUTE.finditer(code)):
            close = match_bracket(code, match.end() - 1, quotes='"')
            if close != -1:
                spans.append((match.start(), close, match.group(1)))
        for match in capped(KTOR_AUTH.finditer(code)):
            close = match_bracket(code, match.end() - 1, quotes='"')
            if close != -1:
                guards.append((match.start(), close))
        for match in capped(KTOR_VERB.finditer(code)):
            close = match_bracket(code, match.end() - 1, quotes='"')
            body = code[match.end(): close] if close != -1 else ""
            prefix = [p for start, stop, p in spans if start < match.start() < stop]
            authed = any(start < match.start() < stop for start, stop in guards)
            route = Route(match.group(1).upper(), _join(*prefix, match.group(2)), rel, line_of(code, match.start()), "ktor")
            routes.append(_assess(route, KTOR, body, mw_auth=authed, auth=bool(re.search(r"\bcall\.principal\b", body))))
    return routes


# ---------- JAX-RS (Quarkus, Jersey) and Micronaut ----------

JAXRS = Patterns(
    db=re.compile(SPRING.db.pattern + r"|\b[A-Z]\w*\.(?:findById|find|listAll|list|deleteById|count|update)\(|\.persist\(\)|\.delete\(\)"),
    mutation=re.compile(SPRING.mutation.pattern + r"|\.persist\(\)|\.delete\(\)|\.deleteById\("),
    owner=re.compile(SPRING.owner.pattern + r"|\bsecurityIdentity\.|\bjwt\.|\bsecurityContext\."),
    validation=re.compile(r"@Valid\b|@Body\s+@Valid"),
    reads=re.compile(r"\w+\s+\w+\s*[,)]|@Body\b"),
    rate=SPRING.rate,
)
JAX_CLASS = re.compile(r"@(?:Path|Controller)\(\s*(?:value\s*=\s*)?\"([^\"]*)\"\s*\)")
JAX_VERB = re.compile(r"@(GET|POST|PUT|PATCH|DELETE)\b(?!\w)|@(Get|Post|Put|Patch|Delete)\b(?:\(\s*(?:value\s*=\s*|uri\s*=\s*)?\"?([^\")]*)\"?\s*\))?")
JAX_PATH = re.compile(r"@Path\(\s*\"([^\"]*)\"\s*\)")
JAX_AUTH = re.compile(r"@RolesAllowed\b|@Authenticated\b|@Secured\b(?!\(\s*SecurityRule\.IS_ANONYMOUS)|@DenyAll\b|\bSecurityIdentity\b|\bJsonWebToken\b|\bAuthentication\s+\w+|\bPrincipal\s+\w+")
JAX_PUBLIC = re.compile(r"@PermitAll\b|@Secured\(\s*SecurityRule\.IS_ANONYMOUS")
JAVA_METHOD = re.compile(r"(?:public|protected|fun)\s+[^;{=\n]*?\b(\w+)\s*\(")


def jaxrs_routes(index: FileIndex) -> list[Route]:
    routes = []
    for rel in index.sources({".java", ".kt"}):
        raw = index.read(rel) or ""
        if not ("jakarta.ws.rs" in raw or "javax.ws.rs" in raw or "io.micronaut.http" in raw):
            continue
        code = strip_comments(raw, quotes='"')
        klass = JAX_CLASS.search(code)
        if not klass:
            continue
        class_end = code.find("{", code.find("class ", klass.end()))
        head = code[:class_end]
        class_auth = bool(JAX_AUTH.search(head))
        for match in capped(JAX_VERB.finditer(code, class_end)):
            method = (match.group(1) or match.group(2)).upper()
            fn = JAVA_METHOD.search(code, match.end(), match.end() + 500)
            if not fn:
                continue
            above = code[match.start(): fn.start()]
            sub = JAX_PATH.search(above)
            params_end = match_bracket(code, fn.end() - 1, quotes='"')
            brace = code.find("{", params_end, params_end + 200) if params_end != -1 else -1
            close = match_bracket(code, brace, quotes='"') if brace != -1 else -1
            body = code[fn.start(): close] if close != -1 else ""
            before = code[max(0, match.start() - 200): match.start()]
            before = before[before.rfind("}") + 1:]
            public = bool(JAX_PUBLIC.search(above) or JAX_PUBLIC.search(before))
            authed = bool(JAX_AUTH.search(above) or JAX_AUTH.search(before) or JAX_AUTH.search(body)) or (class_auth and not public)
            path = _join(klass.group(1), sub.group(1) if sub else (match.group(3) or ""))
            route = Route(method, path, rel, line_of(code, match.start()), "jaxrs")
            routes.append(_assess(route, JAXRS, above + body, auth=authed, public=public))
    return routes


def analyze_more(index: FileIndex) -> list[Route]:
    return rust_routes(index) + js_framework_routes(index) + sinatra_routes(index) + symfony_routes(index) + ktor_routes(index) + jaxrs_routes(index)

