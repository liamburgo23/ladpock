"""The route matrix for backend frameworks outside the JavaScript and Python
worlds: Spring, Go (net/http, chi, gin, echo, fiber), Rails, Laravel and ASP.NET.

Each framework has its own way of declaring routes and login checks, but they
all end in the same Route record, so the access-control and abuse checks work
unchanged. Controllers that hand work to a service class count as touching
data, since that's where the record gets loaded.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

from .files import FileIndex
from .jsparse import capped, line_of, match_bracket, split_args, strip_comments
from .routes import MUTATING, Route
from .server_routes import DYNAMIC, PAID_CALL

SIGNATURE = re.compile(r"(?i)verify_?signature|constructEvent|construct_event|compare_digest|hash_equals|secure_compare|"
                       r"\bhmac\b|hmac\.New|Webhook\.ConstructEvent|EventUtility\.ConstructEvent|Webhook\.constructEvent")


@dataclass(frozen=True)
class Patterns:
    db: re.Pattern[str]
    mutation: re.Pattern[str]
    owner: re.Pattern[str]
    validation: re.Pattern[str]
    reads: re.Pattern[str]
    rate: re.Pattern[str]


def _assess(route: Route, p: Patterns, text: str, *, auth: bool = False, mw_auth: bool = False, mw_rate: bool = False,
            public: bool = False, validated: bool | None = None) -> Route:
    route.public = public
    if SIGNATURE.search(text):
        route.auth = "sig"
    elif auth:
        route.auth = "yes"
    elif mw_auth and not public:
        route.auth = "mw"
    route.db = bool(p.db.search(text))
    route.mutates = route.db and bool(p.mutation.search(text))
    route.paid_api = bool(PAID_CALL.search(text))
    route.dynamic = bool(DYNAMIC.search(route.path))
    if route.db and (route.dynamic or route.method in MUTATING):
        route.owner = "yes" if p.owner.search(text) else "no"
    if route.method in MUTATING and route.method != "DELETE":
        if validated is not None:
            route.validation = "yes" if validated else ("no" if p.reads.search(text) else "n/a")
        else:
            route.validation = ("yes" if p.validation.search(text) else "no") if p.reads.search(text) else "n/a"
    if p.rate.search(text):
        route.rate_limit = "yes"
    elif mw_rate:
        route.rate_limit = "mw"
    return route


def _join(*parts: str) -> str:
    joined = "/".join(p.strip("/") for p in parts if p and p.strip("/"))
    return "/" + joined


# ---------- Spring ----------

SPRING = Patterns(
    db=re.compile(r"\b\w*[Rr]epo(?:sitory)?\.\w+\(|\bjdbcTemplate\.|\bentityManager\.|\bem\.\w+\(|\bsessionFactory\.|\bconnection\.\w+\(|"
                  r"\b\w*(?:Mapper|Dao|Service)\.\w+\("),
    mutation=re.compile(r"\.(?:save\w*|delete\w*|update\w*|create(?!Statement|Query|NativeQuery)\w*|remove\w*|persist|merge|insert\w*|add\w*)\("),
    owner=re.compile(r"\bprincipal\.|\bgetName\(\)|ByIdAndUser|AndOwner|AndUser\w*\(|\bgetCurrentUser\b|\bcurrentUser\b|"
                     r"\bgetOwner\(\)|\bgetUser\(\)\.|@PostAuthorize|\bhasPermission\b|authentication\.\w+|\buser\.getId\(\)"),
    validation=re.compile(r"@Valid\b|@Validated\b"),
    reads=re.compile(r"@RequestBody\b|@ModelAttribute\b"),
    rate=re.compile(r"@RateLimiter\b|@RateLimit\b|\bbucket\.tryConsume\b|\bBucket4j\b|\brateLimiter\."),
)
SPRING_AUTH = re.compile(r"@PreAuthorize\b|@Secured\b|@RolesAllowed\b|@PostAuthorize\b|@AuthenticationPrincipal\b|"
                         r"\bPrincipal\s+\w+|\bAuthentication\s+\w+|SecurityContextHolder|getUserPrincipal|@CurrentUser\b|"
                         r"\bprincipal\s*:\s*Principal")
SPRING_MAPPING = re.compile(r"@(Get|Post|Put|Patch|Delete|Request)Mapping\b")
SPRING_METHOD = re.compile(r"RequestMethod\.(\w+)")
SPRING_MATCHERS = re.compile(r"(?:requestMatchers|antMatchers|mvcMatchers)\(\s*((?:\"[^\"]*\"\s*,?\s*)+)\)\s*\.\s*"
                             r"(permitAll|authenticated|hasRole|hasAnyRole|hasAuthority|hasAnyAuthority|access)\b")


def _first_string(text: str) -> str | None:
    match = re.search(r"\"([^\"]*)\"", text)
    return match.group(1) if match else None


def _spring_annotation(code: str, start: int) -> tuple[str, int]:
    """The (args) of the annotation whose name ends at start, and where it ends."""
    i = start
    while i < len(code) and code[i] in " \t\r\n":
        i += 1
    if i < len(code) and code[i] == "(":
        close = match_bracket(code, i, quotes='"')
        if close > 0:
            return code[i + 1: close], close + 1
    return "", start


def _prefix_matches(patterns: list[str], path: str) -> bool:
    for pattern in patterns:
        base = re.sub(r"/?\*\*?$", "", pattern)
        if path == base or path.startswith(base.rstrip("/") + "/") or not base:
            return True
    return False


def spring_routes(index: FileIndex) -> list[Route]:
    files = {rel: strip_comments(index.read(rel) or "", quotes='"') for rel in index.sources({".java", ".kt"})}
    config = "\n".join(code for code in files.values() if "SecurityFilterChain" in code or "HttpSecurity" in code)
    global_auth = bool(re.search(r"anyRequest\(\)\s*\.\s*(?:authenticated|hasRole|hasAuthority|fullyAuthenticated)\b", config))
    public_paths: list[str] = []
    protected_paths: list[str] = []
    for match in capped(SPRING_MATCHERS.finditer(config)):
        paths = re.findall(r"\"([^\"]*)\"", match.group(1))
        (public_paths if match.group(2) == "permitAll" else protected_paths).extend(paths)
    routes = []
    for rel, code in files.items():
        controller = re.search(r"@(?:Rest)?Controller\b", code)
        if not controller:
            continue
        class_at = re.search(r"\bclass\s+\w+", code[controller.start():])
        if not class_at:
            continue
        head_end = controller.start() + class_at.start()
        head_start = max(code.rfind(";", 0, controller.start()), 0)
        head = code[head_start: head_end]
        prefix = ""
        class_mapping = re.search(r"@RequestMapping\b", head)
        if class_mapping:
            args, _ = _spring_annotation(head, class_mapping.end())
            prefix = _first_string(args) or ""
        class_auth = bool(SPRING_AUTH.search(head))
        previous = head_end
        for match in capped(SPRING_MAPPING.finditer(code, head_end)):
            args, after = _spring_annotation(code, match.end())
            # Skip any further annotations and their arguments to reach the method's own signature.
            pos = max(after, match.end())
            while True:
                next_ann = re.match(r"\s*@\w+(?:\.\w+)*", code[pos:])
                if not next_ann:
                    break
                _, end = _spring_annotation(code, pos + next_ann.end())
                pos = max(end, pos + next_ann.end())
            sig = re.search(r"(\w+)\s*\(", code[pos:])
            if not sig:
                continue
            sig_open = pos + sig.end() - 1
            sig_close = match_bracket(code, sig_open, quotes='"')
            if sig_close < 0:
                continue
            brace = code.find("{", sig_close)
            end = match_bracket(code, brace, quotes='"') if brace > 0 else -1
            if end < 0:
                continue
            text = code[previous: end + 1]
            previous = end + 1
            kind = match.group(1)
            if kind == "Request":
                methods = [m.upper() for m in SPRING_METHOD.findall(args)] or ["ANY"]
            else:
                methods = [kind.upper()]
            path = _join(prefix, _first_string(args) or "")
            public = _prefix_matches(public_paths, path) or "@PermitAll" in text
            for method in methods:
                routes.append(_assess(
                    Route(method, path, rel, line_of(code, match.start()), "spring"), SPRING, text,
                    auth=class_auth or bool(SPRING_AUTH.search(text)),
                    mw_auth=global_auth or _prefix_matches(protected_paths, path), public=public,
                    validated=bool(SPRING.validation.search(text) or re.search(r"@Validated\b", head)),
                ))
    return routes


# ---------- Go ----------

GO = Patterns(
    db=re.compile(r"\b[dD][bB]\.\w+\(|\.Query(?:Row|Context|RowContext)?\(|\.Exec(?:Context)?\(|\bgorm\.|\.First\(&|\.Find\(&|"
                  r"\.Create\(&|\.Save\(&|\.Delete\(&|\bqueries\.\w+\(|\bstore\.\w+\(|\brepo\.\w+\(|\b\w+Repo\.\w+\(|\.Collection\("),
    mutation=re.compile(r"\.Exec(?:Context)?\(|\.Create\(|\.Save\(|\.Delete\(|\.Updates?\(|\.InsertOne\(|\.UpdateOne\(|\.DeleteOne\(|"
                        r"\b(?:INSERT\s+INTO|UPDATE\s+\w+\s+SET|DELETE\s+FROM)\b|\.(?:Create|Update|Delete|Insert)\w*\("),
    owner=re.compile(r"(?i)user_?id\s*=\s*[$?]|\buserID\b|\buser\.ID\b|\bclaims\.\w+|owner_?id|\.UserID\s*(?:==|!=)|user_id\s*=\s*\?"),
    validation=re.compile(r"\bvalidate\.Struct\(|\bvalidator\.|\bShouldBind\w*\(|\bBindJSON\(|\bc\.Validate\(|\.Validate\(\)"),
    reads=re.compile(r"\bjson\.NewDecoder\(\s*r\.Body|\br\.Body\b|\bc\.(?:ShouldBind\w*|Bind\w*|BodyParser)\(|\br\.FormValue\(|\bPostForm\b"),
    rate=re.compile(r"(?i)rate\.NewLimiter|httprate|tollbooth|\blimiter\b|ratelimit|throttle"),
)
GO_AUTH_NAME = re.compile(r"(?i)\b[\w.]*(?:auth|jwt|session|requirelogin|requireuser|loggedin|protected|guard|verifytoken)[\w.]*")
GO_AUTH_BODY = re.compile(r"(?i)\bclaims\b|\bGetUser\(|\bCurrentUser\b|\bUserFromContext\(|\.Value\(\s*\w*(?:user|claims)|"
                          r"\bc\.(?:Get|MustGet|Locals)\(\s*\"(?:user|userID|user_id|claims)\"|\bsession\.Get\(|ParseWithClaims\(|"
                          r"\bauth\.\w+\(")
GO_VERB = "GET|POST|PUT|PATCH|DELETE|Get|Post|Put|Patch|Delete|Any|All|Handle|HandleFunc"
GO_ROUTE = re.compile(rf"\b(\w+)\.({GO_VERB})\(\s*\"([^\"]*)\"")
GO_WITH = re.compile(rf"\.With\(([^)]*)\)\.({GO_VERB})\(\s*\"([^\"]*)\"")
GO_GROUP = re.compile(r"\b(\w+)\s*:?=\s*(\w+)\.Group\(\s*\"([^\"]*)\"\s*(?:,\s*([^)]*))?\)")
GO_USE = re.compile(r"\b(\w+)\.Use\(")
GO_SCOPE = re.compile(r"\.(Route|Group)\(\s*(?:\"([^\"]*)\"\s*,\s*)?func\(\s*\w+\s+[\w.*]*Router\s*\)\s*\{")
GO_FUNC = re.compile(r"(?m)^func\s+(?:\([^)]*\)\s*)?(\w+)\s*\(")
GO_NOT_ROUTER = {"http", "client", "c", "ctx", "req", "resp", "url", "os", "cache", "redis", "viper", "w", "r2"}


def go_routes(index: FileIndex) -> list[Route]:
    files = {rel: strip_comments(index.read(rel) or "", quotes='"`') for rel in index.sources({".go"})}
    functions: dict[str, str] = {}
    for code in files.values():
        for match in capped(GO_FUNC.finditer(code)):
            brace = code.find("{", match.end())
            end = match_bracket(code, brace, quotes='"`') if brace > 0 else -1
            if end > 0:
                functions.setdefault(match.group(1), code[match.start(): end + 1])
    routes = []
    for rel, code in files.items():
        echo = "labstack/echo" in code
        groups: dict[str, tuple[str, str]] = {}  # variable -> (full prefix, parent)
        group_mw: dict[str, str] = {}
        for match in capped(GO_GROUP.finditer(code)):
            parent = groups.get(match.group(2), ("", ""))[0]
            groups[match.group(1)] = (_join(parent, match.group(3)) if match.group(3) or parent else "", match.group(2))
            group_mw[match.group(1)] = match.group(4) or ""
        scopes = []  # (start, end, prefix): chi r.Route("/x", func(r chi.Router) {...}) and r.Group(func...)
        for match in capped(GO_SCOPE.finditer(code)):
            brace = match.end() - 1
            end = match_bracket(code, brace, quotes='"`')
            if end > 0:
                scopes.append((brace, end, match.group(2) or ""))
        uses = []  # (receiver, offset, text)
        for match in capped(GO_USE.finditer(code)):
            close = match_bracket(code, match.end() - 1, quotes='"`')
            if close > 0:
                uses.append((match.group(1), match.start(), code[match.end(): close]))

        def mw_text(receiver: str, offset: int) -> str:
            chain = []
            name = receiver
            visited = set()
            while name and name not in visited:
                visited.add(name)
                chain.append(group_mw.get(name, ""))
                chain.extend(text for r, at, text in uses if r == name and at < offset and not _in_scope(at, scopes))
                name = groups.get(name, ("", ""))[1]
            chain.extend(text for _, at, text in uses for start, end, _p in scopes
                         if start < at < offset and start < offset < end)
            return " ".join(chain)

        def add(receiver: str, verb: str, raw: str, offset: int, open_idx: int, extra_mw: str = "") -> None:
            if receiver in GO_NOT_ROUTER or "FileServer" in code[open_idx: open_idx + 200]:
                return
            pattern = re.match(r"(?:([A-Z]+)\s+)?(/.*)$", raw)
            if not pattern:
                return
            close = match_bracket(code, open_idx, quotes='"`')
            if close < 0:
                return
            args = split_args(code, open_idx, close, quotes='"`')[1:]
            if not args:
                return
            handler = args[0] if echo else args[-1]
            others = ",".join(args[1:] if echo else args[:-1])
            inline = "func(" in handler
            if inline:
                body, wrappers = handler, ""
            else:
                names = re.findall(r"[\w.]+", handler)
                body = functions.get(names[-1].rsplit(".", 1)[-1], "") if names else ""
                wrappers = " ".join(names[:-1])
            prefix = groups.get(receiver, ("", ""))[0]
            for start, end, scope_prefix in scopes:
                if start < offset < end:
                    prefix = _join(prefix, scope_prefix) if scope_prefix or prefix else prefix
            method = pattern.group(1) or ("ANY" if verb in ("Any", "All", "Handle", "HandleFunc") else verb.upper())
            mw = f"{mw_text(receiver, offset)} {extra_mw}"
            routes.append(_assess(
                Route(method, _join(prefix, pattern.group(2)) if prefix else pattern.group(2), rel, line_of(code, offset), "go"),
                GO, body,
                auth=bool(GO_AUTH_NAME.search(f"{others} {wrappers}") or GO_AUTH_BODY.search(body)),
                mw_auth=bool(GO_AUTH_NAME.search(mw)), mw_rate=bool(GO.rate.search(mw)),
            ))

        for match in capped(GO_ROUTE.finditer(code)):
            add(match.group(1), match.group(2), match.group(3), match.start(), code.index("(", match.start() + len(match.group(1)) + 1))
        for match in capped(GO_WITH.finditer(code)):
            open_idx = match.start() + match.group(0).rindex("(")
            add("", match.group(2), match.group(3), match.start(), open_idx, extra_mw=match.group(1))
    return routes


def _in_scope(offset: int, scopes: list[tuple[int, int, str]]) -> bool:
    return any(start < offset < end for start, end, _ in scopes)


# ---------- Rails ----------

RAILS = Patterns(
    db=re.compile(r"\b[A-Z]\w*\.(?:find\w*|where|all|first|last|create!?|new|update\w*|delete\w*|destroy\w*|count|exists\?)\b|"
                  r"@\w+\.(?:save|update|destroy|delete)\b|\bcurrent_user\.\w+"),
    mutation=re.compile(r"\.(?:create|save|update\w*|destroy\w*|delete\w*|insert\w*)\b"),
    owner=re.compile(r"\bcurrent_user\.\w+|\bCurrent\.user\.\w+|\b(?:user|owner|author)(?:_id)?:\s*current_user|\bauthorize!?\b|"
                     r"\bpolicy_scope\b|\bload_and_authorize_resource\b|\bcan\?|\bauthorize_resource\b"),
    validation=re.compile(r"\.permit\(|\b\w+_params\b"),
    reads=re.compile(r"\bparams\b|\b\w+_params\b"),
    rate=re.compile(r"(?m)^\s*rate_limit\s+to:|\bRack::Attack\b"),
)
RAILS_AUTH_FILTER = re.compile(r"(?i)authenticate|require_(?:login|user|auth)|logged_in|signed_in|verify_user|check_auth|ensure_auth")
RAILS_RESOURCE_ACTIONS = {"index": ("GET", ""), "create": ("POST", ""), "show": ("GET", "/:id"), "update": ("PATCH", "/:id"),
                          "destroy": ("DELETE", "/:id")}
RAILS_SINGLE_ACTIONS = {"show": ("GET", ""), "create": ("POST", ""), "update": ("PATCH", ""), "destroy": ("DELETE", "")}
RAILS_VERB = re.compile(r"^(get|post|put|patch|delete)\s+[:'\"]([^'\",\s]*)['\"]?(.*)$")


def _rails_list(text: str, key: str) -> list[str] | None:
    match = re.search(rf"\b{key}:\s*(?:\[([^\]]*)\]|%i\[([^\]]*)\]|:(\w+))", text)
    if not match:
        return None
    return re.findall(r"\w+", match.group(1) or match.group(2) or match.group(3))


def _rails_table(code: str) -> list[tuple[str, str, str, str, bool]]:
    """(method, path, controller path, action, authenticated in routes.rb) for each declared route."""
    table = []
    stack: list[dict] = [{"prefix": "", "module": "", "controller": "", "member": "", "auth": False}]
    for raw in code.splitlines():
        line = raw.split("#", 1)[0].strip() if not re.search(r"['\"][^'\"]*#", raw) else raw.strip()
        if not line:
            continue
        top = stack[-1]
        opens = bool(re.search(r"\bdo\b(?:\s*\|[^|]*\|)?\s*$", line))
        pushed = dict(top)
        if line == "end":
            if len(stack) > 1:
                stack.pop()
            continue
        match = re.match(r"namespace\s+[:'\"](\w+)", line)
        if match:
            pushed.update(prefix=f"{top['prefix']}/{match.group(1)}", module=f"{top['module']}{match.group(1)}/")
        elif re.match(r"scope\b", line):
            path = re.search(r"(?:path:\s*)?['\"]/?([\w/-]+)['\"]", line) or re.search(r"scope\s+:(\w+)", line)
            module = re.search(r"module:\s*[:'\"](\w+)", line)
            if path:
                pushed["prefix"] = f"{top['prefix']}/{path.group(1)}"
            if module:
                pushed["module"] = f"{top['module']}{module.group(1)}/"
        elif re.match(r"(?:authenticate|authenticated)\b", line):
            pushed["auth"] = True
        elif re.match(r"(resources?)\s+[:'\"](\w+)", line):
            match = re.match(r"(resources?)\s+[:'\"](\w+)", line)
            singular, name = match.group(1) == "resource", match.group(2)
            only, exclude = _rails_list(line, "only"), _rails_list(line, "except") or []
            custom = re.search(r"\bcontroller:\s*['\"]([\w/]+)['\"]", line)
            controller = custom.group(1) if custom else (name + "s" if singular else name)
            base = f"{top['prefix']}/{name}"
            for action, (method, suffix) in (RAILS_SINGLE_ACTIONS if singular else RAILS_RESOURCE_ACTIONS).items():
                if (only is None or action in only) and action not in exclude:
                    table.append((method, base + suffix, top["module"] + controller, action, top["auth"]))
            param = "" if singular else f"/:{name.rstrip('s')}_id"
            pushed.update(prefix=base + param, controller=top["module"] + controller, member=base + ("" if singular else "/:id"),
                          collection=base)
        elif line.startswith(("member", "collection")) and opens:
            pushed["prefix"] = top.get("member" if line.startswith("member") else "collection", top["prefix"])
        elif line.startswith("root"):
            target = re.search(r"['\"](\w[\w/]*)#(\w+)['\"]", line)
            if target:
                table.append(("GET", top["prefix"] or "/", top["module"] + target.group(1), target.group(2), top["auth"]))
        else:
            verb = RAILS_VERB.match(line)
            if verb:
                path, rest = verb.group(2), verb.group(3)
                target = re.search(r"['\"](\w[\w/]*)#(\w+)['\"]", rest)
                on = re.search(r"\bon:\s*:(member|collection)", rest)
                base = top.get(on.group(1), top["prefix"]) if on else top["prefix"]
                if target:
                    controller, action = top["module"] + target.group(1), target.group(2)
                elif top.get("controller"):
                    controller, action = top["controller"], path
                elif "/" in path:
                    controller, action = top["module"] + path.rsplit("/", 1)[0], path.rsplit("/", 1)[1]
                else:
                    continue
                table.append((verb.group(1).upper(), f"{base}/{path.lstrip('/')}", controller, action, top["auth"]))
        if opens:
            stack.append(pushed)
    return table


def _ruby_def(code: str, name: str) -> str:
    match = re.search(rf"(?m)^([ \t]*)def\s+{re.escape(name)}\b.*$", code)
    if not match:
        return ""
    end = re.search(rf"(?m)^{match.group(1)}end\b", code[match.end():])
    return code[match.start(): match.end() + (end.start() if end else len(code))]


def _rails_filters(code: str, action: str) -> tuple[list[str], list[str]]:
    """(before_action names that apply to this action, skip_before_action names that apply)."""
    applied, skipped = [], []
    for match in capped(re.finditer(r"(?m)^\s*(skip_)?before_action\s+(.*)$", code)):
        rest = match.group(2)
        only, exclude = _rails_list(rest, "only"), _rails_list(rest, "except")
        if (only is not None and action not in only) or (exclude is not None and action in exclude):
            continue
        names = re.findall(r":(\w+[!?]?)(?=\s*(?:,|$))", rest.split("only:")[0].split("except:")[0])
        (skipped if match.group(1) else applied).extend(names)
    return applied, skipped


def rails_routes(index: FileIndex) -> list[Route]:
    routes_files = [rel for rel in index.sources({".rb"}) if rel.endswith("config/routes.rb")]
    if not routes_files:
        return []
    gems = "\n".join(index.read(rel) or "" for rel in index.iter(names={"Gemfile"}))
    mw_rate = "rack-attack" in gems
    routes = []
    for routes_rel in routes_files:
        root = routes_rel[: -len("config/routes.rb")]
        controllers: dict[str, str] = {}
        by_class: dict[str, str] = {}
        base = f"{root}app/controllers/"
        for rel in index.sources({".rb"}):
            if rel.startswith(base) and rel.endswith("_controller.rb"):
                controllers[rel[len(base): -len("_controller.rb")]] = rel
                match = re.search(r"class\s+([\w:]+)", index.read(rel) or "")
                if match:
                    by_class[match.group(1)] = rel
        for method, path, controller, action, routed_auth in _rails_table(index.read(routes_rel) or ""):
            rel = controllers.get(controller)
            code = index.read(rel) if rel else None
            if not code:
                routes.append(_assess(Route(method, path, routes_rel, 1, "rails"), RAILS, "", auth=routed_auth, mw_rate=mw_rate))
                continue
            chain = [code]
            seen = {rel}
            parent = re.search(r"class\s+[\w:]+\s*<\s*([\w:]+)", code)
            while parent and parent.group(1) in by_class and by_class[parent.group(1)] not in seen:
                seen.add(by_class[parent.group(1)])
                chain.append(index.read(by_class[parent.group(1)]) or "")
                parent = re.search(r"class\s+[\w:]+\s*<\s*([\w:]+)", chain[-1])
            applied, skipped = [], []
            for link in chain:
                a, s = _rails_filters(link, action)
                applied += a
                skipped += s
            active = [name for name in applied if name not in skipped]
            body = _ruby_def(code, action)
            helpers = "\n".join(_ruby_def(link, name.rstrip("!?")) for name in active for link in chain)
            class_level = "\n".join(line for line in code.splitlines() if re.match(r"\s*(?:load_and_authorize_resource|authorize_resource|rate_limit)\b", line))
            text = f"{class_level}\n{body}\n{helpers}"
            line = code[: code.find(body)].count("\n") + 1 if body else 1
            permit_all = "params.permit!" in text
            routes.append(_assess(
                Route(method, path, rel, line, "rails"), RAILS, text,
                auth=routed_auth or any(RAILS_AUTH_FILTER.search(name) for name in active), mw_rate=mw_rate,
                validated=False if permit_all else None,
            ))
    return routes


# ---------- Laravel ----------

LARAVEL = Patterns(
    db=re.compile(r"\b[A-Z]\w*::(?:find\w*|where\w*|all|create|update\w*|destroy|first\w*|query|with|paginate|insert|latest)\b|"
                  r"\bDB::|->(?:save|update|delete|get|first|paginate)\(\)|\b(?!\w*Request\b)[A-Z]\w+\s+\$\w+[,)]"),
    mutation=re.compile(r"::create\(|::destroy\(|::insert\(|::update\(|->save\(|->update\(|->delete\(|DB::(?:insert|update|delete)\b"),
    owner=re.compile(r"\$request->user\(\)->|auth\(\)->user\(\)->|Auth::user\(\)->|auth\(\)->id\(\)|Auth::id\(\)|->authorize\(|Gate::|"
                     r"->can\(|where\(\s*['\"](?:user_id|owner_id|author_id)['\"]|\$this->authorize"),
    validation=re.compile(r"->validate\(|Validator::make\(|->validated\(\)"),
    reads=re.compile(r"\$request->|\brequest\(\)->|\$_POST\b"),
    rate=re.compile(r"\bthrottle\b|RateLimiter::"),
)
LARAVEL_AUTH_MW = re.compile(r"\bauth\b|auth:|sanctum|\bjwt\b|passport|\bcan:|\brole:|\bverified\b|\badmin\b")
LARAVEL_AUTH_BODY = re.compile(r"auth\(\)->(?:user|id|check)\(\)|Auth::(?:user|id|check)\(\)|\$request->user\(\)")
LARAVEL_VERB = re.compile(r"(?:Route::|\)\s*->)(get|post|put|patch|delete|any|apiResource|resource)\(\s*['\"]")
LARAVEL_MW = re.compile(r"middleware\(\s*(\[[^\]]*\]|['\"][^'\"]*['\"])|new\s+Middleware\(\s*['\"]([^'\"]*)['\"]")
LARAVEL_GROUP = re.compile(r"Route::((?:(?!Route::)[^;{}])*?)->group\(\s*function\s*\(\s*\)\s*(?:use\s*\([^)]*\)\s*)?\{|"
                           r"Route::group\(\s*\[([^\]]*(?:\[[^\]]*\][^\]]*)*)\]\s*,\s*function\s*\(\s*\)\s*(?:use\s*\([^)]*\)\s*)?\{")
LARAVEL_RESOURCE_ACTIONS = {"index": ("GET", ""), "store": ("POST", ""), "show": ("GET", "/{id}"), "update": ("PUT", "/{id}"),
                            "destroy": ("DELETE", "/{id}")}


def _laravel_mw(text: str) -> str:
    return " ".join(a or b for a, b in LARAVEL_MW.findall(text))


def _php_method(code: str, name: str) -> tuple[str, int]:
    match = re.search(rf"\bfunction\s+{re.escape(name)}\s*\(", code)
    if not match:
        return "", 0
    brace = code.find("{", match.end())
    end = match_bracket(code, brace, quotes="'\"") if brace > 0 else -1
    return (code[match.start(): end + 1], match.start()) if end > 0 else ("", 0)


def laravel_routes(index: FileIndex) -> list[Route]:
    php = [rel for rel in index.sources({".php"})]
    route_files = [rel for rel in php if re.search(r"(?:^|/)routes/[^/]+\.php$", rel) and not rel.endswith(("console.php", "channels.php"))]
    if not route_files:
        return []
    controllers: dict[str, str] = {}
    for rel in php:
        if "/Controllers/" in rel or rel.startswith("Controllers/"):
            controllers[rel.rsplit("/", 1)[-1][:-4]] = rel
    routes = []
    for rel in route_files:
        code = strip_comments(index.read(rel) or "", quotes="'\"")
        api_prefix = "/api" if rel.endswith("routes/api.php") else ""
        groups = []  # (start, end, prefix, middleware text, controller)
        for match in capped(LARAVEL_GROUP.finditer(code)):
            brace = match.end() - 1
            end = match_bracket(code, brace, quotes="'\"")
            if end < 0:
                continue
            head = match.group(1) or match.group(2) or ""
            prefix = re.search(r"prefix['\"]?\s*(?:=>|\()\s*['\"]([^'\"]*)['\"]", head)
            mw = re.search(r"middleware['\"]?\s*(?:=>|\()\s*(\[[^\]]*\]|['\"][^'\"]*['\"])", head)
            ctrl = re.search(r"controller\(\s*(\w+)::class", head)
            groups.append((brace, end, prefix.group(1) if prefix else "", mw.group(1) if mw else "", ctrl.group(1) if ctrl else ""))
        for match in capped(LARAVEL_VERB.finditer(code)):
            verb = match.group(1)
            open_idx = match.end() - 2
            while code[open_idx] != "(":
                open_idx -= 1
            close = match_bracket(code, open_idx, quotes="'\"")
            if close < 0:
                continue
            args = [a.strip() for a in split_args(code, open_idx, close, quotes="'\"")]
            path = args[0].strip("'\"") if args else ""
            statement_start = code.rfind(";", 0, match.start()) + 1
            before = code[max(statement_start, code.rfind("{", 0, match.start()) + 1): match.start()]
            tail = re.match(r"(?:\s*->\s*\w+\((?:[^()]|\([^()]*\))*\))*", code[close + 1:])
            chain = before + (tail.group(0) if tail else "")
            enclosing = [g for g in groups if g[0] < match.start() < g[1]]
            prefix = _join(api_prefix, *[g[2] for g in enclosing])
            middleware = _laravel_mw(chain + ")") + " ".join(g[3] for g in enclosing)
            group_controller = next((g[4] for g in reversed(enclosing) if g[4]), "")
            handler = args[1] if len(args) > 1 else ""
            if verb in ("resource", "apiResource"):
                ctrl = re.match(r"(\w+)::class", handler)
                only = re.search(r"only\(\s*\[([^\]]*)\]", chain)
                excepted = re.search(r"except\(\s*\[([^\]]*)\]", chain)
                wanted = {a for a in LARAVEL_RESOURCE_ACTIONS}
                if only:
                    wanted &= set(re.findall(r"\w+", only.group(1)))
                if excepted:
                    wanted -= set(re.findall(r"\w+", excepted.group(1)))
                targets = [(LARAVEL_RESOURCE_ACTIONS[a][0], LARAVEL_RESOURCE_ACTIONS[a][1], ctrl.group(1) if ctrl else "", a)
                           for a in LARAVEL_RESOURCE_ACTIONS if a in wanted]
            else:
                method = "ANY" if verb == "any" else verb.upper()
                pair = re.match(r"\[\s*(\w+)::class\s*,\s*['\"](\w+)['\"]\s*\]", handler)
                string = re.match(r"['\"]([\w\\]+)@(\w+)['\"]", handler)
                invokable = re.match(r"(\w+)::class$", handler)
                bare = re.match(r"['\"](\w+)['\"]$", handler)
                if pair:
                    target = (pair.group(1), pair.group(2))
                elif string:
                    target = (string.group(1).rsplit("\\", 1)[-1], string.group(2))
                elif invokable:
                    target = (invokable.group(1), "__invoke")
                elif bare and group_controller:
                    target = (group_controller, bare.group(1))
                else:
                    target = ("", "")
                targets = [(method, "", target[0], target[1])]
            for method, suffix, ctrl_name, action in targets:
                ctrl_rel = controllers.get(ctrl_name)
                ctrl_code = strip_comments(index.read(ctrl_rel) or "", quotes="'\"") if ctrl_rel else ""
                body, offset = _php_method(ctrl_code, action) if ctrl_code else ("", 0)
                if not ctrl_rel:
                    body = handler if "function" in handler or "fn(" in handler or "fn (" in handler else ""
                ctor = _laravel_mw(_php_method(ctrl_code, "__construct")[0] + _php_method(ctrl_code, "middleware")[0]) if ctrl_code else ""
                full = _join(prefix, path) + suffix
                typed_request = re.search(r"\b(\w+Request)\s+\$\w+", body)
                validated = bool(typed_request and typed_request.group(1) != "Request") or bool(LARAVEL.validation.search(body))
                file_, line = (ctrl_rel, line_of(ctrl_code, offset)) if ctrl_rel and body else (rel, line_of(code, match.start()))
                mw_all = f"{middleware} {ctor}"
                routes.append(_assess(
                    Route(method, full, file_, line, "laravel"), LARAVEL, body or handler,
                    auth=bool(LARAVEL_AUTH_MW.search(mw_all) or LARAVEL_AUTH_BODY.search(body)),
                    mw_rate=bool(LARAVEL.rate.search(mw_all)), validated=validated,
                ))
    return routes


# ---------- ASP.NET ----------

ASPNET = Patterns(
    db=re.compile(r"\b_\w*(?:[cC]ontext|[dD]b|[rR]epo(?:sitory)?|[sS]ervice|[sS]tore)\b|\bdb\.\w+|\bcontext\.\w+|\bdbContext\b|\.SaveChanges|"
                  r"\.ToListAsync\(|\.FindAsync\(|\.FirstOrDefault\w*\(|\.QueryAsync|\.ExecuteAsync|\bnew\s+SqlCommand\("),
    mutation=re.compile(r"\.SaveChanges|\.Add(?:Async|Range)?\(|\.Remove(?:Range)?\(|\.Update\(|\.ExecuteAsync\(|\.ExecuteNonQuery|"
                        r"\.(?:Create|Update|Delete|Insert|Remove)\w*(?:Async)?\("),
    owner=re.compile(r"\bUser\.(?:FindFirst\w*|Identity|Claims|GetUserId)|ClaimTypes\.NameIdentifier|\bGetUserId\(|\.UserId\s*==|"
                     r"\.OwnerId\s*==|\bAuthorizeAsync\(|\.GetUserAsync\("),
    validation=re.compile(r"ModelState\.IsValid|\.ValidateAsync\(|\.Validate\("),
    reads=re.compile(r"\[FromBody\]|\[FromForm\]|Request\.Body|Request\.Form|ReadFromJsonAsync"),
    rate=re.compile(r"\[EnableRateLimiting|\.RequireRateLimiting\("),
)
ASP_VERB = re.compile(r"\[(?:\w+,\s*)*Http(Get|Post|Put|Patch|Delete)\s*(?:\(\s*(?:\"([^\"]*)\")?[^)]*\))?[^\]]*\]")
ASP_MAP = re.compile(r"\b(\w+)\.Map(Get|Post|Put|Patch|Delete)\(\s*\"([^\"]*)\"\s*,")
ASP_GROUP = re.compile(r"\b(?:var\s+)?(\w+)\s*=\s*(\w+)\.MapGroup\(\s*\"([^\"]*)\"\s*\)([^;]*);")


def aspnet_routes(index: FileIndex) -> list[Route]:
    files = {rel: strip_comments(index.read(rel) or "", quotes='"') for rel in index.sources({".cs"})}
    everything = "\n".join(files.values())
    fallback_auth = bool(re.search(r"FallbackPolicy\s*=[^;]*RequireAuthenticatedUser|MapControllers\(\)\s*\.\s*RequireAuthorization", everything))
    global_rate = "GlobalLimiter" in everything and "UseRateLimiter" in everything
    routes = []
    for rel, code in files.items():
        for cls in capped(re.finditer(r"\bclass\s+(\w+)\s*(?:\([^)]*\)\s*)?(?::\s*([^{]+))?\{", code)):
            bases = cls.group(2) or ""
            head_start = max(code.rfind("}", 0, cls.start()), code.rfind(";", 0, cls.start()), 0)
            head = code[head_start: cls.start()]
            if not re.search(r"\b(?:Controller|ControllerBase|ApiController)\b", bases) and "[ApiController]" not in head:
                continue
            brace = cls.end() - 1
            end = match_bracket(code, brace, quotes='"')
            body = code[brace: end + 1 if end > 0 else len(code)]
            name = re.sub(r"Controller$", "", cls.group(1))
            route_attr = re.search(r"\[Route\(\s*\"([^\"]*)\"", head)
            prefix = (route_attr.group(1) if route_attr else "").replace("[controller]", name.lower())
            class_auth = bool(re.search(r"\[Authorize\b", head))
            class_public = bool(re.search(r"\[AllowAnonymous\b", head))
            api_controller = "[ApiController]" in head
            previous = 0
            for match in capped(ASP_VERB.finditer(body)):
                sig = re.search(r"\b(\w+)\s*\(", re.sub(r"\[[^\]]*\]", lambda m: " " * len(m.group(0)), body[match.end():]))
                if not sig:
                    continue
                sig_open = match.end() + sig.end() - 1
                sig_close = match_bracket(body, sig_open, quotes='"')
                if sig_close < 0:
                    continue
                arrow = body.find("=>", sig_close)
                open_brace = body.find("{", sig_close)
                if open_brace < 0 or (0 <= arrow < open_brace):
                    stop = body.find(";", sig_close)
                else:
                    stop = match_bracket(body, open_brace, quotes='"')
                if stop < 0:
                    continue
                text = body[previous: stop + 1]
                previous = stop + 1
                action_name = sig.group(1)
                sub = (match.group(2) or "").replace("[action]", action_name.lower())
                path = sub if sub.startswith(("/", "~/")) else _join(prefix, sub)
                public = class_public or "[AllowAnonymous" in text
                typed_body = re.search(r"\[FromBody\]\s*\w+", text)
                routes.append(_assess(
                    Route(match.group(1).upper(), path.lstrip("~"), rel, line_of(code, brace + match.start()), "aspnet"),
                    ASPNET, text, auth=(class_auth or "[Authorize" in text) and not public, mw_auth=fallback_auth,
                    mw_rate=global_rate, public=public,
                    validated=True if api_controller and typed_body else None,
                ))
        groups: dict[str, tuple[str, str]] = {}
        for match in capped(ASP_GROUP.finditer(code)):
            parent = groups.get(match.group(2), ("", ""))
            groups[match.group(1)] = (_join(parent[0], match.group(3)), parent[1] + match.group(4))
        for match in capped(ASP_MAP.finditer(code)):
            open_idx = code.index("(", match.start() + len(match.group(1)) + 1)
            close = match_bracket(code, open_idx, quotes='"')
            if close < 0:
                continue
            args = split_args(code, open_idx, close, quotes='"')
            handler = args[1].strip() if len(args) > 1 else ""
            tail = re.match(r"(?:\s*\.\s*\w+(?:<[^>]*>)?\((?:[^()]|\([^()]*\))*\))*", code[close + 1:])
            chain = tail.group(0) if tail else ""
            group = groups.get(match.group(1), ("", ""))
            if re.fullmatch(r"[\w.]+", handler):
                named = re.search(rf"\b{re.escape(handler.rsplit('.', 1)[-1])}\s*\(", code[close:])
                if named:
                    start = close + named.start()
                    brace = code.find("{", start)
                    stop = match_bracket(code, brace, quotes='"') if brace > 0 else -1
                    handler = code[start: stop + 1] if stop > 0 else ""
                else:
                    handler = ""
            links = chain + group[1]
            public = "AllowAnonymous" in chain
            auth = ("RequireAuthorization" in links or "[Authorize" in handler) and not public
            routes.append(_assess(
                Route(match.group(2).upper(), _join(group[0], match.group(3)), rel, line_of(code, match.start()), "aspnet"),
                ASPNET, f"{chain} {group[1]} {handler}", auth=auth, mw_auth=fallback_auth, mw_rate=global_rate, public=public,
            ))
    return routes


def analyze_backends(index: FileIndex) -> list[Route]:
    return spring_routes(index) + go_routes(index) + rails_routes(index) + laravel_routes(index) + aspnet_routes(index)
