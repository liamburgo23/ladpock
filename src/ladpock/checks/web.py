# ladpock-ignore-file: LP-INJ-006, LP-CRYPTO-002, LP-AUTH-009, LP-INJ-012, LP-CFG-003 (this file defines those patterns)
"""Server-side checks that apply across languages and frameworks: Express,
Fastify, NestJS, Django, Flask, FastAPI, Rails, Laravel, Spring, Go and .NET.

Each pattern names the framework idiom it targets. Where one mistake has a
different spelling in each language (unsafe deserialisation, mass assignment,
switched-off CSRF protection), it's one check with a pattern per language, so
the advice and the grade stay consistent whatever the stack.
"""

from __future__ import annotations

import re
from typing import Iterator

from ..files import CODE_EXT, CONFIG_EXT, JS_EXT, PY_EXT, basename, ext
from ..jsparse import match_bracket, strip_comments
from ..masking import is_placeholder
from ..models import Finding, Severity
from .base import CheckInfo, ScanContext, check, grep, near

TEMPLATE_EXT = frozenset({".html", ".htm", ".ejs", ".hbs", ".handlebars", ".pug", ".jade", ".njk", ".jinja", ".jinja2",
                          ".j2", ".twig", ".erb", ".liquid", ".mustache"})
PHP = frozenset({".php"})
RB = frozenset({".rb", ".erb"})
JVM = frozenset({".java", ".kt", ".scala"})
GO = frozenset({".go"})
CS = frozenset({".cs"})


def _patterns(ctx: ScanContext, info: CheckInfo, table: list[tuple[frozenset[str], re.Pattern[str], dict]],
              unless: re.Pattern[str] | None = None) -> Iterator[Finding]:
    """Run per-language patterns; each table row is (extensions, pattern, finding options)."""
    seen: set[tuple[str, int]] = set()
    for exts, pattern, options in table:
        for rel, lineno, line, _ in grep(ctx, pattern, exts=exts):
            if (rel, lineno) in seen or (unless and unless.search(line)):
                continue
            seen.add((rel, lineno))
            yield ctx.finding(info, rel, lineno, line, **options)


def _project_text_has(ctx: ScanContext, pattern: re.Pattern[str], exts=CODE_EXT | CONFIG_EXT) -> bool:
    for rel in ctx.index.iter(exts, names={"package.json", "requirements.txt", "pyproject.toml", "Gemfile", "composer.json"}):
        if pattern.search(ctx.index.read(rel) or ""):
            return True
    return False


# ---------- injection ----------


@check(
    "LP-INJ-006", "Untrusted data deserialised into objects", "injection", Severity.HIGH,
    why="Formats like pickle, PHP serialize, Java serialization and unsafe YAML can build arbitrary objects. Feeding them "
        "data an attacker controls usually means running the attacker's code on your server.",
    fix="Use a data-only format such as JSON, or the safe loader (yaml.safe_load, YAML.safe_load, json_decode). Never "
        "unpickle or deserialise data from a request, cookie, upload or shared cache.",
    cwe=("CWE-502",),
)
def unsafe_deserialisation(ctx: ScanContext, info: CheckInfo) -> Iterator[Finding]:
    table = [
        (PY_EXT, re.compile(r"\b(?:c?[pP]ickle|dill|cloudpickle)\.loads?\(|\byaml\.load\((?![^)]*(?:SafeLoader|CSafeLoader|BaseLoader))|"
                            r"\byaml\.(?:unsafe_load|full_load)\(|\bmarshal\.loads\(|\bjsonpickle\.decode\(|\bshelve\.open\(|"
                            r"\btorch\.load\([^)]*weights_only\s*=\s*False|\bpandas\.read_pickle\(|\bpd\.read_pickle\("), {}),
        (JS_EXT, re.compile(r"require\(\s*['\"]node-serialize['\"]\)|\bserialize\.unserialize\(|\bfunPack\b|"
                            r"\bjsYaml\.load\([^)]*schema\s*:\s*\w*(?:FULL|DEFAULT_FULL)"), {}),
        (PHP, re.compile(r"\bunserialize\s*\(\s*(?!.*allowed_classes\s*=>\s*false)"), {}),
        (RB, re.compile(r"\bMarshal\.load\(|\bYAML\.unsafe_load\(|\bOj\.load\([^)]*mode:\s*:object"), {}),
        (JVM, re.compile(r"new\s+ObjectInputStream\(|\bXMLDecoder\(|enableDefaultTyping\(|\bnew\s+Yaml\(\s*\)\.load\(|"
                         r"@JsonTypeInfo\(\s*use\s*=\s*JsonTypeInfo\.Id\.CLASS"), {}),
        (CS, re.compile(r"\bBinaryFormatter\b|\bNetDataContractSerializer\b|\bLosFormatter\b|TypeNameHandling\.(?:All|Auto|Objects)|"
                        r"\bSoapFormatter\b"), {}),
    ]
    yield from _patterns(ctx, info, table)


RAW_HTML = [
    (PY_EXT, re.compile(r"\bmark_safe\(|\bMarkup\(\s*(?:f['\"]|[^)'\"]*(?:request|\+|%|format))|"
                        r"Environment\([^)]*autoescape\s*=\s*False|\bSafeString\("), {}),
    (frozenset({".html", ".htm", ".jinja", ".jinja2", ".j2", ".njk", ".twig", ".liquid"}),
     re.compile(r"\|\s*safe\b|\{%-?\s*autoescape\s+(?:off|false)\b|\|\s*raw\b|\{!!"), {"confidence": "low"}),
    (frozenset({".ejs"}), re.compile(r"<%-(?!\s*include\b)"), {}),
    (frozenset({".hbs", ".handlebars", ".mustache"}), re.compile(r"\{\{\{(?!\s*(?:body|>|yield)\s*\}\}\})"), {}),
    (frozenset({".pug", ".jade"}), re.compile(r"!\{|^\s*[\w.#-]*!=\s"), {}),
    (RB, re.compile(r"\.html_safe\b|\braw\(\s*(?:params|@|\w+\.)|<%==\s"), {}),
    (GO, re.compile(r"\btemplate\.(?:HTML|JS|URL)\(\s*(?!\s*\")"), {}),
    (PHP, re.compile(r"\becho\s+\$_(?:GET|POST|REQUEST|COOKIE|SERVER)\b|<\?=\s*\$_(?:GET|POST|REQUEST|COOKIE)\b|"
                     r"\bprint\s+\$_(?:GET|POST|REQUEST)\b|\{!!\s*\$"), {}),
    (JVM, re.compile(r"getWriter\(\)\.(?:print|println|write)\([^)]*getParameter\(|th:utext="), {}),
]


@check(
    "LP-INJ-007", "Data rendered as raw HTML in a server template", "injection", Severity.MEDIUM,
    why="Server templates escape values by default. Marking a value as safe (|safe, mark_safe, <%-, {{{ }}}, html_safe, "
        "{!! !!}) switches that off, so any script inside the data runs in your users' browsers (stored XSS).",
    fix="Render the value normally so it's escaped. If you really need HTML, sanitise it first with an allowlist "
        "sanitiser (bleach/nh3, DOMPurify, sanitize-html, Rails sanitize, HTMLPurifier).",
    cwe=("CWE-79",),
)
def raw_html_in_templates(ctx: ScanContext, info: CheckInfo) -> Iterator[Finding]:
    seen: set[tuple[str, int]] = set()
    for exts, pattern, options in RAW_HTML:
        for rel in ctx.index.iter(exts):
            for i, line in enumerate(ctx.index.lines(rel), 1):
                if len(line) > 2000 or (rel, i) in seen:
                    continue
                if pattern.search(line) and not re.search(r"(?i)sanitiz|bleach|nh3|DOMPurify|purif", line):
                    seen.add((rel, i))
                    yield ctx.finding(info, rel, i, line, **options)


XXE = re.compile(
    r"XMLParser\([^)]*resolve_entities\s*=\s*True|\b(?:etree|ET|ElementTree|minidom)\.(?:fromstring|parseString|parse|XML)\(\s*request\.|"
    r"\bLIBXML_NOENT\b|libxml_disable_entity_loader\(\s*false|DtdProcessing\s*=\s*DtdProcessing\.Parse|=\s*new\s+XmlUrlResolver\(|"
    r"\bnoent\s*:\s*true|\b(?:DocumentBuilderFactory|SAXParserFactory|XMLInputFactory|TransformerFactory|SchemaFactory)\.newInstance\(\)|"
    r"\bnew\s+SAXReader\(\)|\bnew\s+SAXBuilder\("
)
XXE_SAFE = re.compile(r"disallow-doctype-decl|FEATURE_SECURE_PROCESSING|ACCESS_EXTERNAL_(?:DTD|SCHEMA)|SUPPORT_DTD|"
                      r"external-general-entities|setExpandEntityReferences\(\s*false|defusedxml|resolve_entities\s*=\s*False")


@check(
    "LP-INJ-012", "Template built from user input (server-side template injection)", "injection", Severity.HIGH,
    why="Building template source from request data lets an attacker write template code, which in Jinja2, Twig, "
        "ERB, Handlebars and similar engines usually means running their code on your server.",
    fix="Keep templates fixed and pass user data in as variables: render_template('page.html', name=name), not "
        "render_template_string(f'...{name}...').",
    cwe=("CWE-1336", "CWE-94"),
)
def template_injection(ctx: ScanContext, info: CheckInfo) -> Iterator[Finding]:
    table = [
        (PY_EXT, re.compile(r"\brender_template_string\(\s*(?:f['\"]|[^)]*\+|[^)]*%\s|[^)]*\.format\(|request\.)|"
                            r"\b(?:jinja2\.)?Template\(\s*(?:f['\"]|request\.)|\.from_string\(\s*(?:f['\"]|request\.)"), {}),
        (JS_EXT, re.compile(r"\b(?:ejs|pug|nunjucks|Handlebars|handlebars|_)\.(?:render|compile|renderString|template)\(\s*"
                            r"(?:`[^`]*\$\{|(?:req|request)\.(?:body|query|params))"), {}),
        (PHP, re.compile(r"->createTemplate\(\s*\$_(?:GET|POST|REQUEST)|->render\(\s*\$_(?:GET|POST|REQUEST)"), {}),
        (RB, re.compile(r"\bERB\.new\(\s*params|render\s+inline:\s*params"), {}),
    ]
    yield from _patterns(ctx, info, table)


@check(
    "LP-INJ-008", "XML parser accepts external entities", "injection", Severity.MEDIUM,
    why="With external entities on, an uploaded or posted XML file can make your server read local files (/etc/passwd, "
        "secrets) or call internal URLs (XXE).",
    fix="Turn off DTDs and external entities: in Java set disallow-doctype-decl, in Python use defusedxml, in PHP don't "
        "pass LIBXML_NOENT, in .NET keep DtdProcessing.Prohibit and XmlResolver = null.",
    cwe=("CWE-611",),
)
def xml_external_entities(ctx: ScanContext, info: CheckInfo) -> Iterator[Finding]:
    for rel, lineno, line, _ in grep(ctx, XXE):
        if near(ctx.index.lines(rel), lineno, XXE_SAFE, 12) or "defusedxml" in (ctx.index.read(rel) or ""):
            continue
        yield ctx.finding(info, rel, lineno, line)


PATH_SAFE = re.compile(r"basename|secure_filename|safe_join|send_from_directory|path\.normalize|isPathInside|"
                       r"realpath|Path\([^)]*\)\.resolve\(\)\.is_relative_to|\.startsWith\(|filepath\.Clean|getCanonicalPath")


@check(
    "LP-INJ-009", "File path taken from the request", "injection", Severity.HIGH,
    why="Using a filename or path from the request to read, send or delete files lets an attacker escape the folder with "
        "../ and reach your source code, .env file or other users' uploads (path traversal).",
    fix="Never build paths from request input directly. Look the file up by an ID you control, or reduce the input to a "
        "bare file name (path.basename / secure_filename) and check the resolved path is still inside the allowed folder.",
    cwe=("CWE-22",),
)
def path_from_request(ctx: ScanContext, info: CheckInfo) -> Iterator[Finding]:
    table = [
        (JS_EXT, re.compile(r"\b(?:sendFile|download|readFile|readFileSync|createReadStream|createWriteStream|unlink|unlinkSync|"
                            r"writeFile|writeFileSync|rm|rmSync|readdir|readdirSync|appendFile|rename)\s*\([^)]*"
                            r"\b(?:req|request|ctx\.request|ctx)\.(?:params|query|body)\b|"
                            r"\bpath\.(?:join|resolve)\([^)]*\b(?:req|request)\.(?:params|query|body)\b"), {}),
        (PY_EXT, re.compile(r"\bsend_file\(\s*(?:request\.|f['\"][^'\"]*\{request)|\bopen\(\s*(?:request\.|f['\"][^'\"]*\{request)|"
                            r"os\.path\.join\([^)]*request\.(?:args|form|GET|POST|json|data|query_params|path_params)|"
                            r"\bFileResponse\(\s*(?:request\.|f['\"][^'\"]*\{)|os\.(?:remove|unlink)\(\s*request\."), {}),
        (PHP, re.compile(r"\b(?:file_get_contents|fopen|readfile|unlink|file|include|include_once|require|require_once|"
                         r"move_uploaded_file)\s*\(?\s*[^;]*\$_(?:GET|POST|REQUEST|COOKIE)\b"), {}),
        (GO, re.compile(r"http\.ServeFile\([^)]*r\.(?:URL|FormValue)|os\.(?:Open|ReadFile|Remove)\([^)]*r\.(?:URL\.Query|FormValue|PathValue)"), {}),
        (JVM, re.compile(r"new\s+File(?:InputStream)?\([^)]*getParameter\(|Paths\.get\([^)]*getParameter\("), {}),
        (RB, re.compile(r"\b(?:send_file|File\.(?:read|open|delete))\(\s*params\["), {}),
        (CS, re.compile(r"\b(?:File\.(?:ReadAllText|ReadAllBytes|OpenRead|Delete)|PhysicalFile)\([^)]*(?:Request\.|\[FromQuery\])"), {}),
    ]
    yield from _patterns(ctx, info, table, unless=PATH_SAFE)


NOSQL_SANITISED = re.compile(r"express-mongo-sanitize|mongo-sanitize|sanitizeFilter|strictQuery\s*\(\s*true|mongoSanitize")


@check(
    "LP-INJ-010", "Database query built straight from the request (NoSQL injection)", "injection", Severity.HIGH,
    why="MongoDB-style queries treat objects as operators. If a request sends {\"$ne\": null} where you expected a "
        "string, a login or lookup matches every record.",
    fix="Pick out and type-check each field (String(req.body.email), a zod/joi schema), or turn on mongoose's "
        "sanitizeFilter / express-mongo-sanitize. Never pass req.body or req.query as the whole filter.",
    cwe=("CWE-943",),
)
def nosql_injection(ctx: ScanContext, info: CheckInfo) -> Iterator[Finding]:
    whole = re.compile(r"\.(?:find|findOne|findOneAndUpdate|findOneAndDelete|updateOne|updateMany|deleteOne|deleteMany|"
                       r"countDocuments|aggregate|where|exists)\(\s*(?:req|request|ctx\.request)\.(?:body|query|params)\s*[,)]")
    field_ = re.compile(r"\.(?:find|findOne|findOneAndUpdate|findOneAndDelete|updateOne|deleteOne|countDocuments|exists)\(\s*\{"
                        r"[^}]*:\s*(?:req|request)\.(?:body|query)\.\w+\s*[,}]")
    where = re.compile(r"['\"]?\$where['\"]?\s*:")
    sanitised = _project_text_has(ctx, NOSQL_SANITISED)
    for rel, lineno, line, _ in grep(ctx, re.compile(f"{whole.pattern}|{field_.pattern}|{where.pattern}"), exts=JS_EXT | PY_EXT):
        if whole.search(line):
            yield ctx.finding(info, rel, lineno, line, confidence="high" if not sanitised else "medium")
        elif where.search(line):
            yield ctx.finding(info, rel, lineno, line, severity=Severity.MEDIUM,
                              message="$where runs JavaScript inside the database. " + info.why)
        elif not sanitised and "String(" not in line:
            yield ctx.finding(info, rel, lineno, line, severity=Severity.MEDIUM, confidence="low")
    py = re.compile(r"\.(?:find|find_one|update_one|delete_one|delete_many|count_documents)\(\s*request\.(?:json|get_json\(\)|args|form)\s*[,)]")
    for rel, lineno, line, _ in grep(ctx, py, exts=PY_EXT):
        yield ctx.finding(info, rel, lineno, line, confidence="high")


@check(
    "LP-INJ-011", "Object properties set from request data (prototype pollution)", "injection", Severity.MEDIUM,
    why="Deep-merging request JSON into an object, or setting a property named by the request, lets an attacker send "
        "__proto__ and change every object in your server, which can bypass checks or crash it.",
    fix="Copy only the fields you expect, validate with a schema, use Object.create(null) or a Map for dynamic keys, and "
        "avoid deep-merge helpers on request data.",
    cwe=("CWE-1321",),
)
def prototype_pollution(ctx: ScanContext, info: CheckInfo) -> Iterator[Finding]:
    table = [(JS_EXT, re.compile(
        r"\b(?:_|lodash)\.(?:merge|mergeWith|defaultsDeep|set|setWith|zipObjectDeep)\([^)]*\b(?:req|request)\.(?:body|query)\b|"
        r"\b(?:deepmerge|merge|extend|deepExtend)\([^)]*\b(?:req|request)\.(?:body|query)\b|"
        r"\[\s*(?:req|request)\.(?:body|query|params)\.\w+\s*\]\s*=(?!=)"), {})]
    yield from _patterns(ctx, info, table)


# ---------- access control ----------


@check(
    "LP-AUTHZ-004", "Request data saved straight into a database record (mass assignment)", "authz", Severity.MEDIUM,
    why="Saving the whole request body lets a user set fields you never meant them to, like is_admin, role, balance "
        "or another user's ID.",
    fix="Copy only the allowed fields (or validate with a schema that strips unknown keys), use Rails strong parameters "
        "with an explicit permit list, list explicit fields on Django serializers and forms, and set $fillable in Laravel.",
    cwe=("CWE-915",),
)
def mass_assignment(ctx: ScanContext, info: CheckInfo) -> Iterator[Finding]:
    table = [
        (JS_EXT, re.compile(
            r"\.(?:create|insert|insertOne|insertMany|update|updateOne|updateMany|upsert|findByIdAndUpdate|findOneAndUpdate|build)\(\s*"
            r"(?:[^,()]+,\s*)?(?:req|request|ctx\.request)\.body\s*[,)]|\bnew\s+[A-Z]\w*\(\s*(?:req|request)\.body\s*\)|"
            r"\bdata\s*:\s*(?:req\.body|request\.body|ctx\.request\.body)\s*[,}]|"
            r"\bObject\.assign\(\s*(?!\{\s*\})\w+\s*,\s*(?:req|request)\.body\s*\)|\.\.\.(?:req|request)\.body\b"), {}),
        (PY_EXT, re.compile(r"\bfields\s*=\s*['\"]__all__['\"]|\b[A-Z]\w*\(\s*\*\*\s*(?:request\.(?:json|form|data|POST|get_json\(\))|"
                            r"await\s+request\.json\(\))|\.update\(\s*\*\*\s*request\.|\b[A-Z]\w*\(\s*\*\*\s*(?:data|payload|body)\s*\)"), {}),
        (RB, re.compile(r"\bparams\.permit!|\.(?:new|create|update|update_attributes|assign_attributes)\(\s*params\[:\w+\]\s*\)"), {}),
        (PHP, re.compile(r"\$guarded\s*=\s*\[\s*\]|::(?:create|forceCreate)\(\s*\$request->all\(\)\s*\)|"
                         r"->(?:fill|update|forceFill)\(\s*\$request->all\(\)\s*\)"), {}),
    ]
    yield from _patterns(ctx, info, table)


@check(
    "LP-AUTHZ-005", "Security check written as an assert", "authz", Severity.LOW,
    why="Python removes assert statements when run with optimisation (python -O, some production images), so the check "
        "silently disappears.",
    fix="Use an explicit if-statement that raises PermissionDenied / returns 403.",
    cwe=("CWE-617",),
)
def assert_for_security(ctx: ScanContext, info: CheckInfo) -> Iterator[Finding]:
    pattern = re.compile(r"^\s*assert\s+.*\b(?:is_admin|is_staff|is_superuser|is_authenticated|has_perm\w*|role|owner\w*|"
                         r"permission\w*|can_\w+|user\.id|user_id)\b")
    for rel, lineno, line, _ in grep(ctx, pattern, exts=PY_EXT):
        yield ctx.finding(info, rel, lineno, line)


# ---------- auth ----------


@check(
    "LP-AUTH-006", "Passwords stored or compared in plain text", "auth", Severity.HIGH,
    why="Comparing the submitted password directly with the stored one means passwords are stored as written. One "
        "database leak exposes every user's password, which people reuse elsewhere.",
    fix="Store only a password hash (argon2id, bcrypt or scrypt) and check it with the library's verify function "
        "(bcrypt.compare, argon2.verify, check_password). Better still, use your auth provider's sign-in.",
    cwe=("CWE-256", "CWE-312"),
)
def plaintext_password(ctx: ScanContext, info: CheckInfo) -> Iterator[Finding]:
    source = r"(?:req\.body|request\.(?:form|json|POST|data|body)|body|data|input|credentials|params|form|\$_POST|\$request)"
    pattern = re.compile(
        rf"\.password\s*(?:===?|!==?)\s*{source}(?:\.|\[['\"]|->)?\w*|"
        rf"{source}(?:\.|\[['\"]|->)password['\"]?\]?\s*(?:===?|!==?)\s*\$?\w+(?:\.|->)password\b|"
        r"(?i:\bwhere\b[^;\n]*\bpassword\s*=\s*(?:['\"]?\s*(?:\$\{|\$\w|\?|%s|:\w|['\"]\s*[+.])|\?))"
    )
    for rel, lineno, line, _ in grep(ctx, pattern, exts=CODE_EXT):
        if re.search(r"(?i)hash|bcrypt|argon|scrypt|confirm", line):
            continue
        yield ctx.finding(info, rel, lineno, line)


@check(
    "LP-AUTH-007", "Login tokens that never expire", "auth", Severity.LOW,
    why="A token without an expiry works forever. If one leaks (logs, a shared screenshot, a stolen laptop) there's no "
        "way to stop it short of changing the signing secret for everyone.",
    fix="Give access tokens a short lifetime (for example expiresIn: '15m' or an exp claim) and use refresh tokens or "
        "sessions for longer sign-ins.",
    cwe=("CWE-613",),
)
def token_without_expiry(ctx: ScanContext, info: CheckInfo) -> Iterator[Finding]:
    for rel in ctx.index.iter(JS_EXT | PY_EXT):
        text = ctx.index.read(rel) or ""
        if "jwt.sign" not in text and "jwt.encode" not in text and "SignJWT" not in text:
            continue
        code = strip_comments(text) if rel.endswith(tuple(JS_EXT)) else text
        for match in re.finditer(r"\bjwt\.(?:sign|encode)\s*\(|new\s+SignJWT\s*\(", code):
            open_idx = code.find("(", match.start())
            close = match_bracket(code, open_idx)
            if close < 0:
                continue
            call = code[match.start(): close + 1]
            if "SignJWT" in call:
                tail = code[close: close + 400]
                if re.search(r"setExpirationTime", tail):
                    continue
            elif re.search(r"expiresIn|['\"]exp['\"]|\bexp\s*:|expires_delta|timedelta", call):
                continue
            # A payload built elsewhere may carry exp; look a few lines up for it.
            if re.search(r"['\"]exp['\"]\s*[:\]]|\bexp\s*:", code[max(0, match.start() - 600): match.start()]):
                continue
            lineno = code.count("\n", 0, match.start()) + 1
            yield ctx.finding(info, rel, lineno, ctx.index.lines(rel)[lineno - 1], confidence="medium")


@check(
    "LP-AUTH-008", "Password hashing cost set too low", "auth", Severity.LOW,
    why="A low bcrypt cost or few PBKDF2 iterations makes leaked hashes much faster to crack.",
    fix="Use bcrypt cost 10-12 or more, or PBKDF2 with at least 600,000 iterations (SHA-256), or switch to argon2id "
        "with the library defaults.",
    cwe=("CWE-916",),
)
def weak_hash_cost(ctx: ScanContext, info: CheckInfo) -> Iterator[Finding]:
    pattern = re.compile(
        r"\bbcrypt\.(?:hash|hashSync|genSalt|genSaltSync)\(\s*(?:[^,()]+,\s*)?[1-9]\s*\)|\bgenSalt(?:Sync)?\(\s*[1-9]\s*\)|"
        r"\bbcrypt\.gensalt\(\s*(?:rounds\s*=\s*)?[1-9]\s*\)|\bpbkdf2(?:Sync|_hmac)?\([^)]*,\s*(?:\d{1,4}|[1-9]\d{4})\s*[,)]|"
        r"\bPASSWORD_HASHERS\b.*MD5|\bGenerateFromPassword\([^)]*,\s*[1-9]\s*\)"
    )
    for rel, lineno, line, _ in grep(ctx, pattern):
        yield ctx.finding(info, rel, lineno, line)


@check(
    "LP-AUTH-009", "Login errors reveal whether an account exists", "auth", Severity.LOW,
    why="Different messages for 'no such user' and 'wrong password' let attackers check which emails have accounts, "
        "then target them with password guessing or phishing.",
    fix="Return the same message for both cases (for example 'Email or password is incorrect'), with the same status "
        "code and similar timing.",
    cwe=("CWE-204",),
)
def user_enumeration(ctx: ScanContext, info: CheckInfo) -> Iterator[Finding]:
    pattern = re.compile(r"(?i)['\"`](?:user|email|account|username)\s+(?:not found|does not exist|doesn't exist|is not registered|"
                         r"not registered|unknown)\b")
    context = re.compile(r"(?i)login|log_in|signin|sign_in|sign-in|password|authenticate")
    for rel, lineno, line, _ in grep(ctx, pattern):
        if near(ctx.index.lines(rel), lineno, context, 15):
            yield ctx.finding(info, rel, lineno, line)


@check(
    "LP-AUTH-011", "Token decoded but never verified", "auth", Severity.HIGH,
    why="Decoding a JWT only reads it; it doesn't check the signature. Anyone can write a token that says they're an "
        "admin, and this code will believe it.",
    fix="Use the verify function (jwt.verify, jose's jwtVerify, PyJWT's jwt.decode with the key and algorithms) or "
        "your auth provider's helper. Only use decode on the client, for display.",
    cwe=("CWE-345", "CWE-347"),
)
def decoded_not_verified(ctx: ScanContext, info: CheckInfo) -> Iterator[Finding]:
    decode = re.compile(r"\bjwt\.decode\s*\(|\bjwtDecode\s*\(|\bjwt_decode\s*\(|\bdecodeJwt\s*\(")
    for rel in ctx.index.iter(JS_EXT):
        text = ctx.index.read(rel) or ""
        if not decode.search(text) or re.search(r"\bjwt\.verify\b|\bjwtVerify\b|\bverifyToken\b|\bverify\s*\(", text):
            continue
        if not re.search(r"\breq\.|\brequest\.headers|[Aa]uthorization|\bnext\(\)", text):
            continue  # decoding for display in the browser is fine
        for i, line in enumerate(ctx.index.lines(rel), 1):
            if decode.search(line):
                yield ctx.finding(info, rel, i, line)
                break
    for rel, lineno, line, _ in grep(ctx, re.compile(r"\bjwt\.decode\([^)]*verify\s*=\s*False"), exts=PY_EXT):
        yield ctx.finding(info, rel, lineno, line)


# ---------- secrets and crypto ----------

LITERAL = r"['\"]([^'\"]{4,})['\"]"


@check(
    "LP-SEC-007", "Session or app signing key written in the code", "secrets", Severity.HIGH,
    why="Django's SECRET_KEY, Flask's secret_key, Express session secrets and Rails' secret_key_base sign cookies and "
        "sessions. Anyone who reads the code can forge a logged-in session for any user.",
    fix="Read the key from an environment variable or secrets manager, fail at startup if it's missing, and generate a "
        "new one (the old one is now public).",
    cwe=("CWE-798", "CWE-321"),
)
def framework_secret_key(ctx: ScanContext, info: CheckInfo) -> Iterator[Finding]:
    table = [
        (PY_EXT, re.compile(rf"^\s*(?:SECRET_KEY|JWT_SECRET_KEY|SECURITY_PASSWORD_SALT)\s*=\s*{LITERAL}|"
                            rf"\.secret_key\s*=\s*{LITERAL}|config\[['\"](?:SECRET_KEY|JWT_SECRET_KEY)['\"]\]\s*=\s*{LITERAL}|"
                            rf"config\.(?:update|from_mapping)\([^)]*SECRET_KEY\s*=\s*{LITERAL}")),
        (JS_EXT, re.compile(rf"\b(?:session|expressSession|cookieSession|fastifySession|secureSession)\(\s*\{{[^}}]*\bsecret\s*:\s*{LITERAL}|"
                            rf"\bcookieParser\(\s*{LITERAL}|\bkeys\s*:\s*\[\s*{LITERAL}")),
        (RB, re.compile(rf"\bsecret_key_base\s*[:=]\s*{LITERAL}")),
        (PHP, re.compile(rf"['\"]key['\"]\s*=>\s*['\"](base64:[^'\"]{{8,}})['\"]")),
    ]
    multi = re.compile(rf"^\s*secret\s*:\s*{LITERAL}")
    session_call = re.compile(r"\b(?:session|expressSession|cookieSession|fastifySession|secureSession|register)\(")
    for exts, pattern in table:
        for rel, lineno, line, match in grep(ctx, pattern, exts=exts):
            value = next((g for g in match.groups() if g), "")
            if is_placeholder(value) or re.search(r"(?i)environ|getenv|process\.env|ENV\[", line):
                continue
            yield ctx.finding(info, rel, lineno, line, confidence="high")
    for rel, lineno, line, match in grep(ctx, multi, exts=JS_EXT):
        if near(ctx.index.lines(rel), lineno, session_call, 4) and not is_placeholder(match.group(1)):
            yield ctx.finding(info, rel, lineno, line, confidence="high")


@check(
    "LP-CRYPTO-002", "Weak or broken encryption", "crypto", Severity.MEDIUM,
    why="DES, RC4, Blowfish and ECB mode are broken or leak patterns in the data, and Node's createCipher derives keys "
        "badly and uses no IV. Data 'encrypted' this way can often be read or tampered with.",
    fix="Use AES-256-GCM (or ChaCha20-Poly1305) with a random IV per message, through a high-level library where "
        "possible (libsodium, Fernet, Tink, the Web Crypto API).",
    cwe=("CWE-327",),
)
def weak_cipher(ctx: ScanContext, info: CheckInfo) -> Iterator[Finding]:
    pattern = re.compile(
        r"\bcrypto\.createCipher\(|\bcrypto\.createDecipher\(|\bcreateCipher\(|['\"](?:aes-\d+-ecb|des|des-cbc|des-ede3?(?:-cbc)?|rc4|"
        r"bf-cbc|bf-ecb|blowfish)['\"]|\bAES\.MODE_ECB\b|\b(?:DES|DES3|ARC4|Blowfish)\.new\(|\balgorithms\.(?:ARC4|TripleDES|Blowfish)\(|"
        r"\bmodes\.ECB\(|Cipher\.getInstance\(\s*\"(?:DES|DESede|RC4|Blowfish|AES|AES/ECB/\w+)\"|\bCipherMode\.ECB\b|"
        r"\bnew\s+(?:DES|TripleDES|RC2)CryptoServiceProvider\(|\bmcrypt_\w+\(|\bdes\.NewCipher\(|\brc4\.NewCipher\("
    )
    for rel, lineno, line, _ in grep(ctx, pattern):
        yield ctx.finding(info, rel, lineno, line)


# ---------- abuse ----------


@check(
    "LP-ABUSE-003", "Regular expression built from user input", "abuse", Severity.MEDIUM,
    why="A crafted pattern (or a crafted string against a pattern built from input) can make the regex engine run for "
        "minutes, freezing your server for everyone (ReDoS).",
    fix="Escape the input before putting it in a pattern (escape-string-regexp, _.escapeRegExp, re.escape), or search "
        "with plain string matching instead.",
    cwe=("CWE-1333",),
)
def regex_from_input(ctx: ScanContext, info: CheckInfo) -> Iterator[Finding]:
    pattern = re.compile(r"\bnew\s+RegExp\(\s*(?:req\.|request\.|params\.|query\.|body\.|searchParams\.get|ctx\.query|c\.req\.query)|"
                         r"\bre\.(?:compile|search|match|fullmatch|findall|finditer|sub)\(\s*request\.|"
                         r"\b\$regex\s*:\s*(?:req|request)\.")
    for rel, lineno, line, _ in grep(ctx, pattern, exts=JS_EXT | PY_EXT):
        if not re.search(r"(?i)escape", line):
            yield ctx.finding(info, rel, lineno, line)


@check(
    "LP-ABUSE-004", "Request size limit raised very high", "abuse", Severity.LOW,
    why="Accepting very large request bodies lets one client tie up memory and CPU with a few requests.",
    fix="Keep JSON bodies small (the default 100kb-1mb is usually right) and handle big uploads with streaming or "
        "direct-to-storage uploads.",
    cwe=("CWE-770",),
)
def huge_body_limit(ctx: ScanContext, info: CheckInfo) -> Iterator[Finding]:
    pattern = re.compile(r"\b(?:limit|bodyLimit|maxBodySize|sizeLimit)\s*:\s*['\"]?(\d+)\s*(mb|gb)['\"]?|"
                         r"\bbodyLimit\s*:\s*(\d{9,})|DATA_UPLOAD_MAX_MEMORY_SIZE\s*=\s*None|client_max_body_size\s+(\d+)([mg])",
                         re.I)
    for rel, lineno, line, match in grep(ctx, pattern, exts=CODE_EXT | CONFIG_EXT | {".conf"}):
        groups = match.groups()
        size, unit = groups[0], groups[1]
        if groups[3]:
            size, unit = groups[3], groups[4] + "b"
        if size and unit and unit.lower().startswith("m") and int(size) < 20:
            continue
        yield ctx.finding(info, rel, lineno, line)


# ---------- config ----------


@check(
    "LP-CFG-003", "CSRF protection switched off", "config", Severity.MEDIUM,
    why="Cross-site request forgery protection stops other websites from submitting forms as your logged-in users. "
        "With it off, a malicious page can change their email, password or data.",
    fix="Keep CSRF protection on for cookie-authenticated endpoints. Exempt only endpoints that authenticate with a "
        "header token or a verified webhook signature, and keep the exemption as narrow as possible.",
    cwe=("CWE-352",),
)
def csrf_disabled(ctx: ScanContext, info: CheckInfo) -> Iterator[Finding]:
    pattern = re.compile(
        r"@csrf_exempt\b|\bcsrf\(\)\.disable\(\)|\.csrf\(\s*(?:AbstractHttpConfigurer::disable|\w+\s*->\s*\w+\.disable\(\))|"
        r"\bcsrf\s*\{\s*(?:it\.)?disable\(\)|skip_(?:before_)?action\s+:verify_authenticity_token|"
        r"protect_from_forgery\s+with:\s*:null_session|WTF_CSRF_ENABLED['\"]?\]?\s*=\s*False|\bcsrf\.exempt\(|"
        r"\$except\s*=\s*\[\s*['\"]\*['\"]"
    )
    for rel, lineno, line, _ in grep(ctx, pattern, exts=CODE_EXT | CONFIG_EXT):
        yield ctx.finding(info, rel, lineno, line, confidence="low")
    for rel in ctx.index.iter(PY_EXT):
        if basename(rel) != "settings.py" and "/settings/" not in rel:
            continue
        text = ctx.index.read(rel) or ""
        match = re.search(r"^MIDDLEWARE\s*=\s*\[([^\]]*)\]", text, re.M)
        if match and "CsrfViewMiddleware" not in re.sub(r"(?m)^\s*#.*$", "", match.group(1)):
            lineno = text.count("\n", 0, match.start()) + 1
            yield ctx.finding(info, rel, lineno, ctx.index.lines(rel)[lineno - 1],
                              message="Django's CsrfViewMiddleware isn't in MIDDLEWARE, so no view is protected. " + info.why)


@check(
    "LP-CFG-004", "Django accepts any Host header", "config", Severity.MEDIUM,
    why="ALLOWED_HOSTS = ['*'] lets attackers send any Host header, which poisons password-reset links and caches.",
    fix="List your real domains in ALLOWED_HOSTS (read them from an environment variable per deployment).",
    cwe=("CWE-644",),
    stacks=("django",),
)
def django_allowed_hosts(ctx: ScanContext, info: CheckInfo) -> Iterator[Finding]:
    pattern = re.compile(r"^\s*ALLOWED_HOSTS\s*=\s*\[\s*['\"]\*['\"]")
    for rel, lineno, line, _ in grep(ctx, pattern, exts=PY_EXT):
        yield ctx.finding(info, rel, lineno, line, confidence="high")


@check(
    "LP-CFG-005", "Server sends no security headers", "config", Severity.LOW,
    why="Headers like Content-Security-Policy, X-Content-Type-Options, frame protection and HSTS stop whole classes of "
        "attacks (clickjacking, MIME sniffing, downgrade). Express and Fastify send none by default.",
    fix="Add helmet (app.use(helmet())) or @fastify/helmet, and tune its Content-Security-Policy for your app.",
    cwe=("CWE-693",),
    stacks=("express", "fastify"),
)
def missing_security_headers(ctx: ScanContext, info: CheckInfo) -> Iterator[Finding]:
    if _project_text_has(ctx, re.compile(r"\bhelmet\b|@fastify/helmet|fastify-helmet|Content-Security-Policy")):
        return
    pattern = re.compile(r"=\s*express\(\s*\)|=\s*(?:Fastify|fastify)\(\s*(?:\{[^}]*\})?\s*\)|require\(\s*['\"]fastify['\"]\s*\)\(")
    for rel, lineno, line, _ in grep(ctx, pattern, exts=JS_EXT):
        yield ctx.finding(info, rel, lineno, line)
        return


@check(
    "LP-CFG-006", "Client IP taken from headers anyone can set", "config", Severity.LOW,
    why="Trusting X-Forwarded-For from everyone lets a client pretend to be any IP address, which defeats IP-based rate "
        "limits, bans and audit logs.",
    fix="Set trust proxy to the exact number of proxies in front of the app (for example app.set('trust proxy', 1)) "
        "or to your load balancer's addresses, and read the client IP from req.ip.",
    cwe=("CWE-348",),
)
def trusted_forwarded_for(ctx: ScanContext, info: CheckInfo) -> Iterator[Finding]:
    pattern = re.compile(r"\.set\(\s*['\"]trust proxy['\"]\s*,\s*true\s*\)|\btrustProxy\s*:\s*true\b|"
                         r"(?i:headers\[\s*['\"]x-forwarded-for['\"]\s*\]|headers\.get\(\s*['\"]x-forwarded-for['\"])")
    limit = re.compile(r"(?i)rate|limit|throttle|ban|block")
    for rel, lineno, line, _ in grep(ctx, pattern, exts=JS_EXT | PY_EXT):
        if "x-forwarded-for" in line.lower() and not near(ctx.index.lines(rel), lineno, limit, 6):
            continue
        yield ctx.finding(info, rel, lineno, line)


GRAPHQL_SERVER = re.compile(r"new\s+ApolloServer\(|\bcreateYoga\(|\bgraphqlHTTP\(|\bmercurius\b|GraphQLView|\bGraphQLRouter\(|"
                            r"strawberry\.fastapi|graphene_django|\bcreateHandler\(\s*\{\s*schema")
GRAPHQL_LIMIT = re.compile(r"depthLimit|depth_limit|costAnalysis|createComplexityLimitRule|maxDepth|QueryDepthLimiter|"
                           r"MaxDepthPlugin|query_depth|complexity|graphql-armor|max_depth|queryDepth")


@check(
    "LP-API-001", "GraphQL introspection or playground left on", "config", Severity.LOW,
    why="Introspection and the in-browser IDE hand anyone a full map of your API, including fields you didn't mean to "
        "advertise.",
    fix="Turn introspection and the playground off in production (introspection: process.env.NODE_ENV !== 'production').",
    cwe=("CWE-200",),
)
def graphql_introspection(ctx: ScanContext, info: CheckInfo) -> Iterator[Finding]:
    pattern = re.compile(r"\bintrospection\s*:\s*true\b|\bplayground\s*:\s*true\b|\bgraphiql\s*[:=]\s*(?:true|True)\b")
    for rel, lineno, line, _ in grep(ctx, pattern, exts=JS_EXT | PY_EXT):
        yield ctx.finding(info, rel, lineno, line)


@check(
    "LP-API-002", "GraphQL has no query depth or cost limit", "abuse", Severity.LOW,
    why="Without limits, one deeply nested or very wide query can make your server and database do enormous work.",
    fix="Add depth and cost limits (graphql-depth-limit, graphql-armor, Apollo's query planner limits, Strawberry's "
        "QueryDepthLimiter) and a timeout.",
    cwe=("CWE-770",),
)
def graphql_unlimited(ctx: ScanContext, info: CheckInfo) -> Iterator[Finding]:
    if _project_text_has(ctx, GRAPHQL_LIMIT):
        return
    for rel, lineno, line, _ in grep(ctx, GRAPHQL_SERVER, exts=JS_EXT | PY_EXT):
        yield ctx.finding(info, rel, lineno, line, confidence="low")
        return
