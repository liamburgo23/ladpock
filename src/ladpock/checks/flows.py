# ladpock-ignore-file: LP-INJ-001, LP-INJ-002, LP-INJ-003, LP-INJ-004, LP-INJ-005, LP-INJ-009, LP-INJ-012, LP-NATIVE-003 (this file defines these patterns)
"""Following request data through variables, inside one function.

Pattern checks read a line at a time, but generated code usually spreads a bug over three:

    const { id } = req.params;
    const sql = `SELECT * FROM users WHERE id = ${id}`;
    await db.query(sql);

This is a small taint tracker, not a parser. It reads a file statement by statement and keeps a list of
variables holding request data:

- a variable joins the list when it's assigned from a request source, or built from a variable on the list
- it leaves when it's reassigned to something clean, passed through a sanitiser or checked by a guard, or
  when the block it was defined in ends (judged by indentation, which is what generated code reliably has)
- a dangerous call using one of them becomes a finding

It doesn't follow values between functions or files, and it gives up on a value that passes through a
function it doesn't recognise. That misses some bugs in exchange for very few false alarms.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Iterator

from ..files import JS_EXT, ext
from ..jsparse import match_bracket, split_args, strip_comments
from ..models import Finding, Severity
from .base import REGISTRY, CheckInfo, ScanContext, check

LANGUAGE = {**{e: "js" for e in JS_EXT}, ".py": "python", ".php": "php", ".go": "go", ".java": "java", ".kt": "java", ".cs": "csharp", ".rb": "ruby"}
MAX_STATEMENTS = 20_000
MAX_JOINED_LINES = 25
MAX_STATEMENT = 4000
MAX_FLOWS_PER_FILE = 100
MAX_TRACKED = 300  # no real function holds this many request values at once, and each one costs time on every statement

# ---------- where request data comes from ----------

SOURCE = {
    "js": re.compile(
        r"\b(?:req|request)\.(?:body|query|params|headers|cookies)\b|\bctx\.(?:request\.body|request\.query|query|params)\b|"
        r"\bc\.req\.(?:json|query|param|header|parseBody|formData|text)\b|\bsearchParams\.get(?:All)?\(|"
        r"\bawait\s+(?:\w+\.)?(?:req|request)\.(?:json|formData|text)\(\)|\bformData\.get\(|\b(?:getQuery|readBody|getRouterParams?|readFormData)\(|"
        r"\bevent\.(?:body|queryStringParameters|pathParameters)\b|\blocation\.(?:search|hash)\b"),
    "python": re.compile(
        r"\brequest\.(?:args|form|values|json|data|cookies|headers|GET|POST|body|query_params|path_params|get_json|get_data)\b|"
        r"\bawait\s+request\.(?:json|form|body)\(\)|\bevent\[\s*['\"](?:body|queryStringParameters|pathParameters)"),
    "php": re.compile(r"\$_(?:GET|POST|REQUEST|COOKIE)\b|\$_SERVER\[\s*['\"]HTTP_|\$request->(?:input|query|get|post|all|cookie|header|json)\b|\brequest\(\)->\w+|php://input"),
    "go": re.compile(r"\.URL\.Query\(\)|\.(?:Post)?FormValue\(|\.PathValue\(|\bchi\.URLParam\(|\bmux\.Vars\(|\bc\.(?:Param|Params|Query|PostForm|DefaultQuery|FormValue|QueryParam)\(|\.Header\.Get\("),
    "java": re.compile(r"\.getParameter\(|\.getHeader\(|\.getQueryString\(|\.getPathInfo\(|\bcall\.(?:parameters|request\.queryParameters|receiveText|receiveParameters|receive)\b"),
    "csharp": re.compile(r"\bRequest\.(?:Query|Form|Headers|Cookies|RouteValues)\b|\bHttpContext\.Request\."),
    "ruby": re.compile(r"\bparams\[|\bparams\.(?:require|permit|fetch|dig)\b|\brequest\.(?:params|body|query_string|headers)\b|\bcookies\["),
}
# Parameters a framework fills in from the request: @Param('id') id, @RequestParam String name, [FromQuery] string q.
ANNOTATED_PARAM = re.compile(
    r"[@\[](?:Param|Query|Body|Headers?|RequestParam|PathVariable|RequestBody|RequestHeader|PathParam|QueryParam|FormParam|FromQuery|FromBody|FromRoute|FromForm|FromHeader|CookieValue)"
    r"\b(?:\([^)\n]{0,200}\))?\]?\s+(?:final\s+)?(?:([A-Za-z_][\w<>\[\],.?]*)\s+)?([A-Za-z_]\w*)\s*(?::\s*([\w<>\[\]|. ]+))?")
NOT_TEXT_TYPE = re.compile(r"^(?:int|long|short|byte|double|float|bool|boolean|Integer|Long|Short|Double|Float|Boolean|BigDecimal|BigInteger|UUID|Guid|number|bigint|DateTime|Date|LocalDate)\b")
ROUTE_DECORATOR = re.compile(r"^@\w+\.(?:get|post|put|patch|delete|route|api_route)\(")
PY_FUNCTION = re.compile(r"^(?:async\s+)?def\s+\w+\s*\(")
PY_INJECTED = re.compile(r"\b(?:Depends|Security)\s*\(")
PY_NOT_INPUT = {"self", "cls", "request", "response", "db", "session", "background_tasks", "user", "current_user"}
PY_TYPE_NOT_INPUT = re.compile(r"^(?:Request|Response|Session|AsyncSession|BackgroundTasks|WebSocket)\b")
# Extra sources that only mean request data in certain files.
TRPC_INPUT = re.compile(r"\binput\.\w+|\binput\b\s*[,}]")
CONVEX_ARGS = re.compile(r"\bargs\.\w+")
NEXT_PARAMS = re.compile(r"\bparams\b")
ROUTE_FILE = re.compile(r"(?:^|/)(?:route\.[jt]sx?|page\.[jt]sx|\+server\.[jt]s|\+page\.server\.[jt]s)$")
PY_ROUTE_ANYWHERE = re.compile(r"(?m)^[ \t]*@\w+\.(?:get|post|put|patch|delete|route|api_route)\(")

# ---------- what clears a value, and what passes it along ----------

SANITIZED = re.compile(
    r"\b(?:parseInt|parseFloat|Number|BigInt|int|float|bool|Boolean|intval|floatval|basename|secure_filename|safe_join|encodeURI(?:Component)?|escape\w*|sanitize\w*|quote|quote_plus|"
    r"escapeshellarg|escapeshellcmd|mysqli_real_escape_string|htmlspecialchars|htmlentities|createHash|hash\w*|sha\d+|md5|isNaN|len|randomUUID|uuid\d?|UUID)\s*\(|"
    r"\b(?:DOMPurify|bleach|nh3|bcrypt)\.|\btypeof\b|"
    r"\b(?:html|shlex|filepath)\.(?:escape|quote|Base)\b|\.Base\(|\bpath\.basename\b|\bstrconv\.\w+|\b(?:Integer|Long|Double)\.(?:parseInt|parseLong|parseDouble|valueOf)\b|\bint\.(?:Parse|TryParse)\b|\.to_i\b|\.to_f\b|\(int\)|"
    r"\.length\b|\.size\b|\.count\b|!!|===|!==|==|!=|>=|<=|"
    r"\b\w*[Ss]chema\.(?:safe)?[Pp]arse(?:Async)?\b|\bz\.\w+|\.validate\(")
CONDITION = re.compile(r"^(?:if|unless|elif|elsif|else\s+if|assert|require|guard|switch|while|abort_unless|abort_if)\b|^(?:\}\s*else\s+if)\b|^\w+\s+if\b")
GUARD = re.compile(
    r"\b(?:allow\w*|ALLOW\w*|\w*_ALLOW\w*|\w*Allow\w*|white_?list\w*|safe\w*|SAFE\w*|isSafe\w*|is_safe\w*|valid\w*|isValid\w*|is_valid\w*|startsWith|startswith|HasPrefix|start_with\?|"
    r"re\.\w+|regexp?\.\w+|preg_match|isNaN|isUUID|is_numeric|isdigit|isnumeric|hasOwnProperty|url_has_allowed_host\w*|permitted|known\w*|expected\w*|isPathInside|is_relative_to|commonpath)\b|"
    r"\.(?:test|match|includes|has)\(|\bin\s+[A-Z_a-z][\w.]*\s*:|\bnot\s+in\b")
# A call that isn't on this list might return anything (a database row, a user object), so taint stops there.
PASSES_ALONG = re.compile(
    r"(?:^|\.)(?:trim|trimStart|trimEnd|strip|lstrip|rstrip|lower|upper|toLowerCase|toUpperCase|replace|replaceAll|split|join|concat|slice|substring|substr|format|toString|to_s|get|getAll|first|last|at|pop|"
    r"String|str|URL|URLSearchParams|decodeURI|decodeURIComponent|unquote|unquote_plus|atob|from|parse|loads|dumps|stringify|resolve|normalize|dirname|Sprintf|Join|TrimSpace|ToLower|ToUpper|Trim|Clean|"
    r"Path|Paths|File|Combine|Sprint|sprintf|implode|explode|strtolower|strtoupper|trim|urldecode|rawurldecode|base64_decode|json_decode|require|permit|fetch|dig|Query|Vars|URLParam|FormValue|Param|"
    r"getParameter|getHeader|input|post|file_get_contents|Uri|absolute|expanduser|abspath|realpath|fspath|encode|decode|json|text|formData|param|query|header|parseBody|getQuery|readBody|getRouterParams?|"
    r"readFormData|get_json|get_data|getlist|Get|GetString|DefaultQuery|PostForm|PathValue|Header|Params|QueryParam)$|\.fetch$")
LOOKUP = re.compile(r"(?:^|\.)(?:db|prisma|pool|conn|connection|client|cursor|session|store|cache|redis|kv|\w*[Rr]epo(?:sitory)?|\w+Model|axios|requests|httpx|http|https|got|ky|cp|child_process|subprocess)(?:\.|$)")
SQL_WORDS = re.compile(r"(?i)\b(?:SELECT\s.{0,300}?\bFROM|INSERT\s+INTO|UPDATE\s+\S+\s+SET|DELETE\s+FROM|DROP\s+TABLE|WHERE\s+\S+\s*(?:=|LIKE|IN)|ORDER\s+BY)\b", re.S)
MARKUP = re.compile(r"<[a-zA-Z][\w-]*[\s/>]|</[a-zA-Z]")

# ---------- where it becomes dangerous ----------


@dataclass(frozen=True)
class Sink:
    kind: str  # sql | shell | file | ssrf | redirect | eval | html | template
    pattern: re.Pattern[str]
    args: str = "first"  # first | all | rest (what follows the match) | raw (rest, with no check on where the value sits)
    needs_markup: bool = False  # html sinks that only matter if the value is known to hold markup


def _sinks(*rows) -> list[Sink]:
    return [Sink(kind, re.compile(pattern), *options) for kind, pattern, *options in rows]


SINKS = {
    "js": _sinks(
        ("shell", r"(?:(?<![.\w])|\b(?:child_process|cp)\.)(?:exec|execSync)\("),
        ("sql", r"(?:\.(?:query|execute|exec|raw|unsafe|all|get|run|prepare)|\$queryRawUnsafe|\$executeRawUnsafe)\(", "all"),
        ("file", r"(?:\bfs(?:\.promises)?\.\w+|(?<![.\w])(?:readFile|readFileSync|writeFile|writeFileSync|createReadStream|createWriteStream|unlink|unlinkSync|readdir|rm|rmSync)|\bres\.(?:sendFile|download))\("),
        ("ssrf", r"(?:(?<![.\w])fetch|\baxios(?:\.\w+)?|\bgot(?:\.\w+)?|\bsuperagent\.\w+|\bhttps?\.(?:get|request)|(?<![.\w])ky(?:\.\w+)?)\("),
        ("redirect", r"(?:\bres\.redirect|\breply\.redirect|\bctx\.redirect|\bc\.redirect|\bNextResponse\.redirect|\bResponse\.redirect|(?<![.\w])redirect|\blocation\.(?:assign|replace))\(", "all"),
        ("redirect", r"\b(?:window\.)?location(?:\.href)?\s*=(?!=)", "rest"),
        ("eval", r"(?:(?<![.\w])eval|\bnew\s+Function|\bvm\.run\w*)\(", "all"),
        ("html", r"\bres\.(?:send|write|end)\(|\bc\.html\(|\breply\.send\(", "first", True),
        ("html", r"\.(?:innerHTML|outerHTML)\s*\+?=(?!=)", "rest"),
        ("html", r"\bdocument\.write(?:ln)?\(|\.insertAdjacentHTML\(", "all"),
        ("template", r"\b(?:ejs\.render|pug\.render|pug\.compile|nunjucks\.renderString|[Hh]andlebars\.compile|_\.template|lodash\.template)\("),
    ),
    "python": _sinks(
        ("shell", r"\bos\.(?:system|popen)\(|\bsubprocess\.\w+\("),
        ("sql", r"\.(?:execute|executemany|executescript|raw|mogrify)\(|(?<![.\w])text\(", "all"),
        ("file", r"(?<![.\w])open\(|\bsend_file\(|\bos\.(?:remove|unlink|rmdir|listdir)\(|\bshutil\.\w+\(|\bFileResponse\("),
        ("ssrf", r"\brequests\.\w+\(|\bhttpx\.\w+\(|\burlopen\(|\burllib\.request\.\w+\("),
        ("redirect", r"(?<![.\w])redirect\(|\bHttpResponseRedirect\(|\bRedirectResponse\("),
        ("eval", r"(?<![.\w])(?:eval|exec)\("),
        ("html", r"^return\s+", "rest", True),
        ("html", r"\bHttpResponse\(|\bHTMLResponse\(", "first", True),
        ("html", r"\bMarkup\(|\bmark_safe\("),
        ("template", r"\brender_template_string\(|(?<![.\w])Template\(|\.from_string\("),
    ),
    "php": _sinks(
        ("shell", r"(?<![>\w$])(?:shell_exec|exec|system|passthru|popen|proc_open)\("),
        ("sql", r"\b(?:mysqli_query|mysql_query|pg_query)\(|->(?:query|exec|prepare)\(|\bDB::(?:select|statement|unprepared|raw)\(", "all"),
        ("file", r"\b(?:file_get_contents|fopen|readfile|unlink|file_put_contents)\("),
        ("file", r"\b(?:include|require)(?:_once)?\s*\(?", "rest"),
        ("ssrf", r"\bcurl_init\("),
        ("ssrf", r"\bcurl_setopt\([^,\n]+,\s*CURLOPT_URL\s*,", "rest"),
        ("redirect", r"\bheader\(\s*[\"']Location:", "raw"),
        ("redirect", r"(?:(?<![>\w$])|->)redirect\("),
        ("eval", r"\beval\("),
        ("html", r"^(?:echo|print)\b", "rest"),
    ),
    "go": _sinks(
        ("shell", r"\bexec\.Command(?:Context)?\("),
        ("sql", r"\.(?:Query|QueryRow|Exec|QueryContext|QueryRowContext|ExecContext|Raw|Prepare)\(", "all"),
        ("file", r"\bos\.(?:Open|OpenFile|ReadFile|WriteFile|Create|Remove|RemoveAll)\(|\bhttp\.ServeFile\(|\bioutil\.(?:ReadFile|WriteFile)\(", "all"),
        ("ssrf", r"\bhttp\.(?:Get|Post|Head|PostForm|NewRequest(?:WithContext)?)\(", "all"),
        ("redirect", r"\bhttp\.Redirect\(|\bc\.Redirect\(", "all"),
        ("html", r"\bfmt\.Fprint\w*\(|\bio\.WriteString\(", "all", True),
        ("html", r"\btemplate\.HTML\("),
    ),
    "java": _sinks(
        ("shell", r"\.getRuntime\(\)\.exec\(|\bnew\s+ProcessBuilder\("),
        ("sql", r"\.(?:executeQuery|executeUpdate|execute|prepareStatement|prepareCall|createQuery|createNativeQuery|queryForList|queryForObject|queryForMap|update)\(", "all"),
        ("file", r"\bnew\s+File(?:InputStream|OutputStream|Reader|Writer)?\(|(?<![.\w])File\(|\bFiles\.\w+\(|\bPaths\.get\(", "all"),
        ("ssrf", r"\bnew\s+URL\(|\bURI\.create\(|\brestTemplate\.\w+\(|\bwebClient\.\w+\("),
        ("redirect", r"\.sendRedirect\(|\.respondRedirect\("),
        ("html", r"\.getWriter\(\)\.(?:print|println|write)\(", "first", True),
    ),
    "csharp": _sinks(
        ("shell", r"\bProcess\.Start\("),
        ("sql", r"\bnew\s+(?:Sql|Npgsql|MySql|Sqlite)Command\(|\.ExecuteSqlRaw(?:Async)?\(|\.FromSqlRaw\(|\.(?:Query|Execute)(?:Async)?(?:<[^>\n]*>)?\(", "all"),
        ("sql", r"\.CommandText\s*=(?!=)", "rest"),
        ("file", r"\bFile\.\w+\(|\bnew\s+(?:FileStream|StreamReader|StreamWriter)\(|\bPhysicalFile\("),
        ("ssrf", r"\.(?:GetAsync|GetStringAsync|PostAsync|GetStreamAsync)\(|\bnew\s+Uri\(|\bWebRequest\.Create\("),
        ("redirect", r"(?<![.\w])Redirect\(|\bResponse\.Redirect\("),
        ("html", r"\bHtml\.Raw\(|\bnew\s+HtmlString\("),
    ),
    "ruby": _sinks(
        ("shell", r"(?<![.\w])(?:system|exec|spawn)\("),
        ("shell", r"`", "rest"),
        ("sql", r"\.(?:execute|exec_query|find_by_sql|where|select_all|select_one|order)\(", "all"),
        ("file", r"\bFile\.(?:read|open|write|delete|readlines)\(|\bIO\.read\("),
        ("file", r"\bsend_file\b\s*\(?", "rest"),
        ("ssrf", r"\bNet::HTTP\.\w+\(|\bURI\.(?:open|parse)\(|\bHTTParty\.\w+\(|\bFaraday\.\w+\("),
        ("redirect", r"\bredirect_to\b\s*\(?|(?<![.\w])redirect\b\s*\(?", "rest"),
        ("eval", r"(?<![.\w])eval\(|\.(?:instance_eval|class_eval|public_send|send)\("),
        ("html", r"(?<![.\w])raw\("),
    ),
}
# Client code can't reach the server's files or database, and a fetch from a browser isn't a server fetching.
SERVER_ONLY = {"sql", "shell", "file", "ssrf"}
CLIENT_FILE = re.compile(r"""^\s*['"]use client['"]""", re.M)
CLIENT_PATH = re.compile(r"(?:^|/)(?:components?|hooks|pages|views)/|\.(?:vue|svelte|jsx)$")
SHELLS = re.compile(r"""^\s*["'](?:/bin/|/usr/bin/)?(?:sh|bash|zsh|cmd|cmd\.exe|powershell|pwsh)["']\s*$""")
ALREADY_REPORTED_BY = {"sql": ("LP-INJ-003",), "shell": ("LP-INJ-002",), "eval": ("LP-INJ-002",), "file": ("LP-INJ-009",), "ssrf": ("LP-INJ-005",),
                       "redirect": ("LP-INJ-004",), "html": ("LP-INJ-001", "LP-INJ-007"), "template": ("LP-INJ-012",)}

# ---------- reading code ----------

STRING = re.compile(r'''(?:(?<![\w$])(\$?[fFrRbBuU]{1,2}|\$))?("""[\s\S]*?"""|\'\'\'[\s\S]*?\'\'\'|"(?:[^"\\\n]|\\.)*"|'(?:[^'\\\n]|\\.)*'|`(?:[^`\\]|\\.)*`)''')
INTERPOLATION = {
    "js": (re.compile(r"\$\{([^}]*)\}"), "`"),
    "python": (re.compile(r"\{([^{}]*)\}"), "fF"),
    "php": (re.compile(r"(\$\w+)"), '"'),
    "ruby": (re.compile(r"#\{([^}]*)\}"), '"`'),
    "csharp": (re.compile(r"\{([^{}]*)\}"), "$"),
    "java": (re.compile(r"\$\{?(\w+)"), '"'),  # Kotlin's string templates. Java's strings never contain these.
    "go": (None, ""),
}
TOKEN = re.compile(r"(?<![\w.$>:])\$?[A-Za-z_]\w*")
DECLARES = re.compile(r"^(?:export\s+)?(?:const|let|var|val|final)\b")
CALLEE = re.compile(r"([A-Za-z_$][\w$]*(?:(?:\.|->|::)[A-Za-z_$][\w$]*)*)\s*\(")
JS_DECLARE = re.compile(r"^(?:export\s+)?(?:const|let|var)\s+([A-Za-z_$][\w$]*)(?:\s*:\s*[^=]+?)?\s*=(?![=>])\s*([\s\S]+)$")
JS_DESTRUCTURE = re.compile(r"^(?:export\s+)?(?:const|let|var)\s*[{\[]([^=]*?)[}\]]\s*(?::\s*[^=]+?)?\s*=(?![=>])\s*([\s\S]+)$")
PLAIN_ASSIGN = re.compile(r"^([A-Za-z_$][\w$]*)\s*(\+?=)(?![=>~])\s*([\s\S]+)$")
PY_ASSIGN = re.compile(r"^([A-Za-z_]\w*(?:\s*,\s*[A-Za-z_]\w*)*)\s*(?::\s*[^=]+?)?\s*(\+?=)(?!=)\s*([\s\S]+)$")
PHP_ASSIGN = re.compile(r"^\$(\w+)\s*(\.?=)(?![=>])\s*([\s\S]+)$")
GO_ASSIGN = re.compile(r"^(?:var\s+)?((?:[A-Za-z_]\w*\s*,\s*)*[A-Za-z_]\w*)(?:\s+[\w.\[\]*]+)?\s*(:=|\+=|=)(?!=)\s*([\s\S]+)$")
TYPED_ASSIGN = re.compile(r"^(?:(?:final|var|val|const|readonly)\s+)?(?:[A-Za-z_][\w<>\[\],.?]*\s+)?([A-Za-z_]\w*)(?:\s*:\s*[\w<>\[\],.? ]+?)?\s*(\+?=)(?![=>])\s*([\s\S]+)$")


@dataclass
class Tainted:
    name: str
    line: int
    indent: int
    origin: int  # the line the request data came in on
    sql: bool = False
    markup: bool = False
    fixed_start: bool = False  # it starts with text of ours, so it can't choose the host or the redirect target


@dataclass
class Declared:
    """Every variable, tainted or not: a value added inside an if block belongs to the variable outside it."""
    indent: int
    sql: bool = False
    markup: bool = False


@dataclass(frozen=True)
class Flow:
    kind: str
    file: str
    line: int
    snippet: str
    name: str
    built_on: int
    origin: int


def _values(expression: str, language: str) -> str:
    """An expression with the words inside strings removed, keeping what's interpolated into them: only those can carry data."""
    pattern, opens = INTERPOLATION.get(language, (None, ""))

    def keep(match: re.Match[str]) -> str:
        prefix, body = match.group(1) or "", match.group(2)
        if pattern is None:
            return '""'
        interpolated = (body[0] in opens if language in ("js", "php", "ruby", "java") else any(c in prefix for c in opens))
        return " " + " ".join(pattern.findall(body)) + " " if interpolated else '""'

    values = STRING.sub(keep, expression)
    if language in ("python", "ruby"):
        values = re.sub(r"#.*", "", values)
    if language == "python":
        values = re.sub(r"\b\w+\s*=(?!=)", "", values)  # keyword argument names aren't variables
    elif language == "js":
        values = re.sub(r"[{,]\s*[\w$]+\s*:(?!:)", ",", values)  # nor are object keys
    return values


def _used(values: str, tainted: dict[str, Tainted]) -> list[str]:
    if not tainted:
        return []
    return [name for name in (token.lstrip("$") for token in TOKEN.findall(values) if token) if name in tainted]


def _continues(text: str, next_line: str) -> bool:
    """Does this statement carry on onto the next line?"""
    if len(text) > MAX_STATEMENT:
        return False
    if (text.count("`") - text.count("\\`")) % 2 or (text.count('"""') + text.count("'''")) % 2:
        return True
    plain = STRING.sub('""', text).rstrip()
    if plain.endswith("{"):
        return False  # the body of a block: its statements are read one at a time
    if plain.count("(") + plain.count("[") > plain.count(")") + plain.count("]"):
        return True
    if plain.endswith(("+", "\\", "&&", "||")) or (plain.endswith("=") and not plain.endswith(("==", "=>"))) or re.search(r"\s\.$", plain):
        return True
    return next_line.lstrip().startswith(("+ ", ". ", ".", "? ", "|| ", "&& ")) and not next_line.lstrip().startswith("...")


def _statements(code: str, language: str) -> Iterator[tuple[int, int, str]]:
    """(line number, indentation, text) for each statement, with continuation lines joined on."""
    comment = "#" if language in ("python", "ruby") else None
    lines = code.split("\n")
    i, seen = 0, 0
    while i < len(lines) and seen < MAX_STATEMENTS:
        line = lines[i]
        stripped = line.strip()
        if not stripped or (comment and stripped.startswith(comment)):
            i += 1
            continue
        start, text, joined = i, line, 0
        while joined < MAX_JOINED_LINES and i + 1 < len(lines) and _continues(text, lines[i + 1]):
            i += 1
            joined += 1
            text = f"{text}\n{lines[i]}"
        yield start + 1, len(line) - len(line.lstrip()), text.strip()
        i += 1
        seen += 1


def _destructured(names: str) -> list[str]:
    out = []
    for part in names.split(","):
        part = part.strip().lstrip(".")
        if not part:
            continue
        part = part.split(":")[-1].split("=")[0].strip()
        if re.fullmatch(r"[A-Za-z_$][\w$]*", part):
            out.append(part)
    return out


def _assignment(statement: str, language: str) -> tuple[list[str], bool, str] | None:
    """(names assigned, whether it adds to what's there, right-hand side), if this statement is an assignment."""
    code = statement.rstrip().rstrip(";")
    if language == "js":
        match = JS_DESTRUCTURE.match(code)
        if match:
            return _destructured(match.group(1)), False, match.group(2)
        match = JS_DECLARE.match(code)
        if match:
            return [match.group(1)], False, match.group(2)
        match = PLAIN_ASSIGN.match(code)
    elif language == "python":
        match = PY_ASSIGN.match(code)
    elif language == "php":
        match = PHP_ASSIGN.match(code)
    elif language == "go":
        match = GO_ASSIGN.match(code)
    elif language in ("java", "csharp"):
        match = TYPED_ASSIGN.match(code)
    else:
        match = PLAIN_ASSIGN.match(code)
    if not match:
        return None
    names = [n.strip() for n in match.group(1).split(",") if n.strip() not in ("_", "err", "")]
    return names, match.group(2) in ("+=", ".="), match.group(3)


def _controls_start(expression: str, tainted: dict[str, Tainted]) -> bool:
    """Can the request decide how this URL starts? `https://api.example.com/${id}` can't choose the host, and `/login?next=${x}` stays on this site."""
    text = re.sub(r"^(?:await\s+|new\s+URL\(\s*|URL\(\s*|String\(\s*|\s+)+", "", expression)
    quote = re.match(r"""(?:\$|[fF])?(["'`])""", text)
    if not quote:
        first = re.match(r"\$?([A-Za-z_$][\w$]*)", text)
        return bool(first and first.group(1) in tainted and not tainted[first.group(1)].fixed_start)
    body = text[quote.end():]
    rest = re.sub(r"^(?:https?:)?//", "", body)
    inside = re.match(r"(?:\$\{|\{|#\{)\s*\$?([A-Za-z_$][\w$]*)|\$([A-Za-z_]\w*)", rest)
    if inside:
        name = inside.group(1) or inside.group(2)
        return name in tainted and not tainted[name].fixed_start
    # "https://" + host, or "" + url
    joined = re.match(r"""(?:https?://)?["'`]\s*(?:\+|\.)\s*\$?([A-Za-z_$][\w$]*)""", rest)
    return bool(joined and joined.group(1) in tainted and not tainted[joined.group(1)].fixed_start)


def _find_sinks(statement: str, language: str, tainted: dict[str, Tainted]) -> Iterator[tuple[str, Tainted]]:
    done = set()
    for sink in SINKS[language]:
        if sink.kind in done:
            continue
        match = sink.pattern.search(statement)
        if not match:
            continue
        if sink.args in ("rest", "raw"):
            arguments = [statement[match.end():]]
        else:
            open_idx = match.end() - 1
            close = match_bracket(statement, open_idx)
            arguments = split_args(statement, open_idx, close if close != -1 else len(statement))
            all_arguments = arguments
            if sink.kind == "shell" and language == "python" and arguments and arguments[0].lstrip().startswith(("[", "(")) and not re.search(r"\bshell\s*=\s*True\b", statement):
                continue  # a list of arguments, run with no shell, is the safe way to do this
            if language == "go" and sink.kind == "shell" and arguments and SHELLS.match(arguments[0]):
                pass  # exec.Command("sh", "-c", cmd). exec.Command("git", "clone", url) only passes url as one argument
            elif sink.args == "first":
                arguments = arguments[:1]
        markup_in_call = any(MARKUP.search(a) for a in (all_arguments if sink.args not in ("rest", "raw") else arguments))
        for argument in arguments:
            values = _values(argument, language)
            if SANITIZED.search(values):
                continue
            used = _used(values, tainted)
            if not used:
                continue
            var = tainted[used[0]]
            if sink.kind == "sql" and not (any(tainted[n].sql for n in used) or SQL_WORDS.search(argument)):
                continue
            if sink.kind in ("ssrf", "redirect") and sink.args != "raw" and not _controls_start(argument, tainted):
                continue
            if sink.needs_markup and not (any(tainted[n].markup for n in used) or markup_in_call):
                continue
            if sink.needs_markup and re.match(r"\s*(?:[{\[]|jsonify\b|json\b|render\w*\b|redirect\b)", argument):
                continue
            done.add(sink.kind)
            yield sink.kind, next((tainted[n] for n in used if tainted[n].sql), var) if sink.kind == "sql" else var
            break


def _python_route_params(signature: str) -> list[str]:
    """A FastAPI or Flask view's parameters, apart from what the framework injects. Numbers and the like can't carry an attack."""
    open_idx = signature.find("(")
    close = match_bracket(signature, open_idx)
    names = []
    for parameter in split_args(signature, open_idx, close if close != -1 else len(signature)):
        if PY_INJECTED.search(parameter):
            continue
        head = parameter.split("=")[0]
        name, _, kind = head.partition(":")
        name, kind = name.strip().lstrip("*"), kind.strip()
        if not name or name in PY_NOT_INPUT or NOT_TEXT_TYPE.match(kind) or PY_TYPE_NOT_INPUT.match(kind):
            continue
        names.append(name)
    return names


def _file_flows(rel: str, text: str, language: str) -> list[Flow]:
    code = strip_comments(text) if language not in ("python", "ruby") else text
    source = SOURCE[language]
    extras = []
    if language == "js":
        if "rocedure" in text:
            extras.append(TRPC_INPUT)
        if re.search(r"(?:^|/)convex/", rel):
            extras.append(CONVEX_ARGS)
        if ROUTE_FILE.search(rel):
            extras.append(NEXT_PARAMS)
    client = language == "js" and bool(CLIENT_FILE.search(text[:500]) or CLIENT_PATH.search(rel))
    tainted: dict[str, Tainted] = {}
    declared: dict[str, Declared] = {}
    flows: list[Flow] = []
    after_route_decorator = False

    def from_request(values: str) -> bool:
        return bool(source.search(values) or any(extra.search(values) for extra in extras))

    for line, indent, statement in _statements(code, language):
        for name in [n for n, var in tainted.items() if indent < var.indent]:
            del tainted[name]  # the block it was defined in has ended
        for name in [n for n, var in declared.items() if indent < var.indent]:
            del declared[name]

        if language == "python":
            if ROUTE_DECORATOR.match(statement):
                after_route_decorator = True
            elif PY_FUNCTION.match(statement):
                if after_route_decorator:
                    for name in _python_route_params(statement):
                        tainted[name] = Tainted(name, line, indent + 1, line)
                after_route_decorator = False
            elif not statement.startswith("@"):
                after_route_decorator = False
        for match in ANNOTATED_PARAM.finditer(statement):
            kind = match.group(3) or match.group(1) or ""
            if not NOT_TEXT_TYPE.match(kind.strip()):
                tainted[match.group(2)] = Tainted(match.group(2), line, indent + 1, line)

        plain = _values(statement, language)
        if tainted and CONDITION.match(statement) and GUARD.search(statement):
            for name in _used(plain, tainted):
                tainted.pop(name, None)

        if tainted:
            for kind, var in _find_sinks(statement, language, tainted):
                if client and kind in SERVER_ONLY:
                    continue
                flows.append(Flow(kind, rel, line, statement.split("\n")[0], var.name, var.line, var.origin))
                if len(flows) >= MAX_FLOWS_PER_FILE:
                    return flows

        assigned = _assignment(statement, language)
        if not assigned:
            continue
        names, adds, right = assigned
        values = _values(right, language)
        has_sql, has_markup = bool(SQL_WORDS.search(right)), bool(MARKUP.search(right))
        declares = bool(DECLARES.match(statement)) or (language == "go" and ":=" in statement.split("\n")[0])
        if len(declared) > 10 * MAX_TRACKED:
            declared.clear()
        for name in names:
            known = declared.get(name)
            if known is None or declares:
                declared[name] = Declared(indent, has_sql, has_markup)
            elif adds:
                known.sql, known.markup = known.sql or has_sql, known.markup or has_markup
            else:
                known.sql, known.markup = has_sql, has_markup
        direct = from_request(values) or (from_request(right) and not re.match(r"""\s*["'`]""", right))
        used = _used(values, tainted)
        clean = bool(SANITIZED.search(values))
        calls = [callee.replace("->", ".").replace("::", ".") for callee in CALLEE.findall(values)]
        unknown_call = any(LOOKUP.search(callee) or not PASSES_ALONG.search(callee) for callee in calls)
        if clean or unknown_call or not (direct or used):
            if not adds:
                for name in names:
                    tainted.pop(name, None)
            continue
        origin = min((tainted[n].origin for n in used), default=line)
        is_sql = has_sql or any(tainted[n].sql for n in used)
        is_markup = has_markup or any(tainted[n].markup for n in used)
        keep_fixed = not _controls_start(right, tainted) if used and not direct else bool(re.match(r"""\s*(?:\$|[fF])?["'`](?:https?://[^/\s"'`$\{]+/|/(?!/)[^"'`$\{])""", right))
        for name in names:
            if len(tainted) >= MAX_TRACKED and name not in tainted:
                break
            previous = tainted.get(name) if adds else None
            scope = declared[name]
            tainted[name] = Tainted(name, line, scope.indent, previous.origin if previous else origin,
                                    sql=is_sql or scope.sql, markup=is_markup or scope.markup,
                                    fixed_start=previous.fixed_start if previous else (keep_fixed and not adds))
    return flows


def _analyze(ctx: ScanContext) -> dict[str, list[Flow]]:
    cached = getattr(ctx, "_flows", None)
    if cached is not None:
        return cached
    found: dict[str, list[Flow]] = {}
    for rel in ctx.index.sources(frozenset(LANGUAGE)):
        language = LANGUAGE[ext(rel)]
        text = ctx.index.read(rel) or ""
        source = SOURCE[language]
        if not (source.search(text) or ANNOTATED_PARAM.search(text)
                or (language == "python" and PY_ROUTE_ANYWHERE.search(text))
                or (language == "js" and ("rocedure" in text or "convex/" in rel or ROUTE_FILE.search(rel)))):
            continue  # nothing here reads a request, so nothing here can carry one
        for flow in _file_flows(rel, text, language):
            found.setdefault(flow.kind, []).append(flow)
    # A line another check already reports needs saying once.
    for kind, flows in list(found.items()):
        reported: set[tuple[str | None, int | None]] = set()
        for check_id in ALREADY_REPORTED_BY.get(kind, ()):
            info, fn = REGISTRY[check_id]
            try:
                reported.update((f.file, f.line) for f in fn(ctx, info))
            except Exception:  # noqa: BLE001  (losing the comparison only means saying something twice)
                continue
        found[kind] = [f for f in flows if (f.file, f.line) not in reported]
    ctx._flows = found  # type: ignore[attr-defined]
    return found


def _trace(flow: Flow) -> str:
    if flow.built_on != flow.origin:
        return f"{flow.name} (line {flow.built_on}) is built from request data that comes in on line {flow.origin}, and it reaches this call."
    return f"{flow.name} comes from the request on line {flow.origin}, and it reaches this call."


def _register(check_id: str, kind: str, title: str, severity: Severity, why: str, fix: str, cwe: tuple[str, ...]) -> None:
    @check(check_id, title, "injection", severity, why=why, fix=fix, cwe=cwe)
    def run(ctx: ScanContext, info: CheckInfo) -> Iterator[Finding]:
        for flow in _analyze(ctx).get(kind, ()):
            yield ctx.finding(info, flow.file, flow.line, flow.snippet, message=f"{_trace(flow)} {info.why}")


_register(
    "LP-FLOW-001", "sql", "Request data reaches a SQL query", Severity.HIGH,
    "This value is written into the SQL itself, so whoever sends the request can change what the query does: read other people's data, or destroy it.",
    "Pass values separately from the SQL, using placeholders: db.query('SELECT * FROM users WHERE id = $1', [id]), or your ORM's normal query functions.",
    ("CWE-89",),
)
_register(
    "LP-FLOW-002", "shell", "Request data reaches a shell command", Severity.HIGH,
    "A value like ; rm -rf ~ becomes commands of its own, so whoever sends the request can run anything on your server.",
    "Run the program directly with a list of arguments (execFile, subprocess.run([...])) with no shell, and check the value against what you expect.",
    ("CWE-78",),
)
_register(
    "LP-FLOW-003", "file", "Request data chooses a file path", Severity.HIGH,
    "A value like ../../.env walks out of the folder you meant, so whoever sends the request can read or overwrite other files on your server.",
    "Use only the bare file name (path.basename, secure_filename), then check the resolved path is still inside the folder you meant.",
    ("CWE-22",),
)
_register(
    "LP-FLOW-004", "ssrf", "Request data chooses where your server connects", Severity.HIGH,
    "Your server makes this request from inside your network, so someone can point it at internal services or cloud credential addresses and read the answer (SSRF).",
    "Check the host against a short list of allowed hosts, and refuse private and link-local addresses.",
    ("CWE-918",),
)
_register(
    "LP-FLOW-005", "redirect", "Request data chooses where the browser is sent", Severity.MEDIUM,
    "A link on your real domain can send people to a fake sign-in page, and sometimes hand it their login tokens (open redirect).",
    "Only redirect to paths on your own site: check it starts with a single / and isn't followed by another / or a backslash, or use a list of allowed addresses.",
    ("CWE-601",),
)
_register(
    "LP-FLOW-006", "eval", "Request data runs as code", Severity.CRITICAL,
    "Whatever is in this value runs as code on your server, so whoever sends the request can do anything your app can.",
    "Don't run code from a request. Parse the data with JSON.parse or json.loads, or use a list of actions you define.",
    ("CWE-94", "CWE-95"),
)
_register(
    "LP-FLOW-007", "html", "Request data put into a page as HTML", Severity.MEDIUM,
    "A value holding a script tag runs in the browser of whoever opens the page, and can act as them (cross-site scripting).",
    "Escape it before it goes into HTML, or use a template engine that does this by default, and don't turn that off.",
    ("CWE-79",),
)
_register(
    "LP-FLOW-008", "template", "Request data used as a template", Severity.HIGH,
    "A template can run code, so someone can send one that reads your secrets or runs commands on your server (server-side template injection).",
    "Keep templates in fixed files, and pass request data to them as values.",
    ("CWE-1336", "CWE-94"),
)
