"""Checks for how apps get built now: AI features, file uploads, secrets in logs,
trusting what the browser says, and what's left behind after building fast.

Each of these is a mistake a senior reviewer would spot in generated code, and
none of them is about one framework, so each has a pattern per language.
"""

from __future__ import annotations

import re
from typing import Iterator

from ..files import CODE_EXT, JS_EXT, PY_EXT, basename
from ..jsparse import line_of, match_bracket, strip_comments
from ..models import Finding, Severity
from .base import CheckInfo, ScanContext, check, grep, near, regex_check

PHP = frozenset({".php"})
RB = frozenset({".rb"})
JVM = frozenset({".java", ".kt", ".scala"})
GO = frozenset({".go"})
CS = frozenset({".cs"})
REQUEST_JS = r"(?:req\.body|req\.query|req\.params|body|input|args|payload|request\.body|ctx\.request\.body|c\.req\.json\(\))"
REQUEST_PY = r"(?:request\.(?:json|form|data|args|values|POST|GET)|data|body|payload|params)"

AI_FILE = re.compile(
    r"(?i)['\"]openai['\"]|@anthropic-ai|\bnew\s+(?:OpenAI|Anthropic)\b|@ai-sdk/|['\"]ai['\"]|\bgenerateText\(|\bstreamText\(|\buseChat\(|"
    r"chat\.completions|messages\.create|@google/gen(?:erative-)?ai|groq|langchain|llama_?index|ollama|\bllm\b|\bimport\s+(?:openai|anthropic)\b"
)
AI_OUTPUT = r"\w*(?:completion|response|reply|answer|output|result|generated|message|content|text|llm|ai_?\w*)\w*(?:\.\w+|\[[^\]]*\])*"


def _ai_files(ctx: ScanContext, exts=CODE_EXT) -> Iterator[str]:
    for rel in ctx.index.iter(exts):
        if AI_FILE.search(ctx.index.read(rel) or ""):
            yield rel


# ---------- AI features ----------

regex_check(
    "LP-AI-001", "AI API key used from the browser", "secrets", Severity.HIGH,
    why="This turns off the AI SDK's own safety check and calls the API from the page. Your key ships to every visitor, who "
        "can copy it and spend your money.",
    fix="Call the AI API from your server and let the page talk to your server. Only keep this if each user supplies their "
        "own key.",
    pattern=r"\bdangerouslyAllowBrowser\s*:\s*true\b",
    exts=JS_EXT, cwe=("CWE-522", "CWE-200"), confidence="high",
)

_AI_RUNS = [
    (JS_EXT, re.compile(rf"(?:(?<![.\w])|\b(?:child_process|cp)\.)(?:eval|new\s+Function|execSync|exec|spawn|spawnSync)\s*\(\s*{AI_OUTPUT}\s*[,)]")),
    (JS_EXT, re.compile(rf"(?:\$queryRawUnsafe|\$executeRawUnsafe|\bsql\.unsafe|\bsql\.raw|\.raw)\s*\(\s*{AI_OUTPUT}\s*[,)]")),
    (PY_EXT, re.compile(rf"(?:(?<![.\w])(?:eval|exec)|\b(?:os\.system|os\.popen|subprocess\.\w+))\s*\(\s*\[?\s*{AI_OUTPUT}\s*[,)\]]")),
    (PY_EXT, re.compile(rf"\b(?:cursor|cur|conn|connection|db|session|engine)\.(?:execute|executescript)\s*\(\s*(?:text\(\s*)?{AI_OUTPUT}\s*[,)]")),
]


@check(
    "LP-AI-002", "AI reply run as code or as a database query", "injection", Severity.HIGH,
    why="Anything a model reads can steer what it writes, including text a user or a web page puts in front of it. Running "
        "that reply means whoever writes that text can run code or queries on your server.",
    fix="Have the model pick from actions you define, with parameters you validate. If it must write queries or code, run "
        "them in a sandbox with a read-only, least-privilege account, and show them to a person first.",
    cwe=("CWE-94", "CWE-77", "CWE-89"),
)
def ai_output_executed(ctx: ScanContext, info: CheckInfo) -> Iterator[Finding]:
    ai = set(_ai_files(ctx))
    for exts, pattern in _AI_RUNS:
        for rel, lineno, line, _ in grep(ctx, pattern, exts=exts):
            if rel in ai:
                yield ctx.finding(info, rel, lineno, line)


_AI_COST_FROM_REQUEST = [
    (JS_EXT, re.compile(rf"\b(?:model|max_?[tT]okens|maxOutputTokens)\s*:\s*{REQUEST_JS}\??\.\w+")),
    (JS_EXT, re.compile(r"(?:const|let|var)\s*\{[^}]*\b(?:model|max_?[tT]okens)\b[^}]*\}\s*=\s*(?:await\s+\w+\.json\(\)|(?:req\.body|body)\b)")),
    # A keyword argument going into a call. "model = body.get(...)" on its own may just be a setting being saved and checked.
    (PY_EXT, re.compile(rf"(?:[(,]\s*|^\s*)(?:model|max_tokens)=(?!=)\s*{REQUEST_PY}(?:\[|\.get\(|\.\w)")),
]


@check(
    "LP-AI-003", "The caller chooses the AI model or token limit", "abuse", Severity.MEDIUM,
    why="If the request decides which model runs and how much it can write, anyone can ask for your most expensive model at "
        "the highest limit, and you pay for it.",
    fix="Set the model and the token limit on the server. If users may choose, check their choice against a short list.",
    cwe=("CWE-770",),
)
def ai_cost_from_request(ctx: ScanContext, info: CheckInfo) -> Iterator[Finding]:
    ai = set(_ai_files(ctx))
    for exts, pattern in _AI_COST_FROM_REQUEST:
        for rel, lineno, line, _ in grep(ctx, pattern, exts=exts):
            if rel in ai:
                yield ctx.finding(info, rel, lineno, line)


_USER_VALUE = r"[^}]*\b(?:req|request|body|input|args|query|params|user|prompt|message|messages|userInput|user_input)\b"
_SYSTEM_PROMPT = [
    re.compile(rf"""role\s*:\s*['"]system['"]\s*,\s*content\s*:\s*`[^`]*\$\{{{_USER_VALUE}"""),
    re.compile(rf"""\bsystem(?:Prompt|Instruction)?\s*:\s*`[^`]*\$\{{{_USER_VALUE}"""),
    re.compile(rf"""['"]role['"]\s*:\s*['"]system['"]\s*,\s*['"]content['"]\s*:\s*f['"][^'"]*\{{{_USER_VALUE}"""),
    re.compile(rf"""\bsystem(?:_prompt|_instruction)?\s*=\s*f['"][^'"]*\{{{_USER_VALUE}"""),
]


@check(
    "LP-AI-004", "User input written into the AI's system prompt", "injection", Severity.MEDIUM,
    why="The system prompt is what the model trusts most. Text from a user placed there can overrule your instructions "
        "(prompt injection), for example to reveal private data or misuse the model's tools.",
    fix="Keep the system prompt fixed and pass user text as a separate user message. Don't give the model tools or data the "
        "user couldn't reach anyway, because prompt injection can't be fully prevented.",
    cwe=("CWE-1427", "CWE-77"),
)
def ai_system_prompt_injection(ctx: ScanContext, info: CheckInfo) -> Iterator[Finding]:
    for rel in _ai_files(ctx, JS_EXT | PY_EXT):
        code = ctx.index.read(rel) or ""
        for pattern in _SYSTEM_PROMPT:
            for match in pattern.finditer(code):
                yield ctx.finding(info, rel, line_of(code, match.start()), match.group(0))


regex_check(
    "LP-AI-005", "AI agent can run code or shell commands", "injection", Severity.HIGH,
    why="An agent with a shell or Python tool runs whatever the model decides, and what the model decides can be steered by any "
        "text it reads. Someone who gets text in front of it can run commands on your server.",
    fix="Give the agent narrow tools that do one safe thing each. If it really needs to run code, use a sandbox with no "
        "network and no secrets, and ask a person before anything risky.",
    pattern=r"\ballow_dangerous_(?:code|requests)\s*=\s*True\b|\b(?:ShellTool|PythonREPLTool|PythonAstREPLTool|BashProcess|PALChain)\b\s*[.(]|"
            r"\bcreate_(?:pandas_dataframe|csv|python|spark_dataframe)_agent\s*\(|\bnew\s+(?:Shell|Bash)Tool\s*\(",
    exts=PY_EXT | JS_EXT, cwe=("CWE-94", "CWE-78"),
)

# ---------- file uploads ----------

_UPLOAD_NAME = [
    (JS_EXT, re.compile(r"(?:path\.(?:join|resolve)|writeFile\w*|createWriteStream|\bcb\s*\(\s*null|\bcallback\s*\(\s*null)[^;\n]*\boriginal[nN]ame\b")),
    (PY_EXT, re.compile(r"(?:os\.path\.join|\bopen\s*\(|\.save\s*\(|Path\s*\()[^\n]*\b\w*(?:file|upload|image|attachment|photo|\bf)\w*\.filename\b")),
    (PHP, re.compile(r"move_uploaded_file\s*\([^\n]*\$_FILES\s*\[[^\]]+\]\s*\[\s*['\"]name['\"]")),
    (GO, re.compile(r"(?:filepath|path)\.Join\([^\n]*\.Filename\b|os\.Create\([^\n]*\.Filename\b")),
    (CS, re.compile(r"Path\.Combine\([^\n]*\.FileName\b")),
    (JVM, re.compile(r"(?:new\s+File|Paths\.get|Path\.of)\s*\([^\n]*getOriginalFilename\(\)")),
    (RB, re.compile(r"File\.(?:join|open|write)\([^\n]*\.original_filename\b")),
]
_UPLOAD_SAFE = re.compile(r"\bbasename\b|secure_filename|sanitize|safe_?name|randomUUID|uuid|nanoid|GetFileName\(|\.Base\(")


@check(
    "LP-UPLOAD-001", "Uploaded file saved under the name the user chose", "injection", Severity.HIGH,
    why="A file name like ../../app.js writes outside your uploads folder, and a name like shell.php or page.html can end up "
        "being run or served as if it were yours.",
    fix="Generate your own file name (a random ID), keep the original only as data in your database, and check the type from "
        "the file's contents rather than its name.",
    cwe=("CWE-22", "CWE-434"),
)
def upload_user_filename(ctx: ScanContext, info: CheckInfo) -> Iterator[Finding]:
    for exts, pattern in _UPLOAD_NAME:
        for rel, lineno, line, _ in grep(ctx, pattern, exts=exts):
            if not _UPLOAD_SAFE.search(line):
                yield ctx.finding(info, rel, lineno, line)


_MULTER = re.compile(r"\b(multer|fileUpload|formidable)\s*\(")


@check(
    "LP-UPLOAD-002", "File upload accepts any size or type", "abuse", Severity.MEDIUM,
    why="With no size limit, one request can fill your disk or memory. With no type check, people can upload pages or "
        "scripts that your site then serves to others.",
    fix="Set limits (for example multer({ limits: { fileSize: 5 * 1024 * 1024 } })) and a fileFilter that allows only the types "
        "you need. Store uploads outside the web root, or in object storage on a separate domain.",
    cwe=("CWE-400", "CWE-434"),
)
def upload_without_limits(ctx: ScanContext, info: CheckInfo) -> Iterator[Finding]:
    for rel in ctx.index.iter(JS_EXT):
        raw = ctx.index.read(rel) or ""
        if not ("multer" in raw or "fileUpload" in raw or "formidable" in raw):
            continue
        code = strip_comments(raw)
        for match in _MULTER.finditer(code):
            close = match_bracket(code, match.end() - 1)
            if close == -1:
                continue
            options = code[match.end(): close]
            if re.fullmatch(r"\s*\w+\s*", options):
                continue  # options defined elsewhere, so there's nothing to judge
            limited = bool(re.search(r"\blimits\b|\bmaxFileSize\b", options))
            if not limited:
                yield ctx.finding(info, rel, line_of(code, match.start()), match.group(0) + options[:60])
            elif match.group(1) == "multer" and "fileFilter" not in options:
                yield ctx.finding(info, rel, line_of(code, match.start()), match.group(0) + options[:60], severity=Severity.LOW,
                                  message="This upload has a size limit but no check on the file's type, so people can "
                                          "upload pages or scripts that your site may then serve to others.")


regex_check(
    "LP-UPLOAD-003", "Uploads saved into a public web folder", "injection", Severity.MEDIUM,
    why="Files in a public folder are served by your own site. An uploaded HTML or SVG file runs in your site's origin, so "
        "it can act as any visitor who opens it.",
    fix="Store uploads outside the web root or in object storage on a separate domain, and serve them through a handler that "
        "sets Content-Disposition: attachment.",
    pattern=r"""\bdest(?:ination)?\s*:\s*['"`](?:\./)?(?:public|static|wwwroot)\b|['"`](?:\./|/)?(?:public|static|wwwroot)/(?:uploads?|files|images/uploads?)\b""",
    exts=JS_EXT | PY_EXT | PHP | GO | CS | JVM | RB, cwe=("CWE-434", "CWE-79"),
    near_pattern=r"(?i)multer|diskStorage|writeFile|createWriteStream|\.save\(|move_uploaded_file|\.mv\(|['\"]wb['\"]|upload\.|\.store\(|TransferTo|CopyTo",
    window=6,
)

# ---------- logs ----------

_LOG_CALL = re.compile(r"\b(?:console\.(?:log|info|debug|warn|error|trace)|logger\.\w+|logging\.\w+|log\.\w+|print|println|pprint|"
                       r"fmt\.Print\w*|System\.out\.print\w*|Log\.[a-z]\w*|puts|error_log|var_dump|Console\.Write\w*)\s*\(")
_SENSITIVE = re.compile(r"(?i)(?<![\w.])(?:\w+\.)*(?:password|passwd|pwd|client_?secret|api_?key|apikey|access_?token|refresh_?token|auth_?token|"
                        r"id_?token|session_?token|authorization|private_?key|credit_?card|card_?number|cvv|ssn|secret|bearer)\b(?!\s*[\(:=])")
_SENSITIVE_AUTH = re.compile(r"(?i)(?<![\w.])(?:\w+\.)*(?:token|jwt|session|cookies?)\b(?!\s*[\(:=])")
_LOG_SAFE = re.compile(r"(?i)\b(?:mask\w*|redact\w*|sanitize\w*|hash\w*)\s*\(|\.length\b|!!|\btypeof\b|\bBoolean\(|\bis_?\w+\b|\bhas_?\w+\b|\bbool\(|\blen\(")
_AUTH_PATH = re.compile(r"(?i)(?:login|signin|sign-in|signup|sign-up|register|password|auth|credential)")
_WHOLE_BODY = re.compile(r"\bconsole\.\w+\s*\(\s*(?:['\"`][^'\"`]*['\"`]\s*,\s*)?(?:req\.body|body|credentials|req\.headers)\s*\)|"
                         r"\b(?:logger\.\w+|print)\s*\(\s*(?:request\.(?:json|form|data|POST)|credentials)\s*\)")
_STRINGS = re.compile(r"""(f?)"(?:[^"\\\n]|\\.)*"|(f?)'(?:[^'\\\n]|\\.)*'|`(?:[^`\\\n]|\\.)*`""")


def _keep_interpolation(match: re.Match[str]) -> str:
    """A string's text can't leak anything, but the values placed into it can."""
    text = match.group(0)
    if text.startswith("`"):
        return " ".join(re.findall(r"\$\{([^}]*)\}", text))
    if match.group(1) or match.group(2):
        return " ".join(re.findall(r"\{([^{}]*)\}", text))
    return '""'


@check(
    "LP-LOG-001", "Password or token written to the logs", "secrets", Severity.MEDIUM,
    why="Logs get copied to hosting dashboards and monitoring tools, and more people can read them than can read your "
        "database. A password or token there can be used by anyone who sees it.",
    fix="Log who and what (a user ID, an event name), never the secret itself. Remove the line, or mask the value first. "
        "If real secrets have already been logged, change them.",
    cwe=("CWE-532",),
)
def secrets_in_logs(ctx: ScanContext, info: CheckInfo) -> Iterator[Finding]:
    for rel, lineno, line, match in grep(ctx, _LOG_CALL):
        arguments = _STRINGS.sub(_keep_interpolation, line[match.end():])
        found = _SENSITIVE.search(arguments) or (_AUTH_PATH.search(rel) and _SENSITIVE_AUTH.search(arguments))
        if found and not _LOG_SAFE.search(arguments):
            yield ctx.finding(info, rel, lineno, line)
        elif _AUTH_PATH.search(rel) and _WHOLE_BODY.search(line):
            yield ctx.finding(info, rel, lineno, line, message="This logs a whole sign-in request, including the password. " + info.why)


# ---------- trusting what the browser says ----------

_ROLE_FIELDS = r"(?:role|roles|isAdmin|is_admin|admin|isSuperuser|is_superuser|is_staff|isStaff|permissions|credits|balance|emailVerified|email_verified|isVerified|is_verified)"
_ROLE_FROM_REQUEST = [
    (JS_EXT, re.compile(rf"\b{_ROLE_FIELDS}\s*:\s*{REQUEST_JS}\??\.\w+")),
    (PY_EXT, re.compile(rf"\b{_ROLE_FIELDS}\s*=\s*{REQUEST_PY}(?:\[|\.get\(|\.\w)")),
    (RB, re.compile(r"\.permit\([^)\n]*:(?:role|admin|is_admin|superuser)\b")),
    (PHP, re.compile(rf"""['"]{_ROLE_FIELDS}['"]\s*=>\s*\$(?:request|_POST|_REQUEST)\b""")),
]


@check(
    "LP-AUTHZ-008", "Users can choose their own role", "authz", Severity.HIGH,
    why="A field like role or isAdmin is taken straight from the request, so anyone can send role=admin when signing up or "
        "editing their profile and give themselves those rights.",
    fix="Set privileged fields on the server only. Accept an explicit list of safe fields from the request, and put role "
        "changes in an admin-only endpoint.",
    cwe=("CWE-269", "CWE-915"),
)
def role_from_request(ctx: ScanContext, info: CheckInfo) -> Iterator[Finding]:
    for exts, pattern in _ROLE_FROM_REQUEST:
        for rel, lineno, line, _ in grep(ctx, pattern, exts=exts):
            # An admin screen changing roles is the right place for it, and a chat message's role isn't an account's.
            if "admin" not in rel.lower() and "content" not in line:
                yield ctx.finding(info, rel, lineno, line)


_TRUST_NAME = r"(?:isAdmin|is_admin|admin|role|userRole|user_role|isPro|is_pro|isPremium|is_premium|premium|isPaid|is_paid|paid|subscribed|isSubscribed)"
_STORAGE = re.compile(rf"""\b(?:localStorage|sessionStorage|AsyncStorage)\.getItem\(\s*['"`]{_TRUST_NAME}['"`]""")
_COOKIE = re.compile(rf"""\breq(?:uest)?\.cookies(?:\.get\(\s*['"]{_TRUST_NAME}['"]|\.{_TRUST_NAME}\b|\[['"]{_TRUST_NAME}['"]\])|\bcookies\(\)\.get\(\s*['"]{_TRUST_NAME}['"]""")
_HEADER = re.compile(r"""\b(?:req|request)\.(?:headers(?:\.get\(\s*|\[\s*)|get\(\s*|getHeader\(\s*)['"]x-(?:user-id|user-role|user|role|admin|is-admin|account-id)['"]""", re.I)


@check(
    "LP-AUTHZ-009", "Admin or paid status trusted from the browser", "authz", Severity.HIGH,
    why="Browser storage, plain cookies and request headers are all set by the person using the app. Anyone can change them "
        "to unlock admin screens or paid features.",
    fix="Decide on the server, from the verified session and your database. The page can read these values to choose what to "
        "show, but every protected action must be checked again on the server.",
    cwe=("CWE-602", "CWE-807"),
)
def status_trusted_from_browser(ctx: ScanContext, info: CheckInfo) -> Iterator[Finding]:
    for rel, lineno, line, _ in grep(ctx, _STORAGE, exts=JS_EXT):
        yield ctx.finding(info, rel, lineno, line, severity=Severity.MEDIUM,
                          message="This reads admin or paid status from browser storage, which the person using the app can "
                                  "edit. It's only safe for deciding what to show, if the server checks every action as well.")
    for rel, lineno, line, _ in grep(ctx, _COOKIE):
        yield ctx.finding(info, rel, lineno, line)
    for rel, lineno, line, _ in grep(ctx, _HEADER):
        yield ctx.finding(info, rel, lineno, line, confidence="low",
                          message="This trusts a header for who the caller is. It's only safe if something in front of the "
                                  "app removes that header from outside requests and sets it itself.")


_ID_FROM_REQUEST = [
    (JS_EXT, re.compile(rf"\b(?:userId|user_id|ownerId|owner_id|authorId|author_id|createdBy|created_by)\s*:\s*{REQUEST_JS}\??\.\w+")),
    (JS_EXT, re.compile(r"(?:const|let|var)\s*\{[^}]*\b(?:userId|user_id|ownerId|owner_id)\b[^}]*\}\s*=\s*(?:await\s+\w+\.json\(\)|(?:req\.body|req\.query|body)\b)")),
    (PY_EXT, re.compile(rf"\b(?:user_id|owner_id|author_id|created_by)\s*=\s*{REQUEST_PY}(?:\[|\.get\()")),
    (PHP, re.compile(r"""['"](?:user_id|owner_id|author_id)['"]\s*=>\s*\$(?:request|_POST|_REQUEST)\b""")),
]


@check(
    "LP-AUTHZ-010", "User ID taken from the request instead of the session", "authz", Severity.HIGH,
    why="The code decides whose data this is from a value in the request. Anyone can put another person's ID there and act "
        "as them.",
    fix="Take the user's ID from the verified session on the server (for example session.user.id), and ignore any ID the "
        "client sends for this.",
    cwe=("CWE-639", "CWE-862"),
)
def user_id_from_request(ctx: ScanContext, info: CheckInfo) -> Iterator[Finding]:
    for exts, pattern in _ID_FROM_REQUEST:
        for rel, lineno, line, _ in grep(ctx, pattern, exts=exts):
            if "admin" not in rel.lower():
                yield ctx.finding(info, rel, lineno, line, confidence="low")


# ---------- secrets that leave by accident ----------

regex_check(
    "LP-SEC-008", "All environment variables sent out", "secrets", Severity.CRITICAL,
    why="This sends every environment variable in a response: your database URL, API keys and signing secrets. It's usually "
        "debugging code that was never removed.",
    fix="Delete it. If you need to check configuration, log the names of the variables that are set, never the values, and "
        "change any secret that may have been exposed.",
    pattern=r"\b(?:res\.(?:json|send)|Response\.json|NextResponse\.json|c\.json|reply\.send)\(\s*(?:\{\s*(?:env\s*:\s*)?)?(?:\.\.\.)?process\.env\s*\}?\s*\)|"
            r"\b(?:jsonify|JsonResponse|JSONResponse)\(\s*(?:dict\(\s*)?os\.environ\b|\breturn\s+(?:dict\(\s*)?os\.environ\s*\)?\s*$|"
            r"\bjson_encode\(\s*(?:\$_ENV|\$_SERVER|getenv\(\))",
    exts=JS_EXT | PY_EXT | PHP, cwe=("CWE-200", "CWE-526"), confidence="high",
)

_BUILD_CONFIG = re.compile(r"^(?:vite|webpack|next|vue|nuxt|rollup|craco|astro|svelte|esbuild|rsbuild)\.config\.[cm]?[jt]s$|^(?:webpack|rollup)\..*\.[cm]?[jt]s$")
_ENV_ALL = re.compile(
    r"""['"]process\.env['"]\s*:\s*(?:JSON\.stringify\(\s*)?(?:process\.env|env)\b|"""
    r"""\bdefine\s*:\s*\{[^}]*\.\.\.\s*(?:process\.env|env)\b|"""
    r"""\benv\s*:\s*(?:\{\s*\.\.\.\s*process\.env\b|process\.env\b)|"""
    r"""\bDefinePlugin\(\s*\{[^}]*process\.env\s*\)""")


@check(
    "LP-SEC-009", "Build copies every secret into the front end", "secrets", Severity.CRITICAL,
    why="This build setting writes all your environment variables into the JavaScript sent to every visitor, including "
        "database URLs and secret keys, whatever they're named.",
    fix="List only the values the page needs, by name. Vite exposes VITE_* and Next.js exposes NEXT_PUBLIC_* for this. Change "
        "any secret that has been in a deployed build.",
    cwe=("CWE-200", "CWE-540"),
)
def build_exposes_env(ctx: ScanContext, info: CheckInfo) -> Iterator[Finding]:
    for rel in ctx.index.iter(JS_EXT):
        if not _BUILD_CONFIG.search(basename(rel)):
            continue
        code = strip_comments(ctx.index.read(rel) or "")
        match = _ENV_ALL.search(code)
        if match:
            yield ctx.finding(info, rel, line_of(code, match.start()), match.group(0), confidence="high")


# ---------- sign-in details ----------

regex_check(
    "LP-AUTH-012", "Accounts linked by email without proof", "auth", Severity.MEDIUM,
    why="With this on, signing in through any configured provider using someone's email address joins their existing account. "
        "If a provider doesn't verify addresses, that's an account takeover.",
    fix="Leave it off unless every provider you use verifies email addresses, and let signed-in users link accounts themselves.",
    pattern=r"\ballowDangerousEmailAccountLinking\s*:\s*true\b",
    exts=JS_EXT, cwe=("CWE-287",), confidence="high",
)

_OAUTH_URL = re.compile(r"github\.com/login/oauth/authorize|accounts\.google\.com/o/oauth2(?:/v2)?/auth|login\.microsoftonline\.com/[^'\"`\s]*oauth2|"
                        r"discord(?:app)?\.com/(?:api/)?(?:v\d+/)?oauth2/authorize|facebook\.com/[^'\"`\s]*dialog/oauth|slack\.com/oauth/v2/authorize")
_OAUTH_STATE = re.compile(r"\bstate\b")


@check(
    "LP-AUTH-013", "Hand-built sign-in link has no state value", "auth", Severity.MEDIUM,
    why="Without a random state value checked on return, another site can start a sign-in and finish it in your user's "
        "browser, linking your user's account to the attacker's (login CSRF).",
    fix="Generate a random state, store it in a cookie, add it to the link and compare it in the callback. A library like "
        "Auth.js or Authlib does this for you.",
    cwe=("CWE-352",),
)
def oauth_without_state(ctx: ScanContext, info: CheckInfo) -> Iterator[Finding]:
    for rel, lineno, line, _ in grep(ctx, _OAUTH_URL):
        if not near(ctx.index.lines(rel), lineno, _OAUTH_STATE, 8):
            yield ctx.finding(info, rel, lineno, line)


regex_check(
    "LP-AUTH-014", "Password reset link built from the Host header", "auth", Severity.MEDIUM,
    why="The Host header comes from the request, so an attacker can ask for a reset of your user's account with their own site "
        "as the host. Your user then receives a real email linking to the attacker's site, which captures the token.",
    fix="Build links from a fixed setting such as APP_URL, not from the request.",
    pattern=r"""\breq\.headers\.host\b|\breq\.get\(\s*['"]host['"]\)|\brequest\.headers\.get\(\s*['"]host['"]\)|\brequest\.get_host\(\)|"""
            r"""\brequest\.(?:url_root|host_url|base_url)\b|\$_SERVER\[\s*['"]HTTP_HOST['"]\s*\]""",
    near_pattern=r"(?i)reset|verify|magic|invite|confirm|activat",
    window=4, cwe=("CWE-640", "CWE-601"),
)

regex_check(
    "LP-AUTH-015", "Login token set from JavaScript", "auth", Severity.MEDIUM,
    why="A cookie set from page code can't be HttpOnly, so any script on the page, including one injected through an XSS bug, "
        "can read the token and take over the session.",
    fix="Have the server set the session cookie, with HttpOnly, Secure and SameSite.",
    pattern=r"""\bdocument\.cookie\s*=\s*[`'"]\s*\w*(?:token|session|auth|jwt)\w*=|\bCookies\.set\(\s*['"`]\w*(?:token|session|auth|jwt)\w*['"`]""",
    exts=JS_EXT, cwe=("CWE-1004",), flags=re.I,
)

_SECRET_NAMES = r"\w*(?:api_?key|apikey|secret|token|signature|password)"
regex_check(
    "LP-CRYPTO-003", "Secret compared in a way that leaks it", "crypto", Severity.LOW,
    why="An ordinary comparison stops at the first wrong character, and that small timing difference can reveal a secret one "
        "character at a time.",
    fix="Use a constant-time comparison: crypto.timingSafeEqual in Node, hmac.compare_digest in Python, hash_equals in PHP, "
        "subtle.ConstantTimeCompare in Go.",
    pattern=rf"""\b{_SECRET_NAMES}\s*(?:===|!==|==|!=)\s*(?:process\.env\.\w+|os\.environ|os\.getenv\(|settings\.\w+|getenv\(|env\.\w+|`Bearer \$\{{process\.env)|"""
            r"""(?:authorization|authHeader|auth_header)\s*(?:===|!==|==|!=)\s*(?:`Bearer \$\{\s*process\.env|f['"]Bearer \{|process\.env\.\w+)|"""
            rf"""(?:process\.env\.\w*(?:SECRET|KEY|TOKEN|PASSWORD)\w*)\s*(?:===|!==)\s*\w+|"""
            r"""(?:headers\[[^\]]+\]|headers\.get\([^)]*\))\s*(?:===|!==|==|!=)\s*(?:process\.env\.|os\.environ|os\.getenv\(|settings\.|env\.)""",
    exts=JS_EXT | PY_EXT | PHP | GO, cwe=("CWE-208",), flags=re.I,
    unless=r"(?i)timingSafeEqual|compare_digest|hash_equals|ConstantTimeCompare|undefined|null|None|['\"]{2}",
)

# ---------- config and leftovers ----------

regex_check(
    "LP-CFG-009", "Image optimiser accepts any website", "config", Severity.MEDIUM,
    why="With a wildcard, your server fetches and resizes images from any address on request. People can use it as a free proxy, "
        "run up your bill, and sometimes reach internal addresses.",
    fix="List the exact hostnames your images come from.",
    pattern=r"""\bhostname\s*:\s*['"]\*\*?['"]|\bdomains\s*:\s*\[\s*['"]\*""",
    exts=JS_EXT, cwe=("CWE-918", "CWE-770"), names={"next.config.js", "next.config.mjs", "next.config.ts", "next.config.cjs"},
)
regex_check(
    "LP-VIBE-006", "Type or lint errors ignored in the build", "vibe", Severity.LOW,
    why="This lets code with known errors ship. It's often added to get a generated project to build, and it hides the "
        "warnings that would point at real bugs.",
    fix="Turn it off, fix what it reports, and keep the build strict.",
    pattern=r"\b(?:ignoreBuildErrors|ignoreDuringBuilds)\s*:\s*true\b",
    exts=JS_EXT, cwe=("CWE-1164",), confidence="high",
)

regex_check(
    "LP-PAY-003", "Paid status taken from the checkout redirect", "payments", Severity.HIGH,
    why="The page people return to after paying can be opened by anyone, so a flag in that link can be typed in by hand to get "
        "the paid feature for free.",
    fix="Grant access from the payment provider's verified webhook, or look the session up on the server with its secret ID "
        "and check it was paid.",
    pattern=r"""\bsuccess_url\s*[:=][^,\n]*[?&](?:paid|premium|pro|plan|upgrade|upgraded|subscribed|status)=|"""
            r"""\b(?:searchParams|query|params)\.get\(\s*['"](?:paid|premium|upgraded|subscribed)['"]\s*\)""",
    exts=JS_EXT | PY_EXT | PHP | RB, cwe=("CWE-602", "CWE-807"),
)

_ARCHIVE = [
    (PY_EXT, re.compile(r"\.extractall\s*\(")),
    (JS_EXT, re.compile(r"\.extractAllTo\s*\(|\bunzipper\.Extract\s*\(")),
    (GO, re.compile(r"filepath\.Join\([^\n]*\b(?:\w+\.Name|header\.Name|hdr\.Name)\b")),
    (JVM, re.compile(r"new\s+File\([^\n]*\.getName\(\)\s*\)")),
]
_ARCHIVE_SAFE = re.compile(r"filter\s*=|HasPrefix|startsWith|normalize|commonpath|isPathInside")
_ARCHIVE_NEAR = {".py": re.compile(r"\btarfile\b|\.tar\b|\btar\s*="), ".go": re.compile(r"\b(?:zip|tar)\."), ".java": re.compile(r"ZipEntry|TarArchiveEntry"), ".kt": re.compile(r"ZipEntry|TarArchiveEntry"),
                 ".scala": re.compile(r"ZipEntry|TarArchiveEntry")}


@check(
    "LP-INJ-013", "Archive unpacked without checking paths inside it", "injection", Severity.MEDIUM,
    why="A zip or tar file can hold names like ../../app.py. Unpacked without a check, it overwrites files outside the target "
        "folder, including your code (Zip Slip).",
    fix="Check each entry's resolved path stays inside the target folder. In Python 3.12+, use extractall(path, filter='data').",
    cwe=("CWE-22",),
)
def archive_traversal(ctx: ScanContext, info: CheckInfo) -> Iterator[Finding]:
    for exts, pattern in _ARCHIVE:
        for rel, lineno, line, _ in grep(ctx, pattern, exts=exts):
            suffix = "." + rel.rsplit(".", 1)[-1]
            required = _ARCHIVE_NEAR.get(suffix)
            lines = ctx.index.lines(rel)
            if _ARCHIVE_SAFE.search(line) or near(lines, lineno, _ARCHIVE_SAFE, 6) or (required and not near(lines, lineno, required, 12)):
                continue
            yield ctx.finding(info, rel, lineno, line)


_SENDS = re.compile(r"\b(?:sendMail|emails\.send|sgMail\.send|messages\.create|send_mail|send_email|EmailMessage)\b")
_ANY_RECIPIENT = [
    (JS_EXT, re.compile(rf"\bto\s*:\s*{REQUEST_JS}\??\.\w+")),
    (PY_EXT, re.compile(rf"\b(?:to|recipient|recipient_list|to_email|to_emails)\s*=\s*\[?\s*{REQUEST_PY}(?:\[|\.get\()")),
]


@check(
    "LP-ABUSE-012", "Anyone can send email or texts to any address", "abuse", Severity.MEDIUM,
    why="The recipient comes straight from the request. People can use your account to send spam or phishing from your domain, "
        "which you pay for and which can get your domain blocked.",
    fix="Send only to the signed-in user's verified address or a fixed inbox. For invites, require a login and a daily limit.",
    cwe=("CWE-770", "CWE-799"),
)
def message_to_any_recipient(ctx: ScanContext, info: CheckInfo) -> Iterator[Finding]:
    for exts, pattern in _ANY_RECIPIENT:
        for rel, lineno, line, _ in grep(ctx, pattern, exts=exts):
            if near(ctx.index.lines(rel), lineno, _SENDS, 8):
                yield ctx.finding(info, rel, lineno, line)


_UNBOUNDED = re.compile(r"\.findMany\(\s*\)|\.collect\(\s*\)|\bobjects\.all\(\s*\)|\.find\(\s*(?:\{\s*\})?\s*\)|\.findAll\(\s*\)")
# A Django or DRF queryset = X.objects.all() line is usually paged by settings or by the view around it.
_BOUNDED = re.compile(r"\b(?:withIndex|take|limit|filter|paginate|first|where|queryset)\b|\[\s*:\s*\d+\s*\]")


@check(
    "LP-ABUSE-013", "Endpoint returns a whole table", "abuse", Severity.LOW,
    why="With no limit, this answer grows with your data. One request can return everything you hold, slow the app for everyone, "
        "and run up database and bandwidth costs.",
    fix="Page the results (take/limit plus a cursor or offset) with a maximum page size.",
    cwe=("CWE-770",),
)
def unbounded_queries(ctx: ScanContext, info: CheckInfo) -> Iterator[Finding]:
    files = {route.file for route in ctx.routes if route.method in ("GET", "ANY")}
    for rel, lineno, line, _ in grep(ctx, _UNBOUNDED, exts=JS_EXT | PY_EXT):
        if rel in files and not _BOUNDED.search(line):
            yield ctx.finding(info, rel, lineno, line, confidence="low")

