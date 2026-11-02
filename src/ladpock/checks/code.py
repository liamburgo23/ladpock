# ladpock-ignore-file: LP-VIBE-001, LP-VIBE-002, LP-CRYPTO-001 (this file defines those patterns)
"""Pattern checks that apply across languages and frameworks."""

from __future__ import annotations

import re
from typing import Iterator

from ..files import CODE_EXT, CONFIG_EXT, JS_EXT, PY_EXT
from ..models import Finding, Severity
from .base import CheckInfo, ScanContext, check, grep, near, regex_check

# AI-generated code smells

regex_check(
    "LP-VIBE-001", "TLS certificate checks turned off", "vibe", Severity.HIGH,
    why="With verification off, anyone on the network path can read or change this traffic. AI assistants often do this "
        "to make an SSL error go away.",
    fix="Remove the override and fix the real certificate problem (correct hostname, or add the right CA bundle). "
        "Never disable verification in code that ships.",
    pattern=r"rejectUnauthorized\s*:\s*false|NODE_TLS_REJECT_UNAUTHORIZED\s*=\s*['\"]?0|\bverify\s*=\s*False\b|"
            r"InsecureSkipVerify\s*:\s*true|_create_unverified_context|\bCERT_NONE\b|strict-ssl\s*=\s*false|"
            r"danger_accept_invalid_(?:certs|hostnames)\(\s*true\s*\)",
    exts=CODE_EXT | CONFIG_EXT, include_env=True, names={".npmrc"}, cwe=("CWE-295",),
)

regex_check(
    "LP-VIBE-002", "Security check left as a TODO or bypassed 'for now'", "vibe", Severity.MEDIUM,
    why="Temporary bypasses and TODOs on security code have a habit of shipping. This comment says a protection is "
        "missing or switched off.",
    fix="Implement the missing check (or remove the bypass) before this code reaches production.",
    pattern=r"(?i)(?:\b(?:TODO|FIXME|HACK|XXX)\b.{0,80}\b(?:auth\w*|permission|access control|validat\w*|saniti[sz]\w*|"
            r"rate.?limit\w*|csrf|security|verif\w*|ownership)|\b(?:temporar(?:y|ily)|for now|for testing|quick fix)\b.{0,60}"
            r"\b(?:disabl|bypass|skip|remov|turn(?:ed)? off)\w*.{0,40}\b(?:auth\w*|checks?|security|verification|csrf|cors|validation|rls)"
            r"|\b(?:skip|bypass|disable)_?(?:auth|security|verification|csrf)\w*\s*[:=]\s*true)",
    skip_comments=False, cwe=("CWE-1188",),
)

regex_check(
    "LP-VIBE-003", "Default or demo password in code", "vibe", Severity.HIGH,
    why="Default credentials like 'admin' or 'password123' are the first thing attackers try.",
    fix="Remove the hardcoded password. Create real accounts through your sign-up flow or a one-off admin script that "
        "reads the password from an environment variable.",
    pattern=r"(?i)\b(?:password|passwd|pwd)\b['\"]?\s*[:=]\s*['\"](?:admin|password|pass|123456|12345678|changeme|letmein|"
            r"secret|test|test123|qwerty|root|admin123|password1|password123)['\"]",
    cwe=("CWE-798",),
)

regex_check(
    "LP-VIBE-004", "Debug mode switched on", "vibe", Severity.MEDIUM,
    why="Debug mode shows stack traces, settings and sometimes an interactive console to anyone who triggers an error.",
    fix="Read debug mode from an environment variable that defaults to off, and make sure production sets it off.",
    pattern=r"^\s*DEBUG\s*=\s*True\b|\.run\([^)]*debug\s*=\s*True|FastAPI\([^)]*debug\s*=\s*True",
    exts=PY_EXT, confidence="low", cwe=("CWE-489",),
)

regex_check(
    "LP-VIBE-005", "Stack trace sent back to the user", "vibe", Severity.MEDIUM,
    why="Stack traces reveal file paths, library versions and code structure that help an attacker.",
    fix="Log the full error on the server and return a generic message (and maybe an error ID) to the client.",
    pattern=r"(?:json|send|Response\.json|NextResponse\.json|jsonify)\s*\([^)]*\b(?:err|error|e|ex)\.stack\b|"
            r"traceback\.format_exc\(\)",
    cwe=("CWE-209",),
)

# Auth and sign-in

regex_check(
    "LP-AUTH-001", "Token verification switched off", "auth", Severity.HIGH,
    why="Accepting unsigned or expired tokens lets anyone forge a login.",
    fix="Always verify signature and expiry, and pin the algorithm you expect (for example algorithms: ['HS256']).",
    pattern=r"algorithms\s*[:=]\s*\[?\s*['\"]none['\"]|['\"]verify_signature['\"]\s*:\s*False|ignoreExpiration\s*:\s*true|"
            r"verify_exp['\"]\s*:\s*False",
    cwe=("CWE-347",),
)

regex_check(
    "LP-AUTH-002", "Hardcoded or fallback signing secret", "auth", Severity.HIGH,
    why="If the secret that signs sessions or tokens is in the code (or used as a fallback when the env var is missing), "
        "anyone who reads the code can mint valid logins.",
    fix="Read the secret only from the environment and fail at startup if it's missing, instead of falling back to a default.",
    pattern=r"jwt\.sign\([^)]*,\s*['\"][^'\"]{1,64}['\"]|"
            r"process\.env\.\w*(?:SECRET|_KEY|TOKEN)\w*\s*(?:\|\||\?\?)\s*['\"][^'\"]+['\"]|"
            r"os\.(?:environ\.get|getenv)\(\s*['\"]\w*(?:SECRET|_KEY|TOKEN)\w*['\"]\s*,\s*['\"][^'\"]+['\"]",
    unless=r"(?i)publishable|anon|public",
    cwe=("CWE-798", "CWE-321"),
)

regex_check(
    "LP-AUTH-003", "Passwords hashed with a fast hash", "auth", Severity.HIGH,
    why="MD5 and SHA hashes are built to be fast, so leaked password hashes can be cracked by the billion per second.",
    fix="Use a password hashing function: argon2id, bcrypt or scrypt (for example the 'bcrypt' or '@node-rs/argon2' "
        "package, or passlib/argon2-cffi in Python). Better still, let your auth provider handle passwords.",
    pattern=r"createHash\(\s*['\"](?:md5|sha1|sha256|sha512)['\"]|hashlib\.(?:md5|sha1|sha256|sha512)\(",
    near_pattern=r"(?i)passw", cwe=("CWE-916",),
)

regex_check(
    "LP-AUTH-004", "Session token stored in localStorage", "auth", Severity.LOW,
    why="Any script that runs on your page (including one injected via XSS or a compromised npm package) can read "
        "localStorage and steal the session.",
    fix="Prefer an HttpOnly, Secure, SameSite cookie set by the server. Most auth libraries (Supabase SSR, Auth.js, Clerk) do this for you.",
    pattern=r"(?i)localStorage\.setItem\(\s*['\"`][^'\"`]*(?:token|jwt|session|auth)",
    exts=JS_EXT, cwe=("CWE-922",),
)

regex_check(
    "LP-AUTH-005", "Cookie security flag turned off", "auth", Severity.MEDIUM,
    why="Without HttpOnly, scripts can read the cookie. Without Secure, it can travel over plain HTTP.",
    fix="Set httpOnly: true, secure: true (in production) and sameSite: 'lax' or 'strict' on session cookies.",
    pattern=r"(?i)\b(?:httpOnly|http_only)\s*[:=]\s*false\b|\bsecure\s*[:=]\s*false\b",
    near_pattern=r"(?i)cookie", window=6, cwe=("CWE-614", "CWE-1004"),
)

# Crypto and randomness

regex_check(
    "LP-CRYPTO-001", "Predictable random numbers used for a secret value", "crypto", Severity.MEDIUM,
    why="Math.random() and Python's random module are predictable. Tokens, codes and IDs made with them can be guessed.",
    fix="Use crypto.randomUUID() or crypto.getRandomValues() in JavaScript, or the secrets module in Python.",
    pattern=r"Math\.random\(\)|\brandom\.(?:random|randint|choice|choices|randrange|getrandbits)\(",
    near_pattern=r"(?i)token|secret|passw|otp|nonce|salt|session|api_?key|reset|invite|verif|\bcode\b",
    window=0, cwe=("CWE-338",),
)

# Injection

regex_check(
    "LP-INJ-002", "Code or shell command built from input", "injection", Severity.HIGH,
    why="eval, new Function and shell commands assembled from strings let attackers run their own code if any part comes from a user.",
    fix="Remove eval/new Function. For processes, pass arguments as an array (execFile/spawn, or subprocess.run([...]) "
        "without shell=True) and validate the values first.",
    pattern=r"(?<![\w.$])eval\s*\(|\bnew\s+Function\s*\(|\bexec(?:Sync)?\s*\(\s*`[^`]*\$\{|"
            r"\bexec(?:Sync)?\s*\(\s*['\"][^'\"]*['\"]\s*\+|subprocess\.\w+\([^)]*shell\s*=\s*True|"
            r"os\.system\s*\(\s*(?:f['\"]|[^)'\"]*\+)",
    cwe=("CWE-94", "CWE-78"),
)

regex_check(
    "LP-INJ-003", "SQL query built from strings", "injection", Severity.HIGH,
    why="Putting values straight into SQL text lets an attacker rewrite the query and read or delete data.",
    fix="Use parameters: tagged templates (sql`...${id}`), $1 placeholders, the ORM's query builder, or cursor.execute(sql, params).",
    pattern=r"(?:\.(?:query|execute|raw|exec|run|all|prepare)|\$queryRawUnsafe|\$executeRawUnsafe|sql\.unsafe|knex\.raw)\s*\(\s*"
            r"(?:`(?=[^`]*\$\{)(?=[^`]*\b(?i:select|insert|update|delete|where)\b)|['\"][^'\"]*\b(?i:select|insert|update|delete|where)\b[^'\"]*['\"]\s*\+)|"
            r"\$(?:queryRawUnsafe|executeRawUnsafe)\s*\(|"
            r"(?:execute|executemany|text)\s*\(\s*f['\"][^'\"]*\b(?i:select|insert|update|delete|where)\b|"
            r"(?:execute|text)\s*\(\s*['\"][^'\"]*\b(?i:select|insert|update|delete|where)\b[^'\"]*['\"]\s*(?:%|\.format\()",
    cwe=("CWE-89",),
)

regex_check(
    "LP-INJ-004", "Redirect target taken from the request", "injection", Severity.MEDIUM,
    why="Open redirects let phishing links start on your domain and bounce victims to an attacker's site.",
    fix="Only redirect to relative paths you recognise, or check the target against an allowlist of URLs.",
    pattern=r"(?:redirect|res\.redirect|window\.location(?:\.href)?\s*=)\s*\(?\s*(?:new URL\()?\s*"
            r"(?:req\.query|req\.body|request\.nextUrl\.searchParams\.get|searchParams\.get|url\.searchParams\.get|"
            r"request\.args\.get|params\.(?:next|redirect|url|returnTo|callbackUrl))",
    cwe=("CWE-601",),
)

regex_check(
    "LP-INJ-005", "Server fetches a URL supplied by the user", "injection", Severity.MEDIUM,
    why="Server-side request forgery: an attacker can make your server call internal services or cloud metadata endpoints.",
    fix="Validate the URL against an allowlist of hosts, block private and link-local IP ranges, and don't forward the response blindly.",
    pattern=r"(?i)(?:\bfetch|\baxios(?:\.get|\.post)?|\bgot|requests\.(?:get|post)|httpx\.(?:get|post)|urlopen)\s*\(\s*"
            r"(?:req\.(?:body|query)\.\w*|body\.\w*url\w*|searchParams\.get\(\s*['\"]\w*(?:url|uri|link|href|target|endpoint|webhook)\w*['\"]\)|"
            r"request\.args\.get\(\s*['\"]\w*url)",
    cwe=("CWE-918",),
)

regex_check(
    "LP-INJ-001", "HTML injected without sanitising", "injection", Severity.MEDIUM,
    why="Rendering raw HTML from data is the classic route to cross-site scripting (XSS): stolen sessions and actions taken as the user.",
    fix="Render text normally, or sanitise first (for example DOMPurify.sanitize(html)) if you really need HTML.",
    pattern=r"dangerouslySetInnerHTML\s*=\s*\{\s*\{\s*__html\s*:\s*(?!\s*['\"`][^'\"`$]*['\"`]\s*\}|[^}]*(?:DOMPurify|sanitize))|"
            r"\bv-html\s*=|\{@html\s|\.(?:inner|outer)HTML\s*\+?=\s*(?!\s*['\"`][^'\"`$]*['\"`]\s*;?\s*$)",
    exts=JS_EXT | {".html"}, cwe=("CWE-79",),
)

# Payments

regex_check(
    "LP-PAY-002", "Price or amount taken from the client", "payments", Severity.HIGH,
    why="If the browser sends the price, a user can change it and pay what they like.",
    fix="Send only a product or price ID from the client and look the amount up on the server (or use Stripe Price IDs).",
    pattern=r"(?i)\b(?:unit_amount|amount|price)\s*:\s*(?:req\.body|body|data|input|params|formData)\.\w*",
    near_pattern=r"(?i)stripe|checkout|paymentIntents|payment_intent|charge", window=15, cwe=("CWE-602",),
)

# Config

regex_check(
    "LP-CFG-002", "Source maps published in production", "config", Severity.LOW,
    why="Production source maps hand out your original source code, comments included.",
    fix="Turn off browser source maps for production builds, or upload them privately to your error tracker instead.",
    pattern=r"productionBrowserSourceMaps\s*:\s*true|\bsourcemap\s*:\s*true",
    exts=JS_EXT, cwe=("CWE-540",),
)

CORS_ANY = re.compile(
    r"Access-Control-Allow-Origin['\"]?\s*[,:]\s*['\"]\*['\"]|\bcors\(\s*\)|\borigin\s*:\s*(?:['\"]\*['\"]|true\b)|"
    r"allow_origins\s*=\s*\[\s*['\"]\*['\"]\s*\]|CORS_ALLOW_ALL_ORIGINS\s*=\s*True|CORS_ORIGIN_ALLOW_ALL\s*=\s*True"
)
CORS_CREDENTIALS = re.compile(r"(?i)credentials['\"]?\s*[:=]\s*(?:true|True|['\"]true['\"])|allow_credentials\s*=\s*True")


@check(
    "LP-CFG-001", "CORS allows any website", "config", Severity.MEDIUM,
    why="Any website can call this API from a visitor's browser. Combined with credentials, it can act as the logged-in user.",
    fix="List the exact origins that need access (your own domains) instead of '*' or reflecting every origin.",
    cwe=("CWE-942",),
)
def cors_any(ctx: ScanContext, info: CheckInfo) -> Iterator[Finding]:
    for rel, lineno, line, _ in grep(ctx, CORS_ANY, exts=CODE_EXT | CONFIG_EXT):
        with_creds = near(ctx.index.lines(rel), lineno, CORS_CREDENTIALS, 6)
        yield ctx.finding(info, rel, lineno, line, severity=Severity.HIGH if with_creds else Severity.MEDIUM,
                          message=info.why + (" Credentials are allowed here too." if with_creds else ""))


WEBHOOK_VERIFIED = re.compile(
    r"constructEvent(?:Async)?\s*\(|construct_event|verifyHeader|new\s+Webhook\s*\(|verifySignature|verifyWebhook|"
    r"timingSafeEqual|createHmac|hmac\.compare_digest|webhooks\.verify|svix"
)
WEBHOOK_BODY = re.compile(r"await\s+req(?:uest)?\.(?:json|text)\(\)|req(?:uest)?\.body\b|request\.get_json|request\.data\b|request\.body\(\)")


@check(
    "LP-PAY-001", "Webhook accepts requests without checking the signature", "payments", Severity.HIGH,
    why="Anyone who finds the webhook URL can send fake events, for example marking an order as paid.",
    fix="Verify the provider's signature before trusting the payload. For Stripe: read the raw body and call "
        "stripe.webhooks.constructEvent(body, signature, webhookSecret).",
    cwe=("CWE-345",),
)
def webhook_unverified(ctx: ScanContext, info: CheckInfo) -> Iterator[Finding]:
    for rel in ctx.index.iter(CODE_EXT):
        if "webhook" not in rel.lower():
            continue
        text = ctx.index.read(rel) or ""
        if WEBHOOK_VERIFIED.search(text):
            continue
        match = WEBHOOK_BODY.search(text)
        if not match:
            continue
        stripe = re.search(r"(?i)stripe", text) is not None
        lineno = text.count("\n", 0, match.start()) + 1
        yield ctx.finding(info, rel, lineno, ctx.index.lines(rel)[lineno - 1],
                          severity=Severity.HIGH if stripe else Severity.MEDIUM)
