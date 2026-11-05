"""Findings derived from the route matrix, which covers every web framework LadPock can read routes from."""

from __future__ import annotations

import re
from typing import Iterator

from ..models import Finding, Severity
from ..routes import AUTH_FLOW, CRON_PATH, MUTATING, PATH_MATCHED_MIDDLEWARE, Route
from .base import CheckInfo, ScanContext, check

STACKS = ("nextjs", "express", "fastify", "hono", "koa", "nestjs", "fastapi", "flask", "django", "sveltekit", "remix",
          "nuxt", "astro", "spring", "go", "rails", "laravel", "dotnet", "trpc", "convex", "graphql", "firebase", "supabase",
          "vercel", "netlify", "cloudflare", "aws-lambda", "rust-web", "elysia", "hapi", "sinatra", "symfony", "ktor", "jaxrs")


def _finding(ctx: ScanContext, info: CheckInfo, route: Route, **kwargs) -> Finding:
    return ctx.finding(info, route.file, route.line, f"{route.method} {route.path}", **kwargs)


@check(
    "LP-AUTHZ-001", "Endpoint changes data without checking who is calling", "authz", Severity.HIGH,
    why="This handler writes to the database but never checks for a logged-in user, so anyone on the internet can call it.",
    fix="Get the current user at the top of the handler (for example const { data: { user } } = await "
        "supabase.auth.getUser(), or await auth()) and return 401 if there isn't one.",
    cwe=("CWE-306", "CWE-862"),
    stacks=STACKS,
)
def unauthenticated_mutation(ctx: ScanContext, info: CheckInfo) -> Iterator[Finding]:
    for route in ctx.routes:
        if route.auth == "no" and route.mutates and not route.public_path and not route.webhook:
            yield _finding(ctx, info, route)


@check(
    "LP-AUTHZ-002", "Record fetched by ID without checking it belongs to the user", "authz", Severity.HIGH,
    why="The handler checks that someone is logged in, then loads a record by the ID in the URL without checking "
        "ownership. Any logged-in user can change the ID and read or edit someone else's data (an IDOR bug).",
    fix="Filter by the current user as well as the ID (for example .eq('user_id', user.id) or where: { id, userId: user.id }), "
        "or rely on Supabase RLS by using the user's session client instead of an admin client.",
    cwe=("CWE-639",),
    stacks=STACKS,
)
def missing_ownership(ctx: ScanContext, info: CheckInfo) -> Iterator[Finding]:
    for route in ctx.routes:
        admin = "/admin" in route.path  # admin routes need a role check, not an ownership check
        if route.owner == "no" and route.auth in ("yes", "mw") and (route.dynamic or route.mutates) and not admin:
            yield _finding(ctx, info, route, confidence="low")


PRIVATE_DATA = re.compile(r"(?i)user|account|customer|member|profile|order|invoice|payment|billing|subscription|message|chat|conversation|"
                          r"note|document|upload|secret|token|credential|address|patient|medical|salary|employee|report|admin|export|"
                          r"transaction|booking|ticket|contact|lead")
PUBLIC_CONTENT = re.compile(r"(?i)post|blog|article|product|catalog|categor|tag|page|faq|news|event|plan|pricing|feature|price|public|sitemap|"
                            r"health|status|version|config|settings/public|docs?\b")


def _name_of(path: str) -> str:
    """The last fixed part of a path, which is what the endpoint holds: posts in /api/users/[id]/posts."""
    parts = [p for p in re.split(r"/", path) if p and not re.match(r"^(?:\[|:|\{|<|\(\?)", p)]
    return parts[-1] if parts else ""


@check(
    "LP-AUTHZ-007", "Private-looking data readable without logging in", "authz", Severity.HIGH,
    why="This endpoint reads from the database, its name suggests private data, and nothing checks who is calling. Anyone who "
        "finds it can read that data.",
    fix="Check for a logged-in user first and limit the results to their own records. If it really is public, return only "
        "fields that are safe to publish. Run a scan with Live checks on to confirm whether it answers.",
    cwe=("CWE-306", "CWE-862"),
    stacks=STACKS,
)
def unauthenticated_private_read(ctx: ScanContext, info: CheckInfo) -> Iterator[Finding]:
    for route in ctx.routes:
        if route.auth != "no" or not route.db or route.mutates or route.public_path or route.webhook or route.method not in ("GET", "ANY"):
            continue
        name = _name_of(route.path)
        if PRIVATE_DATA.search(name) and not PUBLIC_CONTENT.search(name):
            yield _finding(ctx, info, route, confidence="low")


DEBUG_PATH = re.compile(r"(?i)/(?:debug|test|seeds?|seed-?(?:db|data|users|all)|reset-?(?:db|database)|drop-?(?:db|tables?|all)|wipe|dev|mock|fixtures?|"
                        r"phpinfo|dump|backdoor|impersonate|sudo|make-?admin|init-?db|migrate|_internal)(?:/|$|\.)")


@check(
    "LP-API-003", "Debug, test or seed endpoint left in the app", "abuse", Severity.HIGH,
    why="Endpoints for seeding data, testing or debugging are written to get a job done quickly, with no login. If they reach "
        "production, anyone can call them, and some can reset or fill your database.",
    fix="Delete it, or only register it when running locally (check NODE_ENV or an equivalent setting). Keep seeding in a "
        "script that isn't reachable over the web.",
    cwe=("CWE-489", "CWE-306"),
    stacks=STACKS,
)
def debug_endpoints(ctx: ScanContext, info: CheckInfo) -> Iterator[Finding]:
    for route in ctx.routes:
        if route.auth == "no" and DEBUG_PATH.search(route.path.split("?")[0]):
            yield _finding(ctx, info, route, confidence="medium" if route.db or route.mutates else "low")


CRON_GUARD = re.compile(r"(?i)CRON_SECRET|x-vercel-cron|x-appengine-cron|x-cloudscheduler|\bauthorization\b|\bverifySignature\b|\bsecret\b")


@check(
    "LP-API-004", "Scheduled-job endpoint anyone can trigger", "abuse", Severity.MEDIUM,
    why="A job endpoint is an ordinary URL. Without a secret, anyone can run the job as often as they like, which can send "
        "duplicate emails, repeat billing runs or overload the app.",
    fix="Require a secret (for example check an Authorization header against CRON_SECRET) and reject anything else.",
    cwe=("CWE-306",),
    stacks=STACKS,
)
def open_cron(ctx: ScanContext, info: CheckInfo) -> Iterator[Finding]:
    for route in ctx.routes:
        if route.auth == "no" and CRON_PATH.search(route.path) and not CRON_GUARD.search(ctx.index.read(route.file) or ""):
            yield _finding(ctx, info, route)


@check(
    "LP-AUTHZ-003", "Authentication only enforced in middleware", "authz", Severity.MEDIUM,
    why="If middleware is skipped or its matcher misses a path, the handler is wide open. In 2025 a Next.js bug "
        "(CVE-2025-29927) let attackers bypass middleware entirely with one header.",
    fix="Check the user inside the handler as well. Treat middleware as a convenience for redirects, not as the security boundary.",
    cwe=("CWE-288",),
    stacks=STACKS,
)
def middleware_only(ctx: ScanContext, info: CheckInfo) -> Iterator[Finding]:
    for route in ctx.routes:
        if route.auth == "mw" and (route.db or route.mutates) and route.kind in PATH_MATCHED_MIDDLEWARE:
            yield _finding(ctx, info, route, confidence="low")


@check(
    "LP-ABUSE-010", "Paid AI or messaging API reachable without logging in", "abuse", Severity.HIGH,
    why="Anyone who finds this endpoint can use it as a free proxy to your OpenAI, Anthropic, email or SMS account, "
        "and you pay for every call.",
    fix="Require a logged-in user, add a per-user rate limit and a daily quota, and set a spending cap with the provider.",
    cwe=("CWE-770", "CWE-306"),
    stacks=STACKS,
)
def paid_api_without_auth(ctx: ScanContext, info: CheckInfo) -> Iterator[Finding]:
    for route in ctx.routes:
        if route.paid_api and route.auth == "no" and not route.webhook:
            yield _finding(ctx, info, route, confidence="high")


@check(
    "LP-ABUSE-011", "Paid API endpoint has no rate limit", "abuse", Severity.MEDIUM,
    why="Even logged-in users (or one compromised account) can run up a large bill or exhaust your quota without a rate limit.",
    fix="Add a per-user rate limit (for example @upstash/ratelimit or Arcjet) and a provider-side spending cap.",
    cwe=("CWE-770",),
    stacks=STACKS,
)
def paid_api_without_limit(ctx: ScanContext, info: CheckInfo) -> Iterator[Finding]:
    for route in ctx.routes:
        if route.paid_api and route.rate_limit == "no" and route.auth != "no":
            yield _finding(ctx, info, route)


@check(
    "LP-AUTH-010", "Sign-in or password endpoint has no rate limit", "auth", Severity.MEDIUM,
    why="Without a limit, attackers can try passwords or one-time codes as fast as your server answers.",
    fix="Rate limit by IP and by account (for example 5 attempts per minute), and add a delay or lockout after repeated failures. "
        "Hosted auth (Supabase Auth, Clerk, Auth.js providers) already does this for its own endpoints.",
    cwe=("CWE-307",),
    stacks=STACKS,
)
def auth_flow_without_limit(ctx: ScanContext, info: CheckInfo) -> Iterator[Finding]:
    for route in ctx.routes:
        if AUTH_FLOW.search(route.path) and route.method in MUTATING and route.rate_limit == "no":
            yield _finding(ctx, info, route)
