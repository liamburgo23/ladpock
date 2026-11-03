"""Findings derived from the route matrix: Next.js, Express, Fastify, Hono, NestJS, FastAPI, Flask and Django."""

from __future__ import annotations

from typing import Iterator

from ..models import Finding, Severity
from ..routes import AUTH_FLOW, MUTATING, Route
from .base import CheckInfo, ScanContext, check

STACKS = ("nextjs", "express", "fastify", "hono", "koa", "nestjs", "fastapi", "flask", "django")


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
        if route.auth == "mw" and (route.db or route.mutates):
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
