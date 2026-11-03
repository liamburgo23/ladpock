"""Framework settings in Spring, Rails, Laravel/PHP, ASP.NET and Go that change
how much of the app is protected or how much it reveals."""

from __future__ import annotations

import re
from typing import Iterator

from ..files import CODE_EXT, CONFIG_EXT, basename
from ..models import Finding, Severity
from .base import CheckInfo, ScanContext, check, grep

PROPERTIES = frozenset({".properties", ".yml", ".yaml"})


@check(
    "LP-AUTHZ-006", "Login requirement switched off for every route", "authz", Severity.HIGH,
    why="A catch-all rule that permits every request (or skips the login filter for a whole controller) leaves every "
        "endpoint open unless each one remembers to protect itself, which is how admin pages end up public.",
    fix="Make authentication the default (anyRequest().authenticated(), before_action :authenticate_user!, "
        "DEFAULT_PERMISSION_CLASSES IsAuthenticated) and open up only the specific public routes.",
    cwe=("CWE-306", "CWE-862"),
)
def everything_public(ctx: ScanContext, info: CheckInfo) -> Iterator[Finding]:
    pattern = re.compile(
        r"\banyRequest\(\)\s*\.\s*permitAll\(\)|(?:antMatchers|requestMatchers|mvcMatchers)\(\s*\"/\*\*\"\s*\)\s*\.\s*permitAll\(\)|"
        r"authorize\(\s*anyRequest\s*,\s*permitAll\s*\)|"
        r"^\s*skip_before_action\s+:authenticate_\w+!?\s*$|"
        r"DEFAULT_PERMISSION_CLASSES['\"]?\s*:\s*\[?\s*['\"][\w.]*AllowAny|"
        r"\[AllowAnonymous\]\s*(?:\r?\n\s*)?public\s+class\b"
    )
    for rel, lineno, line, _ in grep(ctx, pattern, exts=CODE_EXT | CONFIG_EXT):
        yield ctx.finding(info, rel, lineno, line, confidence="high" if "anyRequest" in line or "/**" in line else "medium")


@check(
    "LP-CFG-007", "Spring Boot actuator endpoints exposed", "config", Severity.HIGH,
    why="Actuator endpoints like /actuator/env and /actuator/heapdump reveal configuration, credentials and memory "
        "contents. Exposing all of them on a public port hands that over to anyone.",
    fix="Expose only health (and maybe info): management.endpoints.web.exposure.include=health,info. Put any others "
        "on a separate management port that isn't reachable from the internet, behind authentication.",
    cwe=("CWE-200", "CWE-215"),
)
def actuator_exposed(ctx: ScanContext, info: CheckInfo) -> Iterator[Finding]:
    flat = re.compile(r"management\.endpoints\.web\.exposure\.include\s*[=:]\s*['\"]?\*|"
                      r"management\.endpoint\.(?:env|configprops)\.show-values\s*[=:]\s*ALWAYS|"
                      r"management\.security\.enabled\s*[=:]\s*false")
    for rel in ctx.index.iter(PROPERTIES):
        if not basename(rel).startswith(("application", "bootstrap")):
            continue
        lines = ctx.index.lines(rel)
        for i, line in enumerate(lines, 1):
            if flat.search(line):
                yield ctx.finding(info, rel, i, line, confidence="high")
            elif re.match(r"^\s*include:\s*['\"]?\*['\"]?\s*$", line) and any(
                    "exposure" in prev for prev in lines[max(0, i - 3): i - 1]):
                yield ctx.finding(info, rel, i, line, confidence="high")


@check(
    "LP-CFG-008", "Detailed errors shown to visitors in production", "config", Severity.MEDIUM,
    why="Full error pages show stack traces, file paths, SQL and sometimes environment variables, which tells an "
        "attacker exactly how the app is built and where it's weak.",
    fix="Show a generic error page in production and log the details on the server: display_errors Off in PHP, "
        "consider_all_requests_local = false in Rails production, server.error.include-stacktrace=never in Spring, "
        "customErrors on in ASP.NET.",
    cwe=("CWE-209", "CWE-489"),
)
def detailed_errors(ctx: ScanContext, info: CheckInfo) -> Iterator[Finding]:
    pattern = re.compile(
        r"(?i)^\s*display_errors\s*=\s*(?:on|1|true)\b|ini_set\(\s*['\"]display_errors['\"]\s*,\s*['\"]?(?:1|on|true)|"
        r"php_flag\s+display_errors\s+on|server\.error\.include-(?:stacktrace|exception)\s*[=:]\s*(?:always|true)|"
        r"<customErrors\s+mode=\"Off\"|config\.consider_all_requests_local\s*=\s*true"
    )
    targets = CODE_EXT | CONFIG_EXT | {".ini", ".properties"}
    for rel in ctx.index.iter(targets, names={".htaccess", "php.ini", "web.config"}):
        rails_production = rel.endswith("config/environments/production.rb")
        for i, line in enumerate(ctx.index.lines(rel), 1):
            if not pattern.search(line):
                continue
            if "consider_all_requests_local" in line and not rails_production:
                continue  # true is the normal setting in development.rb
            yield ctx.finding(info, rel, i, line)


@check(
    "LP-ABUSE-005", "Go HTTP server without timeouts", "abuse", Severity.LOW,
    why="http.ListenAndServe uses a server with no read or write timeouts, so a few slow clients can hold connections "
        "open forever and exhaust the server (Slowloris).",
    fix="Create an http.Server with ReadHeaderTimeout, ReadTimeout, WriteTimeout and IdleTimeout set, and call its "
        "ListenAndServe method.",
    cwe=("CWE-400",),
)
def go_no_timeouts(ctx: ScanContext, info: CheckInfo) -> Iterator[Finding]:
    pattern = re.compile(r"\bhttp\.ListenAndServe(?:TLS)?\(")
    for rel, lineno, line, _ in grep(ctx, pattern, exts={".go"}):
        yield ctx.finding(info, rel, lineno, line)
