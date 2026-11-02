"""Front-end patterns that hammer your own APIs (and your bill)."""

from __future__ import annotations

import re
from typing import Iterator

from ..files import JS_EXT
from ..jsparse import line_of, match_bracket, split_args, strip_comments
from ..models import Finding, Severity
from .base import CheckInfo, ScanContext, check

FETCHES = re.compile(r"\bfetch\s*\(|\baxios\b|\.from\(\s*['\"`]|\.rpc\(\s*['\"`]|\$fetch\s*\(|\bky\.|\btrpc\.|\.functions\.invoke\(")
USE_EFFECT = re.compile(r"\buseEffect\s*\(")
SET_INTERVAL = re.compile(r"\bsetInterval\s*\(")


@check(
    "LP-ABUSE-001", "Data fetched on every render", "abuse", Severity.MEDIUM,
    why="A useEffect with no dependency array runs after every render. If it fetches and then sets state, it can loop "
        "and fire thousands of requests, which costs money and can get you rate-limited or banned by an API.",
    fix="Add a dependency array: [] to run once, or [id] to re-run when id changes. Consider a data library such as SWR "
        "or TanStack Query, which caches and de-duplicates requests.",
    cwe=("CWE-400",),
)
def effect_without_deps(ctx: ScanContext, info: CheckInfo) -> Iterator[Finding]:
    for rel in ctx.index.iter(JS_EXT):
        text = ctx.index.read(rel) or ""
        if "useEffect" not in text:
            continue
        code = strip_comments(text)
        for match in USE_EFFECT.finditer(code):
            open_idx = match.end() - 1
            close_idx = match_bracket(code, open_idx)
            if close_idx < 0:
                continue
            args = split_args(code, open_idx, close_idx)
            if len(args) == 1 and FETCHES.search(args[0]):
                lineno = line_of(code, match.start())
                yield ctx.finding(info, rel, lineno, ctx.index.lines(rel)[lineno - 1], confidence="high")


@check(
    "LP-ABUSE-002", "Polling an API more than once every two seconds", "abuse", Severity.MEDIUM,
    why="Fast polling multiplies your request count by every open tab. It's an easy way to exhaust a free tier or rate limit.",
    fix="Poll less often (every 10-30 seconds is usually plenty), pause when the tab is hidden, or use realtime "
        "subscriptions / server-sent events instead.",
    cwe=("CWE-400",),
)
def fast_polling(ctx: ScanContext, info: CheckInfo) -> Iterator[Finding]:
    for rel in ctx.index.iter(JS_EXT):
        text = ctx.index.read(rel) or ""
        if "setInterval" not in text:
            continue
        code = strip_comments(text)
        for match in SET_INTERVAL.finditer(code):
            open_idx = match.end() - 1
            close_idx = match_bracket(code, open_idx)
            if close_idx < 0:
                continue
            args = split_args(code, open_idx, close_idx)
            if len(args) < 2:
                continue
            delay = re.fullmatch(r"\s*(\d[\d_]*)\s*", args[1])
            if delay and int(delay.group(1).replace("_", "")) < 2000 and FETCHES.search(args[0]):
                lineno = line_of(code, match.start())
                yield ctx.finding(info, rel, lineno, ctx.index.lines(rel)[lineno - 1], confidence="high")
