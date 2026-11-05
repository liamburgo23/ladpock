"""The check framework.

A check is a function registered with metadata (id, category, severity, why
it matters, how to fix it). Simple pattern checks are declared as data with
``regex_check``; checks that need structure are plain functions. Adding a
framework pack means adding checks here plus a fixture that proves them.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable, Iterable, Iterator

from ..files import CODE_EXT, FileIndex
from ..masking import redact
from ..models import Finding, Severity


@dataclass(frozen=True)
class CheckInfo:
    id: str
    title: str
    category: str
    severity: Severity
    why: str
    fix: str
    cwe: tuple[str, ...] = ()
    stacks: tuple[str, ...] = ()  # empty means the check runs on every project


CheckFn = Callable[["ScanContext", CheckInfo], Iterable[Finding]]
REGISTRY: dict[str, tuple[CheckInfo, CheckFn]] = {}


def check(id: str, title: str, category: str, severity: Severity, why: str, fix: str,
          cwe: tuple[str, ...] = (), stacks: tuple[str, ...] = ()) -> Callable[[CheckFn], CheckFn]:
    def deco(fn: CheckFn) -> CheckFn:
        if id in REGISTRY:
            raise ValueError(f"duplicate check id {id}")
        REGISTRY[id] = (CheckInfo(id, title, category, severity, why, fix, tuple(cwe), tuple(stacks)), fn)
        return fn

    return deco


def describe(id: str, title: str, category: str, severity: Severity, why: str, fix: str,
             cwe: tuple[str, ...] = ()) -> CheckInfo:
    """Register a check whose findings are produced elsewhere (e.g. network lookups)."""
    check(id, title, category, severity, why, fix, cwe)(lambda ctx, info: ())
    return REGISTRY[id][0]


@dataclass
class ScanContext:
    root: Path
    index: FileIndex
    stack: set[str]
    git_files: set[str] | None = None
    _routes: list | None = field(default=None, repr=False)

    @property
    def routes(self) -> list:
        if self._routes is None:
            from ..routes import analyze

            self._routes = analyze(self.index)
        return self._routes

    def finding(self, info: CheckInfo, file: str | None = None, line: int | None = None,
                snippet: str | None = None, message: str | None = None, severity: Severity | None = None,
                confidence: str = "medium", **extra) -> Finding:
        snip = redact(snippet.strip())[:220] if snippet else None
        return Finding(
            check_id=info.id, title=info.title, severity=severity if severity is not None else info.severity,
            category=info.category, message=message or info.why, fix=info.fix, file=file, line=line,
            snippet=snip, confidence=confidence, cwe=info.cwe, extra=extra,
        )


_ID_LIST = r"([A-Z][A-Z0-9-]+(?:\s*,\s*[A-Z][A-Z0-9-]+)*)"
IGNORE_LINE = re.compile(rf"ladpock-ignore(?!-file)(?::\s*{_ID_LIST})?")
IGNORE_FILE = re.compile(rf"ladpock-ignore-file(?::\s*{_ID_LIST})?")


def inline_ignored(ctx: "ScanContext", finding: Finding) -> bool:
    """True if a `ladpock-ignore` comment on (or just above) the line, or a
    `ladpock-ignore-file` comment near the top of the file, covers this finding.
    Either can list check IDs (ladpock-ignore: LP-VIBE-001) to stay narrow."""
    if not finding.file:
        return False

    def covers(match: re.Match[str] | None) -> bool:
        if not match:
            return False
        return not match.group(1) or finding.check_id in {i.strip() for i in match.group(1).split(",")}

    lines = ctx.index.lines(finding.file)
    if any(covers(IGNORE_FILE.search(line)) for line in lines[:5]):
        return True
    if finding.line:
        return any(covers(IGNORE_LINE.search(line)) for line in lines[max(0, finding.line - 2): finding.line])
    return False


# A # starts a comment in Python and shell, but in C and C++ it can start real code like #define.
COMMENT_LINE = re.compile(r"^\s*(//|#(?!\s*(?:define|include|if|ifdef|ifndef|else|elif|endif|undef|pragma)\b)|\*|/\*|<!--|--)")
MAX_LINE = 2000  # longer lines are almost always minified or generated


def grep(ctx: ScanContext, pattern: re.Pattern[str], *, exts=CODE_EXT, include_tests: bool = False,
         include_env: bool = False, skip_comments: bool = True, names: set[str] | None = None,
         pred: Callable[[str], bool] | None = None) -> Iterator[tuple[str, int, str, re.Match[str]]]:
    for rel in ctx.index.iter(exts, include_tests=include_tests, include_env=include_env, names=names, pred=pred):
        for i, line in enumerate(ctx.index.lines(rel), 1):
            if len(line) > MAX_LINE or (skip_comments and COMMENT_LINE.match(line)):
                continue
            match = pattern.search(line)
            if match:
                yield rel, i, line, match


def near(lines: list[str], lineno: int, pattern: re.Pattern[str], window: int) -> bool:
    chunk = lines[max(0, lineno - 1 - window): lineno + window]
    return any(pattern.search(line) for line in chunk)


def regex_check(id: str, title: str, category: str, severity: Severity, why: str, fix: str, pattern: str, *,
                exts=CODE_EXT, cwe: tuple[str, ...] = (), stacks: tuple[str, ...] = (), near_pattern: str | None = None,
                window: int = 3, unless: str | None = None, include_tests: bool = False, include_env: bool = False,
                skip_comments: bool = True, names: set[str] | None = None, confidence: str = "medium",
                flags: int = 0) -> None:
    pat = re.compile(pattern, flags)
    near_pat = re.compile(near_pattern) if near_pattern else None
    unless_pat = re.compile(unless) if unless else None

    @check(id, title, category, severity, why, fix, cwe, stacks)
    def _run(ctx: ScanContext, info: CheckInfo) -> Iterator[Finding]:
        for rel, lineno, line, _ in grep(ctx, pat, exts=exts, include_tests=include_tests, include_env=include_env,
                                         skip_comments=skip_comments, names=names):
            if unless_pat and unless_pat.search(line):
                continue
            if near_pat and not near(ctx.index.lines(rel), lineno, near_pat, window):
                continue
            yield ctx.finding(info, rel, lineno, line, confidence=confidence)


def run_all(ctx: ScanContext, categories: set[str] | None = None) -> tuple[list[Finding], list[str]]:
    findings: list[Finding] = []
    errors: list[str] = []
    for check_id, (info, fn) in sorted(REGISTRY.items()):
        if categories is not None and info.category not in categories:
            continue
        if info.stacks and not set(info.stacks) & ctx.stack:
            continue
        try:
            findings.extend(fn(ctx, info))
        except Exception as exc:  # one broken check must not sink the whole scan
            errors.append(f"{check_id}: {type(exc).__name__}: {exc}")
    return findings, errors
