"""Dependencies, CI workflows and hidden characters."""

from __future__ import annotations

import json
import posixpath
import re
import tomllib
from typing import Iterator

from ..files import LOCKFILES, basename, is_ai_instruction_file
from ..models import Finding, Severity
from .base import CheckInfo, ScanContext, check, describe

NPM_LOCKS = {"package-lock.json", "npm-shrinkwrap.json", "yarn.lock", "pnpm-lock.yaml", "bun.lock", "bun.lockb"}
PY_LOCKS = {"poetry.lock", "uv.lock", "Pipfile.lock"}
USES = re.compile(r"^\s*-?\s*uses:\s*['\"]?([^@\s'\"]+)@([^\s'\"#]+)")
FULL_SHA = re.compile(r"[0-9a-f]{40}")
BIDI = {chr(c) for c in (*range(0x202A, 0x202F), *range(0x2066, 0x206A))}
INVISIBLE = {chr(c) for c in (0x200B, 0x200C, 0x200D, 0x2060, 0xFEFF)}


def _declares_dependencies(ctx: ScanContext, rel: str) -> bool:
    text = ctx.index.read(rel) or ""
    try:
        if rel.endswith(".json"):
            data = json.loads(text)
            return bool(data.get("dependencies") or data.get("devDependencies"))
        data = tomllib.loads(text)
    except (ValueError, tomllib.TOMLDecodeError):
        return True
    poetry = data.get("tool", {}).get("poetry", {}).get("dependencies", {})
    return bool(data.get("project", {}).get("dependencies") or [k for k in poetry if k != "python"])


def _has_lock_above(ctx: ScanContext, rel_dir: str, names: set[str]) -> bool:
    current = rel_dir
    while True:
        for name in names:
            if ctx.index.exists(posixpath.join(current, name) if current else name):
                return True
            if (ctx.root / current / name).exists():  # bun.lockb is binary, so not in the text index
                return True
        if not current:
            return False
        current = posixpath.dirname(current)


@check(
    "LP-SUP-001", "No lockfile for dependencies", "supply-chain", Severity.MEDIUM,
    why="Without a lockfile every install can pull different (possibly compromised) versions, and vulnerability checks "
        "can't tell which versions you actually run.",
    fix="Commit your lockfile (package-lock.json, pnpm-lock.yaml, yarn.lock, poetry.lock or uv.lock) and install with "
        "npm ci / pnpm install --frozen-lockfile in CI.",
    cwe=("CWE-1357",),
)
def missing_lockfile(ctx: ScanContext, info: CheckInfo) -> Iterator[Finding]:
    for rel in ctx.index.iter(names={"package.json", "pyproject.toml", "requirements.txt"}):
        name = basename(rel)
        directory = posixpath.dirname(rel)
        if name == "package.json" and not _has_lock_above(ctx, directory, NPM_LOCKS):
            if _declares_dependencies(ctx, rel):
                yield ctx.finding(info, rel, None, None, confidence="high")
        elif name == "pyproject.toml" and not _has_lock_above(ctx, directory, PY_LOCKS | {"requirements.txt"}):
            if _declares_dependencies(ctx, rel):
                yield ctx.finding(info, rel, None, None, severity=Severity.LOW)
        elif name == "requirements.txt" and not _has_lock_above(ctx, directory, PY_LOCKS):
            text = ctx.index.read(rel) or ""
            loose = [line for line in text.splitlines()
                     if line.strip() and not line.strip().startswith(("#", "-")) and "==" not in line]
            if loose:
                yield ctx.finding(info, rel, None, None, severity=Severity.LOW,
                                  message=f"{len(loose)} requirement(s) aren't pinned with ==, so installs aren't reproducible.")


@check(
    "LP-SUP-002", "GitHub Action not pinned to a commit", "supply-chain", Severity.MEDIUM,
    why="Version tags like @v4 can be moved to point at different code. In March 2026 attackers rewrote the tags of "
        "aquasecurity/trivy-action so existing workflows ran credential-stealing malware.",
    fix="Pin third-party actions to a full 40-character commit SHA (keep the version in a comment), and let Dependabot "
        "or Renovate propose updates.",
    cwe=("CWE-829",),
    stacks=("github-actions",),
)
def unpinned_actions(ctx: ScanContext, info: CheckInfo) -> Iterator[Finding]:
    for rel in ctx.index.iter({".yml", ".yaml"}, include_tests=True):
        if not rel.startswith(".github/workflows/"):
            continue
        for i, line in enumerate(ctx.index.lines(rel), 1):
            match = USES.match(line)
            if not match or match.group(1).startswith(("./", "docker://")) or FULL_SHA.fullmatch(match.group(2)):
                continue
            first_party = match.group(1).split("/", 1)[0] in {"actions", "github"}
            yield ctx.finding(info, rel, i, line, severity=Severity.LOW if first_party else Severity.MEDIUM,
                              confidence="high")


@check(
    "LP-SUP-003", "Workflow runs pull request code with repository secrets", "supply-chain", Severity.HIGH,
    why="pull_request_target runs with your secrets. Checking out the pull request's code there lets anyone who opens a "
        "PR run their code with those secrets.",
    fix="Use the pull_request trigger for building and testing PR code. If you need pull_request_target, never check "
        "out or run the PR's head code in it.",
    cwe=("CWE-829",),
    stacks=("github-actions",),
)
def pr_target_checkout(ctx: ScanContext, info: CheckInfo) -> Iterator[Finding]:
    head = re.compile(r"ref:\s*\$\{\{\s*github\.event\.pull_request\.head\.(?:sha|ref)")
    for rel in ctx.index.iter({".yml", ".yaml"}, include_tests=True):
        if not rel.startswith(".github/workflows/"):
            continue
        text = ctx.index.read(rel) or ""
        if "pull_request_target" not in text:
            continue
        for i, line in enumerate(ctx.index.lines(rel), 1):
            if head.search(line):
                yield ctx.finding(info, rel, i, line, confidence="high")


@check(
    "LP-SUP-004", "Hidden Unicode characters in code or AI instructions", "supply-chain", Severity.HIGH,
    why="Invisible or text-reversing characters can make code (or instructions to your AI assistant) do something "
        "different from what you see on screen. This is used to smuggle instructions into AI rule files.",
    fix="Delete the hidden characters (search for the code points shown). If you didn't put them there, find out "
        "where the file came from.",
    cwe=("CWE-1007",),
)
def hidden_unicode(ctx: ScanContext, info: CheckInfo) -> Iterator[Finding]:
    for rel in ctx.index.iter(include_tests=True):
        if basename(rel) in LOCKFILES:
            continue
        ai_file = is_ai_instruction_file(rel)
        for i, line in enumerate(ctx.index.lines(rel), 1):
            if i == 1:
                line = line.lstrip(chr(0xFEFF))
            tags = any(0xE0000 <= ord(ch) <= 0xE007F for ch in line)
            bidi = any(ch in BIDI for ch in line)
            invisible = ai_file and any(ch in INVISIBLE for ch in line)
            if not (tags or bidi or invisible):
                continue
            shown = "".join(f"<U+{ord(ch):04X}>" if ch in BIDI or ch in INVISIBLE or ord(ch) >= 0xE0000 else ch for ch in line)
            severity = Severity.HIGH if (ai_file or tags) else Severity.MEDIUM
            yield ctx.finding(info, rel, i, shown, severity=severity, confidence="high")
            break  # one finding per file is enough


describe(
    "LP-SUP-005", "Dependency doesn't exist on the package registry", "supply-chain", Severity.CRITICAL,
    why="AI assistants sometimes invent package names. Attackers register those names ('slopsquatting'), so the next "
        "install pulls their code.",
    fix="Remove the dependency or replace it with the real package you meant. Check spelling and the publisher before installing.",
    cwe=("CWE-1357",),
)

describe(
    "LP-DEP-001", "Dependency with a known vulnerability", "supply-chain", Severity.HIGH,
    why="A package version you depend on has a published security advisory.",
    fix="Upgrade to the fixed version shown, then update your lockfile and re-run the scan.",
    cwe=("CWE-1395",),
)
