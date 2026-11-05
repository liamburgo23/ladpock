"""Dependencies, CI workflows and hidden characters."""

from __future__ import annotations

import json
import posixpath
import re
import tomllib
from typing import Iterator

from ..files import LOCKFILES, basename, is_ai_instruction_file
from ..jsparse import strip_comments
from ..models import Finding, Severity
from .base import CheckInfo, ScanContext, check, describe

NPM_LOCKS = {"package-lock.json", "npm-shrinkwrap.json", "yarn.lock", "pnpm-lock.yaml", "bun.lock", "bun.lockb"}
PY_LOCKS = {"poetry.lock", "uv.lock", "Pipfile.lock"}
USES = re.compile(r"^\s*-?\s*uses:\s*['\"]?([^@\s'\"]+)@([^\s'\"#]+)")
FULL_SHA = re.compile(r"[0-9a-f]{40}")
BIDI = {chr(c) for c in (*range(0x202A, 0x202F), *range(0x2066, 0x206A))}
INVISIBLE = {chr(c) for c in (0x200B, 0x200C, 0x200D, 0x2060, 0xFEFF)}


AI_CONFIG_NAMES = {".mcp.json", "mcp.json", "mcp_config.json", "claude_desktop_config.json"}
RUNS_DOWNLOADS = re.compile(r"(?i)\b(?:curl|wget|iwr|irm|Invoke-WebRequest|Invoke-RestMethod|nc|ncat)\b|\bbase64\s+(?:-d|--decode)\b|\bnode\s+-e\b|\bpython3?\s+-c\b|"
                            r"\b(?:ba)?sh\s+-c\b|\bpowershell\b|\beval\b")
INSTALL_SCRIPTS = ("preinstall", "install", "postinstall", "prepare", "prepublish")
NPM_RUNNERS = {"npx", "bunx"}
PY_RUNNERS = {"uvx"}


def _load_jsonc(text: str) -> dict | None:
    try:
        data = json.loads(re.sub(r",(\s*[}\]])", r"\1", strip_comments(text)))
    except ValueError:
        return None
    return data if isinstance(data, dict) else None


def _line_with(ctx: ScanContext, rel: str, needle: str) -> int | None:
    for i, line in enumerate(ctx.index.lines(rel), 1):
        if needle in line:
            return i
    return None


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
    "LP-SUP-008", "Install script downloads or runs code", "supply-chain", Severity.HIGH,
    why="This runs automatically on every install, on your computer and in CI, with access to your files and tokens. A script "
        "that fetches or decodes code is how most malicious packages work, so it needs a close look.",
    fix="Remove it if you don't recognise it. If you need the step, make it a script you run on purpose, with the code in this "
        "repository rather than downloaded.",
    cwe=("CWE-506", "CWE-494"),
)
def install_scripts(ctx: ScanContext, info: CheckInfo) -> Iterator[Finding]:
    for rel in ctx.index.iter(names={"package.json"}):
        if basename(rel) != "package.json":
            continue
        try:
            scripts = json.loads(ctx.index.read(rel) or "{}").get("scripts") or {}
        except (ValueError, AttributeError):
            continue
        for name in INSTALL_SCRIPTS:
            command = scripts.get(name)
            if isinstance(command, str) and RUNS_DOWNLOADS.search(command):
                yield ctx.finding(info, rel, _line_with(ctx, rel, f'"{name}"'), f"{name}: {command}", confidence="high")


NPM_UNUSUAL = re.compile(r"^(?:https?:|git\+|git:|ssh:|github:|gitlab:|bitbucket:|[\w.-]+/[\w.-]+(?:#.*)?$)")
LOCK_RESOLVED = re.compile(r'"resolved"\s*:\s*"(http://[^"]+|git\+[^"]+)"')
PY_SOURCES = re.compile(r"(?m)^\s*(--extra-index-url\s+\S+|--index-url\s+http://\S+|-i\s+http://\S+|--trusted-host\s+\S+|\S*\bgit\+http://\S+|\S+\s*@\s*http://\S+|http://\S+\.(?:whl|tar\.gz|zip)\b)")
NPMRC_RULES = re.compile(r"(?m)^\s*(?:(?:@[\w-]+:)?registry\s*=\s*http://\S+|strict-ssl\s*=\s*false)\s*$")
OTHER_SOURCES = re.compile(r"""(?m)^\s*source\s+['"]http://|['"]secure-http['"]\s*:\s*false""")


@check(
    "LP-SUP-009", "Package comes from outside the registry", "supply-chain", Severity.MEDIUM,
    why="Packages from a URL, a git repository or a second index skip the checks a registry gives you. Over plain HTTP they can be "
        "swapped in transit, and an extra index lets an attacker publish a package with your private package's name "
        "(dependency confusion).",
    fix="Install from the registry at a fixed version, over HTTPS. For private packages, use a scoped registry or a single index "
        "that serves both, rather than an extra one.",
    cwe=("CWE-494", "CWE-829", "CWE-427"),
)
def unusual_sources(ctx: ScanContext, info: CheckInfo) -> Iterator[Finding]:
    for rel in ctx.index.iter(include_lockfiles=True):
        name = basename(rel)
        if name == "package.json":
            try:
                data = json.loads(ctx.index.read(rel) or "{}")
            except ValueError:
                continue
            for section in ("dependencies", "devDependencies", "optionalDependencies"):
                for package, version in (data.get(section) or {}).items():
                    if isinstance(version, str) and NPM_UNUSUAL.match(version):
                        insecure = version.startswith(("http:", "git:", "git+http:"))
                        yield ctx.finding(info, rel, _line_with(ctx, rel, f'"{package}"'), f"{package}: {version}",
                                          severity=Severity.HIGH if insecure else Severity.MEDIUM, confidence="high" if insecure else "low")
        elif name in ("package-lock.json", "npm-shrinkwrap.json"):
            text = ctx.index.read(rel) or ""
            for match in list(LOCK_RESOLVED.finditer(text))[:10]:
                yield ctx.finding(info, rel, text.count("\n", 0, match.start()) + 1, match.group(1), severity=Severity.HIGH, confidence="high")
        elif name.startswith("requirements") and name.endswith(".txt"):
            text = ctx.index.read(rel) or ""
            for match in PY_SOURCES.finditer(text):
                yield ctx.finding(info, rel, text.count("\n", 0, match.start(1)) + 1, match.group(1))
        elif name == ".npmrc" or name == "Gemfile" or name == "composer.json":
            text = ctx.index.read(rel) or ""
            for match in (NPMRC_RULES if name == ".npmrc" else OTHER_SOURCES).finditer(text):
                yield ctx.finding(info, rel, text.count("\n", 0, match.start()) + 1, match.group(0), severity=Severity.HIGH, confidence="high")


@check(
    "LP-SUP-010", "Dependency allows any version", "supply-chain", Severity.LOW,
    why="With * or latest, the next install takes whatever was published most recently, including a compromised release.",
    fix="Use a version range you've tested (for example ^1.2.3) and commit your lockfile.",
    cwe=("CWE-1357", "CWE-829"),
)
def any_version(ctx: ScanContext, info: CheckInfo) -> Iterator[Finding]:
    for rel in ctx.index.iter(names={"package.json"}):
        if basename(rel) != "package.json":
            continue
        try:
            data = json.loads(ctx.index.read(rel) or "{}")
        except ValueError:
            continue
        for section in ("dependencies", "devDependencies"):
            for package, version in (data.get(section) or {}).items():
                if version in ("*", "latest", "", "x"):
                    yield ctx.finding(info, rel, _line_with(ctx, rel, f'"{package}"'), f"{package}: {version or 'no version'}", confidence="high")


def _unpinned_runner(command: str, args: list) -> str | None:
    """The package an MCP server's command runs, if it isn't at a fixed version."""
    name = basename(command.replace("\\", "/")).removesuffix(".cmd").removesuffix(".exe")
    words = [str(a) for a in args]
    if name in NPM_RUNNERS:
        package = next((w for w in words if not w.startswith("-")), None)
        if package and not re.search(r".@\d", package):
            return package
    elif name in PY_RUNNERS:
        package = next((w for w in words if not w.startswith("-")), None)
        if package and "==" not in package and "@" not in package and "--from" not in words:
            return package
    return None


@check(
    "LP-SUP-011", "AI tool runs a package with no fixed version", "supply-chain", Severity.MEDIUM,
    why="This MCP server runs with access to your files and credentials, and it fetches the newest release every time it starts. "
        "If that package is ever compromised, the attacker's code runs on your computer with no update to approve.",
    fix="Pin it to a version you've checked, for example npx -y some-server@1.2.3. Only add MCP servers you trust.",
    cwe=("CWE-829", "CWE-494"),
)
def ai_tool_servers(ctx: ScanContext, info: CheckInfo) -> Iterator[Finding]:
    for rel in ctx.index.iter(names=AI_CONFIG_NAMES):
        if basename(rel) not in AI_CONFIG_NAMES:
            continue
        data = _load_jsonc(ctx.index.read(rel) or "")
        servers = (data or {}).get("mcpServers") or (data or {}).get("servers") or {}
        if not isinstance(servers, dict):
            continue
        for name, server in servers.items():
            if not isinstance(server, dict):
                continue
            url = str(server.get("url") or server.get("serverUrl") or "")
            if url.startswith("http://") and not re.match(r"http://(?:localhost|127\.0\.0\.1|\[::1\])\b", url):
                yield ctx.finding(info, rel, _line_with(ctx, rel, url), f"{name}: {url}", severity=Severity.HIGH, confidence="high",
                                  message="This MCP server is reached over plain HTTP, so anyone on the network can read its traffic, "
                                          "including any tokens, and change what your AI tool is told.")
            package = _unpinned_runner(str(server.get("command") or ""), server.get("args") or [])
            if package:
                yield ctx.finding(info, rel, _line_with(ctx, rel, package), f"{name}: {server.get('command')} {package}", confidence="high")


AUTO_RUN_FILES = {"tasks.json", "devcontainer.json", "settings.json", "settings.local.json", "hooks.json"}


@check(
    "LP-SUP-012", "Project runs a command when opened", "supply-chain", Severity.MEDIUM,
    why="Editors and AI tools can run commands from a project's own settings as soon as you open it or start working. It's a known "
        "way for a cloned repository to run code on your computer, so anything here should be something you recognise.",
    fix="Remove the automatic trigger, or run the step yourself. Be wary of these settings in repositories you didn't write.",
    cwe=("CWE-829", "CWE-506"),
)
def runs_when_opened(ctx: ScanContext, info: CheckInfo) -> Iterator[Finding]:
    for rel in ctx.index.iter(names=AUTO_RUN_FILES):
        name, folder = basename(rel), rel.rsplit("/", 2)[-2] if "/" in rel else ""
        text = ctx.index.read(rel) or ""
        if name == "tasks.json" and folder == ".vscode":
            for i, line in enumerate(ctx.index.lines(rel), 1):
                if re.search(r'"runOn"\s*:\s*"folderOpen"', line):
                    yield ctx.finding(info, rel, i, line)
        elif name == "devcontainer.json" and RUNS_DOWNLOADS.search(text):
            for i, line in enumerate(ctx.index.lines(rel), 1):
                if re.search(r'"(?:initialize|onCreate|updateContent|postCreate|postStart|postAttach)Command"', line) and RUNS_DOWNLOADS.search(line):
                    yield ctx.finding(info, rel, i, line)
        elif folder in (".claude", ".gemini", ".cursor", ".windsurf") and "hooks" in text and RUNS_DOWNLOADS.search(text):
            for i, line in enumerate(ctx.index.lines(rel), 1):
                if '"command"' in line and RUNS_DOWNLOADS.search(line):
                    yield ctx.finding(info, rel, i, line, severity=Severity.HIGH,
                                      message="This AI tool setting runs a command that downloads or decodes something, automatically, "
                                              "with access to your files. Hooks like this are a way for a repository to run code on your computer.")


PIPE_TO_SHELL = re.compile(r"(?i)\b(?:curl|wget)\b[^|;&\n]*\|\s*(?:sudo\s+)?(?:-\S+\s+)*(?:ba|z|da)?sh\b|\b(?:iwr|irm|Invoke-WebRequest|Invoke-RestMethod)\b[^|;\n]*\|\s*(?:iex|Invoke-Expression)\b")


@check(
    "LP-SUP-013", "Build script downloads and runs code in one step", "supply-chain", Severity.MEDIUM,
    why="Whoever controls that address, or anything between you and it, can run anything in your build, with access to your "
        "secrets and everything you deploy.",
    fix="Download a fixed version, check it against a known checksum, then run it. Or install it with a package manager at a fixed version.",
    cwe=("CWE-494",),
)
def pipes_to_shell(ctx: ScanContext, info: CheckInfo) -> Iterator[Finding]:
    def is_script(rel: str) -> bool:
        return rel.startswith(".github/workflows/") or rel.endswith((".sh", ".ps1")) or basename(rel) == "Makefile"

    for rel in ctx.index.iter(pred=is_script):
        for i, line in enumerate(ctx.index.lines(rel), 1):
            if PIPE_TO_SHELL.search(line) and not line.lstrip().startswith("#"):
                yield ctx.finding(info, rel, i, line)


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
