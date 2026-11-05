"""Walks a project once and caches file contents for every check.

Safety rules for scanning code we don't trust:
- symlinks are never followed (a repo could link to files outside itself)
- only text files are read, with a size cap
- nothing in the project is ever executed
"""

from __future__ import annotations

import os
import re
from pathlib import Path
from typing import Callable, Iterator

IGNORE_DIRS = {
    ".git", "node_modules", ".next", ".nuxt", ".output", ".svelte-kit", ".turbo", ".vercel",
    ".netlify", ".cache", ".parcel-cache", "dist", "build", "out", "coverage", ".venv", "venv",
    "env", "__pycache__", ".mypy_cache", ".pytest_cache", ".tox", "vendor", "target", ".idea",
    ".expo", "Pods", ".gradle", "bower_components",
}

JS_EXT = frozenset({".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs", ".mts", ".cts", ".vue", ".svelte", ".astro"})
PY_EXT = frozenset({".py"})
CODE_EXT = JS_EXT | PY_EXT | {".go", ".rb", ".php", ".java", ".kt", ".cs", ".rs", ".swift", ".dart", ".scala", ".m"}
CONFIG_EXT = frozenset({".json", ".jsonc", ".yml", ".yaml", ".toml", ".ini", ".cfg", ".conf", ".xml"})
TEXT_EXT = CODE_EXT | CONFIG_EXT | {
    ".sql", ".md", ".mdc", ".txt", ".html", ".htm", ".css", ".scss", ".rules", ".sh", ".ps1",
    ".bat", ".lock", ".prisma", ".graphql", ".gql", ".tf", ".hcl", ".properties", ".mod", ".sum",
    # server templates
    ".ejs", ".hbs", ".handlebars", ".pug", ".jade", ".njk", ".jinja", ".jinja2", ".j2", ".twig", ".erb", ".liquid",
    ".mustache",
    # infrastructure and platform config
    ".plist", ".gradle", ".kts", ".tfvars", ".csproj", ".config", ".env", ".tfstate", ".props", ".fsproj", ".vbproj",
}
TEXT_NAMES = {
    "Dockerfile", ".gitignore", ".npmrc", ".yarnrc", ".cursorrules", ".windsurfrules", "Procfile",
    "Gemfile", "Makefile", "Pipfile", ".dockerignore", ".gitattributes", ".htaccess",
}
LOCKFILES = {
    "package-lock.json", "npm-shrinkwrap.json", "yarn.lock", "pnpm-lock.yaml", "bun.lock",
    "poetry.lock", "uv.lock", "Pipfile.lock", "Cargo.lock", "composer.lock", "Gemfile.lock", "go.sum",
    "packages.lock.json", "gradle.lockfile", "pubspec.lock", "Package.resolved", "mix.lock", "Podfile.lock",
}
AI_INSTRUCTION_NAMES = {
    "claude.md", "agents.md", "gemini.md", ".cursorrules", ".windsurfrules", "copilot-instructions.md",
}
TEST_DIRS = {"test", "tests", "__tests__", "spec", "specs", "e2e", "cypress", "playwright", "__mocks__", "fixtures"}
_TEST_FILE = re.compile(r"(\.(test|spec|stories)\.[a-z]+$)|(^test_.*\.py$)|(_test\.(py|go)$)")

MAX_BYTES = 1_000_000
MAX_LOCKFILE_BYTES = 60_000_000


def is_env_file(name: str) -> bool:
    lower = name.lower()
    return lower == ".env" or lower.startswith(".env.")


def is_env_template(name: str) -> bool:
    lower = name.lower()
    return is_env_file(lower) and lower.rsplit(".", 1)[-1] in {"example", "sample", "template", "dist", "defaults"}


# File-based routes ship whatever their folder is called: app/api/test/route.ts is a live URL, not a test.
_ROUTE_FILE = re.compile(r"(?:^|/)(?:app/(?:.*/)?route\.[a-z]+$|pages/api/|src/routes/(?:.*/)?\+server\.|netlify/functions/|supabase/functions/)")


def is_test_path(rel: str) -> bool:
    lower = rel.lower()
    parts = lower.split("/")
    if _TEST_FILE.search(parts[-1]):
        return True
    route = _ROUTE_FILE.search(lower)
    if route and not any(p in TEST_DIRS for p in lower[:route.start()].split("/")):
        return False
    return any(p in TEST_DIRS for p in parts[:-1])


def is_ai_instruction_file(rel: str) -> bool:
    lower = rel.lower()
    name = lower.rsplit("/", 1)[-1]
    return (
        name in AI_INSTRUCTION_NAMES
        or lower.startswith((".cursor/rules/", ".claude/", ".windsurf/", ".github/instructions/"))
        or (lower.startswith(".github/") and name.endswith("instructions.md"))
    )


def is_texty(name: str) -> bool:
    if name in TEXT_NAMES or name in LOCKFILES or is_env_file(name):
        return True
    if name.startswith(("Dockerfile.", "Containerfile")) or name.lower().endswith(".dockerfile"):
        return True
    return os.path.splitext(name)[1].lower() in TEXT_EXT


def ext(rel: str) -> str:
    return os.path.splitext(rel)[1].lower()


def basename(rel: str) -> str:
    return rel.rsplit("/", 1)[-1]


class FileIndex:
    def __init__(self, root: str | Path, max_files: int = 50_000):
        self.root = Path(root).resolve()
        self.paths: list[str] = []
        self.skipped_large = 0
        self.truncated = False
        self._cache: dict[str, str | None] = {}
        self._lines: dict[str, list[str]] = {}
        self._walk(max_files)
        self._set = set(self.paths)

    def _walk(self, max_files: int) -> None:
        for dirpath, dirnames, filenames in os.walk(self.root, followlinks=False):
            dirnames[:] = sorted(
                d for d in dirnames if d not in IGNORE_DIRS and not os.path.islink(os.path.join(dirpath, d))
            )
            for name in sorted(filenames):
                full = os.path.join(dirpath, name)
                if os.path.islink(full) or not is_texty(name):
                    continue
                try:
                    size = os.path.getsize(full)
                except OSError:
                    continue
                limit = MAX_LOCKFILE_BYTES if name in LOCKFILES else MAX_BYTES
                if size > limit:
                    self.skipped_large += 1
                    continue
                self.paths.append(Path(full).relative_to(self.root).as_posix())
                if len(self.paths) >= max_files:
                    self.truncated = True
                    return

    def exists(self, rel: str) -> bool:
        return rel in self._set

    def read(self, rel: str) -> str | None:
        if rel not in self._cache:
            text: str | None = None
            try:
                raw = (self.root / rel).read_bytes()
                if b"\x00" not in raw[:8192]:
                    text = raw.decode("utf-8", errors="replace")
            except OSError:
                text = None
            self._cache[rel] = text
        return self._cache[rel]

    def lines(self, rel: str) -> list[str]:
        if rel not in self._lines:
            text = self.read(rel)
            self._lines[rel] = text.splitlines() if text else []
        return self._lines[rel]

    def iter(
        self,
        exts: frozenset[str] | set[str] | None = None,
        *,
        include_tests: bool = False,
        include_lockfiles: bool = False,
        include_env: bool = False,
        names: set[str] | None = None,
        pred: Callable[[str], bool] | None = None,
    ) -> Iterator[str]:
        for rel in self.paths:
            name = basename(rel)
            if not include_lockfiles and name in LOCKFILES:
                continue
            if not include_tests and is_test_path(rel):
                continue
            matched = (
                (exts is None and names is None and pred is None)
                or (exts is not None and ext(rel) in exts)
                or (names is not None and name in names)
                or (include_env and is_env_file(name))
                or (pred is not None and pred(rel))
            )
            if matched:
                yield rel
