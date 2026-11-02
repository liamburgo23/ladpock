"""Builds the dependency inventory (a lightweight SBOM) from lockfiles.

Lockfiles are parsed as data. Package managers are never run, so nothing in
the scanned project gets a chance to execute.
"""

from __future__ import annotations

import json
import re
import tomllib
from typing import Callable

from .files import FileIndex, basename
from .models import Component

_YARN_HEADER = re.compile(r'^"?((?:@[^/@"\s]+/)?[^@"\s,]+)@')
_YARN_VERSION = re.compile(r'^\s+version:?\s+"?([^"\s]+)"?\s*$')
_PNPM_ENTRY = re.compile(r"^  '?/?((?:@[^/@\s']+/)?[^/@\s':(]+)[@/](\d[^:'(\s]*)")
_BUN_ENTRY = re.compile(r'"((?:@[^/"@]+/)?[^"@/]+)":\s*\[\s*"((?:@[^/"@]+/)?[^"@]+)@(?:npm:)?(\d[^"]*)"')
_REQ_LINE = re.compile(r"^\s*([A-Za-z0-9][A-Za-z0-9._-]*)\s*(?:\[[^\]]*\])?\s*(==|===)?\s*([A-Za-z0-9.*+!_-]+)?")
_GEM_SPEC = re.compile(r"^    ([A-Za-z0-9._-]+) \(([^)\s]+)\)")
_GO_REQUIRE = re.compile(r"^\s*(?:require\s+)?([a-z0-9.\-]+\.[a-z]{2,}/[^\s]+)\s+v([0-9][^\s]*)")


def _norm_py(name: str) -> str:
    return re.sub(r"[-_.]+", "-", name).lower()


def parse_npm_lock(text: str, src: str) -> list[Component]:
    data = json.loads(text)
    out: list[Component] = []
    packages = data.get("packages")
    if isinstance(packages, dict):
        for key, meta in packages.items():
            if not key or "node_modules/" not in key or not isinstance(meta, dict) or meta.get("link"):
                continue
            name = meta.get("name") or key.rsplit("node_modules/", 1)[-1]
            version = meta.get("version")
            if name and isinstance(version, str) and version[:1].isdigit():
                out.append(Component("npm", name, version, src))
        return out

    def walk(deps: dict | None) -> None:
        for name, meta in (deps or {}).items():
            if not isinstance(meta, dict):
                continue
            version = meta.get("version")
            if isinstance(version, str) and version[:1].isdigit():
                out.append(Component("npm", name, version, src))
            walk(meta.get("dependencies"))

    walk(data.get("dependencies"))
    return out


def parse_yarn_lock(text: str, src: str) -> list[Component]:
    out: list[Component] = []
    current: str | None = None
    for line in text.splitlines():
        if not line or line.startswith("#"):
            continue
        if not line[0].isspace():
            match = _YARN_HEADER.match(line.strip())
            current = match.group(1) if match and not line.startswith("__metadata") else None
            continue
        if current:
            match = _YARN_VERSION.match(line)
            if match:
                out.append(Component("npm", current, match.group(1), src))
                current = None
    return out


def parse_pnpm_lock(text: str, src: str) -> list[Component]:
    out: list[Component] = []
    in_packages = False
    for line in text.splitlines():
        if line and not line[0].isspace():
            in_packages = line.rstrip() == "packages:"
            continue
        if in_packages:
            match = _PNPM_ENTRY.match(line)
            if match:
                out.append(Component("npm", match.group(1), match.group(2), src))
    return out


def parse_bun_lock(text: str, src: str) -> list[Component]:
    return [Component("npm", m.group(2), m.group(3), src) for m in _BUN_ENTRY.finditer(text)]


def parse_requirements(text: str, src: str) -> list[Component]:
    out: list[Component] = []
    for raw in text.splitlines():
        line = raw.split("#", 1)[0].strip()
        if not line or line.startswith("-") or "://" in line:
            continue
        match = _REQ_LINE.match(line)
        if not match:
            continue
        pinned = match.group(2) is not None and match.group(3) and "*" not in match.group(3)
        out.append(Component("PyPI", _norm_py(match.group(1)), match.group(3) if pinned else None, src))
    return out


def _toml_packages(text: str, src: str, ecosystem: str) -> list[Component]:
    data = tomllib.loads(text)
    out: list[Component] = []
    for pkg in data.get("package", []):
        source = pkg.get("source")
        if isinstance(source, dict) and ({"editable", "virtual", "directory", "path"} & set(source)):
            continue
        name, version = pkg.get("name"), pkg.get("version")
        if name and version:
            out.append(Component(ecosystem, _norm_py(name) if ecosystem == "PyPI" else name, str(version), src))
    return out


def parse_pipfile_lock(text: str, src: str) -> list[Component]:
    data = json.loads(text)
    out: list[Component] = []
    for section in ("default", "develop"):
        for name, meta in (data.get(section) or {}).items():
            version = str(meta.get("version", "")).lstrip("=")
            if version:
                out.append(Component("PyPI", _norm_py(name), version, src))
    return out


def parse_composer_lock(text: str, src: str) -> list[Component]:
    data = json.loads(text)
    out: list[Component] = []
    for section in ("packages", "packages-dev"):
        for pkg in data.get(section) or []:
            name, version = pkg.get("name"), str(pkg.get("version", "")).lstrip("v")
            if name and version[:1].isdigit():
                out.append(Component("Packagist", name, version, src))
    return out


def parse_gemfile_lock(text: str, src: str) -> list[Component]:
    return [Component("RubyGems", m.group(1), m.group(2), src) for m in map(_GEM_SPEC.match, text.splitlines()) if m]


def parse_go_mod(text: str, src: str) -> list[Component]:
    out: list[Component] = []
    for line in text.splitlines():
        match = _GO_REQUIRE.match(line)
        if match:
            out.append(Component("Go", match.group(1), match.group(2).split("+", 1)[0], src))
    return out


PARSERS: dict[str, Callable[[str, str], list[Component]]] = {
    "package-lock.json": parse_npm_lock,
    "npm-shrinkwrap.json": parse_npm_lock,
    "yarn.lock": parse_yarn_lock,
    "pnpm-lock.yaml": parse_pnpm_lock,
    "bun.lock": parse_bun_lock,
    "poetry.lock": lambda t, s: _toml_packages(t, s, "PyPI"),
    "uv.lock": lambda t, s: _toml_packages(t, s, "PyPI"),
    "Pipfile.lock": parse_pipfile_lock,
    "Cargo.lock": lambda t, s: _toml_packages(t, s, "crates.io"),
    "composer.lock": parse_composer_lock,
    "Gemfile.lock": parse_gemfile_lock,
    "go.mod": parse_go_mod,
}


def parser_for(name: str) -> Callable[[str, str], list[Component]] | None:
    if name in PARSERS:
        return PARSERS[name]
    if name.startswith("requirements") and name.endswith(".txt"):
        return parse_requirements
    return None


def _is_fixture(rel: str) -> bool:
    # Test fixtures describe example projects, not dependencies you actually install.
    return "/fixtures/" in f"/{rel}"


def collect(index: FileIndex) -> tuple[list[Component], list[str]]:
    """All pinned components in the project, plus any parse warnings."""
    seen: set[Component] = set()
    out: list[Component] = []
    warnings: list[str] = []
    for rel in index.paths:
        if _is_fixture(rel):
            continue
        parser = parser_for(basename(rel))
        if not parser:
            continue
        text = index.read(rel)
        if not text:
            continue
        try:
            components = parser(text, rel)
        except (ValueError, tomllib.TOMLDecodeError, AttributeError, TypeError) as exc:
            warnings.append(f"Couldn't read {rel}: {exc}")
            continue
        for comp in components:
            if comp.version and comp not in seen:
                seen.add(comp)
                out.append(comp)
    return out, warnings


def direct_dependencies(index: FileIndex) -> list[tuple[str, str, str]]:
    """(ecosystem, name, manifest) for packages the developer asked for by name."""
    out: list[tuple[str, str, str]] = []
    for rel in index.paths:
        if _is_fixture(rel):
            continue
        name = basename(rel)
        if name == "package.json":
            try:
                data = json.loads(index.read(rel) or "{}")
            except json.JSONDecodeError:
                continue
            for section in ("dependencies", "devDependencies"):
                for dep, spec in (data.get(section) or {}).items():
                    spec = str(spec)
                    if spec.startswith(("workspace:", "file:", "link:", "git", "http", "github:", "portal:")):
                        continue
                    if spec.startswith("npm:"):
                        dep = spec[4:].rsplit("@", 1)[0] or dep
                    out.append(("npm", dep, rel))
        elif name.startswith("requirements") and name.endswith(".txt"):
            text = index.read(rel) or ""
            if re.search(r"(?m)^\s*--(?:extra-)?index-url", text):
                continue  # private index: the public registry isn't authoritative
            for comp in parse_requirements(text, rel):
                out.append(("PyPI", comp.name, rel))
    return out
