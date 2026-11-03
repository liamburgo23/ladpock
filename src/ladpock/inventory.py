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


# .NET, Java and other ecosystems. XML files are read with regular expressions rather than an XML parser, so a
# crafted project file can't use entity tricks against the scanner.
_EXACT = re.compile(r"^\d+(?:\.\d+)*(?:[-+][0-9A-Za-z.-]+)?$")
_XML_ATTR = r"\b{name}\s*=\s*\"([^\"]*)\""


def _attr(tag: str, name: str) -> str | None:
    match = re.search(_XML_ATTR.format(name=name), tag, re.I)
    return match.group(1).strip() if match else None


def parse_nuget_lock(text: str, src: str) -> list[Component]:
    data = json.loads(text)
    out: list[Component] = []
    for packages in (data.get("dependencies") or {}).values():
        for name, meta in (packages or {}).items():
            version = (meta or {}).get("resolved")
            if version and (meta or {}).get("type") != "Project":
                out.append(Component("NuGet", name, str(version), src))
    return out


def parse_msbuild(text: str, src: str) -> list[Component]:
    """PackageReference / PackageVersion items in .csproj, Directory.Packages.props, and old packages.config files."""
    out: list[Component] = []
    for match in re.finditer(r"<(PackageReference|PackageVersion|package)\b([^>]*?)(/>|>(.*?)</\1>)", text, re.S | re.I):
        tag, inner = match.group(2), match.group(4) or ""
        name = _attr(tag, "Include") or _attr(tag, "id") or _attr(tag, "Update")
        version = _attr(tag, "Version") or _attr(tag, "version")
        if not version:
            child = re.search(r"<Version>\s*([^<\s]+)\s*</Version>", inner, re.I)
            version = child.group(1) if child else None
        if name and version and _EXACT.match(version.strip("[]")):
            out.append(Component("NuGet", name, version.strip("[]"), src))
    return out


def parse_pom(text: str, src: str) -> list[Component]:
    text = re.sub(r"<!--.*?-->", "", text, flags=re.S)
    properties = {}
    block = re.search(r"<properties>(.*?)</properties>", text, re.S)
    if block:
        properties = {m.group(1): m.group(2).strip() for m in re.finditer(r"<([\w.-]+)>\s*([^<]+?)\s*</\1>", block.group(1))}
    out: list[Component] = []
    for dep in re.finditer(r"<(dependency|plugin)>(.*?)</\1>", text, re.S):
        body = dep.group(2)
        group = re.search(r"<groupId>\s*([^<\s]+)\s*</groupId>", body)
        artifact = re.search(r"<artifactId>\s*([^<\s]+)\s*</artifactId>", body)
        version = re.search(r"<version>\s*([^<\s]+)\s*</version>", body)
        if not (group and artifact and version):
            continue  # version managed by a parent or BOM: unknown here
        value = version.group(1)
        prop = re.fullmatch(r"\$\{([\w.-]+)\}", value)
        if prop:
            value = properties.get(prop.group(1), "")
        if _EXACT.match(value):
            out.append(Component("Maven", f"{group.group(1)}:{artifact.group(1)}", value, src))
    return out


def parse_gradle_lock(text: str, src: str) -> list[Component]:
    out: list[Component] = []
    for line in text.splitlines():
        match = re.match(r"^([\w.-]+):([\w.-]+):([\w.+-]+)=", line.strip())
        if match:
            out.append(Component("Maven", f"{match.group(1)}:{match.group(2)}", match.group(3), src))
    return out


def parse_gradle_build(text: str, src: str) -> list[Component]:
    """Dependencies declared with an exact version in build.gradle(.kts)."""
    pattern = re.compile(r"\b(?:implementation|api|compileOnly|runtimeOnly|kapt|ksp|annotationProcessor|classpath|"
                         r"testImplementation)\s*\(?\s*['\"]([\w.-]+):([\w.-]+):([\w.+-]+)['\"]")
    return [Component("Maven", f"{m.group(1)}:{m.group(2)}", m.group(3), src)
            for m in pattern.finditer(text) if _EXACT.match(m.group(3))]


def parse_version_catalog(text: str, src: str) -> list[Component]:
    """Gradle version catalogs (gradle/libs.versions.toml)."""
    data = tomllib.loads(text)
    versions = {k: v for k, v in (data.get("versions") or {}).items() if isinstance(v, str)}
    out: list[Component] = []
    for lib in (data.get("libraries") or {}).values():
        if isinstance(lib, str):
            parts = lib.split(":")
            if len(parts) == 3 and _EXACT.match(parts[2]):
                out.append(Component("Maven", f"{parts[0]}:{parts[1]}", parts[2], src))
            continue
        if not isinstance(lib, dict):
            continue
        module = lib.get("module") or (f"{lib['group']}:{lib['name']}" if lib.get("group") and lib.get("name") else None)
        version = lib.get("version")
        if isinstance(version, dict):
            version = versions.get(version.get("ref", "")) or version.get("strictly") or version.get("require")
        if module and isinstance(version, str) and _EXACT.match(version):
            out.append(Component("Maven", module, version, src))
    return out


def parse_pubspec_lock(text: str, src: str) -> list[Component]:
    out: list[Component] = []
    name = source = version = None

    def flush() -> None:
        if name and version and source == "hosted":
            out.append(Component("Pub", name, version, src))

    for line in text.splitlines():
        top = re.match(r"^  ([\w-]+):\s*$", line)
        if top:
            flush()
            name, source, version = top.group(1), None, None
            continue
        if re.match(r"^\S", line):
            flush()
            name = None
            continue
        field = re.match(r"^    (source|version):\s*\"?([^\"\s]+)\"?\s*$", line)
        if field and name:
            if field.group(1) == "source":
                source = field.group(2)
            else:
                version = field.group(2)
    flush()
    return out


def parse_swift_resolved(text: str, src: str) -> list[Component]:
    data = json.loads(text)
    pins = data.get("pins") or (data.get("object") or {}).get("pins") or []
    out: list[Component] = []
    for pin in pins:
        url = pin.get("location") or pin.get("repositoryURL") or ""
        version = (pin.get("state") or {}).get("version")
        name = re.sub(r"^(?:https?://|git@)|\.git$", "", url).replace(":", "/")
        if name and version:
            out.append(Component("SwiftURL", name, version, src))
    return out


def parse_mix_lock(text: str, src: str) -> list[Component]:
    return [Component("Hex", m.group(1), m.group(2), src)
            for m in re.finditer(r"\"[\w-]+\":\s*\{:hex,\s*:([\w-]+),\s*\"([^\"]+)\"", text)]


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
    "packages.lock.json": parse_nuget_lock,
    "packages.config": parse_msbuild,
    "Directory.Packages.props": parse_msbuild,
    "pom.xml": parse_pom,
    "gradle.lockfile": parse_gradle_lock,
    "build.gradle": parse_gradle_build,
    "build.gradle.kts": parse_gradle_build,
    "libs.versions.toml": parse_version_catalog,
    "pubspec.lock": parse_pubspec_lock,
    "Package.resolved": parse_swift_resolved,
    "mix.lock": parse_mix_lock,
}


def parser_for(name: str) -> Callable[[str, str], list[Component]] | None:
    if name in PARSERS:
        return PARSERS[name]
    if name.startswith("requirements") and name.endswith(".txt"):
        return parse_requirements
    if name.endswith((".csproj", ".fsproj", ".vbproj")):
        return parse_msbuild
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
