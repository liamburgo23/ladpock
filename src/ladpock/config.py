"""A project's own settings, from ladpock.toml in its root folder.

    [ignore]
    paths = ["legacy/*", "scripts/one-off.py"]
    checks = ["LP-ABUSE-013"]

    [routes]
    auth_functions = ["requireTeamMember"]   # your own helpers that check who's calling
    owner_functions = ["assertOwnsOrder"]    # and that check a record is theirs
    public = ["/api/products", "/api/products/*"]

Whatever this hides is still counted in every report. A config file that hides findings is exactly what an AI assistant might add
to make a scan pass, so it's never silent.
"""

from __future__ import annotations

import fnmatch
import re
import tomllib
from dataclasses import dataclass, field

from .files import FileIndex

NAMES = ("ladpock.toml", ".ladpock.toml")
KNOWN = {"ignore": {"paths", "checks"}, "routes": {"auth_functions", "owner_functions", "public"}}
SAFE_NAME = re.compile(r"^[A-Za-z_][\w.]*$")
MAX_LINES_PER_ROUTE = 120


@dataclass
class ProjectConfig:
    source: str | None = None
    ignore_paths: tuple[str, ...] = ()
    ignore_checks: frozenset[str] = frozenset()
    auth_functions: tuple[str, ...] = ()
    owner_functions: tuple[str, ...] = ()
    public_routes: tuple[str, ...] = ()
    warnings: list[str] = field(default_factory=list)

    def hides(self, check_id: str, file: str | None) -> bool:
        if check_id in self.ignore_checks:
            return True
        return bool(file) and any(fnmatch.fnmatchcase(file, pattern) for pattern in self.ignore_paths)


def _strings(value, where: str, warnings: list[str]) -> tuple[str, ...]:
    if value is None:
        return ()
    if not isinstance(value, list) or not all(isinstance(item, str) for item in value):
        warnings.append(f"{where} should be a list of strings")
        return ()
    return tuple(value)


def load(index: FileIndex) -> ProjectConfig:
    """This project's settings. Read once per scan and kept on the index, since route analysis runs more than once."""
    cached = getattr(index, "_project_config", None)
    if cached is not None:
        return cached
    config = _read(index)
    index._project_config = config  # type: ignore[attr-defined]
    return config


def _read(index: FileIndex) -> ProjectConfig:
    source = next((name for name in NAMES if index.exists(name)), None)
    if not source:
        return ProjectConfig()
    try:
        data = tomllib.loads(index.read(source) or "")
    except tomllib.TOMLDecodeError as exc:
        return ProjectConfig(source=source, warnings=[f"{source} couldn't be read, so it was ignored: {exc}"])
    warnings: list[str] = []
    for section, values in data.items():
        if section not in KNOWN:
            warnings.append(f"{source}: unknown section [{section}]")
        elif isinstance(values, dict):
            warnings.extend(f"{source}: unknown setting {section}.{key}" for key in values if key not in KNOWN[section])
    ignore, routes = data.get("ignore") or {}, data.get("routes") or {}
    names = []
    for name in (*_strings(routes.get("auth_functions"), "routes.auth_functions", warnings),
                 *_strings(routes.get("owner_functions"), "routes.owner_functions", warnings)):
        if not SAFE_NAME.match(name):
            warnings.append(f"{source}: '{name}' isn't a function name")
        names.append(name)
    return ProjectConfig(
        source=source,
        ignore_paths=_strings(ignore.get("paths"), "ignore.paths", warnings),
        ignore_checks=frozenset(_strings(ignore.get("checks"), "ignore.checks", warnings)),
        auth_functions=tuple(n for n in _strings(routes.get("auth_functions"), "", []) if SAFE_NAME.match(n)),
        owner_functions=tuple(n for n in _strings(routes.get("owner_functions"), "", []) if SAFE_NAME.match(n)),
        public_routes=_strings(routes.get("public"), "routes.public", warnings),
        warnings=warnings,
    )


def apply_to_routes(routes: list, index: FileIndex) -> list:
    """Teach the route matrix what only you know: your own login helpers, and what's public on purpose."""
    config = load(index)
    if not (config.ignore_paths or config.auth_functions or config.owner_functions or config.public_routes):
        return routes
    auth = re.compile(r"(?<![\w.])(?:" + "|".join(re.escape(n) for n in config.auth_functions) + r")\b") if config.auth_functions else None
    owner = re.compile(r"(?<![\w.])(?:" + "|".join(re.escape(n) for n in config.owner_functions) + r")\b") if config.owner_functions else None
    kept = [r for r in routes if not any(fnmatch.fnmatchcase(r.file, p) for p in config.ignore_paths)]
    by_file: dict[str, list] = {}
    for route in kept:
        by_file.setdefault(route.file, []).append(route)
    for rel, items in by_file.items():
        lines = index.lines(rel)
        items.sort(key=lambda r: r.line)
        for i, route in enumerate(items):
            if any(fnmatch.fnmatchcase(route.path.split("?")[0], p) for p in config.public_routes):
                route.public = True
            later = [r.line for r in items[i + 1:] if r.line > route.line]
            start = max(0, route.line - 3)  # decorators and middleware sit just above or on the route's own line
            end = min(later[0] - 1 if later else len(lines), route.line + MAX_LINES_PER_ROUTE)
            text = "\n".join(lines[start: end])
            if auth and route.auth in ("no", "mw") and auth.search(text):
                route.auth = "yes"
            if owner and route.owner == "no" and owner.search(text):
                route.owner = "yes"
    return kept
