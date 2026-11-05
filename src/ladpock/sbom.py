"""A software bill of materials: every package version a project uses, as CycloneDX JSON. Read from lockfiles; nothing is sent anywhere."""

from __future__ import annotations

import uuid
from pathlib import Path
from urllib.parse import quote

from . import __version__
from .files import FileIndex
from .inventory import collect
from .models import Component
from .timeutil import iso

PURL_TYPE = {"npm": "npm", "PyPI": "pypi", "Go": "golang", "crates.io": "cargo", "Packagist": "composer", "RubyGems": "gem", "NuGet": "nuget",
             "Maven": "maven", "Pub": "pub", "Hex": "hex", "SwiftURL": "swift", "CocoaPods": "cocoapods"}


def purl(component: Component) -> str | None:
    """The package URL that identifies this version: pkg:npm/%40scope/name@1.2.3."""
    kind = PURL_TYPE.get(component.ecosystem)
    if not kind or not component.version:
        return None
    name = component.name.replace(":", "/") if kind == "maven" else component.name
    parts = "/".join(quote(part, safe="") for part in name.split("/"))
    return f"pkg:{kind}/{parts}@{quote(component.version, safe='')}"


def build(root: str | Path) -> tuple[dict, list[str]]:
    index = FileIndex(root)
    components, warnings = collect(index)
    entries, seen = [], set()
    for component in sorted(components, key=lambda c: (c.ecosystem, c.name, c.version or "")):
        ref = purl(component) or f"{component.ecosystem}:{component.name}@{component.version}"
        if ref in seen:
            continue
        seen.add(ref)
        entry = {"type": "library", "bom-ref": ref, "name": component.name,
                 "properties": [{"name": "ladpock:ecosystem", "value": component.ecosystem}, {"name": "ladpock:source", "value": component.source}]}
        if component.version:
            entry["version"] = component.version
        if purl(component):
            entry["purl"] = purl(component)
        entries.append(entry)
    return {
        "bomFormat": "CycloneDX",
        "specVersion": "1.5",
        "serialNumber": f"urn:uuid:{uuid.uuid4()}",
        "version": 1,
        "metadata": {
            "timestamp": iso(),
            "tools": {"components": [{"type": "application", "name": "LadPock", "version": __version__}]},
            "component": {"type": "application", "name": Path(root).resolve().name, "bom-ref": "project"},
        },
        "components": entries,
    }, warnings
