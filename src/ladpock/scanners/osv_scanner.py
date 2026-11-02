"""OSV-Scanner: used to widen the dependency inventory (more lockfile formats).

Its packages are merged into LadPock's own inventory, so advisories are matched
once, in one place, and don't show up twice.
"""

from __future__ import annotations

import json
import subprocess
from pathlib import Path

from ..models import Component
from .base import ScannerResult, run, version_of, which

INSTALL = "https://google.github.io/osv-scanner/installation/"


def parse(data: dict, root: Path) -> list[Component]:
    out = []
    for result in data.get("results") or []:
        src = (result.get("source") or {}).get("path") or ""
        try:
            src = Path(src).resolve().relative_to(root.resolve()).as_posix()
        except (ValueError, OSError):
            src = Path(src).name
        for pkg in result.get("packages") or []:
            info = pkg.get("package") or {}
            if info.get("name") and info.get("version") and info.get("ecosystem"):
                out.append(Component(info["ecosystem"], info["name"], info["version"], src))
    return out


def scan(root: Path) -> ScannerResult:
    exe = which("osv-scanner")
    if not exe:
        return ScannerResult("osv-scanner", available=False)
    result = ScannerResult("osv-scanner", available=True, version=version_of(exe, "--version"))
    attempts = [[exe, "scan", "source", "-r", "--format", "json", str(root)], [exe, "--format", "json", "-r", str(root)]]
    for args in attempts:
        try:
            proc = run(args, timeout=900)
        except (OSError, subprocess.TimeoutExpired) as exc:
            result.error = str(exc)
            return result
        out = proc.stdout.strip()
        if out.startswith("{"):
            try:
                result.components = parse(json.loads(out), root)
                result.ran = True
                return result
            except ValueError as exc:
                result.error = f"unreadable output: {exc}"
                return result
    result.error = (proc.stderr or "no JSON output").strip()[:300]
    return result
