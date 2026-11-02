from __future__ import annotations

import shutil
import subprocess
from dataclasses import dataclass, field
from pathlib import Path

from ..gitutil import safe_env
from ..models import Component, Finding
from ..paths import data_dir


@dataclass
class ScannerResult:
    name: str
    available: bool
    version: str | None = None
    ran: bool = False
    error: str | None = None
    findings: list[Finding] = field(default_factory=list)
    components: list[Component] = field(default_factory=list)


def which(name: str) -> str | None:
    local = data_dir() / "bin"
    for candidate in (local / name, local / f"{name}.exe"):
        if candidate.is_file():
            return str(candidate)
    return shutil.which(name)


def run(args: list[str], cwd: Path | None = None, timeout: int = 900) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        args, cwd=str(cwd) if cwd else None, capture_output=True, text=True, encoding="utf-8",
        errors="replace", timeout=timeout, env=safe_env(),
    )


def version_of(exe: str, *args: str) -> str | None:
    try:
        proc = run([exe, *(args or ("--version",))], timeout=30)
    except (OSError, subprocess.TimeoutExpired):
        return None
    text = (proc.stdout or proc.stderr).strip().splitlines()
    return text[0][:80] if text else None
