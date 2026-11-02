"""Opengrep (or Semgrep CE): data-flow rules that regexes can't express.

Runs LadPock's own rule files from ladpock/rules/opengrep, never the Semgrep
registry rules, whose licence restricts redistribution.
"""

from __future__ import annotations

import json
import subprocess
from pathlib import Path

from ..masking import redact
from ..models import Finding, Severity
from .base import ScannerResult, run, version_of, which

INSTALL = "https://github.com/opengrep/opengrep#installation"
RULES_DIR = Path(__file__).resolve().parent.parent / "rules" / "opengrep"
_LEVELS = {"ERROR": Severity.HIGH, "WARNING": Severity.MEDIUM, "INFO": Severity.LOW}


def parse(data: dict, root: Path) -> list[Finding]:
    findings = []
    for item in data.get("results") or []:
        extra = item.get("extra") or {}
        meta = extra.get("metadata") or {}
        path = str(item.get("path") or "")
        try:
            path = Path(path).resolve().relative_to(root.resolve()).as_posix() if Path(path).is_absolute() else path.replace("\\", "/")
        except ValueError:
            pass
        rule_id = str(item.get("check_id") or "rule").rsplit(".", 1)[-1]
        findings.append(Finding(
            check_id=f"LP-FLOW-{rule_id}",
            title=str(meta.get("title") or rule_id),
            severity=_LEVELS.get(str(extra.get("severity", "")).upper(), Severity.MEDIUM),
            category=str(meta.get("category") or "injection"),
            message=str(extra.get("message") or ""),
            fix=str(meta.get("fix") or ""),
            file=path or None,
            line=(item.get("start") or {}).get("line"),
            snippet=redact(str(extra.get("lines") or "").strip())[:220] or None,
            confidence=str(meta.get("confidence") or "medium").lower(),
            source="opengrep",
            cwe=tuple(str(c).split(":")[0] for c in (meta.get("cwe") or [])),
        ))
    return findings


def scan(root: Path) -> ScannerResult:
    exe = which("opengrep")
    flavour = "opengrep"
    if not exe:
        exe, flavour = which("semgrep"), "semgrep"
    if not exe:
        return ScannerResult("opengrep", available=False)
    result = ScannerResult(flavour, available=True, version=version_of(exe, "--version"))
    args = [exe, "scan", "--config", str(RULES_DIR), "--json", "--quiet", str(root)]
    if flavour == "semgrep":
        args[2:2] = ["--metrics=off"]
    try:
        proc = run(args, timeout=1200)
        data = json.loads(proc.stdout or "{}")
    except (OSError, ValueError, subprocess.TimeoutExpired) as exc:
        result.error = str(exc)[:300]
        return result
    result.ran = True
    result.findings = parse(data, root)
    if data.get("errors") and not result.findings:
        result.error = str(data["errors"][0].get("message", ""))[:300]
    return result
