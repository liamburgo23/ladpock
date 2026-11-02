"""Gitleaks: secret detection, including secrets buried in git history."""

from __future__ import annotations

import json
import subprocess
import tempfile
from pathlib import Path

from ..masking import mask, redact
from ..models import Finding, Severity
from .base import ScannerResult, run, version_of, which

INSTALL = "https://github.com/gitleaks/gitleaks#installing"


def parse(report: list[dict], history: bool) -> list[Finding]:
    findings = []
    for item in report:
        secret = str(item.get("Secret") or "")
        snippet = redact(str(item.get("Match") or ""))
        if secret and secret != "REDACTED" and secret in snippet:
            snippet = snippet.replace(secret, mask(secret))
        commit = str(item.get("Commit") or "")
        where = f" (in commit {commit[:8]})" if history and commit else ""
        findings.append(Finding(
            check_id=f"GITLEAKS-{item.get('RuleID', 'secret')}",
            title=f"Secret found by Gitleaks: {item.get('Description') or item.get('RuleID')}",
            severity=Severity.HIGH if history and commit else Severity.CRITICAL,
            category="secrets",
            message="Gitleaks matched a credential pattern" + where + ". Secrets in git history stay public even after deletion.",
            fix="Rotate the credential with its provider, then remove it from the code. To scrub history, use git filter-repo, "
                "but rotation is what actually protects you.",
            file=str(item.get("File") or "").replace("\\", "/") or None,
            line=int(item.get("StartLine") or 0) or None,
            snippet=snippet[:220],
            confidence="high",
            source="gitleaks",
            cwe=("CWE-798",),
        ))
    return findings


def scan(root: Path, history: bool = False) -> ScannerResult:
    exe = which("gitleaks")
    if not exe:
        return ScannerResult("gitleaks", available=False)
    result = ScannerResult("gitleaks", available=True, version=version_of(exe, "version"))
    with tempfile.TemporaryDirectory() as tmp:
        report = Path(tmp) / "gitleaks.json"
        common = ["--report-format", "json", "--report-path", str(report), "--redact", "--no-banner",
                  "--exit-code", "0", "--log-level", "error"]
        mode = ["git", str(root)] if history and (root / ".git").exists() else ["dir", str(root)]
        try:
            proc = run([exe, *mode, *common], timeout=900)
            if proc.returncode != 0 and not report.exists():
                # Gitleaks before 8.19 only has 'detect'.
                legacy = ["detect", "--source", str(root)] + ([] if mode[0] == "git" else ["--no-git"])
                proc = run([exe, *legacy, *common], timeout=900)
            if not report.exists():
                result.error = (proc.stderr or proc.stdout).strip()[:300] or f"exit code {proc.returncode}"
                return result
            data = json.loads(report.read_text(encoding="utf-8") or "[]")
        except (OSError, ValueError, subprocess.TimeoutExpired) as exc:
            result.error = str(exc)
            return result
    result.ran = True
    result.findings = parse(data if isinstance(data, list) else [], history)
    for finding in result.findings:
        if finding.file and Path(finding.file).is_absolute():
            try:
                finding.file = Path(finding.file).resolve().relative_to(root.resolve()).as_posix()
            except ValueError:
                pass
    return result
