"""Core data types shared by checks, scanners and reports."""

from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass, field
from enum import IntEnum


class Severity(IntEnum):
    INFO = 0
    LOW = 1
    MEDIUM = 2
    HIGH = 3
    CRITICAL = 4

    @property
    def label(self) -> str:
        return self.name.lower()

    @classmethod
    def parse(cls, value: str) -> "Severity":
        return cls[value.strip().upper()]


CATEGORIES: dict[str, str] = {
    "secrets": "Secrets",
    "auth": "Auth and sign-in",
    "authz": "Authorization",
    "abuse": "API abuse and cost",
    "injection": "Injection",
    "payments": "Payments",
    "crypto": "Crypto and randomness",
    "config": "Config and deployment",
    "supply-chain": "Dependencies and supply chain",
    "vibe": "AI-generated code smells",
}


@dataclass
class Finding:
    check_id: str
    title: str
    severity: Severity
    category: str
    message: str = ""
    fix: str = ""
    file: str | None = None
    line: int | None = None
    snippet: str | None = None
    confidence: str = "medium"
    source: str = "ladpock"
    cwe: tuple[str, ...] = ()
    extra: dict = field(default_factory=dict)

    @property
    def fingerprint(self) -> str:
        # Anchored on content rather than line number, so a finding keeps the
        # same reference (and its suppression) when unrelated lines move.
        anchor = re.sub(r"\s+", " ", self.snippet or self.message or "").strip()
        raw = f"{self.check_id}|{self.file or ''}|{anchor}"
        return hashlib.sha1(raw.encode("utf-8")).hexdigest()[:10]

    @property
    def location(self) -> str:
        if not self.file:
            return ""
        return f"{self.file}:{self.line}" if self.line else self.file

    def to_dict(self) -> dict:
        return {
            "ref": self.fingerprint,
            "check_id": self.check_id,
            "title": self.title,
            "severity": self.severity.label,
            "category": self.category,
            "message": self.message,
            "fix": self.fix,
            "file": self.file,
            "line": self.line,
            "snippet": self.snippet,
            "confidence": self.confidence,
            "source": self.source,
            "cwe": list(self.cwe),
            "extra": self.extra,
        }


@dataclass(frozen=True)
class Component:
    """One installed package version, as recorded in a lockfile."""

    ecosystem: str  # OSV ecosystem name: npm, PyPI, crates.io, Go, Packagist, RubyGems
    name: str
    version: str | None
    source: str  # lockfile path relative to the project root


def finding_from_dict(d: dict) -> Finding:
    """Rebuild a Finding saved with Finding.to_dict()."""
    return Finding(
        check_id=d["check_id"], title=d["title"], severity=Severity.parse(d["severity"]), category=d["category"],
        message=d.get("message", ""), fix=d.get("fix", ""), file=d.get("file"), line=d.get("line"),
        snippet=d.get("snippet"), confidence=d.get("confidence", "medium"), source=d.get("source", "ladpock"),
        cwe=tuple(d.get("cwe") or ()), extra=d.get("extra") or {},
    )
