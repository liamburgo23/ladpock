"""The grounding check: a lead is kept only if the code it quotes really exists
in what the model was shown. This removes most invented findings cheaply."""

from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass

from ..models import CATEGORIES

_LINE_PREFIX = re.compile(r"^\s*\d+\s*\|\s?")
_COMMENT = re.compile(r"^(?://|#|/\*|\*|<!--|--|\"\"\"|''')")
SEVERITY_CAP = {"critical": "high"}  # AI leads top out at high; only the scanner can say critical
MIN_QUOTE = 8


@dataclass
class Lead:
    title: str
    severity: str
    category: str
    line: int
    quote: str
    explanation: str
    fix: str

    @property
    def fingerprint(self) -> str:
        return hashlib.sha1(f"{self.category}|{normalize(self.quote)}".encode("utf-8")).hexdigest()[:12]


def normalize(text: str) -> str:
    text = _LINE_PREFIX.sub("", text.strip().strip("`").strip())
    return re.sub(r"\s+", " ", text).strip()


def ground(issue: dict, lines: dict[int, str]) -> Lead | None:
    """Return a Lead pinned to the real line, or None if the quote isn't in the code."""
    quote_lines = [normalize(part) for part in str(issue.get("quote", "")).splitlines()]
    quote_lines = [q for q in quote_lines if q]
    if not quote_lines or len(" ".join(quote_lines)) < MIN_QUOTE:
        return None
    normalized = {n: normalize(text) for n, text in lines.items()}
    first = quote_lines[0]
    candidates = [n for n, text in normalized.items() if first and first in text]
    if not candidates:
        return None
    for extra in quote_lines[1:]:
        if not any(extra in text for text in normalized.values()):
            return None
    try:
        claimed = int(issue.get("line") or 0)
    except (TypeError, ValueError):
        claimed = 0
    line = min(candidates, key=lambda n: abs(n - claimed))
    if _COMMENT.match(normalized[line]):
        return None  # a lead has to point at code; comments describe intent, they don't do anything
    severity = str(issue.get("severity", "medium")).lower()
    severity = SEVERITY_CAP.get(severity, severity if severity in ("high", "medium", "low") else "medium")
    category = str(issue.get("category", "vibe"))
    return Lead(
        title=str(issue.get("title", "Possible security issue")).strip()[:160] or "Possible security issue",
        severity=severity,
        category=category if category in CATEGORIES else "vibe",
        line=line,
        quote=lines[line].strip()[:300],
        explanation=str(issue.get("explanation", "")).strip()[:1200],
        fix=str(issue.get("fix", "")).strip()[:800],
    )
