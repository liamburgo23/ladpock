"""CVSS v3.x base score calculator (FIRST specification, section 7)."""

from __future__ import annotations

import math

from .models import Severity

_AV = {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.2}
_AC = {"L": 0.77, "H": 0.44}
_PR_UNCHANGED = {"N": 0.85, "L": 0.62, "H": 0.27}
_PR_CHANGED = {"N": 0.85, "L": 0.68, "H": 0.5}
_UI = {"N": 0.85, "R": 0.62}
_CIA = {"H": 0.56, "L": 0.22, "N": 0.0}


def _roundup(value: float) -> float:
    as_int = round(value * 100000)
    if as_int % 10000 == 0:
        return as_int / 100000.0
    return (math.floor(as_int / 10000) + 1) / 10.0


def base_score(vector: str) -> float | None:
    if not vector.startswith("CVSS:3"):
        return None
    try:
        metrics = dict(part.split(":", 1) for part in vector.split("/")[1:])
        changed = metrics["S"] == "C"
        av, ac, ui = _AV[metrics["AV"]], _AC[metrics["AC"]], _UI[metrics["UI"]]
        pr = (_PR_CHANGED if changed else _PR_UNCHANGED)[metrics["PR"]]
        c, i, a = _CIA[metrics["C"]], _CIA[metrics["I"]], _CIA[metrics["A"]]
    except (KeyError, ValueError):
        return None
    iss = 1 - (1 - c) * (1 - i) * (1 - a)
    impact = 7.52 * (iss - 0.029) - 3.25 * (iss - 0.02) ** 15 if changed else 6.42 * iss
    if impact <= 0:
        return 0.0
    exploitability = 8.22 * av * ac * pr * ui
    total = impact + exploitability
    return _roundup(min(1.08 * total if changed else total, 10))


def severity_for(score: float) -> Severity:
    if score >= 9.0:
        return Severity.CRITICAL
    if score >= 7.0:
        return Severity.HIGH
    if score >= 4.0:
        return Severity.MEDIUM
    if score > 0:
        return Severity.LOW
    return Severity.INFO
