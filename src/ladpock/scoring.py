"""Turns findings into category grades and an overall score."""

from __future__ import annotations

from dataclasses import dataclass, field

from .models import CATEGORIES, Finding, Severity

WEIGHTS = {Severity.CRITICAL: 40, Severity.HIGH: 20, Severity.MEDIUM: 8, Severity.LOW: 2, Severity.INFO: 0}
CATEGORY_FLOOR = {Severity.MEDIUM: 70, Severity.LOW: 83, Severity.INFO: 100}
_GRADES = [
    (97, "A+"), (93, "A"), (90, "A-"), (87, "B+"), (83, "B"), (80, "B-"),
    (77, "C+"), (73, "C"), (70, "C-"), (67, "D+"), (63, "D"), (60, "D-"),
]


def grade(score: int) -> str:
    for threshold, letter in _GRADES:
        if score >= threshold:
            return letter
    return "F"


def weight(finding: Finding) -> float:
    base = WEIGHTS[finding.severity]
    return base / 2 if finding.confidence == "low" else base


@dataclass
class CategoryScore:
    key: str
    name: str
    score: int
    grade: str
    counts: dict[str, int] = field(default_factory=dict)


@dataclass
class Scorecard:
    overall: int
    grade: str
    categories: list[CategoryScore]
    counts: dict[str, int]


def _counts(findings: list[Finding]) -> dict[str, int]:
    counts: dict[str, int] = {}
    for f in findings:
        counts[f.severity.label] = counts.get(f.severity.label, 0) + 1
    return counts


def score(findings: list[Finding], categories: set[str] | None = None) -> Scorecard:
    keys = categories if categories is not None else set(CATEGORIES)
    keys = keys | {f.category for f in findings}
    cats = []
    for key in CATEGORIES:
        if key not in keys:
            continue
        in_cat = [f for f in findings if f.category == key]
        value = max(0, round(100 - sum(weight(f) for f in in_cat)))
        # Many small issues shouldn't fail a category on their own: only critical or high findings can
        # take it below C-, and only medium ones below B.
        worst_in_cat = max((f.severity for f in in_cat), default=Severity.INFO)
        value = max(value, CATEGORY_FLOOR.get(worst_in_cat, 0))
        cats.append(CategoryScore(key, CATEGORIES[key], value, grade(value), _counts(in_cat)))

    overall = round(sum(c.score for c in cats) / len(cats)) if cats else 100
    # An open critical or high issue caps the grade: a project with a leaked
    # key shouldn't read as "B" just because everything else is tidy.
    worst = max((f.severity for f in findings if f.confidence != "low"), default=Severity.INFO)
    if worst == Severity.CRITICAL:
        overall = min(overall, 59)
    elif worst == Severity.HIGH:
        overall = min(overall, 79)
    return Scorecard(overall, grade(overall), cats, _counts(findings))


# explaining a grade

CAPS = {Severity.CRITICAL: 59, Severity.HIGH: 79}
SEVERITY_ORDER = [Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW]


def explain(findings: list[Finding], categories: set[str] | None = None) -> dict:
    """Why a project got its grade, and the grade it would reach after each round of fixes."""
    card = score(findings, categories)
    average = round(sum(c.score for c in card.categories) / len(card.categories)) if card.categories else 100
    capping = max((f.severity for f in findings if f.confidence != "low"), default=Severity.INFO)
    cap = None
    if capping in CAPS and average > CAPS[capping]:
        cap = {
            "severity": capping.label,
            "limit": CAPS[capping],
            "refs": [f.fingerprint for f in findings if f.severity == capping and f.confidence != "low"],
        }

    cats = []
    for cat in card.categories:
        in_cat = [f for f in findings if f.category == cat.key]
        raw = round(100 - sum(weight(f) for f in in_cat))
        deductions = sorted(
            ({"ref": f.fingerprint, "check_id": f.check_id, "title": f.title, "severity": f.severity.label,
              "confidence": f.confidence, "points": weight(f), "file": f.file, "line": f.line} for f in in_cat),
            key=lambda d: (-d["points"], d["title"]))
        cats.append({"key": cat.key, "name": cat.name, "score": cat.score, "grade": cat.grade, "raw": raw,
                     "floored": cat.score > max(raw, 0), "deductions": deductions})

    # The path to A+: fix the worst severity first, since that's what lifts the caps.
    plan, remaining = [], list(findings)
    for level in SEVERITY_ORDER:
        fixing = [f for f in remaining if f.severity == level]
        if not fixing:
            continue
        remaining = [f for f in remaining if f.severity != level]
        after = score(remaining, categories)
        plan.append({"severity": level.label, "refs": [f.fingerprint for f in fixing], "count": len(fixing),
                     "score": after.overall, "grade": after.grade})

    return {"score": card.overall, "grade": card.grade, "average": average, "cap": cap, "categories": cats,
            "plan": plan, "perfect": not findings}
