"""Runs a local AI review: resumable, incremental and polite.

- Units already reviewed with the same code, model and prompt are skipped, so
  after the first run only changed code is re-read.
- Progress is saved after every unit, so stopping (deadline, battery, Ctrl+C,
  a reboot) loses nothing; the next run picks up where this one stopped.
"""

from __future__ import annotations

import json
import time
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Callable

from ..db import DB
from ..files import FileIndex
from ..timeutil import iso
from . import prompts
from .client import LocalModelError, OllamaClient
from .grounding import ground
from .system import on_battery
from .units import Unit, build_units, describe

MAX_CONSECUTIVE_ERRORS = 3


@dataclass
class ReviewSummary:
    project: str
    status: str = "done"  # done | paused | stopped | error
    total: int = 0
    cached: int = 0
    done: int = 0
    leads: int = 0
    dropped: int = 0  # quoted code didn't exist
    rejected: int = 0  # failed the model's own second look
    duplicates: int = 0  # the scanner already reports that line
    errors: int = 0
    message: str = ""
    kinds: dict = field(default_factory=dict)


def estimate_seconds(units: list[Unit], prompt_rate: float, output_rate: float, think: bool) -> float:
    """Rough time for these units given measured tokens/second (calibrated on real reviews)."""
    prompt_tokens = sum(len(prompts.SYSTEM) + len(u.code) + len(u.facts) + 400 for u in units) / 3.5
    output_tokens = len(units) * (1500 if think else 450)
    checks = len(units) * 0.3 * (len(prompts.SYSTEM) / 3.5 + 900)  # second-look calls for candidate leads
    return (prompt_tokens + checks) / max(prompt_rate, 1) + output_tokens / max(output_rate, 0.5) + len(units) * 0.3


def _latest_findings(db: DB, project_id: int) -> list[dict]:
    scan = db.latest_scan(project_id)
    return db.scan_findings(scan["id"]) if scan else []


def pending_units(db: DB, project_id: int, model: str) -> tuple[list[Unit], list[Unit]]:
    """(all units, units still to review) for a project."""
    row = db.get_project_by_id(project_id)
    index = FileIndex(row["path"])
    units = build_units(index, _latest_findings(db, project_id))
    done = db.ai_reviewed_units(project_id)
    todo = [u for u in units if done.get(u.key) != (u.content_hash, model, prompts.PROMPT_VERSION)]
    return units, todo


def run_review(db: DB, project_id: int, client: OllamaClient, *, deadline: datetime | None = None,
               should_stop: Callable[[], bool] = lambda: False, log: Callable[[str], None] = print,
               trigger: str = "manual", require_ac: bool = False, max_units: int | None = None,
               progress: Callable[[int, int], None] = lambda _done, _total: None) -> ReviewSummary:
    row = db.get_project_by_id(project_id)
    if not row:
        raise ValueError("Project not found")
    summary = ReviewSummary(row["name"])
    if not Path(row["path"]).is_dir():
        summary.status, summary.message = "error", "Project folder not found"
        return summary

    units, todo = pending_units(db, project_id, client.model or "")
    db.ai_prune(project_id, {u.key for u in units})
    known: dict[str, set[tuple[int, str]]] = {}  # (line, category) the scanner already reports, so leads don't repeat them
    for f in _latest_findings(db, project_id):
        if f.get("file") and f.get("line"):
            known.setdefault(f["file"], set()).add((f["line"], f["category"]))
    summary.total, summary.cached, summary.kinds = len(units), len(units) - len(todo), describe(todo)
    if max_units:
        todo = todo[:max_units]
    log(f"{row['name']}: {len(units)} parts, {summary.cached} unchanged since the last review, {len(todo)} to review "
        f"with {client.model}")
    run_id = db.ai_run_start(project_id, client.model or "", trigger, len(units), summary.cached)

    try:
        progress(0, len(todo))
        _review_all(db, project_id, client, todo, summary, run_id, deadline, should_stop, require_ac, log, known,
                    progress)
    except KeyboardInterrupt:
        summary.status, summary.message = "stopped", "Stopped with Ctrl+C; the next run continues from here"
        raise
    finally:
        db.ai_run_update(run_id, status=summary.status, done=summary.done, leads=summary.leads,
                         dropped=summary.dropped, rejected=summary.rejected, errors=summary.errors,
                         message=summary.message, finished_at=iso())
    log(f"{row['name']}: {summary.status}. Reviewed {summary.done}, {summary.leads} new lead(s). Filtered out: "
        f"{summary.dropped} quoting code that doesn't exist, {summary.rejected} that failed a second look, "
        f"{summary.duplicates} the scanner already reports.")
    return summary


def _review_all(db: DB, project_id: int, client: OllamaClient, todo: list[Unit], summary: ReviewSummary, run_id: int,
                deadline: datetime | None, should_stop: Callable[[], bool], require_ac: bool,
                log: Callable[[str], None], known: dict[str, set[tuple[int, str]]],
                progress: Callable[[int, int], None]) -> None:
    consecutive_errors = 0
    for i, unit in enumerate(todo, 1):
        if should_stop():
            summary.status, summary.message = "stopped", "Stopped; the next run continues from here"
            return
        if deadline and datetime.now() >= deadline:
            summary.status, summary.message = "paused", "Reached the time limit; the next run continues from here"
            return
        if require_ac and on_battery():
            summary.status, summary.message = "paused", "Paused because the computer is on battery"
            return
        started = time.monotonic()
        try:
            _review_unit(db, project_id, client, unit, summary, known)
            consecutive_errors = 0
        except LocalModelError as exc:
            summary.errors += 1
            consecutive_errors += 1
            log(f"  [{i}/{len(todo)}] {unit.title}: {exc}")
            if consecutive_errors >= MAX_CONSECUTIVE_ERRORS:
                summary.status, summary.message = "error", str(exc)
                return
            continue
        summary.done += 1
        progress(i, len(todo))
        log(f"  [{i}/{len(todo)}] {unit.title} ({time.monotonic() - started:.0f}s)")
        db.ai_run_update(run_id, done=summary.done, leads=summary.leads, dropped=summary.dropped,
                         rejected=summary.rejected, errors=summary.errors)


def _review_unit(db: DB, project_id: int, client: OllamaClient, unit: Unit, summary: ReviewSummary,
                 known: dict[str, set[tuple[int, str]]]) -> None:
    if unit.kind == "verdict":
        result, _ = client.chat(prompts.SYSTEM, prompts.verdict_prompt(unit.title, unit.finding_message, unit.code),
                                prompts.VERDICT_SCHEMA)
        verdict = result.get("verdict") if result.get("verdict") in ("real", "false_alarm", "unsure") else "unsure"
        db.ai_save_verdict(project_id, unit.finding_ref or "", verdict, str(result.get("reason", ""))[:600], client.model or "")
    else:
        result, _ = client.chat(prompts.SYSTEM, prompts.review_prompt(unit.kind, unit.title, unit.facts, unit.code),
                                prompts.ISSUES_SCHEMA)
        issues = result.get("issues") if isinstance(result.get("issues"), list) else []
        leads = []
        for issue in issues[:5]:
            lead = ground(issue, unit.lines) if isinstance(issue, dict) else None
            if not lead:
                summary.dropped += 1
            elif any(abs(lead.line - n) <= 2 and cat == lead.category for n, cat in known.get(unit.file, ())):
                summary.duplicates += 1
            elif not _second_look(client, unit, lead):
                summary.rejected += 1
            else:
                leads.append(lead)
        summary.leads += db.ai_save_leads(project_id, unit.key, unit.file, leads, client.model or "")
    db.ai_mark_reviewed(project_id, unit.key, unit.content_hash, client.model or "", prompts.PROMPT_VERSION)


def _second_look(client: OllamaClient, unit: Unit, lead) -> bool:
    """Ask the model to check its own claim against the code. Removes most confident-sounding misreadings."""
    result, _ = client.chat(prompts.SYSTEM, prompts.check_prompt(lead.title, lead.explanation, lead.line, unit.code),
                            prompts.CHECK_SCHEMA)
    return result.get("accurate") is True


def benchmark(client: OllamaClient) -> dict:
    """Time one realistic review on this machine (includes loading the model)."""
    sample_lines = {
        1: "export async function GET(req: Request, { params }: { params: { id: string } }) {",
        2: "  const session = await auth();",
        3: '  if (!session) return Response.json({ error: "unauthorised" }, { status: 401 });',
        4: "  const order = await db.order.findUnique({ where: { id: params.id } });",
        5: "  return Response.json(order);",
        6: "}",
    }
    unit = Unit("benchmark", "route", "app/api/orders/[id]/route.ts", "GET /api/orders/[id]",
                "Auth: yes. Ownership check: no.", sample_lines, [(1, 6)], 0)
    prompt = prompts.review_prompt(unit.kind, unit.title, unit.facts, unit.code)
    started = time.monotonic()
    result, stats = client.chat(prompts.SYSTEM, prompt, prompts.ISSUES_SCHEMA)
    load = stats.load_seconds
    if load > 1:  # the first call loaded the model; time a warm one for realistic rates
        started = time.monotonic()
        result, stats = client.chat(prompts.SYSTEM, prompt, prompts.ISSUES_SCHEMA)
    wall = time.monotonic() - started
    grounded = [ground(i, unit.lines) for i in result.get("issues", []) if isinstance(i, dict)]
    return {
        "model": client.model,
        "seconds": round(wall, 1),
        "load_seconds": round(load, 1),
        "prompt_rate": round(stats.prompt_tokens / stats.prompt_seconds, 1) if stats.prompt_seconds else 0,
        "output_rate": round(stats.output_tokens / stats.output_seconds, 1) if stats.output_seconds else 0,
        "found_sample_bug": any(lead is not None for lead in grounded),
        "raw": json.dumps(result)[:400],
    }
