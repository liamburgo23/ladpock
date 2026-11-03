"""Paid online AI review with Claude. Optional and off until you set it up.

- What's sent: the same review units the local model reads (routes, commands,
  findings worth a second opinion, then the rest of the code), with secrets
  masked first. Nothing is sent for a project marked "never send online".
- What it costs: Anthropic bills your own API account. Every call's cost is
  recorded, and a run stops before it would go over your monthly budget.
  Unchanged code isn't sent again, so later runs only pay for what changed.
- It also gives a second opinion on the local model's open leads.

The Anthropic SDK is an optional install (`pip install anthropic`), so LadPock
itself keeps zero dependencies.
"""

from __future__ import annotations

import importlib.util
import json
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable

from ..db import DB
from ..files import FileIndex
from ..timeutil import iso
from . import keys, prompts
from .grounding import ground
from .units import Unit, _take, build_units, describe

MODEL = "claude-opus-5-5"
PRICE_PER_MTOK = {"input": 4.0, "output": 20.0, "cache_read": 0.4, "cache_write": 5.0}  # US dollars
FALLBACK_BETA = "server-side-fallback-2026-07-01"
EFFORTS = ("low", "medium", "high")
DEFAULT_EFFORT = "medium"
DEFAULT_BUDGET = 5.0
MAX_TOKENS = 16000
KEY_PREFIX = "online:"
# Rough output per call, thinking included, used to stay under the budget before a call is made.
OUTPUT_ESTIMATE = {"low": 900, "medium": 2000, "high": 4500}
MAX_CONSECUTIVE_ERRORS = 3


class OnlineAIError(Exception):
    def __init__(self, message: str, usage: "Usage | None" = None, fatal: bool = False):
        super().__init__(message)
        self.usage = usage
        self.fatal = fatal  # a bad key or an empty account won't fix itself on the next unit


class Declined(OnlineAIError):
    """The model (and its fallback) declined to answer."""


@dataclass
class Usage:
    input_tokens: int = 0
    output_tokens: int = 0
    cache_read: int = 0
    cache_write: int = 0

    @property
    def cost(self) -> float:
        p = PRICE_PER_MTOK
        return (self.input_tokens * p["input"] + self.output_tokens * p["output"] + self.cache_read * p["cache_read"]
                + self.cache_write * p["cache_write"]) / 1_000_000

    @classmethod
    def of(cls, usage) -> "Usage":
        return cls(int(getattr(usage, "input_tokens", 0) or 0), int(getattr(usage, "output_tokens", 0) or 0),
                   int(getattr(usage, "cache_read_input_tokens", 0) or 0),
                   int(getattr(usage, "cache_creation_input_tokens", 0) or 0))


def sdk_installed() -> bool:
    return importlib.util.find_spec("anthropic") is not None


def strict_schema(schema: dict) -> dict:
    """Our Ollama schemas, adjusted for structured outputs: closed objects and no array length limits."""
    if not isinstance(schema, dict):
        return schema
    out = {k: strict_schema(v) if isinstance(v, dict) else v for k, v in schema.items()
           if k not in ("maxItems", "minItems")}
    if "properties" in out:
        out["properties"] = {k: strict_schema(v) for k, v in out["properties"].items()}
    if out.get("type") == "object":
        out["additionalProperties"] = False
    return out


def estimate_cost(units: list[Unit], effort: str = DEFAULT_EFFORT) -> float:
    return sum(unit_cost(len(u.code) + len(u.facts), effort) for u in units)


def unit_cost(chars: int, effort: str = DEFAULT_EFFORT) -> float:
    prompt_tokens = (len(prompts.SYSTEM) + chars + 600) / 3.5
    return Usage(int(prompt_tokens), OUTPUT_ESTIMATE.get(effort, 2000)).cost


def _explain(exc: Exception) -> OnlineAIError:
    """Turn an SDK error into something a person can act on."""
    name = type(exc).__name__
    message = getattr(exc, "message", None) or str(exc)
    if name == "AuthenticationError":
        return OnlineAIError("Anthropic rejected the API key. Check it, or add a new one in settings.", fatal=True)
    if name == "PermissionDeniedError":
        return OnlineAIError(f"This API key isn't allowed to use {MODEL}: {message}", fatal=True)
    if name == "RateLimitError":
        return OnlineAIError("Anthropic is rate limiting this key. Try again in a few minutes.", fatal=True)
    if name == "BadRequestError" and "credit" in message.lower():
        return OnlineAIError("Your Anthropic account is out of credit.", fatal=True)
    if name in ("APIConnectionError", "APITimeoutError"):
        return OnlineAIError("Couldn't reach the Anthropic API. Check your internet connection.", fatal=True)
    return OnlineAIError(f"{name}: {message}"[:400])


def _make_sdk():
    if not sdk_installed():
        raise OnlineAIError("The Anthropic SDK isn't installed. Install it with: python -m pip install anthropic",
                            fatal=True)
    import anthropic

    key = keys.load()
    try:
        # With no saved key the SDK finds one itself: ANTHROPIC_API_KEY or an `ant auth login` profile.
        return anthropic.Anthropic(api_key=key) if key else anthropic.Anthropic()
    except Exception as exc:
        raise OnlineAIError(f"No Anthropic API key found. Add one in the dashboard's AI settings, or set "
                            f"ANTHROPIC_API_KEY. ({exc})", fatal=True) from exc


class OnlineClient:
    def __init__(self, sdk=None, model: str = MODEL, effort: str = DEFAULT_EFFORT):
        self.sdk = sdk if sdk is not None else _make_sdk()
        self.model = model
        self.effort = effort if effort in EFFORTS else DEFAULT_EFFORT

    def chat(self, system: str, user: str, schema: dict) -> tuple[dict, Usage]:
        params = dict(
            model=self.model,
            max_tokens=MAX_TOKENS,
            system=[{"type": "text", "text": system, "cache_control": {"type": "ephemeral"}}],
            messages=[{"role": "user", "content": user}],
            output_config={"effort": self.effort, "format": {"type": "json_schema", "schema": strict_schema(schema)}},
            betas=[FALLBACK_BETA],
            extra_body={"fallbacks": "default"},  # a declined request is retried on Anthropic's recommended model
        )
        try:
            with self.sdk.beta.messages.stream(**params) as stream:
                response = stream.get_final_message()
        except OnlineAIError:
            raise
        except Exception as exc:
            raise _explain(exc) from exc
        usage = Usage.of(response.usage)
        if response.stop_reason == "refusal":
            raise Declined("The model declined to review this part", usage)
        if response.stop_reason == "max_tokens":
            raise OnlineAIError("The answer was cut off before it finished", usage)
        text = next((b.text for b in response.content if getattr(b, "type", "") == "text"), "")
        try:
            result = json.loads(text)
        except json.JSONDecodeError as exc:
            raise OnlineAIError("The answer wasn't valid JSON", usage) from exc
        return (result if isinstance(result, dict) else {}), usage


# settings, kept in the meta table (the key itself never is)


def budget(db: DB) -> float:
    try:
        return max(0.0, float(db.get_meta("online_budget") or DEFAULT_BUDGET))
    except ValueError:
        return DEFAULT_BUDGET


def effort(db: DB) -> str:
    value = db.get_meta("online_effort")
    return value if value in EFFORTS else DEFAULT_EFFORT


def enabled(db: DB) -> bool:
    return db.get_meta("online_enabled") == "1"


def save(db: DB, *, enabled_: bool | None = None, budget_: float | None = None, effort_: str | None = None) -> None:
    if enabled_ is not None:
        db.set_meta("online_enabled", "1" if enabled_ else "0")
    if budget_ is not None:
        if not 0 <= budget_ <= 1000:
            raise ValueError("The monthly budget must be between $0 and $1,000")
        db.set_meta("online_budget", f"{budget_:.2f}")
    if effort_ is not None:
        if effort_ not in EFFORTS:
            raise ValueError(f"Effort must be one of: {', '.join(EFFORTS)}")
        db.set_meta("online_effort", effort_)


def status(db: DB) -> dict:
    key = keys.status()
    spent = db.online_spent()
    return {
        "sdk_installed": sdk_installed(), "key": key, "enabled": enabled(db), "model": MODEL, "effort": effort(db),
        "efforts": list(EFFORTS), "budget": budget(db), "spent": round(spent, 4),
        "left": round(max(0.0, budget(db) - spent), 4),
        "ready": sdk_installed() and enabled(db) and (key["stored"] or key["env"]),
        "prices": PRICE_PER_MTOK,
    }


# the review


@dataclass
class OnlineSummary:
    project: str
    status: str = "done"  # done | stopped | budget | error | skipped
    total: int = 0
    cached: int = 0
    done: int = 0
    leads: int = 0
    dropped: int = 0
    duplicates: int = 0
    declined: int = 0
    verified: int = 0
    errors: int = 0
    cost: float = 0.0
    message: str = ""
    kinds: dict = field(default_factory=dict)


def _latest_findings(db: DB, project_id: int) -> list[dict]:
    scan = db.latest_scan(project_id)
    return db.scan_findings(scan["id"]) if scan else []


def pending_units(db: DB, project_id: int, model: str = MODEL) -> tuple[list[Unit], list[Unit]]:
    row = db.get_project_by_id(project_id)
    units = build_units(FileIndex(row["path"]), _latest_findings(db, project_id))
    done = db.ai_reviewed_units(project_id)
    todo = [u for u in units if done.get(KEY_PREFIX + u.key) != (u.content_hash, model, prompts.PROMPT_VERSION)]
    return units, todo


def plan(db: DB, project_id: int) -> dict:
    """What an online review of this project would send and roughly cost, before anything is sent."""
    row = db.get_project_by_id(project_id)
    if not row or not Path(row["path"]).is_dir():
        return {"units": 0, "cost": 0.0, "never": bool(row and row["online_never"])}
    units, todo = pending_units(db, project_id)
    leads = db.ai_leads_to_verify(project_id, MODEL)
    level = effort(db)
    cost = estimate_cost(todo, level) + len(leads) * unit_cost(4000, level)
    return {"units": len(todo), "total": len(units), "leads": len(leads), "cost": round(cost, 2),
            "kinds": describe(todo), "never": bool(row["online_never"])}


def run_online_review(db: DB, project_id: int, client: OnlineClient, *, should_stop: Callable[[], bool] = lambda: False,
                      log: Callable[[str], None] = print, limit: float | None = None,
                      progress: Callable[[int, int], None] = lambda _done, _total: None) -> OnlineSummary:
    row = db.get_project_by_id(project_id)
    if not row:
        raise ValueError("Project not found")
    summary = OnlineSummary(row["name"])
    if row["online_never"]:
        summary.status, summary.message = "skipped", "This project is set to never be sent online"
        return summary
    if not Path(row["path"]).is_dir():
        summary.status, summary.message = "error", "Project folder not found"
        return summary

    limit = budget(db) if limit is None else limit
    units, todo = pending_units(db, project_id, client.model)
    db.ai_prune(project_id, {u.key for u in units})
    leads = db.ai_leads_to_verify(project_id, client.model)
    summary.total, summary.cached, summary.kinds = len(units), len(units) - len(todo), describe(todo)
    log(f"{row['name']}: {len(todo)} part(s) to send to {client.model} ({summary.cached} unchanged since its last "
        f"review), plus {len(leads)} local lead(s) to double-check. Spent this month: ${db.online_spent():.2f} of "
        f"${limit:.2f}.")
    run_id = db.ai_run_start(project_id, client.model, "online", len(units), summary.cached)
    known: dict[str, set[tuple[int, str]]] = {}
    for f in _latest_findings(db, project_id):
        if f.get("file") and f.get("line"):
            known.setdefault(f["file"], set()).add((f["line"], f["category"]))
    index = FileIndex(row["path"])
    steps = [("lead", lead) for lead in leads] + [("unit", unit) for unit in todo]
    errors_in_a_row = 0
    try:
        progress(0, len(steps))
        for i, (kind, item) in enumerate(steps, 1):
            if should_stop():
                summary.status, summary.message = "stopped", "Stopped; the next run continues from here"
                break
            chars = 8000 if kind == "lead" else len(item.code) + len(item.facts)
            if db.online_spent() + unit_cost(chars, client.effort) > limit:
                summary.status = "budget"
                summary.message = (f"Stopped at your monthly budget (${limit:.2f}). Raise it in AI settings to "
                                   "continue; the next run picks up where this one stopped.")
                break
            started = time.monotonic()
            try:
                if kind == "lead":
                    _verify_lead(db, client, index, item, summary, project_id)
                else:
                    _review_unit(db, project_id, client, item, summary, known)
                errors_in_a_row = 0
            except OnlineAIError as exc:
                if exc.usage:
                    _record(db, project_id, client, exc.usage, summary)
                if isinstance(exc, Declined):
                    summary.declined += 1
                    if kind == "unit":  # don't pay to ask again until the code changes
                        db.ai_mark_reviewed(project_id, KEY_PREFIX + item.key, item.content_hash, client.model,
                                            prompts.PROMPT_VERSION)
                    log(f"  [{i}/{len(steps)}] declined: {_title(kind, item)}")
                    continue
                summary.errors += 1
                errors_in_a_row += 1
                log(f"  [{i}/{len(steps)}] {_title(kind, item)}: {exc}")
                if exc.fatal or errors_in_a_row >= MAX_CONSECUTIVE_ERRORS:
                    summary.status, summary.message = "error", str(exc)
                    break
                continue
            progress(i, len(steps))
            log(f"  [{i}/{len(steps)}] {_title(kind, item)} ({time.monotonic() - started:.0f}s, "
                f"${summary.cost:.2f} so far)")
            db.ai_run_update(run_id, done=summary.done, leads=summary.leads, dropped=summary.dropped,
                             errors=summary.errors)
    finally:
        db.ai_run_update(run_id, status=summary.status, done=summary.done, leads=summary.leads,
                         dropped=summary.dropped, errors=summary.errors, finished_at=iso(),
                         message=summary.message or f"Cost ${summary.cost:.2f}")
    log(f"{row['name']}: {summary.status}. Reviewed {summary.done} part(s), {summary.leads} new lead(s), "
        f"double-checked {summary.verified} local lead(s). Cost about ${summary.cost:.2f}.")
    return summary


def _title(kind: str, item) -> str:
    return f"check local lead: {item['title']}" if kind == "lead" else item.title


def _record(db: DB, project_id: int, client: OnlineClient, usage: Usage, summary: OnlineSummary) -> None:
    db.online_record(project_id, client.model, usage.input_tokens, usage.output_tokens, usage.cache_read,
                     usage.cache_write, usage.cost)
    summary.cost += usage.cost


def _review_unit(db: DB, project_id: int, client: OnlineClient, unit: Unit, summary: OnlineSummary,
                 known: dict[str, set[tuple[int, str]]]) -> None:
    if unit.kind == "verdict":
        result, usage = client.chat(prompts.SYSTEM, prompts.verdict_prompt(unit.title, unit.finding_message, unit.code),
                                    prompts.VERDICT_SCHEMA)
        _record(db, project_id, client, usage, summary)
        verdict = result.get("verdict") if result.get("verdict") in ("real", "false_alarm", "unsure") else "unsure"
        db.ai_save_verdict(project_id, unit.finding_ref or "", verdict, str(result.get("reason", ""))[:600], client.model)
    else:
        result, usage = client.chat(prompts.SYSTEM, prompts.review_prompt(unit.kind, unit.title, unit.facts, unit.code),
                                    prompts.ISSUES_SCHEMA)
        _record(db, project_id, client, usage, summary)
        issues = result.get("issues") if isinstance(result.get("issues"), list) else []
        leads = []
        for issue in issues[:8]:
            lead = ground(issue, unit.lines) if isinstance(issue, dict) else None
            if not lead:
                summary.dropped += 1
            elif any(abs(lead.line - n) <= 2 and cat == lead.category for n, cat in known.get(unit.file, ())):
                summary.duplicates += 1
            else:
                leads.append(lead)
        summary.leads += db.ai_save_leads(project_id, KEY_PREFIX + unit.key, unit.file, leads, client.model)
    db.ai_mark_reviewed(project_id, KEY_PREFIX + unit.key, unit.content_hash, client.model, prompts.PROMPT_VERSION)
    summary.done += 1


def _verify_lead(db: DB, client: OnlineClient, index: FileIndex, lead, summary: OnlineSummary,
                 project_id: int) -> None:
    """Ask the stronger online model whether a local model's lead holds up."""
    if not lead["file"] or not index.exists(lead["file"]):
        db.ai_set_online_verdict(lead["id"], "unsure", "The file no longer exists")
        return
    lines: dict[int, str] = {}
    line = int(lead["line"] or 1)
    start, end = _take(index, lead["file"], line - 40, line + 40, lines)
    code = "\n".join(f"{n:>5}| {lines[n]}" for n in range(start, end + 1) if n in lines)
    result, usage = client.chat(prompts.SYSTEM, prompts.check_prompt(lead["title"], lead["explanation"] or "", line, code),
                                prompts.CHECK_SCHEMA)
    _record(db, project_id, client, usage, summary)
    db.ai_set_online_verdict(lead["id"], "confirmed" if result.get("accurate") is True else "doubtful",
                             str(result.get("reason", ""))[:600])
    summary.verified += 1
