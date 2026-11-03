"""`ladpock ai ...` commands."""

from __future__ import annotations

import argparse
import sys
from datetime import datetime
from pathlib import Path

from ..db import DB
from . import settings, system
from .client import LocalModelError
from .review import benchmark, estimate_seconds, pending_units, run_review


def add_parser(sub) -> None:
    ai = sub.add_parser("ai", help="local AI review with a model on this computer (Ollama)")
    actions = ai.add_subparsers(dest="ai_command", required=True)

    actions.add_parser("status", help="show Ollama, installed models and the nightly schedule")

    use = actions.add_parser("use", help="choose the model LadPock uses")
    use.add_argument("model")
    use.add_argument("--think", action=argparse.BooleanOptionalAction, default=None,
                     help="let reasoning models think before answering (slower, sometimes better)")

    bench = actions.add_parser("benchmark", help="time the model on this computer and estimate a full review")
    bench.add_argument("path", nargs="?")
    bench.add_argument("--model")

    review = actions.add_parser("review", help="review a project now (resumes where the last run stopped)")
    review.add_argument("path", nargs="?", default=".")
    review.add_argument("--all", action="store_true", help="review every project with nightly review switched on")
    review.add_argument("--model")
    review.add_argument("--think", action=argparse.BooleanOptionalAction, default=None)
    review.add_argument("--until", help="stop at this local time, e.g. 07:00")
    review.add_argument("--max-minutes", type=int)
    review.add_argument("--limit", type=int, help="review at most this many parts")
    review.add_argument("--require-ac", action="store_true", help="pause if the computer switches to battery")
    review.add_argument("--no-scan", action="store_true", help="with --all, skip the static scan before reviewing")
    review.add_argument("--log-file", help="also append progress to this file")

    leads = actions.add_parser("leads", help="list what the AI review found")
    leads.add_argument("path", nargs="?", default=".")

    nightly = actions.add_parser("nightly", help="include or exclude a project from the nightly review")
    nightly.add_argument("state", choices=["on", "off"])
    nightly.add_argument("path", nargs="?", default=".")

    sched = actions.add_parser("schedule", help="run the review every night (Windows Task Scheduler)")
    sched.add_argument("--at", default="01:00")
    sched.add_argument("--until", default="07:00")
    sched.add_argument("--wake", action="store_true", help="wake the computer from sleep to run it")
    sched.add_argument("--yes", action="store_true", help="don't ask for confirmation")

    actions.add_parser("unschedule", help="remove the nightly task")

    paid = actions.add_parser("online", help="paid online AI review with Claude (your Anthropic API key, your budget)")
    online_actions = paid.add_subparsers(dest="online_command", required=True)
    online_actions.add_parser("status", help="show the key, budget and spend this month")
    online_actions.add_parser("key", help="save your Anthropic API key in Windows Credential Manager")
    online_actions.add_parser("forget-key", help="remove the saved key")
    setup = online_actions.add_parser("set", help="turn the online review on or off, set the budget and effort")
    setup.add_argument("--enable", action=argparse.BooleanOptionalAction, default=None,
                       help="allow LadPock to send redacted code to Anthropic")
    setup.add_argument("--budget", type=float, help="monthly limit in US dollars (default 5)")
    setup.add_argument("--effort", choices=["low", "medium", "high"], help="how hard the model thinks (and costs)")
    paid_review = online_actions.add_parser("review", help="review a project now, after showing the estimated cost")
    paid_review.add_argument("path", nargs="?", default=".")
    paid_review.add_argument("--yes", action="store_true", help="don't ask for confirmation")
    never = online_actions.add_parser("never", help="never send this project online (on), or allow it again (off)")
    never.add_argument("state", choices=["on", "off"])
    never.add_argument("path", nargs="?", default=".")


def _project(db: DB, path: str):
    root = Path(path).resolve()
    if not root.is_dir():
        raise FileNotFoundError(f"{root} is not a folder")
    row = db.get_project(root)
    return row or db.get_project_by_id(db.upsert_project(root))


def _logger(log_file: str | None):
    handle = open(log_file, "a", encoding="utf-8") if log_file else None

    def log(message: str) -> None:
        print(message, flush=True)
        if handle:
            handle.write(f"{datetime.now():%Y-%m-%d %H:%M:%S} {message}\n")
            handle.flush()

    return log


def run(args, db: DB) -> int:
    try:
        return _dispatch(args, db)
    except LocalModelError as exc:
        print(f"Local AI: {exc}", file=sys.stderr)
        print("Is Ollama running? Install it from https://ollama.com and pull a model, e.g. ollama pull qwen2.5-coder:14b",
              file=sys.stderr)
        return 2


def _online(args, db: DB) -> int:
    from . import keys, online

    cmd = args.online_command
    if cmd == "status":
        info = online.status(db)
        key = info["key"]
        print(f"Anthropic SDK: {'installed' if info['sdk_installed'] else 'not installed (python -m pip install anthropic)'}")
        print(f"API key: {key['masked'] or ('from ANTHROPIC_API_KEY' if key['env'] else 'not set (ladpock ai online key)')}")
        print(f"Online review: {'on' if info['enabled'] else 'off (ladpock ai online set --enable)'}, model "
              f"{info['model']}, effort {info['effort']}")
        print(f"Spent this month: ${info['spent']:.2f} of ${info['budget']:.2f}")
        return 0
    if cmd == "key":
        import getpass

        try:
            keys.store(getpass.getpass("Paste your Anthropic API key (it won't be shown): "))
        except keys.KeyError_ as exc:
            print(exc, file=sys.stderr)
            return 2
        print(f"Saved {keys.masked(keys.load())} in Windows Credential Manager.")
        return 0
    if cmd == "forget-key":
        print("Removed the saved key." if keys.delete() else "No saved key.")
        return 0
    if cmd == "set":
        try:
            online.save(db, enabled_=args.enable, budget_=args.budget, effort_=args.effort)
        except ValueError as exc:
            print(exc, file=sys.stderr)
            return 2
        return _online(argparse.Namespace(online_command="status"), db)
    project = _project(db, args.path)
    if cmd == "never":
        db.set_online_never(project["id"], args.state == "on")
        print(f"{project['name']}: {'never sent online' if args.state == 'on' else 'may be sent to the online review'}")
        return 0
    if not online.enabled(db):
        print("The online review is off. Turn it on with: ladpock ai online set --enable", file=sys.stderr)
        return 2
    plan = online.plan(db, project["id"])
    info = online.status(db)
    print(f"{project['name']}: {plan['units']} part(s) and {plan['leads']} local lead(s) to send, about "
          f"${plan['cost']:.2f} (up to ${info['left']:.2f} left this month). Secrets are masked before sending.")
    if not args.yes:
        from ..cli import ask_yes

        if not ask_yes("Send them to Anthropic now? [y/N] "):
            return 1
    try:
        summary = online.run_online_review(db, project["id"], online.OnlineClient(effort=online.effort(db)))
    except online.OnlineAIError as exc:
        print(exc, file=sys.stderr)
        return 2
    if summary.message:
        print(summary.message)
    return 0 if summary.status in ("done", "budget") else 1


def _dispatch(args, db: DB) -> int:
    cmd = args.ai_command
    if cmd == "online":
        return _online(args, db)
    if cmd == "status":
        info = settings.status(db)
        if not info["available"]:
            print(f"Ollama: not reachable ({info.get('error')})")
        else:
            gpu = f" (GPU memory {info['gpu_gb']} GB)" if info["gpu_gb"] else ""
            print(f"Ollama: running{gpu}")
            for m in info["models"]:
                mark = "*" if m["name"] == info["model"] else " "
                fit = "fits GPU" if m["fits_gpu"] else "larger than GPU memory: slower"
                print(f"  {mark} {m['name']:<28} {m['size_gb']:>5} GB  {m['parameters']:>7}  {fit}")
            print(f"Using: {info['model']}  (thinking {'on' if info['think'] else 'off'}). Change with: ladpock ai use <model>")
        sched = system.schedule_status()
        if sched.get("scheduled"):
            print(f"Nightly review: scheduled, next run {sched['next_run']}")
        else:
            print("Nightly review: not scheduled. Set up with: ladpock ai schedule")
        nightly = db.ai_nightly_projects()
        print(f"Projects in the nightly review: {', '.join(p['name'] for p in nightly) or 'none (ladpock ai nightly on <path>)'}")
        return 0

    if cmd == "use":
        client = settings.make_client(db, model=args.model)  # validates it's installed
        settings.save(db, model=client.model, think=args.think)
        print(f"LadPock will use {client.model}" + ("" if args.think is None else f", thinking {'on' if args.think else 'off'}"))
        return 0

    if cmd == "benchmark":
        client = settings.make_client(db, model=args.model)
        print(f"Timing {client.model} on a sample review (the first call loads the model) ...")
        result = benchmark(client)
        print(f"  Model load: {result['load_seconds']}s. Sample review: {result['seconds']}s. "
              f"Reading {result['prompt_rate']} tokens/s, writing {result['output_rate']} tokens/s.")
        print(f"  Found the planted ownership bug: {'yes' if result['found_sample_bug'] else 'no'}")
        if args.path:
            project = _project(db, args.path)
            units, todo = pending_units(db, project["id"], client.model)
            seconds = estimate_seconds(todo, result["prompt_rate"], result["output_rate"], client.think)
            print(f"  {project['name']}: {len(todo)} of {len(units)} parts to review, about {_duration(seconds)}.")
        return 0

    if cmd == "review":
        client = settings.make_client(db, model=args.model, think=args.think)
        log = _logger(args.log_file)
        deadline = system.deadline_from(args.until, args.max_minutes)
        if args.all:
            projects = db.ai_nightly_projects()
            if not projects:
                log("No projects have nightly review switched on. Use: ladpock ai nightly on <path>")
                return 0
            system.lower_priority()
        else:
            projects = [_project(db, args.path)]
        with system.keep_awake():
            for project in projects:
                if deadline and datetime.now() >= deadline:
                    log("Reached the time limit.")
                    break
                if args.all and not args.no_scan and Path(project["path"]).is_dir():
                    from ..scan import run_scan

                    result = run_scan(project["path"], db, log=lambda _m: None)
                    log(f"{project['name']}: static scan grade {result.scorecard.grade}")
                run_review(db, project["id"], client, deadline=deadline, log=log,
                           trigger="nightly" if args.all else "manual", require_ac=args.require_ac,
                           max_units=args.limit)
        return 0

    if cmd == "leads":
        project = _project(db, args.path)
        leads = db.ai_leads(project["id"])
        if not leads:
            print("No AI leads yet. Run: ladpock ai review")
        for lead in leads:
            status = "" if lead["status"] == "new" else f" [{lead['status']}]"
            print(f"{lead['severity']:<7} {lead['title']}{status}\n        {lead['file']}:{lead['line']}  > {lead['quote']}\n"
                  f"        {lead['explanation']}\n")
        return 0

    if cmd == "nightly":
        project = _project(db, args.path)
        db.set_ai_nightly(project["id"], args.state == "on")
        print(f"Nightly review {'on' if args.state == 'on' else 'off'} for {project['name']}")
        return 0

    if cmd == "schedule":
        program, arguments, _ = system.task_command(args.until)
        print("This creates a Windows scheduled task (only for your user account) that runs every night:")
        print(f"  {args.at}: {Path(program).name} {arguments}")
        print("  Only when plugged in. Stops on battery and at the --until time." +
              (" Wakes the computer from sleep." if args.wake else ""))
        from ..cli import ask_yes

        if not args.yes and not ask_yes("Create it? [y/N] "):
            print("Cancelled.")
            return 1
        system.schedule(args.at, args.until, args.wake)
        print("Scheduled. Remove it any time with: ladpock ai unschedule")
        return 0

    if cmd == "unschedule":
        print("Removed the nightly task." if system.unschedule() else "There was no nightly task.")
        return 0
    return 2


def _duration(seconds: float) -> str:
    minutes = seconds / 60
    if minutes < 2:
        return "a minute or two"
    if minutes < 90:
        return f"{round(minutes)} minutes"
    return f"{minutes / 60:.1f} hours"
