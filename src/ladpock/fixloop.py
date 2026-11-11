"""Fixing findings one at a time, from a chat with an AI assistant.

The assistant does the editing; LadPock decides what's next, checks each fix with a fresh scan, and keeps the
record the dashboard shows. LadPock still never edits or commits code itself.

- **One finding at a time, worst first.** A fix counts only when a re-scan no longer finds it, and the same check
  doesn't turn up again in the same file under a new ref (the code changed but the problem didn't).
- **New problems join the list.** Anything the re-scan finds that wasn't there when the run started is added, at
  its own severity, so a fix that breaks something else gets fixed too.
- **The assistant stops on trouble.** Two failed tries, or a fix that introduces something high or critical, ends
  in STOP and a question for the person.
- **Accepting a risk is visible, never hiding.** The assistant can accept a non-critical finding with a written
  reason and an expiry of at most a year. It's listed under Known risks, labelled as accepted by the assistant,
  and the person can undo it from the dashboard. Critical findings need the person.
"""

from __future__ import annotations

import re
import shutil
import subprocess
from datetime import timedelta
from pathlib import Path

from . import github
from .db import DB
from .gitutil import safe_env
from .models import Severity
from .scan import ScanResult, run_scan
from .timeutil import iso, now

SCOPES = ("critical", "high", "medium", "low", "all")
OPEN = ("queued", "working")
MAX_TRIES = 2
MIN_REASON = 15
MAX_ACCEPT_DAYS = 365
REMOTE = re.compile(r"github\.com[:/]+([A-Za-z0-9-]+)/([A-Za-z0-9._-]+?)(?:\.git)?/?\s*$")

RULES = """How this works:
1. Fix only the finding LadPock gives you, with the smallest change that does it. Don't refactor unrelated code.
2. When it's done, call ladpock_fix_check. LadPock re-scans and tells you whether the fix worked, then gives you the next one.
3. If a fix would change what users see or can do (a page now needs signing in, a setting changes, an endpoint goes away),
   or you're not sure the finding is a real problem, ask the user before changing anything.
4. If it isn't a real problem, or it's a deliberate choice, call ladpock_accept_risk with a clear reason (not allowed for
   critical findings), or ladpock_fix_skip to leave it for the user. Never hide a finding with ignore comments or config.
5. When LadPock says STOP, stop and ask the user."""


class FixError(Exception):
    """Something the assistant should tell the person, in words they can act on."""


# ---------- settings and projects ----------

def commits_enabled(db: DB) -> bool:
    return db.get_meta("fix_commits") != "0"


def set_commits(db: DB, enabled: bool) -> None:
    db.set_meta("fix_commits", "1" if enabled else "0")


def find_project(db: DB, path: str | Path):
    """The folder a chat is working in, and its LadPock project if there is one (a parent folder counts)."""
    if not str(path or "").strip() or not Path(path).expanduser().is_absolute():
        raise FixError("path must be the absolute path of the folder you're working in")
    root = Path(path).expanduser().resolve()
    if not root.is_dir():
        raise FixError(f"{root} is not a folder")
    for folder in (root, *root.parents):
        row = db.get_project(folder)
        if row:
            return folder, row
    return root, None


def github_remote(root: Path) -> str | None:
    """owner/repo if this folder is a clone of a GitHub repository. Reads .git/config as text: no git runs."""
    try:
        text = (root / ".git" / "config").read_text(encoding="utf-8", errors="replace")[:100_000]
    except OSError:
        return None
    section = None
    for line in text.splitlines():
        line = line.strip()
        if line.startswith("["):
            section = line
        elif section == '[remote "origin"]' and line.replace(" ", "").startswith("url="):
            match = REMOTE.search(line.split("=", 1)[1].strip())
            return f"{match.group(1)}/{match.group(2)}" if match else None
    return None


def _refuse_github_copy(root: Path) -> None:
    name = github.managed_name(root)
    if name:
        raise FixError(f"This folder is LadPock's own copy of {name}. It's reset from GitHub before every scan, so fixes made here "
                       f"would be lost. Open your own clone of github.com/{name} and run this from there.")


def _is_git(root: Path) -> bool:
    return (root / ".git").exists() and bool(shutil.which("git"))


def _recent_commits(root: Path) -> list[tuple[str, str]]:
    git = shutil.which("git")
    if not git:
        return []
    try:
        proc = subprocess.run([git, "-c", "core.fsmonitor=false", "-C", str(root), "log", "-n", "50", "--format=%h%x00%s"],
                              capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=20, env=safe_env(),
                              stdin=subprocess.DEVNULL)
    except (OSError, subprocess.SubprocessError):
        return []
    if proc.returncode != 0:
        return []
    return [tuple(line.split("\0", 1)) for line in proc.stdout.splitlines() if "\0" in line]  # type: ignore[misc]


def note_commits(db: DB, run, root: Path) -> None:
    """Match commits to fixes by the ref in their message, so the dashboard can show which commit fixed what."""
    # Only fixes from the last day: after that, a fix nobody committed shouldn't cost a git call on every look.
    recent = iso(now() - timedelta(days=1))
    waiting = [i for i in db.fix_items(run["id"]) if i["status"] == "fixed" and not i["commit_sha"] and (i["updated_at"] or "") >= recent]
    if not waiting or not run["commits"]:
        return
    commits = _recent_commits(root)
    for item in waiting:
        sha = next((sha for sha, subject in commits if item["ref"] in subject), None)
        if sha:
            db.fix_item_update(run["id"], item["ref"], commit_sha=sha)


# ---------- the loop ----------

def _rank(item) -> int:
    try:
        return int(Severity.parse(item["severity"] or "info"))
    except (KeyError, ValueError):
        return 0


def _brief(f: dict) -> dict:
    return {k: f.get(k) for k in ("ref", "check_id", "title", "severity", "file", "line")}


def _scan(db: DB, root: Path, offline: bool) -> ScanResult:
    return run_scan(root, db, profile="standard", offline=offline, log=lambda _m: None)


def _wanted(scope: str, refs: list[str] | None, findings: list[dict]) -> list[dict]:
    if refs:
        chosen = [f for f in findings if f["ref"] in set(refs)]
        missing = set(refs) - {f["ref"] for f in chosen}
        if missing:
            raise FixError(f"No open finding with ref {', '.join(sorted(missing))}. Call ladpock_findings for the current list.")
        return chosen
    if scope not in SCOPES:
        raise FixError(f"which must be one of {', '.join(SCOPES)}")
    floor = Severity.INFO if scope == "all" else Severity.parse(scope)
    return [f for f in findings if Severity.parse(f["severity"]) >= floor]


def start(db: DB, path: str, which: str = "high", refs: list[str] | None = None, notes: str = "", agent: str = "",
          offline: bool = False) -> str:
    root, _ = find_project(db, path)
    _refuse_github_copy(root)
    result = _scan(db, root, offline)
    findings = [f.to_dict() for f in result.findings]
    chosen = _wanted(which, refs, findings)
    name = result.root.name
    if not chosen:
        scope = "the findings you named" if refs else ("any open findings" if which == "all" else f"anything {which} or worse")
        return (f"{name}: grade {result.scorecard.grade}. Nothing to fix: LadPock didn't find {scope}."
                + (f" There are {len(findings)} lower-severity finding(s); call ladpock_fix_start with which='all' to work through them."
                   if findings else ""))
    commits = commits_enabled(db) and _is_git(root)
    run_id = db.fix_run_start(result.project_id, ",".join(refs) if refs else which, notes.strip()[:2000], agent[:80], commits,
                              [f["ref"] for f in findings], [_brief(f) for f in chosen])
    lines = [f"Fix run {run_id} for {name} (grade {result.scorecard.grade}): {len(chosen)} finding(s) to work through, worst first. "
             f"The user can follow along on this project's page in the LadPock dashboard.",
             "Commit each fix separately: yes." if commits else
             ("Commits: no, this folder isn't a git repository." if commits_enabled(db)
              else "Commits: no, the user has switched that off in LadPock. Leave committing to them."),
             "", RULES]
    if notes.strip():
        lines += ["", f"The user's notes for every fix: {notes.strip()[:2000]}"]
    return "\n".join(lines) + "\n\n" + _present_next(db, db.fix_run(run_id), root)


def _run_for(db: DB, path: str):
    root, row = find_project(db, path)
    _refuse_github_copy(root)
    run = db.active_fix_run(row["id"]) if row else None
    if not run:
        raise FixError("There's no fix run going for this project. Call ladpock_fix_start to begin one.")
    return root, row, run


def _progress(db: DB, run_id: int) -> str:
    items = db.fix_items(run_id)
    counts: dict[str, int] = {}
    for item in items:
        counts[item["status"]] = counts.get(item["status"], 0) + 1
    words = {"fixed": "fixed", "accepted": "accepted as known risks", "needs_you": "left for the user", "gone": "gone on their own"}
    done = ", ".join(f"{counts[k]} {v}" for k, v in words.items() if counts.get(k))
    left = counts.get("queued", 0) + counts.get("working", 0)
    return f"{len(items) - left} of {len(items)} done" + (f" ({done})" if done else "") + f", {left} to go"


def _current(db: DB, run_id: int):
    items = [i for i in db.fix_items(run_id) if i["status"] in OPEN]
    working = [i for i in items if i["status"] == "working"]
    if working:
        return working[0]
    return max(items, key=lambda i: (_rank(i), -i["position"]), default=None)


def _finding(db: DB, project_id: int, ref: str) -> dict | None:
    scan = db.latest_scan(project_id)
    return next((f for f in db.scan_findings(scan["id"]) if f["ref"] == ref), None) if scan else None


def _present_next(db: DB, run, root: Path) -> str:
    note_commits(db, run, root)
    item = _current(db, run["id"])
    if item is None:
        return _finish(db, run)
    db.fix_item_update(run["id"], item["ref"], status="working")
    f = _finding(db, run["project_id"], item["ref"]) or dict(item)
    where = f"{f.get('file')}:{f.get('line')}" if f.get("file") and f.get("line") else (f.get("file") or "the project as a whole")
    lines = [f"Next ({_progress(db, run['id'])}):",
             f"[{(f.get('severity') or '').upper()}] {f.get('title')}",
             f"Where: {where}",
             f"Check: {f.get('check_id')}, ref {item['ref']}"]
    if f.get("snippet"):
        lines.append(f"Code (secrets masked):\n{f['snippet']}")
    if f.get("message"):
        lines.append(f"Why it matters: {f['message']}")
    if f.get("fix"):
        lines.append(f"How to fix: {f['fix']}")
    if run["notes"]:
        lines.append(f"The user's notes: {run['notes']}")
    lines.append(f"When you've fixed it, call ladpock_fix_check. LadPock will re-scan and confirm that ref {item['ref']} is gone "
                 f"and nothing new appeared.")
    return "\n".join(lines)


def _finish(db: DB, run) -> str:
    db.fix_run_finish(run["id"], "done")
    items = db.fix_items(run["id"])
    scan = db.latest_scan(run["project_id"])
    lines = [f"All done: {_progress(db, run['id'])}. Grade now {scan['grade'] if scan else 'unknown'}."]
    left = [i for i in items if i["status"] == "needs_you"]
    accepted = [i for i in items if i["status"] == "accepted"]
    if left:
        lines.append("Left for the user: " + "; ".join(f"{i['title']} ({i['note'] or 'no reason given'})" for i in left))
    if accepted:
        lines.append("Accepted as known risks (the user can undo these in the dashboard): "
                     + "; ".join(f"{i['title']} ({i['note']})" for i in accepted))
    lines.append("Tell the user what was fixed, what's left for them, and anything you accepted.")
    return "\n".join(lines)


def next_item(db: DB, path: str) -> str:
    root, _, run = _run_for(db, path)
    return _present_next(db, run, root)


def check(db: DB, path: str, note: str = "", offline: bool = False) -> str:
    root, _, run = _run_for(db, path)
    item = _current(db, run["id"])
    if item is None:
        return _finish(db, run)
    result = _scan(db, root, offline)
    now = {f.fingerprint: f for f in result.findings}
    known = set(_json_list(run["baseline"])) | {i["ref"] for i in db.fix_items(run["id"])}
    fresh = [f for ref, f in now.items() if ref not in known]
    same_spot = [f for f in fresh if f.check_id == item["check_id"] and f.file == item["file"]]

    if item["ref"] in now or same_spot:
        tries = item["attempts"] + 1
        why = ("LadPock still finds it." if item["ref"] in now else
               f"The code changed but the same problem is still there (now ref {same_spot[0].fingerprint}, line {same_spot[0].line}).")
        if tries >= MAX_TRIES:
            db.fix_item_update(run["id"], item["ref"], status="needs_you", attempts=tries, note=f"Not fixed after {tries} tries")
            return (f"Not fixed: {why} That's {tries} tries.\nSTOP: tell the user this one needs them, explain what you tried, and ask "
                    f"whether to keep going with the rest (call ladpock_fix_next) or stop (ladpock_fix_stop).")
        db.fix_item_update(run["id"], item["ref"], attempts=tries)
        target = now.get(item["ref"]) or same_spot[0]
        return (f"Not fixed yet: {why} Found at {target.location or 'the project'}: {target.message}\nFix: {target.fix}\n"
                f"Try once more, then call ladpock_fix_check again.")

    db.fix_item_update(run["id"], item["ref"], status="fixed", attempts=item["attempts"] + 1, note=note.strip()[:500] or None)
    lines = [f"Fixed: LadPock no longer finds {item['title']} (grade now {result.scorecard.grade})."]
    if fresh:
        db.fix_items_append(run["id"], [_brief(f.to_dict()) for f in fresh])
        worst = max(fresh, key=lambda f: f.severity)
        lines.append(f"But {len(fresh)} new finding(s) appeared since this run started, now added to the list: "
                     + "; ".join(f"[{f.severity.label}] {f.title} at {f.location or 'project'}" for f in fresh[:5]))
        if worst.severity >= Severity.HIGH:
            db.fix_item_update(run["id"], item["ref"], note=(note.strip()[:400] + " " if note.strip() else "") + "(introduced a new problem)")
            lines.append("STOP: your change may have introduced a serious problem. Tell the user what appeared, then fix it next "
                         "(call ladpock_fix_next) unless they say otherwise.")
            return "\n".join(lines)
    if run["commits"]:
        lines.append(f"Now commit just this fix: git add only the files you changed for it, then\n"
                     f"git commit -m \"Fix: {_commit_title(item['title'])} (LadPock {item['ref']})\"\n"
                     f"Don't push, and don't include unrelated changes. Then carry on with the next one below.")
    lines.append("")
    lines.append(_present_next(db, db.fix_run(run["id"]), root))
    return "\n".join(lines)


def _commit_title(title: str | None) -> str:
    text = re.sub(r"[\"`$\\]", "", title or "security finding")
    return text[:60].rstrip(" .")


def _json_list(text: str | None) -> list:
    import json

    try:
        value = json.loads(text or "[]")
    except ValueError:
        return []
    return value if isinstance(value, list) else []


def skip(db: DB, path: str, reason: str, ref: str | None = None) -> str:
    root, _, run = _run_for(db, path)
    item = _item(db, run, ref)
    if len(reason.strip()) < MIN_REASON:
        raise FixError("Say why you're leaving this one for the user, in a sentence they can act on.")
    db.fix_item_update(run["id"], item["ref"], status="needs_you", note=reason.strip()[:500])
    return f"Left for the user: {item['title']}.\n\n" + _present_next(db, db.fix_run(run["id"]), root)


def _item(db: DB, run, ref: str | None):
    items = db.fix_items(run["id"])
    if ref:
        item = next((i for i in items if i["ref"] == ref), None)
        if not item:
            raise FixError(f"Ref {ref} isn't in this fix run.")
        return item
    item = _current(db, run["id"])
    if not item:
        raise FixError("Nothing left in this fix run.")
    return item


def accept_risk(db: DB, path: str, ref: str, reason: str, days: int = 90) -> str:
    root, row = find_project(db, path)
    _refuse_github_copy(root)
    if not row:
        raise FixError("This project hasn't been scanned yet. Call ladpock_scan first.")
    if not re.fullmatch(r"[0-9a-f]{10}", ref or ""):
        raise FixError("ref should be the 10-character reference LadPock gave for the finding")
    finding = _finding(db, row["id"], ref)
    if not finding:
        raise FixError(f"No finding with ref {ref} in the last scan. Call ladpock_findings for the current list.")
    if finding.get("severity") == "critical":
        raise FixError("Critical findings can't be accepted by an assistant. Explain the risk to the user; if they decide to accept it, "
                       "they can do that on the finding in the LadPock dashboard.")
    reason = reason.strip()
    if len(reason) < MIN_REASON:
        raise FixError("Give a real reason (a sentence) why this is acceptable. It's shown to the user and kept with the risk.")
    if not isinstance(days, int) or not 1 <= days <= MAX_ACCEPT_DAYS:
        raise FixError(f"days must be between 1 and {MAX_ACCEPT_DAYS}: an assistant can't accept a risk forever")
    db.add_suppression(row["id"], ref, reason[:500], days, by="agent")
    run = db.active_fix_run(row["id"])
    text = (f"Accepted as a known risk for {days} days: {finding['title']}. It isn't hidden: it's listed under Known risks on the "
            f"project's page, marked as accepted by an assistant with your reason, the grade notes it, and the user can undo it. "
            f"Tell the user you accepted it and why.")
    if run and any(i["ref"] == ref for i in db.fix_items(run["id"])):
        db.fix_item_update(run["id"], ref, status="accepted", note=reason[:500])
        text += "\n\n" + _present_next(db, db.fix_run(run["id"]), root)
    return text


def stop(db: DB, path: str) -> str:
    root, _, run = _run_for(db, path)
    note_commits(db, run, root)
    for item in db.fix_items(run["id"]):
        if item["status"] == "working":
            db.fix_item_update(run["id"], item["ref"], status="queued")
    db.fix_run_finish(run["id"], "stopped")
    return f"Stopped: {_progress(db, run['id'])}. Call ladpock_fix_start to begin again later."
