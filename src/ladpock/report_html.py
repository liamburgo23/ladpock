"""A one-page report to keep or pass on: a single HTML file with no scripts and nothing loaded from elsewhere.

Snippets come from scanned code, so everything is escaped, and the page's own
Content-Security-Policy stops anything running even if something slipped through.
Secrets are already masked by the time findings get here. The project's folder
isn't included, because a report often leaves the computer it was made on.
"""

from __future__ import annotations

from datetime import datetime
from html import escape

from . import __version__

SEVERITIES = ("critical", "high", "medium", "low", "info")
GRADE_NOTE = ("A+ means no open findings. Any open finding limits the grade: at most F with a critical finding, C+ with a high one, "
              "B+ with a medium one and A with a low one (one step less if it's low confidence).")
LIMITS = ("LadPock catches common, recognisable mistakes. It doesn't understand your business logic and can't see production settings, "
          "so a good grade means no obvious problems were found, not that the software is secure.")

STYLE = """
:root { color-scheme: light dark; --bg: #fff; --fg: #1a1d21; --muted: #5b6470; --line: #dfe3e8; --panel: #f6f7f9;
  --critical: #b3123a; --high: #c2410c; --medium: #a16207; --low: #0e7490; --info: #5b6470; --good: #15803d; }
@media (prefers-color-scheme: dark) {
  :root { --bg: #14171b; --fg: #e8eaed; --muted: #9aa3ae; --line: #2c3238; --panel: #1c2025;
    --critical: #fb7185; --high: #fb923c; --medium: #facc15; --low: #22d3ee; --info: #9aa3ae; --good: #4ade80; } }
* { box-sizing: border-box; }
body { margin: 0 auto; max-width: 860px; padding: 32px 16px 64px; background: var(--bg); color: var(--fg);
  font: 15px/1.55 system-ui, -apple-system, "Segoe UI", Roboto, sans-serif; overflow-wrap: anywhere; }
h1 { font-size: 26px; margin: 0 0 4px; } h2 { font-size: 18px; margin: 36px 0 10px; } h3 { font-size: 15px; margin: 0; }
p { margin: 8px 0; } .muted { color: var(--muted); } .small { font-size: 13px; }
code, pre { font: 13px/1.5 ui-monospace, Consolas, Menlo, monospace; }
pre { background: var(--panel); border: 1px solid var(--line); border-radius: 6px; padding: 8px 10px; white-space: pre-wrap; margin: 8px 0; }
.hero { display: flex; gap: 20px; align-items: center; background: var(--panel); border: 1px solid var(--line); border-radius: 10px; padding: 18px; margin-top: 20px; }
.grade { font-size: 44px; font-weight: 700; line-height: 1; min-width: 84px; text-align: center; }
.g-A { color: var(--good); } .g-B { color: var(--low); } .g-C { color: var(--medium); } .g-D, .g-F { color: var(--critical); }
table { border-collapse: collapse; width: 100%; font-size: 14px; }
th, td { text-align: left; padding: 6px 10px 6px 0; border-bottom: 1px solid var(--line); vertical-align: top; }
th { color: var(--muted); font-weight: 600; font-size: 13px; }
article { border: 1px solid var(--line); border-radius: 8px; padding: 12px 14px; margin: 10px 0; break-inside: avoid; }
.head { display: flex; gap: 8px; flex-wrap: wrap; align-items: baseline; }
.sev { font-size: 12px; font-weight: 700; text-transform: uppercase; letter-spacing: .03em; }
.sev-critical { color: var(--critical); } .sev-high { color: var(--high); } .sev-medium { color: var(--medium); } .sev-low { color: var(--low); } .sev-info { color: var(--info); }
.tag { font-size: 12px; border: 1px solid var(--line); border-radius: 99px; padding: 0 8px; color: var(--muted); }
.fix { border-left: 3px solid var(--good); padding-left: 10px; }
@media print { body { max-width: none; padding: 0; } .hero, article, pre { border-color: #bbb; } }
"""


def _e(value) -> str:
    return escape(str(value if value is not None else ""), quote=True)


def _grade_class(grade: str) -> str:
    return f"g-{(grade or 'F')[0]}"


def _plural(count: int, word: str) -> str:
    return f"{count} {word}{'' if count == 1 else 's'}"


def _when(stamp: str | None) -> str:
    if not stamp:
        return ""
    try:
        return datetime.fromisoformat(stamp.replace("Z", "+00:00")).strftime("%d %B %Y, %H:%M UTC")
    except ValueError:
        return stamp


def _finding(f: dict) -> str:
    place = f.get("file") or ""
    if place and f.get("line"):
        place = f"{place}:{f['line']}"
    tags = []
    seen_live = (f.get("extra") or {}).get("live")
    if f.get("source") == "live" or seen_live == "confirmed":
        tags.append("Confirmed on the running app")
    elif seen_live == "refused":
        tags.append("The running app refused this")
    elif f.get("confidence") == "low":
        tags.append("Unconfirmed, worth checking")
    tags.extend(str(c) for c in (f.get("cwe") or ())[:3])
    return (
        f'<article><div class="head"><span class="sev sev-{_e(f.get("severity"))}">{_e(f.get("severity"))}</span>'
        f'<h3>{_e(f.get("title"))}</h3>{"".join(f"""<span class="tag">{_e(t)}</span>""" for t in tags)}</div>'
        + (f'<p class="small muted"><code>{_e(place)}</code></p>' if place else "")
        + f'<p>{_e(f.get("message"))}</p>'
        + (f'<pre>{_e(f.get("snippet"))}</pre>' if f.get("snippet") else "")
        + f'<p class="fix"><strong>How to fix it:</strong> {_e(f.get("fix"))}</p></article>'
    )


def _routes(routes: list[dict]) -> str:
    risky = [r for r in routes if r.get("gaps")]
    if not routes:
        return ""
    head = f"<h2>Endpoints</h2><p>{_plural(len(routes), 'endpoint')} found, {len(risky)} with gaps.</p>"
    if not risky:
        return head
    rows = "".join(
        f'<tr><td><code>{_e(r.get("method"))} {_e(r.get("path"))}</code></td><td>{_e(", ".join(r["gaps"]))}</td>'
        f'<td class="small muted"><code>{_e(r.get("file"))}{":" + _e(r.get("line")) if r.get("line") else ""}</code></td></tr>'
        for r in risky[:200])
    more = f'<p class="small muted">Showing the first 200 of {len(risky)}.</p>' if len(risky) > 200 else ""
    return f"{head}<table><tr><th>Endpoint</th><th>Missing</th><th>Where</th></tr>{rows}</table>{more}"


def _checked(*, coverage: dict, checks_run, dependencies, scanners: list[dict], feeds: list[dict], live: dict | None, suppressed: int) -> str:
    items = []
    if checks_run:
        items.append(f"{_plural(int(checks_run), 'built-in check')} ran")
    if coverage.get("deep"):
        items.append("Framework-aware checks for " + ", ".join(coverage["deep"]))
    if coverage.get("generic"):
        items.append("Generic checks only for " + ", ".join(coverage["generic"]))
    items.append(f"{_plural(int(dependencies or 0), 'dependency').replace('dependencys', 'dependencies')} checked against known vulnerabilities")
    ran = [s["name"] for s in scanners if s.get("ran")]
    missing = [s["name"] for s in scanners if not s.get("available")]
    if ran:
        items.append("Other scanners that ran: " + ", ".join(ran))
    if missing:
        items.append("Other scanners not installed: " + ", ".join(missing))
    stale = [f["name"] for f in feeds if not f.get("ok")]
    if stale:
        items.append("Vulnerability data not refreshed: " + ", ".join(stale))
    if live and live.get("error"):
        items.append(f"Live checks couldn't run: {live['error']}")
    elif live:
        line = f"Live checks against the running app: {_plural(int(live.get('requests') or 0), 'request')}, {_plural(int(live.get('confirmed') or 0), 'problem')} confirmed"
        accounts = live.get("accounts")
        if accounts:
            line += (f". Two test accounts: {_plural(int(accounts.get('records_checked') or 0), 'record')} tried as the other account, "
                     f"{accounts.get('exposed', 0)} opened, {accounts.get('protected', 0)} refused")
        items.append(line)
    else:
        items.append("The running app wasn't tested, only its code")
    if suppressed:
        items.append(f"{_plural(int(suppressed), 'finding')} hidden by accept-risk decisions, ladpock-ignore comments or ladpock.toml")
    return "<h2>What was checked</h2><ul>" + "".join(f"<li>{_e(i)}</li>" for i in items) + "</ul>"


def render(project: str, *, grade: str, score, profile: str, started: str | None, categories: list[dict], findings: list[dict],
           coverage: dict | None = None, checks_run=None, dependencies=None, scanners: list[dict] | None = None,
           feeds: list[dict] | None = None, live: dict | None = None, routes: list[dict] | None = None, suppressed: int = 0) -> str:
    counts = {s: sum(1 for f in findings if f.get("severity") == s) for s in SEVERITIES}
    open_text = ", ".join(f"{counts[s]} {s}" for s in SEVERITIES if counts[s])
    headline = f"{_plural(len(findings), 'open finding')}: {open_text}." if findings else "No open findings from these checks."
    order = {s: i for i, s in enumerate(SEVERITIES)}
    ranked = sorted(findings, key=lambda f: (order.get(f.get("severity"), 9), f.get("confidence") == "low", f.get("title") or ""))
    category_rows = "".join(
        f'<tr><td>{_e(c.get("name"))}</td><td class="{_grade_class(c.get("grade"))}"><strong>{_e(c.get("grade"))}</strong></td>'
        f'<td class="muted">{_e(", ".join(f"{n} {s}" for s, n in (c.get("counts") or {}).items()) or "nothing open")}</td></tr>'
        for c in categories)
    sections = "".join(_finding(f) for f in ranked)
    return (
        '<!doctype html><html lang="en"><head><meta charset="utf-8">'
        '<meta name="viewport" content="width=device-width, initial-scale=1">'
        "<meta http-equiv=\"Content-Security-Policy\" content=\"default-src 'none'; style-src 'unsafe-inline'\">"
        f"<title>Security report: {_e(project)}</title><style>{STYLE}</style></head><body>"
        f'<h1>{_e(project)}</h1><p class="muted">Security report · {_e(_when(started))} · {_e(profile)} scan · LadPock {_e(__version__)}</p>'
        f'<section class="hero"><div class="grade {_grade_class(grade)}">{_e(grade)}</div><div><strong>{_e(score)}/100</strong>'
        f'<p>{_e(headline)}</p><p class="small muted">{_e(GRADE_NOTE)}</p></div></section>'
        + (f"<h2>By category</h2><table><tr><th>Category</th><th>Grade</th><th>Open</th></tr>{category_rows}</table>" if categories else "")
        + (f"<h2>What to fix, most serious first</h2>{sections}" if ranked else "")
        + _routes(routes or [])
        + _checked(coverage=coverage or {}, checks_run=checks_run, dependencies=dependencies, scanners=scanners or [], feeds=feeds or [],
                   live=live, suppressed=suppressed)
        + f'<h2>Limits</h2><p class="muted">{_e(LIMITS)}</p>'
        '<p class="small muted">Secrets found in code are masked in this report. Code snippets are included, so share it only with people who could see the code.</p>'
        "</body></html>"
    )
