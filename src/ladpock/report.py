"""Terminal, JSON, SARIF and fix-prompt output."""

from __future__ import annotations

import os
import shutil
import sys
import textwrap

from . import __version__
from .advisories import AdvisoryHit
from .models import Finding, Severity
from .routes import Route, gaps
from .stack import coverage
from .timeutil import ago

SEVERITY_COLOR = {Severity.CRITICAL: "1;31", Severity.HIGH: "31", Severity.MEDIUM: "33", Severity.LOW: "36", Severity.INFO: "2"}


def enable_ansi() -> bool:
    if os.environ.get("NO_COLOR") or not sys.stdout.isatty():
        return False
    if sys.platform == "win32":
        try:
            import ctypes

            kernel32 = ctypes.windll.kernel32
            handle = kernel32.GetStdHandle(-11)
            mode = ctypes.c_uint32()
            if kernel32.GetConsoleMode(handle, ctypes.byref(mode)):
                kernel32.SetConsoleMode(handle, mode.value | 0x0004)
        except (AttributeError, OSError):
            return False
    return True


class Style:
    def __init__(self, color: bool):
        self.color = color

    def __call__(self, text: str, code: str) -> str:
        return f"\033[{code}m{text}\033[0m" if self.color else text

    def bold(self, text: str) -> str:
        return self(text, "1")

    def dim(self, text: str) -> str:
        return self(text, "2")

    def sev(self, severity: Severity, text: str | None = None) -> str:
        return self(text or severity.label.upper(), SEVERITY_COLOR[severity])

    def grade(self, grade: str) -> str:
        code = "32" if grade.startswith("A") else "36" if grade.startswith("B") else "33" if grade.startswith("C") else "31"
        return self(grade, "1;" + code)


def _width() -> int:
    return max(60, min(110, shutil.get_terminal_size((100, 20)).columns))


def _wrap(text: str, indent: str) -> str:
    return textwrap.fill(text, width=_width(), initial_indent=indent, subsequent_indent=indent)


def _counts_line(counts: dict[str, int], s: Style) -> str:
    parts = []
    for sev in (Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW):
        n = counts.get(sev.label, 0)
        if n:
            parts.append(s.sev(sev, f"{n} {sev.label}"))
    return "  ".join(parts) if parts else s("no issues found", "32")


def render_scan(result, s: Style, show_human: bool = False) -> str:
    deep, generic = coverage(result.stack)
    out = [
        f"{s.bold('LadPock')} {__version__}  {s.bold(result.root.name)}  {s.dim(str(result.root))}",
        f"  Stack     {', '.join(deep + generic) or 'not recognised (generic checks only)'}",
        f"  Coverage  deep checks: {', '.join(deep) or 'none'}"
        + (f"; generic only: {', '.join(generic)}" if generic else ""),
        "  Data      " + " | ".join(f"{f.name} {f.detail}" if f.ok else s(f"{f.name} {f.detail}", "33") for f in result.feeds),
    ]
    scanner_bits = [f"built-in {result.checks_run} checks"]
    for sc in result.scanners:
        if not sc.available:
            scanner_bits.append(s.dim(f"{sc.name} not installed"))
        elif sc.ran:
            scanner_bits.append(f"{sc.name} ran")
        else:
            scanner_bits.append(s(f"{sc.name} failed", "33"))
    out.append("  Scanners  " + " | ".join(scanner_bits))
    out.append(f"  Checked   {result.components} dependencies, {len(result.routes)} routes, profile '{result.profile}'")
    out.append("")
    card = result.scorecard
    out.append(f"  Overall  {s.grade(card.grade.ljust(2))}  {card.overall}/100    {_counts_line(card.counts, s)}")
    out.append("")
    for cat in card.categories:
        out.append(f"    {cat.name.ljust(32)} {s.grade(cat.grade.ljust(3))} {_counts_line(cat.counts, s) if cat.counts else ''}")
    out.append("")

    for sev in (Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW, Severity.INFO):
        group = [f for f in result.findings if f.severity == sev]
        if not group:
            continue
        out.append(s.sev(sev, f"{sev.label.upper()} ({len(group)})"))
        for f in group:
            out.extend(_render_finding(f, s))
        out.append("")

    if result.suppressed:
        out.append(s(f"{len(result.suppressed)} finding(s) hidden by 'ladpock suppress' or ladpock-ignore comments. "
                     "Check any you didn't add yourself.", "33"))
    if result.errors:
        out.append(s("Warnings", "33"))
        out.extend(_wrap(e, "  ") for e in result.errors[:10])
        out.append("")
    root = str(result.root)
    gap_count = sum(1 for r in result.routes if gaps(r))
    if result.routes:
        out.append(f"  Routes        {len(result.routes)} found, {gap_count} with gaps. See: ladpock routes \"{root}\"")
    if result.findings:
        out.append(f"  Fix prompt    ladpock fix-prompt \"{root}\"  (paste into Claude Code or your AI assistant)")
    out.append(f"  Needs a human {len(result.human)} things no scanner can check. See: ladpock scan \"{root}\" --human")
    out.append(s.dim("  Not covered: business logic, runtime behaviour, and anything outside the code. A good grade is not a guarantee."))
    if show_human:
        out.append("")
        out.append(s.bold("Needs a human"))
        for item_id, text in result.human:
            out.append(_wrap(f"[ ] {item_id}  {text}", "  "))
    return "\n".join(out)


def _render_finding(f: Finding, s: Style) -> list[str]:
    lines = [f"  {s.bold(f.check_id)}  {f.title}"]
    meta = [f.location] if f.location else []
    meta.append(f"confidence {f.confidence}")
    if f.source != "ladpock":
        meta.append(f"via {f.source}")
    lines.append(s.dim("    " + "   ".join(meta)))
    if f.snippet:
        lines.append("    > " + f.snippet[:160])
    lines.append(_wrap(f"Why: {f.message}", "    "))
    if f.fix:
        lines.append(_wrap(f"Fix: {f.fix}", "    "))
    lines.append(s.dim(f"    ref {f.fingerprint}"))
    return lines


def render_routes(routes: list[Route], s: Style) -> str:
    if not routes:
        return "No Next.js routes or server actions found."
    headers = ["Method", "Path", "Auth", "Owner", "Valid.", "Rate", "Gaps"]
    rows = []
    for r in routes:
        rows.append([r.method, r.path, r.auth, r.owner, r.validation, r.rate_limit, ", ".join(gaps(r)) or "-"])
    widths = [max(len(h), *(len(row[i]) for row in rows)) for i, h in enumerate(headers)]
    widths[1] = min(widths[1], 42)
    out = ["  ".join(h.ljust(widths[i]) for i, h in enumerate(headers)), "  ".join("-" * w for w in widths)]
    for r, row in zip(routes, rows):
        cells = []
        for i, cell in enumerate(row):
            text = cell if len(cell) <= widths[i] or i == 6 else cell[: widths[i] - 1] + "~"
            padded = text.ljust(widths[i]) if i < 6 else text
            if i in (2, 3, 4, 5) and cell == "no":
                padded = s(padded, "31")
            elif i == 6 and cell != "-":
                padded = s(padded, "33")
            cells.append(padded)
        out.append("  ".join(cells))
    out.append("")
    out.append(s.dim("Auth: yes = checked in handler, mw = only in middleware, sig = webhook signature, no = none found."))
    out.append(s.dim("Owner: yes = filters by current user, rls = relies on Supabase RLS, no = loads by ID only, n/a = not needed."))
    out.append(s.dim("Heuristic: it recognises common auth, validation and rate-limit libraries. Treat 'no' as 'go and look'."))
    return "\n".join(out)


def render_commands(commands, s: Style) -> str:
    from .tauri import command_gaps

    headers = ["Command", "Page input", "Files", "Path check", "Runs", "Net", "Gaps"]
    rows = [[c.name + ("" if c.registered else " *"), ", ".join(c.inputs) or "-", c.file_access, c.path_check,
             "yes" if c.runs_programs else "no", "yes" if c.network else "no", ", ".join(command_gaps(c)) or "-"]
            for c in commands]
    widths = [max(len(h), *(len(r[i]) for r in rows)) for i, h in enumerate(headers)]
    widths[1] = min(widths[1], 30)
    out = [s.bold("Tauri commands"), "  ".join(h.ljust(widths[i]) for i, h in enumerate(headers)),
           "  ".join("-" * w for w in widths)]
    for row in rows:
        cells = []
        for i, cell in enumerate(row):
            text = cell if len(cell) <= widths[i] or i == 6 else cell[: widths[i] - 1] + "~"
            padded = text.ljust(widths[i]) if i < 6 else text
            if (i == 3 and cell == "none") or (i == 4 and cell == "yes"):
                padded = s(padded, "31")
            elif i == 6 and cell != "-":
                padded = s(padded, "33")
            cells.append(padded)
        out.append("  ".join(cells))
    out.append("")
    out.append(s.dim("Path check: dir = confirms the path is inside an allowed folder, ext = file type only, none = no check."))
    if any(not c.registered for c in commands):
        out.append(s.dim("* defined but not registered in generate_handler!, so the page can't call it."))
    return "\n".join(out)


def render_status(projects, hits: list[AdvisoryHit], new: list[AdvisoryHit], feeds, problems: dict[int, str],
                  last_opened: str | None, s: Style) -> str:
    out = [f"{s.bold('LadPock')} {__version__}", ""]
    out.append("  Data  " + " | ".join(f"{f.name} {f.detail}" if f.ok else s(f"{f.name} {f.detail}", "33") for f in feeds))
    out.append("")
    if new:
        affected = sorted({h.project_name for h in new})
        exploited = [h for h in new if h.kev_added]
        headline = (f"{len(new)} new advisor{'y affects' if len(new) == 1 else 'ies affect'} {len(affected)} of your "
                    f"projects since you last checked ({ago(last_opened)})")
        out.append(s(f"  ! {headline}", "1;31"))
        if exploited:
            out.append(s(f"    {len(exploited)} {'is' if len(exploited) == 1 else 'are'} on CISA's actively exploited list", "31"))
        for hit in new[:12]:
            label = hit.cves[0] if hit.cves else hit.advisory_id
            fix = f" -> fixed in {hit.fixed}" if hit.fixed else ""
            kev_tag = s(" [actively exploited]", "1;31") if hit.kev_added else ""
            out.append(f"    {s.sev(hit.effective_severity, hit.effective_severity.label.ljust(8))} "
                       f"{hit.project_name}: {hit.name} {hit.version}  {label}{fix}{kev_tag}")
        if len(new) > 12:
            out.append(f"    ... and {len(new) - 12} more. See: ladpock advisories")
        out.append("")
    elif last_opened:
        out.append(s("  No new advisories affect your projects since you last checked.", "32"))
        out.append("")

    if not projects:
        out.append("  No projects yet. Add one with: ladpock scan <folder>  or  ladpock projects discover <folder>")
        return "\n".join(out)
    vulnerable: dict[int, set[tuple[str, str]]] = {}
    for hit in hits:
        vulnerable.setdefault(hit.project_id, set()).add((hit.name, hit.version))
    out.append(s.bold("  Your projects"))
    for p in projects:
        grade = p["last_grade"] or "-"
        scanned = f"scanned {ago(p['last_scan_at'])}" if p["last_scan_at"] else "not scanned yet"
        vulns = len(vulnerable.get(p["id"], ()))
        vuln_text = (s(f"{vulns} vulnerable dependenc{'y' if vulns == 1 else 'ies'}", "33") if vulns
                     else s.dim("no known vulnerable dependencies"))
        problem = s(f"  ({problems[p['id']]})", "33") if p["id"] in problems else ""
        out.append(f"    {s.grade(grade.ljust(3))} {p['name'].ljust(28)} {s.dim(scanned.ljust(22))} {vuln_text}{problem}")
    return "\n".join(out)


def render_advisories(hits: list[AdvisoryHit], s: Style) -> str:
    if not hits:
        return "No known vulnerable dependencies in your projects."
    out = []
    for hit in hits:
        label = ", ".join(hit.cves) or hit.advisory_id
        bits = [hit.advisory_id] if hit.cves else []
        if hit.fixed:
            bits.append(f"fixed in {hit.fixed}")
        if hit.epss is not None:
            bits.append(f"EPSS {hit.epss:.0%}")
        if hit.kev_added:
            bits.append(s("actively exploited", "1;31"))
        out.append(f"{s.sev(hit.effective_severity, hit.effective_severity.label.ljust(8))} {hit.project_name}: "
                   f"{hit.name} {hit.version}  {label}")
        out.append(s.dim(f"         {hit.summary[:100]}  ({'; '.join(bits)})"))
    return "\n".join(out)


def to_sarif(result) -> dict:
    rules: dict[str, dict] = {}
    results = []
    levels = {Severity.CRITICAL: "error", Severity.HIGH: "error", Severity.MEDIUM: "warning",
              Severity.LOW: "note", Severity.INFO: "note"}
    for f in result.findings:
        rules.setdefault(f.check_id, {
            "id": f.check_id,
            "name": f.check_id,
            "shortDescription": {"text": f.title},
            "help": {"text": f.fix or f.title},
            "properties": {"category": f.category, "tags": ["security", *f.cwe]},
        })
        entry = {
            "ruleId": f.check_id,
            "level": levels[f.severity],
            "message": {"text": f"{f.title}. {f.message}"},
            "partialFingerprints": {"ladpock/v1": f.fingerprint},
            "properties": {"severity": f.severity.label, "confidence": f.confidence, "source": f.source},
        }
        if f.file:
            location = {"artifactLocation": {"uri": f.file}}
            if f.line:
                location["region"] = {"startLine": f.line}
            entry["locations"] = [{"physicalLocation": location}]
        results.append(entry)
    return {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {"driver": {"name": "LadPock", "version": __version__,
                                "informationUri": "https://github.com/liamburgo23/ladpock", "rules": list(rules.values())}},
            "results": results,
        }],
    }


def fix_prompt(project_name: str, findings: list[dict], limit: int = 25) -> str:
    """A paste-ready prompt for an AI coding assistant. Snippets are already masked."""
    order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
    ranked = sorted(findings, key=lambda f: order.get(f["severity"], 5))[:limit]
    lines = [
        f"LadPock found these security issues in {project_name}. Please fix them one at a time, most serious first.",
        "Rules: keep existing behaviour otherwise, don't disable or weaken any security check to make an error go away,",
        "don't put secrets in code, and tell me about anything you can't fix (for example keys that need rotating by hand).",
        "",
    ]
    for i, f in enumerate(ranked, 1):
        where = f" in {f['file']}" + (f":{f['line']}" if f.get("line") else "") if f.get("file") else ""
        lines.append(f"{i}. [{f['severity']}] {f['title']}{where}")
        lines.append(f"   Problem: {f['message']}")
        if f.get("fix"):
            lines.append(f"   Expected fix: {f['fix']}")
    if len(findings) > limit:
        lines.append(f"\n({len(findings) - limit} lower-priority issues left out; re-run LadPock after these are fixed.)")
    lines.append("\nWhen you're done, summarise what you changed for each item so I can re-run `ladpock scan` to confirm.")
    return "\n".join(lines)
