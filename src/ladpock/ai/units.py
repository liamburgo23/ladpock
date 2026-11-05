"""Splits a project into review units, most valuable first.

1. Routes, backend functions and Tauri commands, with what the static analysis found
2. Scanner findings worth a second opinion, plus database and storage access rules
3. The rest of the source, in chunks

Every line goes through secret redaction before a model sees it, and units
carry their real line numbers so answers can be checked against the code.
"""

from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass, field

from .. import tauri
from ..files import CODE_EXT, FileIndex
from ..masking import redact
from ..routes import analyze, gaps

CHUNK_LINES = 160
MAX_SEGMENT = 160
VERDICT_SEVERITIES = {"critical", "high", "medium"}
# Generated code and developer tooling (build scripts, benchmarks, examples) aren't attack surface.
SKIP_FILE = re.compile(
    r"\.(?:d\.ts|min\.js|generated\.\w+)$|(?:^|/)(?:migrations?|__generated__|gen|scripts|tools|bench(?:marks?)?|examples?|docs)/"
)
INFRA_FILE = re.compile(
    r"(?:^|/)(?:Dockerfile[^/]*|Containerfile|[^/]*\.dockerfile|docker-compose[^/]*\.ya?ml|compose\.ya?ml|[^/]+\.tf|serverless\.ya?ml|template\.ya?ml|"
    r"vercel\.json|netlify\.toml|wrangler\.toml|firebase\.json|nginx[^/]*\.conf|default\.conf)$|"
    r"^\.github/workflows/[^/]+\.ya?ml$"
)
# Who may read and write what: Supabase policies and Firebase rules. Often the app's only access control.
POLICY_FILE = re.compile(r"(?:^|/)(?:firestore|storage)\.rules$|(?:^|/)database\.rules\.json$|(?:^|/)supabase/(?:migrations/[^/]+|schema|policies[^/]*)\.sql$|"
                         r"(?:^|/)supabase/migrations/[^/]+\.sql$")
POLICY_TEXT = re.compile(r"(?i)\bcreate\s+policy\b|\bsecurity\s+definer\b|\benable\s+row\s+level\s+security\b|\bcreate\s+(?:or\s+replace\s+)?view\b|\ballow\s+\w|\.read|\.write")
# Reached straight from the browser with details that ship in the front end, so nothing on the page protects them.
DIRECT_CLIENT = {"convex", "firebase-fn", "trpc", "graphql", "supabase-edge"}
K8S = re.compile(r"(?m)^apiVersion:\s*\S+[\s\S]*^kind:\s*\w+")
HOT_PATH = re.compile(r"(?i)api|route|server|auth|session|login|admin|payment|webhook|action|command|handler|db|sql|upload|file")


@dataclass
class Unit:
    key: str
    kind: str  # route | command | verdict | file
    file: str
    title: str
    facts: str
    lines: dict[int, str]  # line number -> redacted text
    segments: list[tuple[int, int]]
    priority: int
    finding_ref: str | None = None
    finding_message: str = ""
    extra: dict = field(default_factory=dict)

    @property
    def code(self) -> str:
        parts = []
        for start, end in self.segments:
            if len(self.segments) > 1:
                parts.append(f"// --- lines {start}-{end} ---")
            parts.extend(f"{n:>5}| {self.lines[n]}" for n in range(start, end + 1) if n in self.lines)
        return "\n".join(parts)

    @property
    def content_hash(self) -> str:
        return hashlib.sha1(f"{self.kind}|{self.title}|{self.facts}|{self.code}".encode("utf-8")).hexdigest()


def _take(index: FileIndex, rel: str, start: int, end: int, into: dict[int, str]) -> tuple[int, int]:
    lines = index.lines(rel)
    start = max(1, start)
    end = min(len(lines), end, start + MAX_SEGMENT - 1)
    for n in range(start, end + 1):
        into[n] = redact(lines[n - 1])[:400]
    return start, end


def route_units(index: FileIndex) -> list[Unit]:
    routes = analyze(index)
    by_file: dict[str, list] = {}
    for r in routes:
        by_file.setdefault(r.file, []).append(r)
    units = []
    for rel, items in by_file.items():
        items.sort(key=lambda r: r.line)
        total = len(index.lines(rel))
        for i, r in enumerate(items):
            end = items[i + 1].line - 1 if i + 1 < len(items) and items[i + 1].line > r.line else total
            lines: dict[int, str] = {}
            segments = []
            if r.line > 1:  # imports and module setup often decide auth (clients, wrappers)
                segments.append(_take(index, rel, 1, min(r.line - 1, 25), lines))
            segments.append(_take(index, rel, r.line, end, lines))
            facts = (f"{r.method} {r.path} ({r.kind}). Auth: {r.auth}. Ownership check: {r.owner}. Validation: "
                     f"{r.validation}. Rate limit: {r.rate_limit}. Calls paid API: {r.paid_api}. Writes data: {r.mutates}. "
                     f"Gaps noticed: {', '.join(gaps(r)) or 'none'}."
                     + (" Anyone can call this directly using details that ship in the front end, so checks on the page don't "
                        "protect it." if r.kind in DIRECT_CLIENT else ""))
            units.append(Unit(f"route:{rel}:{r.method}:{r.path}", "route", rel, f"{r.method} {r.path}", facts,
                              lines, segments, 0))
    return units


def command_units(index: FileIndex) -> list[Unit]:
    if not tauri.is_tauri_project(index):
        return []
    units = []
    for cmd in tauri.analyze_commands(index):
        if not cmd.registered:
            continue
        lines: dict[int, str] = {}
        segments = [_take(index, cmd.file, cmd.line - 1, cmd.end_line, lines)]
        for start, end in cmd.helper_lines[:4]:
            segments.append(_take(index, cmd.file, start, end, lines))
        facts = (f"Tauri command {cmd.name}. Inputs from the page: {', '.join(cmd.inputs) or 'none'}. File access: "
                 f"{cmd.file_access}. Path check: {cmd.path_check}. Runs programs: {cmd.runs_programs}. Network: "
                 f"{cmd.network}. Gaps noticed: {', '.join(tauri.command_gaps(cmd)) or 'none'}.")
        units.append(Unit(f"command:{cmd.file}:{cmd.name}", "command", cmd.file, f"Tauri command {cmd.name}",
                          facts, lines, segments, 0))
    return units


def verdict_units(index: FileIndex, findings: list[dict]) -> list[Unit]:
    units = []
    for f in findings:
        if f.get("severity") not in VERDICT_SEVERITIES or not f.get("file") or not f.get("line"):
            continue
        if f.get("category") == "secrets" or not index.exists(f["file"]):
            continue  # a leaked key is real regardless of context
        if f.get("source") == "live" or (f.get("extra") or {}).get("live") == "confirmed":
            continue  # seen on the running app, so there's nothing for a model to weigh in on
        lines: dict[int, str] = {}
        segments = [_take(index, f["file"], f["line"] - 20, f["line"] + 20, lines)]
        units.append(Unit(f"verdict:{f['ref']}", "verdict", f["file"], f["title"], "", lines, segments, 1,
                          finding_ref=f["ref"], finding_message=f.get("message", "")))
    return units


def file_units(index: FileIndex, covered: set[str]) -> list[Unit]:
    units = []
    for rel in index.iter(CODE_EXT):
        if SKIP_FILE.search(rel) or rel in covered:
            continue
        lines = index.lines(rel)
        if not lines or max((len(line) for line in lines), default=0) > 2000:
            continue  # empty, minified or generated
        hot = bool(HOT_PATH.search(rel))
        for start in range(1, len(lines) + 1, CHUNK_LINES):
            chunk: dict[int, str] = {}
            seg = _take(index, rel, start, start + CHUNK_LINES - 1, chunk)
            if not any(text.strip() for text in chunk.values()):
                continue
            units.append(Unit(f"file:{rel}:{start}", "file", rel, f"{rel} lines {seg[0]}-{seg[1]}", "", chunk,
                              [seg], 2 if hot else 3))
    return units


def infra_units(index: FileIndex) -> list[Unit]:
    """Dockerfiles, Compose, Kubernetes, Terraform and CI workflows, read with infrastructure-specific instructions."""
    units = []
    for rel in index.iter({".yml", ".yaml", ".tf"}, pred=lambda r: bool(INFRA_FILE.search(r))):
        lines = index.lines(rel)
        if not lines:
            continue
        if rel.endswith((".yml", ".yaml")) and not INFRA_FILE.search(rel) and not K8S.search(index.read(rel) or ""):
            continue
        for start in range(1, len(lines) + 1, CHUNK_LINES):
            chunk: dict[int, str] = {}
            seg = _take(index, rel, start, start + CHUNK_LINES - 1, chunk)
            if any(text.strip() for text in chunk.values()):
                units.append(Unit(f"infra:{rel}:{start}", "infra", rel, f"{rel} lines {seg[0]}-{seg[1]}", "", chunk,
                                  [seg], 2))
    return units


def policy_units(index: FileIndex) -> list[Unit]:
    """Supabase policies and Firebase rules, in chunks. These decide who can reach the data, so they rank near the top."""
    units = []
    for rel in index.iter(None, pred=lambda r: bool(POLICY_FILE.search(r))):
        text = index.read(rel) or ""
        lines = index.lines(rel)
        if not lines or not POLICY_TEXT.search(text):
            continue
        for start in range(1, len(lines) + 1, CHUNK_LINES):
            chunk: dict[int, str] = {}
            seg = _take(index, rel, start, start + CHUNK_LINES - 1, chunk)
            if POLICY_TEXT.search("\n".join(chunk.values())):
                units.append(Unit(f"policy:{rel}:{start}", "policy", rel, f"{rel} lines {seg[0]}-{seg[1]}", "", chunk, [seg], 1))
    return units


def build_units(index: FileIndex, findings: list[dict]) -> list[Unit]:
    entry = route_units(index) + command_units(index)
    covered = {u.file for u in entry if u.kind == "route"}
    units = entry + verdict_units(index, findings) + policy_units(index) + file_units(index, covered) + infra_units(index)
    units.sort(key=lambda u: (u.priority, u.file, min(u.lines, default=0)))
    return units


def describe(units: list[Unit]) -> dict[str, int]:
    counts: dict[str, int] = {}
    for u in units:
        counts[u.kind] = counts.get(u.kind, 0) + 1
    return counts
