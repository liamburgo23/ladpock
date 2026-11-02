"""Tauri pack: what the web page inside your desktop app is allowed to do."""

from __future__ import annotations

import re
from typing import Iterator

from .. import tauri
from ..models import Finding, Severity
from .base import CheckInfo, ScanContext, check, grep

STACKS = ("tauri",)
UNSAFE_SCRIPT = re.compile(r"'unsafe-eval'|'unsafe-inline'|(?:^|\s)\*(?:\s|$)|(?:^|\s)(?:https?:|data:|blob:)(?:\s|$)|https?://(?!localhost|127\.0\.0\.1|ipc\.localhost|asset\.localhost|tauri\.localhost)")
SHELL_RUN = re.compile(r"^shell:(?:allow-execute|allow-spawn|allow-stdin-write|allow-kill)$")
FS_BROAD = re.compile(r"^fs:(?:read-all|write-all|allow-\w+-recursive|scope-(?:home|document|download|desktop|public)\w*|allow-(?:home|document|download|desktop|public)-\w+)$")


def _configs(ctx: ScanContext) -> list[tauri.TauriConfig]:
    if not hasattr(ctx, "_tauri_configs"):
        ctx._tauri_configs = tauri.load_configs(ctx.index)[0]  # type: ignore[attr-defined]
    return ctx._tauri_configs  # type: ignore[attr-defined]


def _capabilities(ctx: ScanContext) -> list[tauri.Capability]:
    if not hasattr(ctx, "_tauri_caps"):
        ctx._tauri_caps = tauri.load_capabilities(ctx.index, _configs(ctx))  # type: ignore[attr-defined]
    return ctx._tauri_caps  # type: ignore[attr-defined]


def _script_policy(csp: str) -> str:
    directives = {}
    for part in csp.split(";"):
        bits = part.strip().split(None, 1)
        if bits:
            directives[bits[0].lower()] = bits[1] if len(bits) > 1 else ""
    return directives.get("script-src", directives.get("default-src", "*"))


@check(
    "LP-TAURI-001", "No Content Security Policy for the app window", "config", Severity.HIGH,
    why="Without a CSP, any script that gets into the page (from a malicious file, a dependency or an XSS bug) runs "
        "with full access to every command and permission your app exposes.",
    fix="Set app.security.csp in tauri.conf.json, starting from \"default-src 'self'; script-src 'self'; "
        "object-src 'none'; base-uri 'none'\" and adding only what the app needs.",
    cwe=("CWE-1021", "CWE-79"),
    stacks=STACKS,
)
def missing_csp(ctx: ScanContext, info: CheckInfo) -> Iterator[Finding]:
    for cfg in _configs(ctx):
        key = "tauri.security.csp" if cfg.version == 1 else "app.security.csp"
        csp = cfg.get(key)
        if not csp:
            yield ctx.finding(info, cfg.file, cfg.line_of('"csp"'), f"{key}: {'null' if cfg.has(key) else 'not set'}",
                              confidence="high")


@check(
    "LP-TAURI-002", "Content Security Policy lets risky scripts run", "config", Severity.MEDIUM,
    why="The policy allows inline scripts, eval, or scripts from other websites. That's the gap an attacker needs to "
        "turn injected text into code that can call your app's commands.",
    fix="Limit script-src to 'self'. Move inline scripts into files, and avoid eval and new Function.",
    cwe=("CWE-1021",),
    stacks=STACKS,
)
def weak_csp(ctx: ScanContext, info: CheckInfo) -> Iterator[Finding]:
    for cfg in _configs(ctx):
        csp = cfg.get("app.security.csp", "tauri.security.csp")
        if isinstance(csp, dict):
            csp = "; ".join(f"{k} {v if isinstance(v, str) else ' '.join(v)}" for k, v in csp.items())
        if isinstance(csp, str) and csp.strip():
            policy = _script_policy(csp)
            if UNSAFE_SCRIPT.search(f" {policy} "):
                yield ctx.finding(info, cfg.file, cfg.line_of('"csp"'), f"script-src {policy}", confidence="high")


@check(
    "LP-TAURI-003", "Websites on the internet can call your app's commands", "authz", Severity.HIGH,
    why="A capability with remote URLs (or v1's dangerousRemoteDomainIpcAccess) lets pages loaded from those sites use "
        "the permissions and commands in it. If that site is compromised, or the pattern is broad, so is the app.",
    fix="Remove remote access unless you truly need it. If you do, list exact https origins you control and grant "
        "that capability only the few permissions those pages need.",
    cwe=("CWE-346", "CWE-284"),
    stacks=STACKS,
)
def remote_ipc(ctx: ScanContext, info: CheckInfo) -> Iterator[Finding]:
    for cap in _capabilities(ctx):
        urls = (cap.data.get("remote") or {}).get("urls") if isinstance(cap.data.get("remote"), dict) else None
        for url in urls or []:
            broad = bool(re.match(r"^(?:https?://)?\*|^http://|^\*", str(url)))
            yield ctx.finding(info, cap.file, cap.line_of(str(url)), f"remote url: {url}",
                              severity=Severity.CRITICAL if broad else Severity.HIGH, confidence="high")
    for cfg in _configs(ctx):
        if cfg.get("tauri.security.dangerousRemoteDomainIpcAccess"):
            yield ctx.finding(info, cfg.file, cfg.line_of("dangerousRemoteDomainIpcAccess"),
                              "dangerousRemoteDomainIpcAccess", confidence="high")


@check(
    "LP-TAURI-004", "Web page can read or write files anywhere", "authz", Severity.HIGH,
    why="Broad file-system permissions mean any script running in the page can read your documents or SSH keys, or "
        "overwrite files, without asking.",
    fix="Grant only the narrowest fs permissions, scoped to your app's own folders ($APPDATA/**). Let users pick "
        "files with the dialog plugin, which grants access to just that file.",
    cwe=("CWE-732", "CWE-22"),
    stacks=STACKS,
)
def broad_fs(ctx: ScanContext, info: CheckInfo) -> Iterator[Finding]:
    for cap in _capabilities(ctx):
        for perm in cap.permissions:
            pid = tauri.permission_id(perm)
            broad_paths = [p for p in tauri.permission_paths(perm) if tauri.is_broad_path(p)]
            if pid.startswith("fs:") and (FS_BROAD.match(pid) or broad_paths):
                shown = f"{pid} {broad_paths}" if broad_paths else pid
                yield ctx.finding(info, cap.file, cap.line_of(pid), shown, confidence="high")
    for cfg in _configs(ctx):
        fs = cfg.get("tauri.allowlist.fs") or {}
        scope = fs.get("scope", []) if isinstance(fs, dict) else []
        scope = scope.get("allow", []) if isinstance(scope, dict) else scope
        if cfg.get("tauri.allowlist.all") or (isinstance(fs, dict) and fs.get("all")) or any(
                tauri.is_broad_path(str(p)) for p in scope):
            yield ctx.finding(info, cfg.file, cfg.line_of('"fs"') or cfg.line_of('"all"'), "allowlist fs: broad",
                              confidence="high")


@check(
    "LP-TAURI-005", "Web page can run programs on the computer", "authz", Severity.HIGH,
    why="Shell execute or spawn permissions let script in the page start processes. One XSS bug becomes full "
        "control of the user's machine.",
    fix="Remove shell execute/spawn permissions. If the app must run a tool, do it from a Rust command that runs a "
        "fixed program with validated arguments, or use a sidecar with an argument allowlist.",
    cwe=("CWE-78",),
    stacks=STACKS,
)
def shell_permissions(ctx: ScanContext, info: CheckInfo) -> Iterator[Finding]:
    for cap in _capabilities(ctx):
        for perm in cap.permissions:
            pid = tauri.permission_id(perm)
            if SHELL_RUN.match(pid):
                yield ctx.finding(info, cap.file, cap.line_of(pid), pid, confidence="high")
            elif pid == "shell:allow-open":
                yield ctx.finding(info, cap.file, cap.line_of(pid), pid, severity=Severity.LOW,
                                  message="shell:allow-open lets the page open URLs and paths with the default app. "
                                          "Check its scope only allows https links you expect.")
    for cfg in _configs(ctx):
        shell = cfg.get("tauri.allowlist.shell") or {}
        if isinstance(shell, dict) and (shell.get("all") or shell.get("execute") or shell.get("sidecar")):
            yield ctx.finding(info, cfg.file, cfg.line_of('"shell"'), "allowlist shell: execute", confidence="high")


@check(
    "LP-TAURI-006", "Tauri API exposed as a global object", "config", Severity.LOW,
    why="withGlobalTauri puts window.__TAURI__ on every page, which makes any injected script's job easier.",
    fix="Turn off withGlobalTauri and import from @tauri-apps/api in your bundled code instead.",
    cwe=("CWE-749",),
    stacks=STACKS,
)
def global_tauri(ctx: ScanContext, info: CheckInfo) -> Iterator[Finding]:
    for cfg in _configs(ctx):
        if cfg.get("app.withGlobalTauri", "build.withGlobalTauri") is True:
            yield ctx.finding(info, cfg.file, cfg.line_of("withGlobalTauri"), "withGlobalTauri: true", confidence="high")


@check(
    "LP-TAURI-007", "Asset protocol can serve files from anywhere", "authz", Severity.MEDIUM,
    why="The asset protocol lets the page load local files by path. A broad scope lets it fetch any file the user can read.",
    fix="Scope assetProtocol to the folders the app really displays from, for example [\"$APPDATA/media/**\"].",
    cwe=("CWE-22",),
    stacks=STACKS,
)
def asset_scope(ctx: ScanContext, info: CheckInfo) -> Iterator[Finding]:
    for cfg in _configs(ctx):
        proto = cfg.get("app.security.assetProtocol") or {}
        scope = proto.get("scope", []) if isinstance(proto, dict) else []
        if cfg.version == 1:
            scope = cfg.get("tauri.security.assetScope") or []
        scope = scope.get("allow", []) if isinstance(scope, dict) else scope
        broad = [str(p) for p in scope if tauri.is_broad_path(str(p))]
        if broad and (cfg.version == 1 or proto.get("enable")):
            yield ctx.finding(info, cfg.file, cfg.line_of("ssetProtocol") or cfg.line_of("assetScope"),
                              f"asset scope {broad}", confidence="high")


@check(
    "LP-TAURI-008", "App updates aren't safely verified", "supply-chain", Severity.HIGH,
    why="If updates are fetched over plain HTTP or the update signature key is missing, someone on the network can "
        "push their own build to every user.",
    fix="Use https endpoints only, set the updater pubkey from `tauri signer generate`, and keep the private key out of the repo.",
    cwe=("CWE-494",),
    stacks=STACKS,
)
def updater(ctx: ScanContext, info: CheckInfo) -> Iterator[Finding]:
    for cfg in _configs(ctx):
        up = cfg.get("plugins.updater", "tauri.updater")
        if not isinstance(up, dict) or (cfg.version == 1 and not up.get("active")):
            continue
        insecure = [e for e in up.get("endpoints") or [] if str(e).startswith("http://")]
        if insecure or up.get("dangerousInsecureTransportProtocol"):
            yield ctx.finding(info, cfg.file, cfg.line_of("endpoints"), f"endpoints {insecure or 'insecure transport allowed'}",
                              confidence="high")
        if not up.get("pubkey"):
            yield ctx.finding(info, cfg.file, cfg.line_of("updater"), "updater without pubkey", confidence="high",
                              message="The updater has no public key, so updates can't be verified. " + info.why)


@check(
    "LP-TAURI-009", "Command reads or writes whatever path the page sends", "authz", Severity.MEDIUM,
    why="This command takes a file path from the web page and uses it without checking which folder it's in. If "
        "script in the page is ever compromised, it can read or overwrite any file the user can.",
    fix="Prefer paths chosen by the user through the dialog plugin, or resolve the path and check it's inside an "
        "allowed folder (canonicalize, then starts_with) before touching it.",
    cwe=("CWE-22",),
    stacks=STACKS,
)
def command_paths(ctx: ScanContext, info: CheckInfo) -> Iterator[Finding]:
    for cmd in _commands(ctx):
        if cmd.registered and cmd.file_access != "none" and cmd.path_check in ("none", "ext"):
            if cmd.path_check == "ext" and cmd.file_access == "read":
                continue  # reading only one file type is a reasonable limit
            severity = Severity.MEDIUM if cmd.path_check == "none" else Severity.LOW
            yield ctx.finding(info, cmd.file, cmd.line, f"{cmd.name}({', '.join(cmd.path_inputs)}) {cmd.file_access}s files",
                              severity=severity, confidence="low",
                              message=info.why if cmd.path_check == "none" else
                              "This command writes to a path from the page and only checks the file extension, so it can "
                              "still drop files of that type in any folder.")


@check(
    "LP-TAURI-010", "Command runs a program using input from the page", "injection", Severity.MEDIUM,
    why="This command starts a process and takes input from the web page. If that input reaches the program or its "
        "arguments unchecked, a compromised page can run commands on the user's machine.",
    fix="Run a fixed program, pass arguments as separate values (never through a shell), and validate them against "
        "what you expect.",
    cwe=("CWE-78",),
    stacks=STACKS,
)
def command_processes(ctx: ScanContext, info: CheckInfo) -> Iterator[Finding]:
    for cmd in _commands(ctx):
        if cmd.registered and cmd.runs_programs and cmd.inputs:
            yield ctx.finding(info, cmd.file, cmd.line, f"{cmd.name}({', '.join(cmd.inputs)}) starts a process",
                              confidence="low")


def _commands(ctx: ScanContext) -> list[tauri.TauriCommand]:
    if not hasattr(ctx, "_tauri_commands"):
        ctx._tauri_commands = tauri.analyze_commands(ctx.index)  # type: ignore[attr-defined]
    return ctx._tauri_commands  # type: ignore[attr-defined]


LISTENER = re.compile(r"(?:TcpListener|UdpSocket)::bind\(")
LOOPBACK = re.compile(r"127\.0\.0\.1|localhost|LOCALHOST|::1|Ipv4Addr::new\(\s*127")


@check(
    "LP-RUST-001", "App listens for network connections from other machines", "config", Severity.LOW,
    why="This opens a port that other devices on the network may reach (it isn't bound to 127.0.0.1). That's sometimes "
        "the point, for example a phone remote, but every request it accepts needs authentication and input limits.",
    fix="Bind to 127.0.0.1 unless other devices genuinely need access. If they do, require a random token, rate limit, "
        "and validate every input.",
    cwe=("CWE-1327",),
)
def network_listener(ctx: ScanContext, info: CheckInfo) -> Iterator[Finding]:
    for rel, lineno, line, _ in grep(ctx, LISTENER, exts={".rs"}):
        if LOOPBACK.search(line):
            continue
        if '"0.0.0.0' in line or "UNSPECIFIED" in line:
            yield ctx.finding(info, rel, lineno, line, severity=Severity.MEDIUM, confidence="high",
                              message="This listens on every network interface (0.0.0.0). " + info.why)
        else:
            yield ctx.finding(info, rel, lineno, line, confidence="low")
