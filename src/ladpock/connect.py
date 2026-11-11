"""`ladpock connect`: add LadPock's MCP server to the AI coding apps on this computer.

Each app keeps its MCP servers in its own settings file. LadPock adds one entry named "ladpock" and touches
nothing else: it leaves an existing "ladpock" entry alone, keeps a backup of the file before changing it, writes
the new file in one step, and won't edit a file it can't read exactly (VS Code allows comments in its file, for
example). In that case it prints what to add instead.

For Claude Code it also adds a /ladpock command (a Markdown file in ~/.claude/commands).
"""

from __future__ import annotations

import json
import os
import shutil
import sys
import tempfile
from dataclasses import dataclass
from pathlib import Path

NAME = "ladpock"


def server_command() -> list[str]:
    """How an app should start LadPock's MCP server. Absolute paths, since apps started from a menu may not share your PATH."""
    exe = shutil.which("ladpock")
    return [str(Path(exe).resolve()), "mcp"] if exe else [sys.executable, "-m", "ladpock", "mcp"]


def _vscode_dir() -> Path:
    if os.name == "nt":
        return Path(os.environ.get("APPDATA", Path.home() / "AppData" / "Roaming")) / "Code" / "User"
    if sys.platform == "darwin":
        return Path.home() / "Library" / "Application Support" / "Code" / "User"
    return Path.home() / ".config" / "Code" / "User"


@dataclass
class App:
    key: str
    name: str
    config: Path
    shape: str  # "mcpServers" (Claude Code, Cursor, Windsurf), "servers" (VS Code) or "toml" (Codex)
    present: Path  # this existing means the app is probably installed

    def installed(self) -> bool:
        return self.present.exists()


def apps() -> list[App]:
    home = Path.home()
    return [
        App("claude", "Claude Code", home / ".claude.json", "mcpServers", home / ".claude"),
        App("codex", "Codex", home / ".codex" / "config.toml", "toml", home / ".codex"),
        App("cursor", "Cursor", home / ".cursor" / "mcp.json", "mcpServers", home / ".cursor"),
        App("vscode", "VS Code", _vscode_dir() / "mcp.json", "servers", _vscode_dir()),
        App("windsurf", "Windsurf", home / ".codeium" / "windsurf" / "mcp_config.json", "mcpServers", home / ".codeium" / "windsurf"),
    ]


def find(key: str) -> App:
    for app in apps():
        if app.key == key:
            return app
    raise ValueError(f"Unknown app '{key}'. Choose from: {', '.join(a.key for a in apps())}")


# ---------- reading and writing settings files ----------

def _entry(app: App) -> dict:
    command, *args = server_command()
    entry = {"command": command, "args": args}
    return {"type": "stdio", **entry} if app.shape in ("servers",) or app.key == "claude" else entry


def _toml_block() -> str:
    command, *args = server_command()

    def literal(text: str) -> str:
        if "'" in text or "\n" in text:
            return json.dumps(text)  # a basic TOML string; JSON escaping is valid TOML for these characters
        return f"'{text}'"

    return f"\n[mcp_servers.{NAME}]\ncommand = {literal(command)}\nargs = [{', '.join(literal(a) for a in args)}]\n"


def snippet(app: App) -> str:
    """What to add by hand."""
    if app.shape == "toml":
        return _toml_block().strip()
    return json.dumps({app.shape: {NAME: _entry(app)}}, indent=2)


def is_connected(app: App) -> bool:
    try:
        text = app.config.read_text(encoding="utf-8")
    except OSError:
        return False
    if app.shape == "toml":
        return f"[mcp_servers.{NAME}]" in text
    try:
        data = json.loads(text)
    except ValueError:
        return f'"{NAME}"' in text
    return isinstance(data, dict) and isinstance(data.get(app.shape), dict) and NAME in data[app.shape]


def _write(path: Path, text: str) -> None:
    """Back up the old file, then replace it in one step, so a crash can't leave it half written."""
    path.parent.mkdir(parents=True, exist_ok=True)
    if path.exists():
        shutil.copy2(path, path.with_name(path.name + ".ladpock-backup"))
    handle, temp = tempfile.mkstemp(dir=path.parent, prefix=f".{path.name}.", suffix=".tmp")
    try:
        with os.fdopen(handle, "w", encoding="utf-8", newline="") as out:
            out.write(text)
        os.replace(temp, path)
    except BaseException:
        Path(temp).unlink(missing_ok=True)
        raise


class ConnectError(Exception):
    pass


def add_server(app: App) -> str:
    if is_connected(app):
        return f"{app.name} already has a '{NAME}' MCP server, so it was left as it is."
    if app.shape == "toml":
        existing = app.config.read_text(encoding="utf-8") if app.config.exists() else ""
        _write(app.config, existing.rstrip("\n") + ("\n" if existing else "") + _toml_block())
        return f"Added LadPock to {app.name} ({app.config})."
    data: dict = {}
    if app.config.exists():
        try:
            data = json.loads(app.config.read_text(encoding="utf-8") or "{}")
        except ValueError as exc:
            raise ConnectError(f"{app.config} has something LadPock can't read exactly (comments, perhaps), so it wasn't changed. "
                               f"Add this to it yourself:\n{snippet(app)}") from exc
        if not isinstance(data, dict) or not isinstance(data.get(app.shape, {}), dict):
            raise ConnectError(f"{app.config} isn't laid out as expected, so it wasn't changed. Add this yourself:\n{snippet(app)}")
    data.setdefault(app.shape, {})[NAME] = _entry(app)
    _write(app.config, json.dumps(data, indent=2) + "\n")
    return f"Added LadPock to {app.name} ({app.config})."


def remove_server(app: App) -> str:
    if not is_connected(app):
        return f"{app.name} doesn't have a '{NAME}' MCP server."
    text = app.config.read_text(encoding="utf-8")
    if app.shape == "toml":
        lines, out, skipping = text.splitlines(keepends=True), [], False
        for line in lines:
            stripped = line.strip()
            if stripped.startswith("["):
                skipping = stripped == f"[mcp_servers.{NAME}]"
            if not skipping:
                out.append(line)
        _write(app.config, "".join(out))
    else:
        try:
            data = json.loads(text)
        except ValueError as exc:
            raise ConnectError(f"{app.config} has something LadPock can't read exactly, so it wasn't changed. Remove '{NAME}' yourself.") from exc
        data[app.shape].pop(NAME, None)
        _write(app.config, json.dumps(data, indent=2) + "\n")
    return f"Removed LadPock from {app.name}."


# ---------- the /ladpock command for Claude Code ----------

COMMAND_FILE = Path.home() / ".claude" / "commands" / "ladpock.md"
COMMAND_MARK = "<!-- Added by LadPock -->"
COMMAND = f"""---
description: Ask LadPock what it found in this project, or fix the findings one by one
argument-hint: "[fix [critical|high|medium|low|all]] or a question"
---
{COMMAND_MARK}
Use the LadPock MCP tools on the project in the folder you're working in (pass its absolute path).

What I asked: $ARGUMENTS

- If I asked nothing: call ladpock_scan, then tell me in a few lines the grade, the most serious problems (with file
  and line) and any known risks that were accepted. Offer to fix them one by one.
- If I asked to fix (for example "fix" or "fix all"): call ladpock_fix_start with which set to the severity I named
  (high if I didn't), then follow LadPock's instructions exactly: one finding at a time, ladpock_fix_check after each,
  commit when it says to, and stop to ask me when it says STOP. At the end, tell me what was fixed, what's left for me,
  and any risks you accepted and why.
- Otherwise: answer my question using ladpock_findings, ladpock_explain_grade or ladpock_routes.

Never hide a finding with ignore comments or LadPock settings. If something isn't a real problem, say so, and only
accept it as a known risk with ladpock_accept_risk and a clear reason.
"""


def add_command() -> str:
    if COMMAND_FILE.exists() and COMMAND_MARK not in COMMAND_FILE.read_text(encoding="utf-8", errors="replace"):
        return f"You already have your own {COMMAND_FILE}, so the /ladpock command was left as it is."
    _write(COMMAND_FILE, COMMAND)
    return "Added the /ladpock command to Claude Code (/ladpock for a summary, /ladpock fix to fix one by one)."


def remove_command() -> str:
    if COMMAND_FILE.exists() and COMMAND_MARK in COMMAND_FILE.read_text(encoding="utf-8", errors="replace"):
        COMMAND_FILE.unlink()
        return "Removed the /ladpock command from Claude Code."
    return ""


def connect(key: str, remove: bool = False) -> list[str]:
    app = find(key)
    lines = [remove_server(app) if remove else add_server(app)]
    if app.key == "claude":
        extra = remove_command() if remove else add_command()
        if extra:
            lines.append(extra)
    if not remove:
        lines.append(f"Restart {app.name} (or start a new chat) so it picks LadPock up.")
    return lines
