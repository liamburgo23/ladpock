"""Tauri apps: reading the app config and capabilities, and the command matrix.

Tauri's security model is: the web page (which may be hit by XSS) can only do
what the Rust side exposes. That's the Content-Security-Policy, the capability
files that grant plugin permissions, and every #[tauri::command] function the
page can invoke. This module reads all three for Tauri v2, plus v1's allowlist.
"""

from __future__ import annotations

import json
import re
import tomllib
from dataclasses import dataclass, field

from .files import FileIndex, basename
from .jsparse import line_of, match_bracket, strip_comments

CONFIG_NAMES = ("tauri.conf.json", "Tauri.toml")
INJECTED_TYPES = re.compile(r"\b(?:AppHandle|State|Window|WebviewWindow|Webview|Request|Channel|Runtime|InvokeMessage)\b")
PATHISH_NAME = re.compile(r"(?i)path|file|dir|folder|dest|target|src|source|location|filename|out")
STRING_TYPE = re.compile(r"\b(?:String|PathBuf|Path|str|OsString)\b")

FS_WRITE = re.compile(
    r"\b(?:std::|tokio::)?fs::(?:write|create_dir\w*|remove\w*|rename|copy|hard_link|set_permissions)\b|"
    r"File::create\b|OpenOptions\b|\.write_all\("
)
FS_READ = re.compile(r"\b(?:std::|tokio::)?fs::read\w*\b|File::open\b")
# "Is this path inside an allowed folder?": a path-like receiver or argument to starts_with/strip_prefix.
# (bytes.starts_with(b"%PDF-") is a content check, so the argument must look like a folder, not a literal.)
DIR_CHECK = re.compile(
    r"\b(?:\w*(?:path|dir|root|base|canon)\w*|p)\.(?:starts_with|strip_prefix)\(|"
    r"\.(?:starts_with|strip_prefix)\(\s*&?\s*\w*(?:base|root|dir|allowed|folder|home)\w*|\bis_within\w*\(|\ballowed_\w*\("
)
EXT_CHECK = re.compile(r"\.extension\(\)|\bhas_ext\w*\(|\.ends_with\(\s*\"\.\w+\"")
PROCESS = re.compile(r"\bCommand::new\(|\bstd::process::|\btokio::process::|\.shell\(\)\.command\(|\bopen::that\w*\(|\bopener::")
NETWORK = re.compile(r"\breqwest::|\bureq::|\bTcpStream::|\bTcpListener::|\bUdpSocket::|\baxum::serve\(")
COMMAND_ATTR = re.compile(r"#\[\s*tauri::command\b[^\]]*\]")
FN_DEF = re.compile(r"\bfn\s+(\w+)\s*(?:<[^>{]*>)?\s*\(")
HANDLER = re.compile(r"generate_handler!\s*\[([^\]]*)\]")


@dataclass
class TauriConfig:
    file: str
    version: int  # 1 or 2
    data: dict
    text: str

    def get(self, *paths: str):
        """First value found at any of the dotted paths, or None."""
        for path in paths:
            node = self.data
            for key in path.split("."):
                if not isinstance(node, dict) or key not in node:
                    node = None
                    break
                node = node[key]
            if node is not None:
                return node
        return None

    def has(self, path: str) -> bool:
        node = self.data
        for key in path.split("."):
            if not isinstance(node, dict) or key not in node:
                return False
            node = node[key]
        return True

    def line_of(self, needle: str) -> int | None:
        idx = self.text.find(needle)
        return None if idx < 0 else self.text.count("\n", 0, idx) + 1


@dataclass
class Capability:
    file: str
    data: dict
    text: str

    @property
    def permissions(self) -> list:
        perms = self.data.get("permissions")
        return perms if isinstance(perms, list) else []

    def line_of(self, needle: str) -> int | None:
        idx = self.text.find(needle)
        return None if idx < 0 else self.text.count("\n", 0, idx) + 1


@dataclass
class TauriCommand:
    name: str
    file: str
    line: int
    inputs: list[str] = field(default_factory=list)  # parameters the page controls
    path_inputs: list[str] = field(default_factory=list)
    file_access: str = "none"  # none | read | write
    path_check: str = "n/a"  # dir | ext | none | n/a
    runs_programs: bool = False
    network: bool = False
    registered: bool = True

    def to_dict(self) -> dict:
        return {k: getattr(self, k) for k in (
            "name", "file", "line", "inputs", "path_inputs", "file_access", "path_check", "runs_programs",
            "network", "registered")}


def is_tauri_project(index: FileIndex) -> bool:
    return any(basename(rel) in CONFIG_NAMES or basename(rel) == "tauri.conf.json5" for rel in index.paths)


def load_configs(index: FileIndex) -> tuple[list[TauriConfig], list[str]]:
    configs: list[TauriConfig] = []
    warnings: list[str] = []
    for rel in index.iter(names=set(CONFIG_NAMES) | {"tauri.conf.json5"}):
        text = index.read(rel) or ""
        try:
            data = tomllib.loads(text) if rel.endswith(".toml") else json.loads(text)
        except (ValueError, tomllib.TOMLDecodeError):
            warnings.append(f"Couldn't read {rel} (JSON5 and invalid JSON aren't supported yet)")
            continue
        if not isinstance(data, dict):
            continue
        version = 1 if "tauri" in data and isinstance(data["tauri"], dict) else 2
        configs.append(TauriConfig(rel, version, data, text))
    return configs, warnings


def load_capabilities(index: FileIndex, configs: list[TauriConfig]) -> list[Capability]:
    caps: list[Capability] = []
    for rel in index.iter({".json", ".toml"}):
        if "/capabilities/" not in f"/{rel}":
            continue
        text = index.read(rel) or ""
        try:
            data = tomllib.loads(text) if rel.endswith(".toml") else json.loads(text)
        except (ValueError, tomllib.TOMLDecodeError):
            continue
        items = data if isinstance(data, list) else data.get("capabilities", [data]) if isinstance(data, dict) else []
        caps.extend(Capability(rel, item, text) for item in items if isinstance(item, dict))
    for cfg in configs:  # capabilities can also be inlined in the app config
        for item in cfg.get("app.security.capabilities") or []:
            if isinstance(item, dict):
                caps.append(Capability(cfg.file, item, cfg.text))
    return caps


def permission_id(perm) -> str:
    if isinstance(perm, str):
        return perm
    if isinstance(perm, dict):
        return str(perm.get("identifier", ""))
    return ""


def permission_paths(perm) -> list[str]:
    """Scope paths attached to a permission object ({identifier, allow: [{path}]})."""
    if not isinstance(perm, dict):
        return []
    out = []
    for entry in perm.get("allow") or []:
        if isinstance(entry, dict) and isinstance(entry.get("path"), str):
            out.append(entry["path"])
        elif isinstance(entry, str):
            out.append(entry)
    return out


BROAD_PATH = re.compile(r"^(?:\*\*|/\*\*|[A-Za-z]:[/\\]?\*\*|\$HOME(?:/\*\*)?|\$HOME/\*|~/\*\*|\$\{?HOME\}?/\*\*|/|\*)$")


def is_broad_path(path: str) -> bool:
    return bool(BROAD_PATH.match(path.strip()))


# command matrix


def _split_params(text: str) -> list[str]:
    params, depth, start = [], 0, 0
    for i, c in enumerate(text):
        if c in "<([{":
            depth += 1
        elif c in ">)]}":
            depth -= 1
        elif c == "," and depth == 0:
            params.append(text[start:i])
            start = i + 1
    if text[start:].strip():
        params.append(text[start:])
    return [p.strip() for p in params if p.strip()]


def _functions(code: str) -> dict[str, tuple[int, int, str]]:
    """name -> (start, end, params text) for every fn with a body in this file."""
    out = {}
    for match in FN_DEF.finditer(code):
        open_paren = match.end() - 1
        close_paren = match_bracket(code, open_paren, quotes='"')
        if close_paren < 0:
            continue
        brace = code.find("{", close_paren)
        semicolon = code.find(";", close_paren)
        if brace < 0 or (0 <= semicolon < brace):
            continue  # trait method declaration, no body
        end = match_bracket(code, brace, quotes='"')
        if end > 0:
            out[match.group(1)] = (match.start(), end, code[open_paren + 1:close_paren])
    return out


def analyze_commands(index: FileIndex) -> list[TauriCommand]:
    rust_files = [rel for rel in index.iter({".rs"}) if "/target/" not in f"/{rel}"]
    registered: set[str] | None = None
    sources: dict[str, str] = {}
    for rel in rust_files:
        code = strip_comments(index.read(rel) or "", quotes='"')
        sources[rel] = code
        for match in HANDLER.finditer(code):
            names = {n.strip().split("::")[-1] for n in match.group(1).split(",") if n.strip()}
            registered = (registered or set()) | names

    commands: list[TauriCommand] = []
    for rel, code in sources.items():
        if "tauri::command" not in code:
            continue
        functions = _functions(code)
        for attr in COMMAND_ATTR.finditer(code):
            fn = FN_DEF.search(code, attr.end())
            if not fn or fn.group(1) not in functions:
                continue
            name = fn.group(1)
            start, end, params_text = functions[name]
            body = code[start:end]
            # Follow calls into helpers in the same file one level deep (e.g. write_atomic, reveal).
            for helper, (h_start, h_end, _) in functions.items():
                if helper != name and re.search(rf"\b{re.escape(helper)}\s*\(", body):
                    body += "\n" + code[h_start:h_end]
            cmd = TauriCommand(name, rel, line_of(code, fn.start()))
            for param in _split_params(params_text):
                pname, _, ptype = param.partition(":")
                pname = pname.replace("mut ", "").strip()
                if not ptype or INJECTED_TYPES.search(ptype) or pname.startswith("_"):
                    continue
                cmd.inputs.append(pname)
                if STRING_TYPE.search(ptype) and PATHISH_NAME.search(pname):
                    cmd.path_inputs.append(pname)
            if FS_WRITE.search(body):
                cmd.file_access = "write"
            elif FS_READ.search(body):
                cmd.file_access = "read"
            if cmd.file_access != "none" and cmd.path_inputs:
                cmd.path_check = "dir" if DIR_CHECK.search(body) else "ext" if EXT_CHECK.search(body) else "none"
            cmd.runs_programs = bool(PROCESS.search(body))
            cmd.network = bool(NETWORK.search(body))
            cmd.registered = registered is None or name in registered
            commands.append(cmd)
    commands.sort(key=lambda c: (not c.registered, c.file, c.line))
    return commands


def command_gaps(cmd: TauriCommand) -> list[str]:
    out = []
    if cmd.file_access != "none" and cmd.path_check == "none":
        out.append(f"{cmd.file_access}s any path the page sends")
    elif cmd.file_access == "write" and cmd.path_check == "ext":
        out.append("checks file type only, not folder")
    if cmd.runs_programs and cmd.inputs:
        out.append("runs a program with page input")
    if not cmd.registered:
        out.append("not registered (unused?)")
    return out
