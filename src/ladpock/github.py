"""Scanning repositories on GitHub: LadPock keeps its own copy of each, and refreshes it before every scan.

Paste a profile link (github.com/you) to choose from all your repositories, or one repository's link.

- **Copies live in LadPock's data folder** (github/owner/repo), separate from your own folders, so updating
  one can never touch work you have on disk.
- **Nothing in a repository runs.** Git hooks are pointed at nothing, symbolic links are checked out as
  plain files, submodules and local-file transports are refused, and LadPock's file reading never follows links.
- **Private repositories work through the GitHub CLI** (`gh`), if you're signed in to it. Git asks gh for
  credentials as it needs them; LadPock never sees or stores a token. Without gh, public repositories still work.
- **Copies are shallow** (the latest commit only), which is quick and small. Scanning git history for deleted
  secrets needs a project on disk with its full history.
"""

from __future__ import annotations

import json
import os
import re
import shutil
import stat
import subprocess
import sys
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Callable

from .feeds import http
from .paths import data_dir

OWNER = re.compile(r"^[A-Za-z0-9](?:[A-Za-z0-9-]{0,38})$")
REPO = re.compile(r"^[A-Za-z0-9._-]{1,100}$")
LINK = re.compile(
    r"^(?:(?:https?://)?(?:www\.)?github\.com/|git@github\.com:|ssh://git@github\.com/)?"
    r"(?P<owner>[A-Za-z0-9-]+)(?:/(?P<repo>[A-Za-z0-9._-]+?))?(?:\.git)?(?:/(?:tree|blob|pulls?|issues|actions|commits?)(?:/.*)?)?/?(?:[?#].*)?$")
CLONE_TIMEOUT = 600
LIST_LIMIT = 400
# Each of these stops something in a repository from running on this computer, or reaching outside its folder.
SAFE_GIT = ["-c", "core.hooksPath=" + os.devnull, "-c", "core.symlinks=false", "-c", "core.fsmonitor=false",
            "-c", "protocol.file.allow=never", "-c", "protocol.ext.allow=never", "-c", "submodule.recurse=false",
            "-c", "core.longpaths=true", "-c", "advice.detachedHead=false"]


class GitHubError(Exception):
    """Something the person can act on, in words they can act on."""


@dataclass
class Repo:
    full_name: str
    private: bool = False
    archived: bool = False
    fork: bool = False
    empty: bool = False
    description: str = ""
    language: str = ""
    pushed_at: str = ""
    size_kb: int = 0

    def to_dict(self) -> dict:
        return asdict(self)


def parse_link(text: str) -> tuple[str, str | None]:
    """(owner, repository or None) from a link like github.com/owner or github.com/owner/repo, or owner/repo."""
    text = (text or "").strip()
    match = LINK.match(text)
    if not match:
        raise GitHubError("That isn't a GitHub link. Paste something like https://github.com/you or https://github.com/you/your-app")
    owner, repo = match.group("owner"), match.group("repo")
    if not OWNER.match(owner) or owner.lower() in {"orgs", "settings", "login", "about", "features", "topics", "explore"}:
        raise GitHubError(f"'{owner}' isn't a GitHub account name")
    if repo is not None and (not REPO.match(repo) or repo in (".", "..")):
        raise GitHubError(f"'{repo}' isn't a repository name")
    return owner, repo


def root() -> Path:
    path = data_dir() / "github"
    path.mkdir(parents=True, exist_ok=True)
    return path


def copy_path(full_name: str) -> Path:
    owner, repo = full_name.split("/", 1)
    if not OWNER.match(owner) or not REPO.match(repo) or repo in (".", ".."):
        raise GitHubError(f"'{full_name}' isn't a repository name")
    return root() / owner / repo


def managed_name(path: str | Path) -> str | None:
    """owner/repo if this folder is one of LadPock's own GitHub copies."""
    try:
        relative = Path(path).resolve().relative_to((data_dir() / "github").resolve())
    except ValueError:
        return None
    parts = relative.parts
    return f"{parts[0]}/{parts[1]}" if len(parts) == 2 else None


# ---------- tools ----------

def _run(args: list[str], *, cwd: Path | None = None, timeout: float = 60) -> subprocess.CompletedProcess:
    env = {**os.environ, "GIT_TERMINAL_PROMPT": "0", "GCM_INTERACTIVE": "never", "GH_PROMPT_DISABLED": "1", "GIT_LFS_SKIP_SMUDGE": "1"}
    flags = subprocess.CREATE_NO_WINDOW if os.name == "nt" else 0
    return subprocess.run(args, cwd=cwd, env=env, capture_output=True, text=True, encoding="utf-8", errors="replace",
                          timeout=timeout, creationflags=flags, stdin=subprocess.DEVNULL)


def _gh() -> str | None:
    return shutil.which("gh")


def tools() -> dict:
    """What's available: git is needed for everything, gh for private repositories."""
    git = shutil.which("git")
    gh, login = _gh(), None
    if gh:
        try:
            result = _run([gh, "api", "user", "--jq", ".login"], timeout=20)
            login = result.stdout.strip() if result.returncode == 0 else None
        except (OSError, subprocess.SubprocessError):
            login = None
    return {"git": bool(git), "gh": bool(gh), "gh_login": login}


def _credentials() -> list[str]:
    """Let git ask the GitHub CLI for a login when it needs one. LadPock never handles the token itself."""
    gh = _gh()
    if not gh:
        return []
    helper = "!" + gh.replace("\\", "/").replace(" ", "\\ ") + " auth git-credential"
    return ["-c", "credential.https://github.com.helper=", "-c", f"credential.https://github.com.helper={helper}"]


def _error(result: subprocess.CompletedProcess, full_name: str) -> GitHubError:
    text = (result.stderr or result.stdout or "").strip()
    if re.search(r"(?i)not found|could not resolve|could not read username|authentication|403|denied", text):
        hint = "" if _gh() else " If it's private, install the GitHub CLI (gh) and run 'gh auth login'."
        return GitHubError(f"Couldn't get {full_name}: it doesn't exist or you don't have access.{hint}")
    return GitHubError(f"Couldn't get {full_name}: {text.splitlines()[-1][:200] if text else 'git failed'}")


# ---------- listing ----------

def _from_gh(item: dict) -> Repo:
    language = item.get("primaryLanguage") or {}
    return Repo(item.get("nameWithOwner", ""), bool(item.get("isPrivate")), bool(item.get("isArchived")), bool(item.get("isFork")),
                bool(item.get("isEmpty")), (item.get("description") or "")[:200], language.get("name") or "" if isinstance(language, dict) else "",
                item.get("pushedAt") or "", int(item.get("diskUsage") or 0))


def _from_api(item: dict) -> Repo:
    return Repo(item.get("full_name", ""), bool(item.get("private")), bool(item.get("archived")), bool(item.get("fork")),
                int(item.get("size") or 0) == 0, (item.get("description") or "")[:200], item.get("language") or "",
                item.get("pushed_at") or "", int(item.get("size") or 0))


GH_FIELDS = "nameWithOwner,isPrivate,isArchived,isFork,isEmpty,description,primaryLanguage,pushedAt,diskUsage"


def list_repos(owner: str, repo: str | None = None) -> tuple[list[Repo], str]:
    """The repositories behind a link, and how they were found ("gh" sees private ones, "api" only public)."""
    gh = _gh()
    if gh:
        args = [gh, "repo", "view", f"{owner}/{repo}", "--json", GH_FIELDS] if repo else \
               [gh, "repo", "list", owner, "--limit", str(LIST_LIMIT), "--json", GH_FIELDS]
        try:
            result = _run(args, timeout=60)
        except (OSError, subprocess.SubprocessError) as exc:
            raise GitHubError(f"The GitHub CLI didn't answer: {exc}") from exc
        if result.returncode == 0:
            data = json.loads(result.stdout or "[]")
            items = [data] if isinstance(data, dict) else data
            return sorted((_from_gh(i) for i in items if isinstance(i, dict)), key=lambda r: r.pushed_at, reverse=True), "gh"
        if "auth login" not in (result.stderr or ""):
            raise _error(result, f"{owner}/{repo}" if repo else owner)
    try:
        if repo:
            status, _, body = http.request(f"https://api.github.com/repos/{owner}/{repo}", headers={"Accept": "application/vnd.github+json"})
            items = [json.loads(body)] if status == 200 else []
        else:
            items = []
            for page in range(1, 5):
                status, _, body = http.request(f"https://api.github.com/users/{owner}/repos?per_page=100&sort=pushed&page={page}",
                                               headers={"Accept": "application/vnd.github+json"})
                batch = json.loads(body) if status == 200 else []
                items.extend(batch if isinstance(batch, list) else [])
                if len(batch) < 100:
                    break
    except http.FeedError as exc:
        raise GitHubError(f"Couldn't reach GitHub: {exc}") from exc
    except ValueError as exc:
        raise GitHubError("GitHub sent an answer LadPock couldn't read") from exc
    if not items:
        raise GitHubError(f"Found nothing at github.com/{owner}{'/' + repo if repo else ''}. If it's private, install the GitHub CLI (gh) and run 'gh auth login'.")
    return sorted((_from_api(i) for i in items if isinstance(i, dict)), key=lambda r: r.pushed_at, reverse=True), "api"


# ---------- copies ----------

def fetch(full_name: str, log: Callable[[str], None] = lambda _: None) -> Path:
    """Make LadPock's copy of a repository, or bring an existing one up to date. Returns its folder."""
    git = shutil.which("git")
    if not git:
        raise GitHubError("Git isn't installed. Install it from https://git-scm.com and try again.")
    dest = copy_path(full_name)
    url = f"https://github.com/{full_name}.git"
    base = [git, *SAFE_GIT, *_credentials()]
    try:
        if (dest / ".git").is_dir():
            log(f"Updating {full_name} from GitHub ...")
            result = _run([*base, "-C", str(dest), "fetch", "--depth", "1", "--no-tags", "--no-recurse-submodules", "origin", "HEAD"],
                          timeout=CLONE_TIMEOUT)
            if result.returncode != 0:
                raise _error(result, full_name)
            for step in (["reset", "--hard", "FETCH_HEAD"], ["clean", "-fdx", "-q"]):
                result = _run([*base, "-C", str(dest), *step], timeout=120)
                if result.returncode != 0:
                    raise _error(result, full_name)
            return dest
        log(f"Copying {full_name} from GitHub ...")
        if dest.exists():
            remove_copy(dest)  # a copy that never finished
        dest.parent.mkdir(parents=True, exist_ok=True)
        result = _run([*base, "clone", "--depth", "1", "--no-tags", "--single-branch", "--no-recurse-submodules", "--", url, str(dest)],
                      timeout=CLONE_TIMEOUT)
        if result.returncode != 0:
            if dest.exists():
                remove_copy(dest)
            raise _error(result, full_name)
    except subprocess.TimeoutExpired as exc:
        raise GitHubError(f"{full_name} took too long to download (over {CLONE_TIMEOUT // 60} minutes)") from exc
    except OSError as exc:
        raise GitHubError(f"Couldn't run git: {exc}") from exc
    return dest


def remove_copy(path: str | Path) -> bool:
    """Delete one of LadPock's own copies. Refuses anything outside its github folder."""
    target = Path(path).resolve()
    if not managed_name(target):
        return False

    def writable(func, name, _exc):  # git marks its object files read-only on Windows
        os.chmod(name, stat.S_IWRITE)
        func(name)

    if sys.version_info >= (3, 12):
        shutil.rmtree(target, onexc=writable)
    else:
        shutil.rmtree(target, onerror=writable)
    owner = target.parent
    if owner != root().resolve() and not any(owner.iterdir()):
        owner.rmdir()
    return True
