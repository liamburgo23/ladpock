"""Read-only git helpers that are safe to run inside an untrusted repository."""

from __future__ import annotations

import os
import shutil
import subprocess
from pathlib import Path


def safe_env() -> dict[str, str]:
    """Environment for any subprocess that may invoke git on a scanned repo.

    A repository's own .git/config can set core.fsmonitor to an arbitrary
    command, which git runs on many read operations. Forcing it off stops a
    malicious repo from executing code when we look at it.
    """
    env = dict(os.environ)
    env.update(
        {
            "GIT_CONFIG_COUNT": "1",
            "GIT_CONFIG_KEY_0": "core.fsmonitor",
            "GIT_CONFIG_VALUE_0": "false",
            "GIT_TERMINAL_PROMPT": "0",
        }
    )
    return env


def tracked_files(root: Path) -> set[str] | None:
    """Files committed to git, or None if this isn't a git repo we can read."""
    git = shutil.which("git")
    if not git or not (root / ".git").exists():
        return None
    try:
        proc = subprocess.run(
            [git, "-c", "core.fsmonitor=false", "-C", str(root), "ls-files", "-z"],
            capture_output=True,
            timeout=60,
            env=safe_env(),
        )
    except (OSError, subprocess.TimeoutExpired):
        return None
    if proc.returncode != 0:
        return None
    return {p for p in proc.stdout.decode("utf-8", "replace").split("\0") if p}
