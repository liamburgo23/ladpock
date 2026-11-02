"""Where LadPock keeps its local database."""

from __future__ import annotations

import os
import sys
from pathlib import Path


def data_dir() -> Path:
    override = os.environ.get("LADPOCK_HOME")
    if override:
        path = Path(override)
    elif sys.platform == "win32":
        base = os.environ.get("LOCALAPPDATA") or str(Path.home() / "AppData" / "Local")
        path = Path(base) / "LadPock"
    elif sys.platform == "darwin":
        path = Path.home() / "Library" / "Application Support" / "LadPock"
    else:
        base = os.environ.get("XDG_DATA_HOME") or str(Path.home() / ".local" / "share")
        path = Path(base) / "ladpock"
    path.mkdir(parents=True, exist_ok=True)
    return path


def db_path() -> Path:
    return data_dir() / "ladpock.db"
