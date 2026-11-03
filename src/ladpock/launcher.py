"""A double-click way to open the dashboard: a Start Menu (and optional Desktop)
shortcut on Windows, a .command file on macOS, and a menu entry on Linux.

Each one runs `ladpock ui` in a terminal window, so it's always obvious that
LadPock is running, and closing the window stops it.
"""

from __future__ import annotations

import os
import shutil
import subprocess
import sys
from pathlib import Path

NAME = "LadPock"


def command() -> list[str]:
    """How to start the dashboard with the LadPock that's running now."""
    exe = shutil.which("ladpock")
    if exe:
        return [str(Path(exe).resolve()), "ui"]
    return [sys.executable, "-m", "ladpock", "ui"]


def locations(platform: str = sys.platform, home: Path | None = None, desktop: bool = False) -> list[Path]:
    real_home = home is None
    home = home or Path.home()
    if platform == "win32":
        appdata = Path(os.environ["APPDATA"]) if real_home and os.environ.get("APPDATA") else home / "AppData" / "Roaming"
        paths = [appdata / "Microsoft" / "Windows" / "Start Menu" / "Programs" / f"{NAME}.lnk"]
        if desktop:
            paths.append(home / "Desktop" / f"{NAME}.lnk")
        return paths
    if platform == "darwin":
        paths = [home / "Applications" / f"{NAME}.command"]
        if desktop:
            paths.append(home / "Desktop" / f"{NAME}.command")
        return paths
    paths = [home / ".local" / "share" / "applications" / "ladpock.desktop"]
    if desktop:
        paths.append(home / "Desktop" / "ladpock.desktop")
    return paths


def _quote_ps(text: str) -> str:
    return "'" + text.replace("'", "''") + "'"


def _write_lnk(path: Path, argv: list[str]) -> None:
    script = (
        "$s = (New-Object -ComObject WScript.Shell).CreateShortcut(" + _quote_ps(str(path)) + "); "
        f"$s.TargetPath = {_quote_ps(argv[0])}; "
        f"$s.Arguments = {_quote_ps(subprocess.list2cmdline(argv[1:]))}; "
        f"$s.WorkingDirectory = {_quote_ps(str(Path.home()))}; "
        "$s.Description = 'Open the LadPock security dashboard (close the window to stop it)'; "
        "$s.Save()"
    )
    proc = subprocess.run(["powershell", "-NoProfile", "-NonInteractive", "-Command", script],
                          capture_output=True, text=True, timeout=60)
    if proc.returncode != 0 or not path.exists():
        raise OSError(f"Couldn't create {path}: {proc.stderr.strip() or 'PowerShell failed'}")


def _shell_line(argv: list[str]) -> str:
    return " ".join("'" + a.replace("'", "'\\''") + "'" for a in argv)


def install(platform: str = sys.platform, home: Path | None = None, desktop: bool = False,
            argv: list[str] | None = None) -> list[Path]:
    argv = argv or command()
    made = []
    for path in locations(platform, home, desktop):
        path.parent.mkdir(parents=True, exist_ok=True)
        if platform == "win32":
            _write_lnk(path, argv)
        elif platform == "darwin":
            path.write_text(f"#!/bin/sh\n# Opens the LadPock dashboard. Close this window to stop it.\nexec {_shell_line(argv)}\n",
                            encoding="utf-8")
            path.chmod(0o755)
        else:
            path.write_text(
                "[Desktop Entry]\nType=Application\nName=LadPock\n"
                "Comment=Security checks for your own projects (close the terminal to stop)\n"
                f"Exec={_shell_line(argv)}\nTerminal=true\nCategories=Development;Security;\n",
                encoding="utf-8",
            )
            path.chmod(0o755)
        made.append(path)
    return made


def remove(platform: str = sys.platform, home: Path | None = None) -> list[Path]:
    removed = []
    for path in locations(platform, home, desktop=True):
        if path.exists():
            path.unlink()
            removed.append(path)
    return removed
