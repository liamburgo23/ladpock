"""Being a good overnight guest: power checks, keep-awake, low priority, and the
Windows scheduled task that runs the nightly review."""

from __future__ import annotations

import contextlib
import os
import shutil
import subprocess
import sys
import tempfile
from datetime import datetime, timedelta
from pathlib import Path
from xml.sax.saxutils import escape

import ladpock

from ..paths import data_dir

TASK_NAME = r"LadPock\Nightly AI review"


def on_battery() -> bool:
    """True only when we know the computer is running on battery."""
    if sys.platform != "win32":
        return False
    try:
        import ctypes

        class PowerStatus(ctypes.Structure):
            _fields_ = [("ACLineStatus", ctypes.c_byte), ("BatteryFlag", ctypes.c_byte),
                        ("BatteryLifePercent", ctypes.c_byte), ("SystemStatusFlag", ctypes.c_byte),
                        ("BatteryLifeTime", ctypes.c_ulong), ("BatteryFullLifeTime", ctypes.c_ulong)]

        status = PowerStatus()
        if ctypes.windll.kernel32.GetSystemPowerStatus(ctypes.byref(status)):
            return status.ACLineStatus == 0
    except (AttributeError, OSError):
        pass
    return False


@contextlib.contextmanager
def keep_awake():
    """Stop Windows sleeping while a review runs (the display may still turn off)."""
    if sys.platform != "win32":
        yield
        return
    import ctypes

    es_continuous, es_system_required = 0x80000000, 0x00000001
    try:
        ctypes.windll.kernel32.SetThreadExecutionState(es_continuous | es_system_required)
        yield
    finally:
        ctypes.windll.kernel32.SetThreadExecutionState(es_continuous)


def lower_priority() -> None:
    try:
        if sys.platform == "win32":
            import ctypes

            below_normal = 0x4000
            ctypes.windll.kernel32.SetPriorityClass(ctypes.windll.kernel32.GetCurrentProcess(), below_normal)
        else:
            os.nice(10)
    except (AttributeError, OSError):
        pass


def deadline_from(until: str | None, max_minutes: int | None) -> datetime | None:
    """Turn '07:00' (the next one) and/or a minute budget into a local deadline."""
    now = datetime.now()
    candidates = []
    if until:
        hour, minute = (int(part) for part in until.split(":", 1))
        target = now.replace(hour=hour, minute=minute, second=0, microsecond=0)
        if target <= now:
            target += timedelta(days=1)
        candidates.append(target)
    if max_minutes:
        candidates.append(now + timedelta(minutes=max_minutes))
    return min(candidates) if candidates else None


# scheduling


def task_command(until: str) -> tuple[str, str, str]:
    """(program, arguments, working folder) for the scheduled run."""
    program = sys.executable
    if program.lower().endswith("python.exe"):
        quiet = Path(program).with_name("pythonw.exe")  # no console window popping up at 1am
        if quiet.exists():
            program = str(quiet)
    log = data_dir() / "ai-nightly.log"
    args = f'-m ladpock ai review --all --until {until} --require-ac --log-file "{log}"'
    workdir = str(Path(ladpock.__file__).resolve().parent.parent)  # works from a source checkout too
    return program, args, workdir


def task_xml(at: str, until: str, wake: bool) -> str:
    program, args, workdir = task_command(until)
    hour, minute = (int(part) for part in at.split(":", 1))
    start = datetime.now().replace(hour=hour, minute=minute, second=0, microsecond=0)
    if start <= datetime.now():
        start += timedelta(days=1)
    return f"""<?xml version="1.0" encoding="UTF-16"?>
<Task version="1.2" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">
  <RegistrationInfo>
    <Description>LadPock nightly local AI security review. Remove with: ladpock ai unschedule</Description>
  </RegistrationInfo>
  <Triggers>
    <CalendarTrigger>
      <StartBoundary>{start.strftime('%Y-%m-%dT%H:%M:%S')}</StartBoundary>
      <Enabled>true</Enabled>
      <ScheduleByDay><DaysInterval>1</DaysInterval></ScheduleByDay>
    </CalendarTrigger>
  </Triggers>
  <Principals>
    <Principal id="Author">
      <LogonType>InteractiveToken</LogonType>
      <RunLevel>LeastPrivilege</RunLevel>
    </Principal>
  </Principals>
  <Settings>
    <MultipleInstancesPolicy>IgnoreNew</MultipleInstancesPolicy>
    <DisallowStartIfOnBatteries>true</DisallowStartIfOnBatteries>
    <StopIfGoingOnBatteries>true</StopIfGoingOnBatteries>
    <StartWhenAvailable>false</StartWhenAvailable>
    <WakeToRun>{'true' if wake else 'false'}</WakeToRun>
    <ExecutionTimeLimit>PT12H</ExecutionTimeLimit>
    <Priority>7</Priority>
    <Enabled>true</Enabled>
  </Settings>
  <Actions Context="Author">
    <Exec>
      <Command>{escape(program)}</Command>
      <Arguments>{escape(args)}</Arguments>
      <WorkingDirectory>{escape(workdir)}</WorkingDirectory>
    </Exec>
  </Actions>
</Task>
"""


def _schtasks() -> str:
    exe = shutil.which("schtasks")
    if sys.platform != "win32" or not exe:
        raise RuntimeError("Nightly scheduling is built in on Windows. On macOS or Linux, add this to your crontab:\n"
                           f"  0 1 * * * {sys.executable} -m ladpock ai review --all --until 07:00 --require-ac")
    return exe


def schedule(at: str = "01:00", until: str = "07:00", wake: bool = False) -> None:
    exe = _schtasks()
    with tempfile.TemporaryDirectory() as tmp:
        path = Path(tmp) / "ladpock-task.xml"
        path.write_text(task_xml(at, until, wake), encoding="utf-16")
        proc = subprocess.run([exe, "/Create", "/TN", TASK_NAME, "/XML", str(path), "/F"],
                              capture_output=True, text=True, timeout=30)
    if proc.returncode != 0:
        raise RuntimeError((proc.stderr or proc.stdout).strip() or "schtasks failed")


def unschedule() -> bool:
    exe = _schtasks()
    proc = subprocess.run([exe, "/Delete", "/TN", TASK_NAME, "/F"], capture_output=True, text=True, timeout=30)
    return proc.returncode == 0


def schedule_status() -> dict:
    """{'scheduled': bool, 'next_run': str|None} without changing anything."""
    exe = shutil.which("schtasks")
    if sys.platform != "win32" or not exe:
        return {"scheduled": False, "next_run": None, "supported": False}
    proc = subprocess.run([exe, "/Query", "/TN", TASK_NAME, "/FO", "LIST"], capture_output=True, text=True, timeout=30)
    if proc.returncode != 0:
        return {"scheduled": False, "next_run": None, "supported": True}
    next_run = None
    for line in proc.stdout.splitlines():
        if line.lower().startswith("next run time:"):
            next_run = line.split(":", 1)[1].strip()
    return {"scheduled": True, "next_run": next_run, "supported": True}
