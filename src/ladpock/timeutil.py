from __future__ import annotations

from datetime import datetime, timezone


def now() -> datetime:
    return datetime.now(timezone.utc)


def iso(dt: datetime | None = None) -> str:
    return (dt or now()).isoformat(timespec="seconds")


def parse_iso(value: str | None) -> datetime | None:
    if not value:
        return None
    try:
        dt = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None
    return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)


def age_seconds(value: str | None) -> float | None:
    dt = parse_iso(value)
    return None if dt is None else (now() - dt).total_seconds()


def ago(value: str | None) -> str:
    seconds = age_seconds(value)
    if seconds is None:
        return "never"
    if seconds < 90:
        return "just now"
    minutes = seconds / 60
    if minutes < 90:
        return f"{round(minutes)} min ago"
    hours = minutes / 60
    if hours < 36:
        return f"{round(hours)} h ago"
    return f"{round(hours / 24)} days ago"
