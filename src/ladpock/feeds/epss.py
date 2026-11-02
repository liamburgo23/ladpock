"""FIRST EPSS: the probability a CVE will be exploited in the next 30 days."""

from __future__ import annotations

from ..db import DB
from ..timeutil import age_seconds
from . import http

API = "https://api.first.org/data/v1/epss"
BATCH = 50
NAME = "first-epss"


def refresh(db: DB, cves: list[str]) -> None:
    """Fetch scores for CVEs we don't have, or have from more than a day ago."""
    cached = db.epss_scores(cves)
    stale = sorted({c for c in cves if c not in cached or (age_seconds(cached[c]["fetched_at"]) or 1e9) > 86400})
    if not stale:
        db.save_feed(NAME, fetched=True)  # everything we need is already fresh
        return
    rows = []
    try:
        for start in range(0, len(stale), BATCH):
            chunk = stale[start:start + BATCH]
            _, data = http.get_json(f"{API}?cve={','.join(chunk)}", timeout=30)
            for item in (data or {}).get("data", []) if isinstance(data, dict) else []:
                rows.append((item["cve"], float(item["epss"]), float(item["percentile"])))
    except http.FeedError as exc:
        db.save_feed(NAME, error=str(exc))
        raise
    finally:
        if rows:
            db.save_epss(rows)
    db.save_feed(NAME, fetched=True)
