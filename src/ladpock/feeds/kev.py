"""CISA Known Exploited Vulnerabilities: CVEs attackers are actively using."""

from __future__ import annotations

import json

from ..db import DB
from . import http

URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
NAME = "cisa-kev"


def refresh(db: DB) -> None:
    """Conditional GET: re-downloads only when CISA has published a new catalog."""
    row = db.get_feed(NAME)
    headers = {}
    if row and row["data"]:
        if row["etag"]:
            headers["If-None-Match"] = row["etag"]
        if row["last_modified"]:
            headers["If-Modified-Since"] = row["last_modified"]
    try:
        status, resp_headers, raw = http.request(URL, headers=headers, timeout=60)
    except http.FeedError as exc:
        db.save_feed(NAME, error=str(exc))
        raise
    if status == 304:
        db.save_feed(NAME, fetched=True)
        return
    catalog = json.loads(raw)
    mapping = {v["cveID"]: v.get("dateAdded", "") for v in catalog.get("vulnerabilities", []) if "cveID" in v}
    db.save_feed(
        NAME,
        data=json.dumps({"version": catalog.get("catalogVersion"), "cves": mapping}),
        etag=resp_headers.get("ETag"),
        last_modified=resp_headers.get("Last-Modified"),
        fetched=True,
    )


def load(db: DB) -> dict[str, str]:
    """CVE id -> date CISA added it to the catalog."""
    row = db.get_feed(NAME)
    if not row or not row["data"]:
        return {}
    return json.loads(row["data"]).get("cves", {})
