"""OSV.dev: open vulnerability data for npm, PyPI, Go, crates.io and more.

Queried live on every run, so results always reflect the newest advisories.
"""

from __future__ import annotations

import urllib.parse
from concurrent.futures import ThreadPoolExecutor

from ..models import Component
from . import http

API = "https://api.osv.dev/v1"
BATCH = 1000


def query_batch(components: list[Component]) -> dict[Component, list[tuple[str, str]]]:
    """Map each component to the (advisory id, modified) pairs that affect it."""
    found: dict[Component, list[tuple[str, str]]] = {}
    pinned = [c for c in components if c.version]
    for start in range(0, len(pinned), BATCH):
        chunk = pinned[start:start + BATCH]
        queries = [{"package": {"name": c.name, "ecosystem": c.ecosystem}, "version": c.version} for c in chunk]
        _, data = http.get_json(f"{API}/querybatch", data={"queries": queries}, timeout=90)
        results = (data or {}).get("results", []) if isinstance(data, dict) else []
        for comp, result in zip(chunk, results):
            vulns = (result or {}).get("vulns") or []
            if vulns:
                found[comp] = [(v["id"], v.get("modified", "")) for v in vulns if "id" in v]
    return found


def get_vuln(vuln_id: str) -> dict | None:
    _, data = http.get_json(f"{API}/vulns/{urllib.parse.quote(vuln_id)}", timeout=30)
    return data if isinstance(data, dict) else None


def get_vulns(ids: list[str], workers: int = 8) -> dict[str, dict]:
    def fetch(vuln_id: str) -> tuple[str, dict | None]:
        try:
            return vuln_id, get_vuln(vuln_id)
        except http.FeedError:
            return vuln_id, None

    with ThreadPoolExecutor(max_workers=workers) as pool:
        return {vid: data for vid, data in pool.map(fetch, ids) if data}
