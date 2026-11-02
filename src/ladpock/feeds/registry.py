"""Checks that directly declared packages actually exist on npm / PyPI.

A missing package usually means an AI assistant invented the name. That's
dangerous because anyone can register the name and wait for installs.
"""

from __future__ import annotations

import urllib.parse
from concurrent.futures import ThreadPoolExecutor

from ..db import DB
from . import http


def _exists(ecosystem: str, name: str) -> bool | None:
    try:
        if ecosystem == "npm":
            url = f"https://registry.npmjs.org/-/package/{urllib.parse.quote(name, safe='@')}/dist-tags"
            status, _, _ = http.request(url, timeout=20)
        elif ecosystem == "PyPI":
            status, _, _ = http.request(f"https://pypi.org/simple/{urllib.parse.quote(name)}/", method="HEAD", timeout=20)
        else:
            return None
    except http.FeedError:
        return None
    if status == 404:
        return False
    return True if status == 200 else None


def missing_packages(db: DB, deps: list[tuple[str, str, str]]) -> list[tuple[str, str, str]]:
    """Subset of (ecosystem, name, manifest) that the public registry says don't exist."""
    unique = sorted({(eco, name) for eco, name, _ in deps})
    to_check = [(eco, name) for eco, name in unique if db.registry_lookup(eco, name) is None]

    with ThreadPoolExecutor(max_workers=8) as pool:
        results = list(pool.map(lambda item: (item, _exists(*item)), to_check))
    for (eco, name), found in results:
        if found is not None:
            db.registry_save(eco, name, found)

    missing = {(eco, name) for eco, name in unique if db.registry_lookup(eco, name) is False}
    return [(eco, name, src) for eco, name, src in deps if (eco, name) in missing]
