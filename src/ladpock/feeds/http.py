from __future__ import annotations

import gzip
import json
import urllib.error
import urllib.request

from .. import __version__

USER_AGENT = f"LadPock/{__version__} (+https://github.com/liamburgo23/ladpock)"
MAX_RESPONSE_BYTES = 50_000_000


class FeedError(Exception):
    """A feed couldn't be reached or returned something unexpected."""


def request(url: str, *, data: object | None = None, headers: dict[str, str] | None = None,
            method: str | None = None, timeout: float = 30) -> tuple[int, dict[str, str], bytes]:
    if not url.startswith("https://"):
        raise FeedError(f"refusing non-HTTPS URL: {url}")
    hdrs = {"User-Agent": USER_AGENT, "Accept-Encoding": "gzip"}
    hdrs.update(headers or {})
    body = None
    if data is not None:
        body = json.dumps(data).encode("utf-8")
        hdrs["Content-Type"] = "application/json"
    req = urllib.request.Request(url, data=body, headers=hdrs, method=method)
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            raw = resp.read(MAX_RESPONSE_BYTES + 1)
            if len(raw) > MAX_RESPONSE_BYTES:
                raise FeedError(f"{url}: response too large")
            if resp.headers.get("Content-Encoding") == "gzip":
                raw = gzip.decompress(raw)
            return resp.status, dict(resp.headers), raw
    except urllib.error.HTTPError as exc:
        if exc.code in (304, 404):
            return exc.code, dict(exc.headers or {}), b""
        raise FeedError(f"{url}: HTTP {exc.code}") from exc
    except (urllib.error.URLError, TimeoutError, OSError) as exc:
        raise FeedError(f"{url}: {getattr(exc, 'reason', exc)}") from exc


def get_json(url: str, **kwargs) -> tuple[int, object | None]:
    status, _, raw = request(url, **kwargs)
    if not raw:
        return status, None
    try:
        return status, json.loads(raw)
    except ValueError as exc:
        raise FeedError(f"{url}: invalid JSON") from exc
