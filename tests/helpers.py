"""Test helpers.

Fixtures never contain real-looking secrets on disk. They hold placeholders
like {{FAKE_STRIPE_SECRET}} which are swapped for generated fakes in a temp
copy, so the repository doesn't trip secret scanners (including GitHub's).
"""

from __future__ import annotations

import base64
import json
import os
import shutil
import tempfile
from pathlib import Path

FIXTURES = Path(__file__).parent / "fixtures"


def _b64(data: dict) -> str:
    return base64.urlsafe_b64encode(json.dumps(data, separators=(",", ":")).encode()).decode().rstrip("=")


def _key_block(kind: str, newline: str = "\n") -> str:
    return newline.join([f"-----BEGIN {kind}PRIVATE KEY-----", "LadPockFixtureNotARealKey", f"-----END {kind}PRIVATE KEY-----"])


FAKES = {
    "{{FAKE_RSA_PRIVATE_KEY}}": _key_block("RSA "),
    "{{FAKE_OPENSSH_PRIVATE_KEY}}": _key_block("OPENSSH "),
    "{{FAKE_PKCS8_PRIVATE_KEY}}": _key_block(""),
    "{{FAKE_JSON_PRIVATE_KEY}}": _key_block("", "\\n"),
    "{{FAKE_CREDENTIAL}}": "LadPock" + "FixtureCredential",
    "{{FAKE_STRIPE_SECRET}}": "sk_" + "live_" + "LadPockFixture" + "Q1w2E3r4T5y6U7",
    "{{FAKE_OPENAI_KEY}}": "sk-" + "proj-" + "LadPockFixture" + "A1b2C3d4E5f6G7h8I9j0K1l2",
    "{{FAKE_GITHUB_TOKEN}}": "ghp_" + "LadPockFixtureToken" + "1a2b3c4d5e6f7g8h9i",
    "{{SERVICE_ROLE_JWT}}": ".".join([
        _b64({"alg": "HS256", "typ": "JWT"}),
        _b64({"iss": "supabase", "ref": "fixture", "role": "service_role"}),
        "LadPockFixtureSignature0123",
    ]),
    "{{BIDI}}": chr(0x202E),
}


def materialize(name: str) -> tempfile.TemporaryDirectory:
    """Copy a fixture into a temp dir with placeholders replaced. Use as a context manager."""
    tmp = tempfile.TemporaryDirectory(prefix=f"ladpock-{name}-")
    dest = Path(tmp.name) / name
    shutil.copytree(FIXTURES / name, dest)
    for path in dest.rglob("*"):
        if not path.is_file():
            continue
        text = path.read_text(encoding="utf-8")
        new = text
        for placeholder, value in FAKES.items():
            new = new.replace(placeholder, value)
        if new != text:
            path.write_text(new, encoding="utf-8")
    return tmp


def isolated_home() -> tempfile.TemporaryDirectory:
    """Point LadPock's database at a throwaway folder for the duration of a test."""
    tmp = tempfile.TemporaryDirectory(prefix="ladpock-home-")
    os.environ["LADPOCK_HOME"] = tmp.name
    return tmp
