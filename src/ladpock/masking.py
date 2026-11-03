"""Secret patterns and masking.

Every snippet LadPock stores or prints goes through ``redact`` first, so the
local database and any exported report never contain a usable credential.
"""

from __future__ import annotations

import base64
import json
import re

from .models import Severity

SECRET_PATTERNS: list[tuple[str, re.Pattern[str], Severity]] = [
    ("Stripe secret key", re.compile(r"\b[rs]k_live_[0-9A-Za-z]{20,}"), Severity.CRITICAL),
    ("Supabase secret key", re.compile(r"\bsb_secret_[0-9A-Za-z_-]{16,}"), Severity.CRITICAL),
    ("Anthropic API key", re.compile(r"\bsk-ant-[0-9A-Za-z_-]{20,}"), Severity.CRITICAL),
    ("OpenAI API key", re.compile(r"\bsk-(?!ant-)(?:proj-|svcacct-|admin-)?[0-9A-Za-z_-]{32,}"), Severity.CRITICAL),
    ("GitHub token", re.compile(r"\b(?:gh[pousr]_[0-9A-Za-z]{36,}|github_pat_[0-9A-Za-z_]{40,})"), Severity.CRITICAL),
    ("AWS access key ID", re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b"), Severity.HIGH),
    ("Slack token", re.compile(r"\bxox[abprs]-[0-9A-Za-z-]{10,}"), Severity.HIGH),
    ("SendGrid API key", re.compile(r"\bSG\.[0-9A-Za-z_-]{16,}\.[0-9A-Za-z_-]{16,}"), Severity.HIGH),
    ("Google API key", re.compile(r"\bAIza[0-9A-Za-z_-]{35}\b"), Severity.LOW),
    ("Private key", re.compile(r"-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP |ENCRYPTED )?PRIVATE KEY-----"), Severity.CRITICAL),
    (
        "Database URL with password",
        re.compile(r"\b(?:postgres(?:ql)?|mysql|mongodb(?:\+srv)?|rediss?)://[^:\s/'\"@]+:([^@\s'\"]{3,})@([^\s/'\":]+)"),
        Severity.HIGH,
    ),
]

JWT = re.compile(r"\beyJ[0-9A-Za-z_-]{8,}\.eyJ[0-9A-Za-z_-]{8,}\.[0-9A-Za-z_-]{8,}")

_PLACEHOLDER = re.compile(
    r"(?i)x{4,}|your[_-]|example|placeholder|dummy|changeme|replace[_-]?me|<[^>]+>|\*{3,}|\.\.\.|0{12,}"
)
_ASSIGNMENT = re.compile(
    r"(?i)((?:password|passwd|pwd|secret|token|api[_-]?key|private[_-]?key)[\w-]*['\"]?\s*[:=]\s*['\"])([^'\"\s]{6,})(['\"])"
)
# Unquoted env-style assignments (.env, Dockerfile ENV/ARG, shell export), keyed by an UPPER_CASE secret name.
_ENV_ASSIGNMENT = re.compile(
    r"(?m)^(\s*(?:export\s+|ENV\s+|ARG\s+|-\s*)?[A-Z][A-Z0-9_]*(?:PASSWORD|PASSWD|SECRET|TOKEN|API_KEY|APIKEY|PRIVATE_KEY|"
    r"ACCESS_KEY)[A-Z0-9_]*\s*=\s*)([^\s'\"$]{6,})"
)
LOCAL_DB_HOSTS = {"localhost", "127.0.0.1", "0.0.0.0", "db", "postgres", "mysql", "redis", "mongo", "host.docker.internal"}


def is_placeholder(value: str) -> bool:
    return bool(_PLACEHOLDER.search(value))


def mask(value: str) -> str:
    """Keep a recognisable prefix and the last four characters, hide the rest."""
    match = re.match(r"^(?:[A-Za-z]{1,10}[_-]){1,2}", value)
    prefix = match.group(0) if match and len(match.group(0)) < len(value) - 6 else value[:4]
    tail = value[-4:] if len(value) >= len(prefix) + 10 else ""
    return f"{prefix}****{tail}"


def jwt_claims(token: str) -> dict | None:
    try:
        payload = token.split(".")[1]
        payload += "=" * (-len(payload) % 4)
        claims = json.loads(base64.urlsafe_b64decode(payload))
    except (IndexError, ValueError, UnicodeDecodeError):
        return None
    return claims if isinstance(claims, dict) else None


def _mask_match(name: str, match: re.Match[str]) -> str:
    text = match.group(0)
    if name == "Private key":
        return text
    if name == "Database URL with password":
        return text.replace(match.group(1), "****", 1)
    return mask(text)


def redact(text: str) -> str:
    for name, pattern, _ in SECRET_PATTERNS:
        text = pattern.sub(lambda m, n=name: _mask_match(n, m), text)
    text = JWT.sub(lambda m: "eyJ****" + m.group(0)[-4:], text)
    text = _ASSIGNMENT.sub(
        lambda m: m.group(0) if "****" in m.group(2) else m.group(1) + mask(m.group(2)) + m.group(3),
        text,
    )
    text = _ENV_ASSIGNMENT.sub(lambda m: m.group(0) if "****" in m.group(2) else m.group(1) + mask(m.group(2)), text)
    return text
