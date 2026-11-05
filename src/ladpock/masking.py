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
    ("OpenRouter API key", re.compile(r"\bsk-or-v1-[0-9a-f]{64}\b"), Severity.CRITICAL),
    ("OpenAI API key", re.compile(r"\bsk-(?!ant-|or-v1-)(?:proj-|svcacct-|admin-)?[0-9A-Za-z_-]{32,}"), Severity.CRITICAL),
    ("Stripe webhook secret", re.compile(r"\bwhsec_[0-9A-Za-z]{32,}"), Severity.HIGH),
    ("GitLab token", re.compile(r"\bgl(?:pat|dt|rt|ptt|cbt|oas)-[0-9A-Za-z_-]{20,}"), Severity.CRITICAL),
    ("npm token", re.compile(r"\bnpm_[A-Za-z0-9]{36}\b"), Severity.CRITICAL),
    ("PyPI token", re.compile(r"\bpypi-AgEIcHlwaS5vcmc[A-Za-z0-9_-]{50,}"), Severity.CRITICAL),
    ("Supabase access token", re.compile(r"\bsbp_[0-9a-f]{40}\b"), Severity.CRITICAL),
    ("Hugging Face token", re.compile(r"\bhf_[A-Za-z0-9]{34,}\b"), Severity.HIGH),
    ("Groq API key", re.compile(r"\bgsk_[A-Za-z0-9]{48,}\b"), Severity.HIGH),
    ("xAI API key", re.compile(r"\bxai-[A-Za-z0-9]{60,}\b"), Severity.HIGH),
    ("Perplexity API key", re.compile(r"\bpplx-[A-Za-z0-9]{40,}\b"), Severity.HIGH),
    ("Replicate API token", re.compile(r"\br8_[A-Za-z0-9]{30,}\b"), Severity.HIGH),
    ("LangSmith API key", re.compile(r"\blsv2_(?:pt|sk)_[0-9a-f]{32}_[0-9a-f]{10}\b"), Severity.HIGH),
    ("Resend API key", re.compile(r"\bre_[A-Za-z0-9]{8}_[A-Za-z0-9]{20,}\b"), Severity.HIGH),
    ("Google OAuth client secret", re.compile(r"\bGOCSPX-[0-9A-Za-z_-]{28}\b"), Severity.HIGH),
    ("Azure storage key", re.compile(r"AccountKey=[A-Za-z0-9+/]{86}=="), Severity.HIGH),
    ("AWS secret access key", re.compile(r"(?i)\baws_?(?:secret|private)_?(?:access_?)?key\w*['\"]?\s*[:=]\s*['\"]?[A-Za-z0-9/+=]{40}\b"),
     Severity.CRITICAL),
    ("Twilio API key", re.compile(r"\bSK[0-9a-fA-F]{32}\b"), Severity.HIGH),
    ("Mailgun API key", re.compile(r"\bkey-[0-9a-f]{32}\b"), Severity.HIGH),
    ("Mailchimp API key", re.compile(r"\b[0-9a-f]{32}-us\d{1,2}\b"), Severity.HIGH),
    ("Brevo API key", re.compile(r"\bxkeysib-[0-9a-f]{64}-[A-Za-z0-9]{16}\b"), Severity.HIGH),
    ("Telegram bot token", re.compile(r"\b\d{8,10}:AA[0-9A-Za-z_-]{33}\b"), Severity.HIGH),
    ("Discord bot token", re.compile(r"\b[MNO][A-Za-z\d_-]{23,25}\.[A-Za-z\d_-]{6}\.[A-Za-z\d_-]{27,38}\b"), Severity.HIGH),
    ("Slack webhook URL", re.compile(r"https://hooks\.slack\.com/(?:services|workflows)/T[A-Z0-9]+/[A-Z0-9]+/[A-Za-z0-9]{20,}"),
     Severity.MEDIUM),
    ("Discord webhook URL", re.compile(r"https://(?:ptb\.|canary\.)?discord(?:app)?\.com/api/webhooks/\d+/[\w-]{60,}"),
     Severity.MEDIUM),
    ("Shopify access token", re.compile(r"\bshp(?:at|ca|pa|ss)_[0-9a-fA-F]{32}\b"), Severity.HIGH),
    ("Square access token", re.compile(r"\b(?:EAAA[0-9A-Za-z_-]{60}|sq0csp-[0-9A-Za-z_-]{43})\b"), Severity.HIGH),
    ("PayPal Braintree token", re.compile(r"access_token\$production\$[0-9a-z]{16}\$[0-9a-f]{32}"), Severity.CRITICAL),
    ("DigitalOcean token", re.compile(r"\bdo[opr]_v1_[0-9a-f]{64}\b"), Severity.HIGH),
    ("Linear API key", re.compile(r"\blin_api_[A-Za-z0-9]{40}\b"), Severity.HIGH),
    ("Notion token", re.compile(r"\bntn_[A-Za-z0-9]{40,}\b"), Severity.HIGH),
    ("Airtable token", re.compile(r"\bpat[A-Za-z0-9]{14}\.[0-9a-f]{64}\b"), Severity.HIGH),
    ("Mapbox secret token", re.compile(r"\bsk\.eyJ[A-Za-z0-9_-]{50,}\.[A-Za-z0-9_-]{20,}"), Severity.HIGH),
    ("Sentry auth token", re.compile(r"\b(?:sntrys_[A-Za-z0-9+/=_-]{60,}|sntryu_[0-9a-f]{64})"), Severity.HIGH),
    ("Grafana token", re.compile(r"\b(?:glsa_[A-Za-z0-9]{32}_[0-9a-fA-F]{8}|glc_[A-Za-z0-9+/]{32,}={0,2})"), Severity.HIGH),
    ("Databricks token", re.compile(r"\bdapi[0-9a-f]{32}(?:-\d)?\b"), Severity.HIGH),
    ("Doppler token", re.compile(r"\bdp\.(?:pt|st|sa|ct|scim|audit)\.[A-Za-z0-9]{40,44}\b"), Severity.HIGH),
    ("HashiCorp Vault token", re.compile(r"\bhvs\.[A-Za-z0-9_-]{90,}"), Severity.HIGH),
    ("Terraform Cloud token", re.compile(r"\b[A-Za-z0-9]{14}\.atlasv1\.[A-Za-z0-9_=-]{60,70}"), Severity.HIGH),
    ("PlanetScale token", re.compile(r"\bpscale_(?:tkn|pw|oauth)_[A-Za-z0-9_.-]{32,}"), Severity.HIGH),
    ("Postman API key", re.compile(r"\bPMAK-[0-9a-f]{24}-[0-9a-f]{34}\b"), Severity.HIGH),
    ("Atlassian API token", re.compile(r"\bATATT3[A-Za-z0-9_=-]{180,}"), Severity.HIGH),
    ("Firebase Cloud Messaging key", re.compile(r"\bAAAA[A-Za-z0-9_-]{7}:[A-Za-z0-9_-]{140}"), Severity.HIGH),
    ("age secret key", re.compile(r"\bAGE-SECRET-KEY-1[0-9A-Z]{58}\b"), Severity.CRITICAL),
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
# Unquoted YAML values under a secret-looking key (Kubernetes Secrets, Compose, CI). Values that look like code
# (z.string(), process.env.X, req.body.password) are left alone so code snippets stay readable.
_YAML_SECRET = re.compile(
    r"(?im)^(\s*-?\s*[\w.-]*(?:password|passwd|secret|token|api_?key|private_?key|access_?key|credentials?)[\w.-]*\s*:\s*)"
    r"(?![a-z_$][\w$]*\s*[.(\[])(?!(?:true|false|null|yes|no)\s*$)([^\s'\"#{(\$][^'\"\n#(]{5,})$"
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
    except (IndexError, ValueError, UnicodeDecodeError, RecursionError):
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
    text = _YAML_SECRET.sub(lambda m: m.group(0) if "****" in m.group(2) else m.group(1) + mask(m.group(2).strip()), text)
    return text
