"""Every provider-specific secret format is detected and masked.

Samples are generated at runtime from a fixed seed, so no realistic-looking
token is ever committed (which would trip GitHub's push protection).
"""

from __future__ import annotations

import random
import string
import unittest

from ladpock.checks.secrets import _classify_secret
from ladpock.masking import redact

RND = random.Random(20261103)
ALNUM = string.ascii_letters + string.digits
HEX = "0123456789abcdef"
UPPER_DIGITS = string.ascii_uppercase + string.digits


def r(chars: str, n: int) -> str:
    return "".join(RND.choice(chars) for _ in range(n))


SAMPLES = {
    "OpenRouter API key": "sk-" + "or-v1-" + r(HEX, 64),
    "Stripe webhook secret": "whsec" + "_" + r(ALNUM, 32),
    "GitLab token": "glpat" + "-" + r(ALNUM, 20),
    "npm token": "npm" + "_" + r(ALNUM, 36),
    "PyPI token": "pypi-" + "AgEIcHlwaS5vcmc" + r(ALNUM, 60),
    "Supabase access token": "sbp" + "_" + r(HEX, 40),
    "Hugging Face token": "hf" + "_" + r(ALNUM, 34),
    "Groq API key": "gsk" + "_" + r(ALNUM, 52),
    "xAI API key": "xai" + "-" + r(ALNUM, 80),
    "Perplexity API key": "pplx" + "-" + r(ALNUM, 48),
    "Replicate API token": "r8" + "_" + r(ALNUM, 37),
    "LangSmith API key": "lsv2_pt" + "_" + r(HEX, 32) + "_" + r(HEX, 10),
    "Resend API key": "re" + "_" + r(ALNUM, 8) + "_" + r(ALNUM, 24),
    "Google OAuth client secret": "GOCSPX" + "-" + r(ALNUM, 28),
    "Azure storage key": "AccountKey=" + r(ALNUM, 86) + "==",
    "AWS secret access key": 'aws_secret_access_key = "' + r(ALNUM, 40) + '"',
    "Twilio API key": "SK" + r(HEX, 32),
    "Mailgun API key": "key" + "-" + r(HEX, 32),
    "Mailchimp API key": r(HEX, 32) + "-us14",
    "Brevo API key": "xkeysib" + "-" + r(HEX, 64) + "-" + r(ALNUM, 16),
    "Telegram bot token": "1234567890" + ":AA" + r(ALNUM, 33),
    "Discord bot token": "M" + r(ALNUM, 23) + "." + r(ALNUM, 6) + "." + r(ALNUM, 30),
    "Slack webhook URL": "https://hooks.slack.com/services/T" + r(UPPER_DIGITS, 9) + "/B" + r(UPPER_DIGITS, 9) + "/" + r(ALNUM, 24),
    "Discord webhook URL": "https://discord.com/api/webhooks/" + "123456789012345678/" + r(ALNUM, 68),
    "Shopify access token": "shpat" + "_" + r(HEX, 32),
    "Square access token": "EAAA" + r(ALNUM, 60),
    "PayPal Braintree token": "access_token$production$" + r(string.ascii_lowercase + string.digits, 16) + "$" + r(HEX, 32),
    "DigitalOcean token": "dop" + "_v1_" + r(HEX, 64),
    "Linear API key": "lin_api" + "_" + r(ALNUM, 40),
    "Notion token": "ntn" + "_" + r(ALNUM, 46),
    "Airtable token": "pat" + r(ALNUM, 14) + "." + r(HEX, 64),
    "Mapbox secret token": "sk.eyJ" + r(ALNUM, 60) + "." + r(ALNUM, 22),
    "Sentry auth token": "sntryu" + "_" + r(HEX, 64),
    "Grafana token": "glsa" + "_" + r(ALNUM, 32) + "_" + r(HEX, 8),
    "Databricks token": "dapi" + r(HEX, 32),
    "Doppler token": "dp.pt." + r(ALNUM, 43),
    "HashiCorp Vault token": "hvs." + r(ALNUM, 95),
    "Terraform Cloud token": r(ALNUM, 14) + ".atlasv1." + r(ALNUM, 67),
    "PlanetScale token": "pscale_tkn" + "_" + r(ALNUM, 43),
    "Postman API key": "PMAK" + "-" + r(HEX, 24) + "-" + r(HEX, 34),
    "Atlassian API token": "ATATT3" + r(ALNUM, 186),
    "Firebase Cloud Messaging key": "AAAA" + r(ALNUM, 7) + ":" + r(ALNUM, 140),
    "age secret key": "AGE-SECRET-KEY-1" + r(UPPER_DIGITS, 58),
}


class SecretFormats(unittest.TestCase):
    def test_each_format_is_detected_and_masked(self):
        for label, sample in SAMPLES.items():
            with self.subTest(label):
                line = f'const value = "{sample}";' if "=" not in sample else sample
                hit = _classify_secret(line)
                self.assertIsNotNone(hit, line)
                self.assertEqual(hit[0], label)
                masked = redact(line)
                self.assertNotIn(sample[-24:-4], masked)

    def test_unquoted_config_values_are_masked(self):
        self.assertNotIn("Winter2026-Prod", redact("  DATABASE_PASSWORD: Winter2026-Prod!"))
        self.assertNotIn("q9w8e7r6t5y4", redact("  session_secret: q9w8e7r6t5y4u3i2"))
        self.assertNotIn("abcdef123456", redact("ENV API_TOKEN=abcdef123456"))
        for code in ("  password: z.string().min(12),", "  password: req.body.password,", "  token: process.env.TOKEN",
                     "  secretKeyRef:", "      password: ${{ secrets.DB_PASSWORD }}", "  passwordReset: true"):
            with self.subTest(code):
                self.assertEqual(redact(code), code)

    def test_ordinary_values_are_left_alone(self):
        for line in ('const id = "sk_test_fixture";', "integrity sha512-SKqvn2mJ0ZYxvY3E1F1c2Lb7dJ8fK9rLm==",
                     'const uuid = "123e4567-e89b-12d3-a456-426614174000";', "keyboard: true", "re_render_count = 4"):
            with self.subTest(line):
                self.assertIsNone(_classify_secret(line))


if __name__ == "__main__":
    unittest.main()
