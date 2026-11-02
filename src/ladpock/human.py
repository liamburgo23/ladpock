"""Things no scanner can verify. Shown so a good grade isn't mistaken for 'secure'."""

from __future__ import annotations

CHECKLIST: list[tuple[str, str, tuple[str, ...]]] = [
    ("H-01", "Two-factor login is on for GitHub, your hosting provider, your database and your domain registrar.", ()),
    ("H-02", "Backups exist, run automatically, and you have actually restored one to check it works.", ()),
    ("H-03", "You know how to rotate every key and password the app uses, and roughly how long it would take.", ()),
    ("H-04", "Spending limits or alerts are set on every paid API (AI, email, SMS, maps, cloud).", ()),
    ("H-05", "Sign-ins, password resets and permission changes are logged somewhere you can search.", ()),
    ("H-06", "Users can delete their account and data (a legal requirement in many places).", ()),
    ("H-07", "Someone checks dependency update PRs at least monthly.", ()),
    ("H-08", "Every table has RLS on in the Supabase dashboard, not just in migrations, and the policies were reviewed by a person.", ("supabase",)),
    ("H-09", "Firebase rules were tested with the Rules Playground or emulator for logged-out and other-user access.", ("firebase",)),
    ("H-10", "Stripe is in live mode only in production, and the webhook secret is different per environment.", ("stripe",)),
    ("H-11", "You logged in as user A and tried to open user B's pages and API URLs (the most common real bug).", ()),
]


def items_for(stack: set[str]) -> list[tuple[str, str]]:
    return [(item_id, text) for item_id, text, stacks in CHECKLIST if not stacks or set(stacks) & stack]
