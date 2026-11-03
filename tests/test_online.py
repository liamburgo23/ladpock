"""Paid online AI review, tested with a fake Anthropic client so nothing is sent or billed."""

from __future__ import annotations

import json
import unittest
from pathlib import Path
from types import SimpleNamespace

from helpers import isolated_home, materialize

from ladpock.ai import keys, online, prompts
from ladpock.ai.grounding import Lead
from ladpock.db import DB
from ladpock.scan import run_scan

IDOR_LINE = "const order = await db.order.findUnique({ where: { id: params.id } });"


class AuthenticationError(Exception):
    """Named like the SDK's, which is all the client looks at."""


class FakeStream:
    def __init__(self, response):
        self.response = response

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False

    def get_final_message(self):
        return self.response


class FakeAnthropic:
    """Answers like the Messages API: one real issue and one invented one for the IDOR route."""

    def __init__(self, stop_reason: str = "end_turn", error: Exception | None = None):
        self.calls: list[dict] = []
        self.stop_reason = stop_reason
        self.error = error
        self.beta = SimpleNamespace(messages=SimpleNamespace(stream=self.stream))

    def stream(self, **params):
        self.calls.append(params)
        if self.error:
            raise self.error
        prompt = params["messages"][0]["content"]
        if "Scanner finding:" in prompt:
            answer = {"verdict": "false_alarm", "reason": "Validated earlier."}
        elif "Another reviewer made the claim" in prompt:
            answer = {"accurate": True, "reason": "Confirmed."}
        elif IDOR_LINE in prompt:
            answer = {"issues": [
                {"title": "Any user can read any order", "severity": "high", "category": "authz", "line": 1,
                 "quote": IDOR_LINE, "explanation": "No ownership check.", "fix": "Filter by user id."},
                {"title": "Invented", "severity": "high", "category": "injection", "line": 2,
                 "quote": "await db.dropEverything();", "explanation": "Not real.", "fix": "n/a"},
            ]}
        else:
            answer = {"issues": []}
        usage = SimpleNamespace(input_tokens=2000, output_tokens=1000, cache_read_input_tokens=0,
                                cache_creation_input_tokens=0)
        content = [] if self.stop_reason == "refusal" else [SimpleNamespace(type="text", text=json.dumps(answer))]
        return FakeStream(SimpleNamespace(stop_reason=self.stop_reason, content=content, usage=usage))


class Basics(unittest.TestCase):
    def test_strict_schema_closes_objects_and_drops_array_limits(self):
        schema = online.strict_schema(prompts.ISSUES_SCHEMA)
        self.assertFalse(schema["additionalProperties"])
        issues = schema["properties"]["issues"]
        self.assertNotIn("maxItems", issues)
        self.assertFalse(issues["items"]["additionalProperties"])
        self.assertIn("maxItems", prompts.ISSUES_SCHEMA["properties"]["issues"])  # the original is untouched

    def test_cost_uses_per_million_token_prices(self):
        self.assertAlmostEqual(online.Usage(1_000_000, 0).cost, online.PRICE_PER_MTOK["input"])
        self.assertAlmostEqual(online.Usage(0, 1_000_000).cost, online.PRICE_PER_MTOK["output"])

    def test_key_shape_is_checked_before_anything_is_stored(self):
        for bad in ("", "hello", "sk-ant-short", "sk-ant-" + "x" * 30 + " spaced"):
            with self.assertRaises(keys.KeyError_):
                keys.store(bad)
        self.assertEqual(keys.masked("sk-ant-api03-abcdefghijklmnop-wxyz"), "sk-ant-…wxyz")
        self.assertIsNone(keys.masked(None))


class Review(unittest.TestCase):
    def setUp(self):
        self.home = isolated_home()
        self.tmp = materialize("vuln-next-supabase")
        self.root = Path(self.tmp.name) / "vuln-next-supabase"
        self.db = DB()
        run_scan(self.root, self.db, offline=True, external=False, log=lambda _: None)
        self.pid = self.db.get_project(self.root)["id"]

    def tearDown(self):
        self.db.close()
        self.tmp.cleanup()
        self.home.cleanup()

    def review(self, sdk, **kw):
        return online.run_online_review(self.db, self.pid, online.OnlineClient(sdk), log=lambda _: None, **kw)

    def test_review_grounds_records_cost_and_never_resends_unchanged_code(self):
        sdk = FakeAnthropic()
        summary = self.review(sdk)
        self.assertEqual(summary.status, "done", summary.message)
        self.assertGreater(summary.done, 3)
        self.assertEqual(summary.dropped, 1)  # the invented issue never reaches you
        leads = self.db.ai_leads(self.pid)
        self.assertEqual([(l["title"], l["model"]) for l in leads], [("Any user can read any order", online.MODEL)])
        self.assertTrue(any(v["model"] == online.MODEL for v in self.db.ai_verdicts(self.pid).values()))
        self.assertAlmostEqual(self.db.online_spent(), summary.cost)
        self.assertAlmostEqual(summary.cost, len(sdk.calls) * online.Usage(2000, 1000).cost)

        params = sdk.calls[0]
        self.assertEqual(params["model"], online.MODEL)
        self.assertEqual(params["extra_body"], {"fallbacks": "default"})
        self.assertEqual(params["betas"], [online.FALLBACK_BETA])
        self.assertEqual(params["output_config"]["format"]["type"], "json_schema")
        self.assertFalse(params["output_config"]["format"]["schema"]["additionalProperties"])
        self.assertNotIn("LadPockFixtureQ1w2E3r4", json.dumps(sdk.calls))  # secrets are masked before anything is sent

        again = FakeAnthropic()
        self.assertEqual(self.review(again).done, 0)
        self.assertEqual(again.calls, [])
        self.assertEqual(self.db.ai_last_run(self.pid, online=True)["trigger"], "online")
        self.assertIsNone(self.db.ai_last_run(self.pid))  # local and online runs are reported separately

    def test_budget_stops_before_spending(self):
        sdk = FakeAnthropic()
        summary = self.review(sdk, limit=0.0)
        self.assertEqual((summary.status, sdk.calls), ("budget", []))
        self.assertIn("budget", summary.message)

    def test_never_send_projects_are_skipped(self):
        self.db.set_online_never(self.pid, True)
        sdk = FakeAnthropic()
        self.assertEqual(self.review(sdk).status, "skipped")
        self.assertEqual(sdk.calls, [])
        self.assertTrue(online.plan(self.db, self.pid)["never"])

    def test_declined_parts_are_paid_for_once(self):
        summary = self.review(FakeAnthropic(stop_reason="refusal"))
        self.assertEqual(summary.declined, summary.total)
        self.assertGreater(self.db.online_spent(), 0)
        again = FakeAnthropic()
        self.assertEqual(self.review(again).done, 0)  # not asked again until the code changes

    def test_a_rejected_key_stops_the_run(self):
        sdk = FakeAnthropic(error=AuthenticationError("401"))
        summary = self.review(sdk)
        self.assertEqual((summary.status, len(sdk.calls)), ("error", 1))
        self.assertIn("API key", summary.message)

    def test_local_leads_get_a_second_opinion(self):
        lead = Lead("Possible IDOR", "high", "vibe", 1, IDOR_LINE, "Looks unchecked.", "Check the owner.")
        self.db.ai_save_leads(self.pid, "route:x", "app/api/orders/[id]/route.ts", [lead], "fake:7b")
        summary = self.review(FakeAnthropic())
        self.assertEqual(summary.verified, 1)
        row = next(l for l in self.db.ai_leads(self.pid) if l["model"] == "fake:7b")
        self.assertEqual(row["online_verdict"], "confirmed")

    def test_local_pruning_keeps_online_reviews(self):
        self.review(FakeAnthropic())
        before = {k for k in self.db.ai_reviewed_units(self.pid) if k.startswith("online:")}
        units, _ = online.pending_units(self.db, self.pid)
        self.db.ai_prune(self.pid, {u.key for u in units})
        after = {k for k in self.db.ai_reviewed_units(self.pid) if k.startswith("online:")}
        self.assertEqual(before, after)
        self.assertTrue(after)

    def test_plan_estimates_cost_before_sending(self):
        plan = online.plan(self.db, self.pid)
        self.assertGreater(plan["units"], 3)
        self.assertGreater(plan["cost"], 0)


if __name__ == "__main__":
    unittest.main()
