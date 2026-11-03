"""Unit tests for the pieces checks and feeds are built on."""

from __future__ import annotations

import unittest
from datetime import timedelta
from pathlib import Path

from helpers import isolated_home

from ladpock import advisories, cvss, inventory, scoring
from ladpock.db import DB
from ladpock.jsparse import match_bracket, split_args, strip_comments
from ladpock.masking import mask, redact
from ladpock.models import Component, Finding, Severity
from ladpock.timeutil import iso, now


class Masking(unittest.TestCase):
    def test_mask_keeps_prefix_and_tail(self):
        self.assertEqual(mask("sk_live_abcdefghijklmnopqrstuvwxyz1234"), "sk_live_****1234")

    def test_redact_hides_known_keys(self):
        key = "sb_secret_" + "Zx9" * 10
        out = redact(f'const k = "{key}"')
        self.assertNotIn(key, out)
        self.assertIn("sb_secret_****", out)

    def test_redact_hides_assigned_passwords(self):
        self.assertNotIn("hunter2hunter2", redact('password = "hunter2hunter2"'))

    def test_redact_hides_db_password_only(self):
        out = redact("postgres://app:s3cretpass@db.example.com:5432/app")
        self.assertIn("app:****@db.example.com", out)


class Cvss(unittest.TestCase):
    def test_known_scores(self):
        self.assertEqual(cvss.base_score("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"), 9.8)
        self.assertEqual(cvss.base_score("CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N"), 6.1)
        self.assertEqual(cvss.base_score("CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N"), 5.5)

    def test_rejects_other_versions(self):
        self.assertIsNone(cvss.base_score("CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N"))


class Inventory(unittest.TestCase):
    def test_npm_lock_v3(self):
        text = '{"lockfileVersion":3,"packages":{"":{},"node_modules/a":{"version":"1.0.0"},' \
               '"node_modules/a/node_modules/@s/b":{"version":"2.0.0"},"node_modules/l":{"link":true}}}'
        got = {(c.name, c.version) for c in inventory.parse_npm_lock(text, "package-lock.json")}
        self.assertEqual(got, {("a", "1.0.0"), ("@s/b", "2.0.0")})

    def test_yarn_classic_and_berry(self):
        classic = '"@babel/core@^7.0.0", "@babel/core@^7.1.0":\n  version "7.2.0"\n\nlodash@^4.17.0:\n  version "4.17.21"\n'
        berry = '"lodash@npm:^4.17.21":\n  version: 4.17.21\n  resolution: "lodash@npm:4.17.21"\n'
        self.assertEqual({(c.name, c.version) for c in inventory.parse_yarn_lock(classic, "yarn.lock")},
                         {("@babel/core", "7.2.0"), ("lodash", "4.17.21")})
        self.assertEqual([(c.name, c.version) for c in inventory.parse_yarn_lock(berry, "yarn.lock")], [("lodash", "4.17.21")])

    def test_pnpm_v9_and_v6(self):
        v9 = "lockfileVersion: '9.0'\n\npackages:\n\n  '@next/env@15.0.0':\n    resolution: {}\n\n  react@19.0.0:\n    resolution: {}\n\nsnapshots:\n\n  react@19.0.0: {}\n"
        v6 = "lockfileVersion: '6.0'\n\npackages:\n\n  /next@14.1.0(react@18.2.0):\n    resolution: {}\n"
        self.assertEqual({(c.name, c.version) for c in inventory.parse_pnpm_lock(v9, "p")}, {("@next/env", "15.0.0"), ("react", "19.0.0")})
        self.assertEqual([(c.name, c.version) for c in inventory.parse_pnpm_lock(v6, "p")], [("next", "14.1.0")])

    def test_requirements(self):
        got = inventory.parse_requirements("Django==4.2.1\nrequests>=2\n# comment\n-r other.txt\nFlask_Login[x]==0.6.3\n", "r")
        self.assertEqual([(c.name, c.version) for c in got], [("django", "4.2.1"), ("requests", None), ("flask-login", "0.6.3")])

    def test_go_mod(self):
        text = "module x\n\nrequire (\n\tgolang.org/x/net v0.17.0\n\tgithub.com/a/b v1.2.3 // indirect\n)\n"
        self.assertEqual({(c.name, c.version) for c in inventory.parse_go_mod(text, "go.mod")},
                         {("golang.org/x/net", "0.17.0"), ("github.com/a/b", "1.2.3")})


class JsParse(unittest.TestCase):
    def test_strip_comments_keeps_strings_and_offsets(self):
        code = 'const u = "https://x"; // gone\n/* block */ f()'
        out = strip_comments(code)
        self.assertEqual(len(out), len(code))
        self.assertIn('"https://x"', out)
        self.assertNotIn("gone", out)

    def test_split_args_ignores_nested_commas(self):
        code = "useEffect(() => { a(1, 2) }, [x, y])"
        open_idx = code.index("(")
        args = split_args(code, open_idx, match_bracket(code, open_idx))
        self.assertEqual(len(args), 2)


class Advisories(unittest.TestCase):
    def test_severity_prefers_ghsa_label(self):
        vuln = {"id": "GHSA-x", "database_specific": {"severity": "MODERATE"},
                "severity": [{"type": "CVSS_V3", "score": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"}]}
        self.assertEqual(advisories.severity_of(vuln), (Severity.MEDIUM, 9.8))
        self.assertEqual(advisories.severity_of({"id": "MAL-2025-1"})[0], Severity.CRITICAL)

    def test_fixed_version_picks_next_fix_above_installed(self):
        affected = [{"ecosystem": "npm", "name": "next", "fixed": ["13.5.9", "14.2.25", "15.2.3"]}]
        self.assertEqual(advisories.fixed_version(affected, Component("npm", "next", "14.1.0", "p")), "14.2.25")

    def test_new_since_detects_first_seen_and_newly_exploited(self):
        home = isolated_home()
        db = DB()
        try:
            project_id = db.upsert_project(Path(home.name))
            db.upsert_advisory("GHSA-a", "m", "old issue", ["CVE-2020-0001"], int(Severity.HIGH), None, [])
            comp = Component("npm", "pkg", "1.0.0", "package-lock.json")
            db.sync_project_advisories(project_id, [("GHSA-a", comp, "1.0.1")])
            db.conn.execute("UPDATE project_advisories SET first_seen = ?", (iso(now() - timedelta(days=3)),))
            cutoff = iso(now() - timedelta(days=1))
            all_hits = advisories.hits(db, {})
            self.assertEqual(advisories.new_since(all_hits, cutoff), [])
            exploited = advisories.hits(db, {"CVE-2020-0001": now().date().isoformat()})
            self.assertEqual(len(advisories.new_since(exploited, cutoff)), 1)
            self.assertEqual(exploited[0].effective_severity, Severity.CRITICAL)
            db.upsert_advisory("GHSA-b", "m", "new issue", [], int(Severity.LOW), None, [])
            db.sync_project_advisories(project_id, [("GHSA-a", comp, "1.0.1"), ("GHSA-b", comp, None)])
            fresh = advisories.new_since(advisories.hits(db, {}), cutoff)
            self.assertEqual([h.advisory_id for h in fresh], ["GHSA-b"])
            db.sync_project_advisories(project_id, [])
            self.assertEqual(advisories.hits(db, {}), [])
        finally:
            db.close()
            home.cleanup()


class Scoring(unittest.TestCase):
    def _f(self, severity: Severity, confidence: str = "medium") -> Finding:
        return Finding("X", "t", severity, "secrets", confidence=confidence)

    def test_clean_project_scores_full_marks(self):
        self.assertEqual(scoring.score([]).grade, "A+")

    def test_critical_caps_grade(self):
        self.assertEqual(scoring.score([self._f(Severity.CRITICAL)]).grade, "F")

    def test_high_caps_below_b(self):
        self.assertLessEqual(scoring.score([self._f(Severity.HIGH)]).overall, 79)

    def test_mediums_alone_cant_fail_a_category(self):
        findings = [Finding("X", "t", Severity.MEDIUM, "supply-chain") for _ in range(8)]
        findings += [Finding("Y", "t", Severity.LOW, "secrets") for _ in range(20)]
        card = scoring.score(findings)
        grades = {c.key: c.grade for c in card.categories}
        self.assertEqual(grades["supply-chain"], "C-")
        self.assertEqual(grades["secrets"], "B")
        highs = scoring.score([Finding("Z", "t", Severity.HIGH, "authz") for _ in range(4)])
        self.assertEqual(next(c.grade for c in highs.categories if c.key == "authz"), "F")

    def test_low_confidence_counts_half_and_doesnt_cap(self):
        card = scoring.score([self._f(Severity.HIGH, "low")])
        self.assertEqual(next(c.score for c in card.categories if c.key == "secrets"), 90)
        self.assertGreater(card.overall, 79)


if __name__ == "__main__":
    unittest.main()
