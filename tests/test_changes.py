"""What changed between two scans of the same project."""

from __future__ import annotations

import unittest
from pathlib import Path

from helpers import isolated_home, materialize

from ladpock import report
from ladpock.db import DB
from ladpock.scan import run_scan


class ScanChanges(unittest.TestCase):
    def test_new_and_fixed_findings(self):
        home = isolated_home()
        db = DB()
        try:
            with materialize("vuln-next-supabase") as tmp:
                root = Path(tmp) / "vuln-next-supabase"
                first = run_scan(root, db, offline=True, external=False, log=lambda _: None)
                self.assertIsNone(first.changes)  # nothing to compare with yet

                same = run_scan(root, db, offline=True, external=False, log=lambda _: None)
                self.assertEqual((same.changes["new"], same.changes["fixed_count"]), ([], 0))

                dashboard = root / "components" / "Dashboard.tsx"
                fixed_refs = {f.fingerprint for f in same.findings if f.file == "components/Dashboard.tsx"}
                dashboard.unlink()
                (root / "lib" / "random.ts").write_text("export const resetToken = Math.random().toString(36);\n",
                                                        encoding="utf-8")
                after = run_scan(root, db, offline=True, external=False, log=lambda _: None)
                changes = after.changes
                self.assertTrue(fixed_refs)
                self.assertEqual({f["ref"] for f in changes["fixed"]} & fixed_refs, fixed_refs)
                new = [f for f in after.findings if f.fingerprint in changes["new"]]
                self.assertEqual([(f.check_id, f.file) for f in new], [("LP-CRYPTO-001", "lib/random.ts")])
                self.assertTrue(changes["same_profile"])

                text = report.render_scan(after, report.Style(False))
                self.assertIn(f"{changes['fixed_count']} fixed, 1 new", text)
        finally:
            db.close()
            home.cleanup()


if __name__ == "__main__":
    unittest.main()
