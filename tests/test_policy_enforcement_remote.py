from __future__ import annotations
import json, unittest
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]

class PolicyEnforcementRemoteEvidenceTest(unittest.TestCase):
    def test_gap007_stays_blocked_without_merge_enforcement(self):
        ev=json.loads((ROOT/"evidence/open-source-enforcement-evidence.json").read_text())
        gaps=json.loads((ROOT/"readiness/gap-register.json").read_text())
        gap=next(x for x in gaps["gaps"] if x["id"]=="GAP-007")
        remote=ev["remote_verification"]
        self.assertEqual(remote["historical_policy_run"]["conclusion"],"success")
        self.assertFalse(remote["merge_enforcement"]["active"])
        self.assertFalse(remote["branch_protected"])
        self.assertEqual(remote["ruleset_count"],0)
        self.assertFalse(remote["closure_claim"])
        self.assertEqual(gap["status"],"BLOCKED")
        self.assertTrue(set(remote["merge_enforcement"]["blockers"]).issubset(set(gap["blockers"])))

if __name__=="__main__": unittest.main()
