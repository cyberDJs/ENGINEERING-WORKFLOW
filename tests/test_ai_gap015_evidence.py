from __future__ import annotations
import json, unittest
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]

class AIGap015EvidenceTest(unittest.TestCase):
    def test_gap015_is_implemented_but_not_closed_without_independent_acceptance(self):
        ev=json.loads((ROOT/"evidence/ai-control-plane-gap015-evidence.json").read_text())
        gaps=json.loads((ROOT/"readiness/gap-register.json").read_text())
        score=json.loads((ROOT/"readiness/domain-scorecard.json").read_text())
        gap=next(x for x in gaps["gaps"] if x["id"]=="GAP-015")
        dom=next(x for x in score["domains"] if x["id"]=="ai-engineering")
        self.assertTrue(ev["acceptance"]["technical_controls_implemented"])
        self.assertEqual(ev["controls"]["permission"]["write_without_authority"],"APPROVAL_REQUIRED")
        self.assertEqual(ev["controls"]["permission"]["deploy"],"BLOCKED")
        self.assertEqual(ev["controls"]["evaluation"]["result"],"PASS")
        self.assertEqual(ev["controls"]["red_team"]["pass_rate"],1.0)
        self.assertFalse(ev["acceptance"]["independent_security_review_complete"])
        self.assertFalse(ev["acceptance"]["human_acceptance_complete"])
        self.assertFalse(ev["acceptance"]["gap_closed"])
        self.assertEqual(gap["status"],"BLOCKED")
        self.assertEqual(dom["evidence_maturity"],"IMPLEMENTED")
        self.assertEqual(dom["score"],7.0)

if __name__=="__main__": unittest.main()
