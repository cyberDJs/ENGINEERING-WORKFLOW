from __future__ import annotations
import json, unittest
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]

class SupplyChainGap009EvidenceTest(unittest.TestCase):
    def test_gap009_is_implemented_but_not_closed_without_signing_and_review(self):
        ev=json.loads((ROOT/"evidence/supply-chain-assurance-evidence.json").read_text())
        gaps=json.loads((ROOT/"readiness/gap-register.json").read_text())
        score=json.loads((ROOT/"readiness/domain-scorecard.json").read_text())
        gap=next(x for x in gaps["gaps"] if x["id"]=="GAP-009")
        dom=next(x for x in score["domains"] if x["id"]=="supply-chain")
        self.assertTrue(ev["continuity_verification"]["implementation_unchanged_since_verified_head"])
        self.assertEqual(ev["continuity_verification"]["historical_run_live_reverified"]["build_scan"],"success")
        self.assertEqual(ev["continuity_verification"]["historical_run_live_reverified"]["attest_sign_verify"],"skipped")
        self.assertFalse(ev["closure_claim"])
        self.assertEqual(gap["status"],"BLOCKED")
        self.assertEqual(dom["evidence_maturity"],"IMPLEMENTED")
        self.assertEqual(dom["score"],7.0)

if __name__=="__main__": unittest.main()
