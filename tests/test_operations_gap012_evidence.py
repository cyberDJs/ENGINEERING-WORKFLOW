import json, unittest
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
class OperationsGap012EvidenceTest(unittest.TestCase):
    def test_gap012_is_implemented_but_not_closed_without_real_operations(self):
        gaps=json.loads((ROOT/'readiness/gap-register.json').read_text())['gaps']; g=next(x for x in gaps if x['id']=='GAP-012')
        self.assertEqual(g['status'],'BLOCKED'); self.assertIn('REAL_OPERATED_SERVICE_MISSING',g['blockers']); self.assertIn('PRODUCTION_MEASUREMENT_WINDOW_MISSING',g['blockers'])
        score=next(x for x in json.loads((ROOT/'readiness/domain-scorecard.json').read_text())['domains'] if x['id']=='operations')
        self.assertEqual(score['evidence_maturity'],'IMPLEMENTED'); self.assertEqual(score['score'],7.0)
    def test_evidence_never_claims_production_slo_or_operation(self):
        e=json.loads((ROOT/'evidence/reference-service-operations-evidence.json').read_text())
        self.assertFalse(e['closure_claim']); self.assertFalse(e['service']['production_service']); self.assertFalse(e['slo_spec']['production_slo_claimed']); self.assertIn('operational readiness',e['not_claimed'])
if __name__=='__main__': unittest.main()
