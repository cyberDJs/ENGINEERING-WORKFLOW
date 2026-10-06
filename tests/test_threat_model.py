import json
import unittest
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
class ThreatModelTest(unittest.TestCase):
    def test_model_covers_critical_boundaries_and_remains_unaccepted(self):
        m=json.loads((ROOT/'assurance/engineering-workflow-threat-model.json').read_text())
        ids={x['id'] for x in m['threats']}
        self.assertTrue({'TM-01','TM-05','TM-07','TM-08','TM-09','TM-10'} <= ids)
        self.assertEqual(m['review']['independent_review_status'],'PENDING')
        self.assertFalse(m['review']['accepted_residual_risk'])
        self.assertFalse(m['testing_authority']['production_exploitation'])
    def test_gap008_is_blocked_not_closed(self):
        gaps=json.loads((ROOT/'readiness/gap-register.json').read_text())['gaps']
        gap=next(x for x in gaps if x['id']=='GAP-008')
        self.assertEqual(gap['status'],'BLOCKED')
        self.assertIn('INDEPENDENT_SECURITY_REVIEW_PENDING',gap['blockers'])
        domain=next(x for x in json.loads((ROOT/'readiness/domain-scorecard.json').read_text())['domains'] if x['id']=='security')
        self.assertEqual(domain['evidence_maturity'],'IMPLEMENTED')
        self.assertEqual(domain['score'],7.0)
if __name__=='__main__': unittest.main()
