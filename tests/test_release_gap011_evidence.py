import json
import unittest
from pathlib import Path

ROOT=Path(__file__).resolve().parents[1]

class ReleaseGap011EvidenceTest(unittest.TestCase):
    def test_gap011_is_implemented_but_not_closed_without_real_release_authority(self):
        gaps=json.loads((ROOT/'readiness/gap-register.json').read_text())['gaps']
        gap=next(x for x in gaps if x['id']=='GAP-011')
        self.assertEqual(gap['status'],'BLOCKED')
        self.assertIn('REAL_RELEASE_AUTHORITY_NOT_EXERCISED',gap['blockers'])
        score=json.loads((ROOT/'readiness/domain-scorecard.json').read_text())['domains']
        release=next(x for x in score if x['id']=='release')
        self.assertEqual(release['evidence_maturity'],'IMPLEMENTED')
        self.assertEqual(release['score'],7.0)
        evidence=json.loads((ROOT/'evidence/release-rehearsal-evidence.json').read_text())
        self.assertFalse(evidence['closure_claim'])
        self.assertFalse(evidence['governance']['production_effects'])
        self.assertFalse(evidence['governance']['release_performed'])

if __name__=='__main__': unittest.main()
