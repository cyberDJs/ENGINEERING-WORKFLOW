import importlib.util
import json
import tempfile
import unittest
from pathlib import Path

MODULE_PATH = Path(__file__).resolve().parents[1] / "scripts/run_release_rehearsal.py"
spec = importlib.util.spec_from_file_location("release_rehearsal", MODULE_PATH)
mod = importlib.util.module_from_spec(spec)
assert spec.loader is not None
spec.loader.exec_module(mod)


class ReleaseRehearsalTest(unittest.TestCase):
    def test_promotion_preserves_candidate_and_rollback_restores_baseline(self):
        with tempfile.TemporaryDirectory() as td:
            state = Path(td) / "active.json"
            baseline = {"source_ref": "a" * 40, "sha256": "1" * 64}
            candidate = {"source_ref": "b" * 40, "sha256": "2" * 64}
            result = mod.promote_and_rollback(state, baseline, candidate)
            self.assertTrue(result["promotion_ok"])
            self.assertTrue(result["rollback_ok"])
            self.assertEqual(json.loads(state.read_text()), {"slot": "baseline", **baseline})

    def test_transition_never_claims_production_authority(self):
        source = MODULE_PATH.read_text(encoding="utf-8")
        self.assertIn('"production_effects": False', source)
        self.assertIn('"release_authority_exercised": False', source)
        self.assertIn('"release_performed": False', source)


if __name__ == "__main__":
    unittest.main()
