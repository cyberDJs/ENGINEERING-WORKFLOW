import importlib.util, json, tempfile, unittest
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]; P=ROOT/'scripts/run_reference_service_rehearsal.py'
spec=importlib.util.spec_from_file_location('ops_rehearsal',P); mod=importlib.util.module_from_spec(spec); spec.loader.exec_module(mod)
class OperationsRehearsalTest(unittest.TestCase):
    def test_reference_service_health_metrics_and_restore(self):
        with tempfile.TemporaryDirectory() as td:
            out=Path(td)/'receipt.json'; r=mod.run(out,probes=8)
            self.assertEqual(r['status'],'VERIFIED'); self.assertEqual(r['measurements']['success_ratio'],1.0)
            self.assertTrue(r['recovery']['restore_identity_verified']); self.assertTrue(r['checks']['latency_target_met']); self.assertTrue(r['checks']['restore_target_met'])
    def test_rehearsal_never_claims_production_operation(self):
        with tempfile.TemporaryDirectory() as td:
            r=mod.run(Path(td)/'receipt.json',probes=3)
            self.assertFalse(r['service']['production_service']); self.assertFalse(r['governance']['production_effects']); self.assertFalse(r['governance']['operational_readiness_claimed']); self.assertFalse(r['slo_spec']['production_slo_claimed'])
if __name__=='__main__': unittest.main()
