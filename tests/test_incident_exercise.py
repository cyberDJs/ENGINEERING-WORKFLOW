from __future__ import annotations
import hashlib, json, subprocess, sys, tempfile, unittest
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
SCRIPT=ROOT/'scripts/run_incident_exercise.py'
class IncidentExerciseTest(unittest.TestCase):
    def test_isolated_drift_is_detected_recovered_and_source_unchanged(self):
        lock=ROOT/'platform/toolchain.lock.json'; before=hashlib.sha256(lock.read_bytes()).hexdigest()
        with tempfile.TemporaryDirectory() as td:
            out=Path(td)/'receipt.json'; cp=subprocess.run([sys.executable,str(SCRIPT),'--output',str(out)],cwd=ROOT,text=True,capture_output=True,check=False)
            self.assertEqual(cp.returncode,0,cp.stdout+cp.stderr); r=json.loads(out.read_text())
            self.assertEqual(r['status'],'VERIFIED'); self.assertFalse(r['governance']['source_repository_mutated']); self.assertFalse(r['governance']['production_effects']); self.assertFalse(r['governance']['network_used'])
            phases={x['phase']:x for x in r['timeline']}; self.assertEqual(phases['VERIFY']['status'],'PASS'); self.assertNotEqual(phases['VERIFY']['evidence']['validator_exit'],0); self.assertEqual(phases['RECOVER']['status'],'PASS'); self.assertEqual(phases['RECOVER']['evidence']['validator_exit'],0)
        self.assertEqual(before,hashlib.sha256(lock.read_bytes()).hexdigest())
if __name__=='__main__': unittest.main()
