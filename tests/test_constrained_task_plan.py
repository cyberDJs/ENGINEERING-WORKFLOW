from __future__ import annotations
import json, subprocess, sys, tempfile, unittest
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
BUILDER=ROOT/'scripts/build_constrained_task_plan.py'
VALIDATOR=ROOT/'scripts/validate_ai_control_plane.py'

class ConstrainedTaskPlanTest(unittest.TestCase):
    def fixture(self, root: Path):
        context={"schema_version":"1.0.0","packet_id":"PCP-test","project":{"id":"p","path":"/tmp/p","branch":"main","head":"a"*40,"dirty":False},"task":{"objective":"bounded change","mode":"IMPLEMENT","scope_in":["x"],"scope_out":[]},"authority_sources":[{"path":"README.md","sha256":"b"*64,"content":""}],"context_sources":[],"constraints":{"allowed_effects":["read","plan","write","git"],"prohibited_effects":["deploy","release","secrets"],"secret_policy":"no-secret-values"},"build":{"builder":"test","built_at":"2026-10-04T00:00:00Z","content_included":False}}
        mapping={"schema_version":"1.0.0","record_id":"CMR-test","capability":{"id":"x/y","class":"tool","authority_mode":"ADVISORY","lifecycle_status":"WATCH"},"admission_refs":["a"],"evaluation_refs":["e"],"registry_binding":{"authority_type":"NONE","registry_ref":None,"capability_ref":None,"binding_status":"UNBOUND"},"project_mappings":[{"project_id":"p","project_ref":"p","status":"WATCH","allowed_use":["local"],"prohibited_use":["production"],"environments":["local"],"execution_authority_ref":None,"production_eligible":False,"evidence_refs":["e"]}],"governance":{"mapping_grants_execution":False,"project_authority_required":True,"fail_closed_on_missing_binding":True},"evidence":["e"]}
        cp=root/'context.json'; mp=root/'mapping.json'; cp.write_text(json.dumps(context)); mp.write_text(json.dumps(mapping)); return cp,mp
    def run_plan(self,effects,authorities=()):
        td=tempfile.TemporaryDirectory(); root=Path(td.name); cp,mp=self.fixture(root); out=root/'plan.json'; cmd=[sys.executable,str(BUILDER),'--context',str(cp),'--mapping',str(mp),'--output',str(out)]
        for x in effects: cmd += ['--effect',x]
        for x in authorities: cmd += ['--authority',x]
        r=subprocess.run(cmd,cwd=ROOT,text=True,capture_output=True,check=False); return td,out,r
    def test_protected_effect_requires_authority(self):
        td,out,r=self.run_plan(['read','write']); self.addCleanup(td.cleanup); self.assertEqual(r.returncode,0); plan=json.loads(out.read_text()); self.assertEqual(plan['status'],'APPROVAL_REQUIRED'); self.assertFalse(plan['governance']['execution_performed'])
    def test_prohibited_effect_blocks(self):
        td,out,r=self.run_plan(['deploy']); self.addCleanup(td.cleanup); self.assertEqual(r.returncode,0); self.assertEqual(json.loads(out.read_text())['status'],'BLOCKED')
    def test_attributable_authority_allows_plan_not_execution(self):
        td,out,r=self.run_plan(['write'],['write:AUTH-123']); self.addCleanup(td.cleanup); plan=json.loads(out.read_text()); self.assertEqual(plan['status'],'PLANNED'); self.assertFalse(plan['governance']['plan_grants_execution']); v=subprocess.run([sys.executable,str(VALIDATOR),'--kind','constrained-task-plan','--file',str(out)],cwd=ROOT,text=True,capture_output=True); self.assertEqual(v.returncode,0,v.stdout+v.stderr)
        plan['governance']['plan_grants_execution']=True; out.write_text(json.dumps(plan)); v=subprocess.run([sys.executable,str(VALIDATOR),'--kind','constrained-task-plan','--file',str(out)],cwd=ROOT,text=True,capture_output=True); self.assertNotEqual(v.returncode,0)
if __name__=='__main__': unittest.main()
