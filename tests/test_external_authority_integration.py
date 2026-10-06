from __future__ import annotations
import hashlib, json, subprocess, sys, tempfile, unittest
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
BUILDER=ROOT/'scripts/build_external_authority_projection.py'
VALIDATOR=ROOT/'scripts/validate_ai_control_plane.py'

class ExternalAuthorityIntegrationTest(unittest.TestCase):
    def fixture(self, tmp: Path) -> tuple[Path,Path,Path,Path]:
        packet={"project":{"id":"engineering-workflow","path":str(ROOT),"branch":"main","head":"a"*40,"dirty":False}}
        pcp=tmp/'pcp.json'; pcp.write_text(json.dumps(packet))
        source=tmp/'source.json'; source.write_text(json.dumps({"receipt_id":"EVAL-1","verdict":"PASS"}))
        gd=tmp/'goverdocs.schema.json'; gd.write_text('{"type":"object"}')
        vc=tmp/'control_plane_contracts.py'; vc.write_text('PROJECT_SCHEMA="voodoo.project-descriptor.v1"\n')
        return pcp,source,gd,vc
    def run_builder(self,tmp:Path,pcp:Path,source:Path,gd:Path,vc:Path):
        out=tmp/'out'
        result=subprocess.run([sys.executable,str(BUILDER),'--project-context',str(pcp),'--source-record',str(source),'--change-digest','b'*64,'--repository','nulleimy/ENGINEERING-WORKFLOW','--goverdocs-schema',str(gd),'--voodoo-contract',str(vc),'--output-dir',str(out)],cwd=ROOT,text=True,capture_output=True,check=False)
        return result,out
    def test_projection_is_read_only_and_unbound(self):
        with tempfile.TemporaryDirectory() as td:
            tmp=Path(td); pcp,source,gd,vc=self.fixture(tmp); result,out=self.run_builder(tmp,pcp,source,gd,vc)
            self.assertEqual(result.returncode,0,msg=result.stdout+result.stderr)
            binding=json.loads((out/'external-authority-binding.json').read_text())
            self.assertEqual(binding['integration_status'],'PROJECTION_READY')
            self.assertFalse(binding['governance']['record_grants_authority']); self.assertFalse(binding['governance']['external_write_performed'])
            self.assertEqual(binding['goverdocs']['verification_status'],'UNVERIFIED'); self.assertEqual(binding['voodoo_project_registry']['binding_status'],'UNBOUND')
            valid=subprocess.run([sys.executable,str(VALIDATOR),'--kind','external-authority-binding','--file',str(out/'external-authority-binding.json')],cwd=ROOT,text=True,capture_output=True,check=False)
            self.assertEqual(valid.returncode,0,msg=valid.stdout+valid.stderr)
    def test_dirty_context_fails_closed(self):
        with tempfile.TemporaryDirectory() as td:
            tmp=Path(td); pcp,source,gd,vc=self.fixture(tmp); data=json.loads(pcp.read_text()); data['project']['dirty']=True; pcp.write_text(json.dumps(data))
            result,_=self.run_builder(tmp,pcp,source,gd,vc); self.assertNotEqual(result.returncode,0); self.assertIn('clean project state',result.stderr)
    def test_binding_cannot_claim_authority_or_bound_without_upstream_refs(self):
        with tempfile.TemporaryDirectory() as td:
            tmp=Path(td); pcp,source,gd,vc=self.fixture(tmp); result,out=self.run_builder(tmp,pcp,source,gd,vc); self.assertEqual(result.returncode,0)
            path=out/'external-authority-binding.json'; data=json.loads(path.read_text()); data['governance']['external_write_performed']=True; path.write_text(json.dumps(data))
            bad=subprocess.run([sys.executable,str(VALIDATOR),'--kind','external-authority-binding','--file',str(path)],cwd=ROOT,text=True,capture_output=True,check=False); self.assertNotEqual(bad.returncode,0)
            data['governance']['external_write_performed']=False; data['integration_status']='BOUND'; path.write_text(json.dumps(data))
            bad=subprocess.run([sys.executable,str(VALIDATOR),'--kind','external-authority-binding','--file',str(path)],cwd=ROOT,text=True,capture_output=True,check=False); self.assertNotEqual(bad.returncode,0)

if __name__=='__main__': unittest.main()
