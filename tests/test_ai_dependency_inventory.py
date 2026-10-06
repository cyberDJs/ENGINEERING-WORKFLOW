\
from __future__ import annotations
import copy, json, subprocess, sys, tempfile, unittest
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
VALIDATOR=ROOT/'scripts/validate_ai_control_plane.py'

class AIDependencyInventoryTest(unittest.TestCase):
    def base(self):
        return {'schema_version':'1.0.0','snapshot_id':'INV-test','project':{'id':'Voodoo-One','path':'/tmp/Voodoo-One','branch':'main','head':'a'*40,'dirty':False},'providers':[{'provider_id':'local-llama','provider_type':'LOCAL_RUNTIME','identity_ref':'/opt/llama-server','digest':'b'*64,'endpoint_scope':'LOCALHOST_ONLY','external_data_transfer':False,'retention_mode':'PROCESS_EPHEMERAL','training_use':'NOT_APPLICABLE','credentials_required':False,'data_policy_ref':None,'evidence_refs':['runtime-hash']}],'models':[{'model_id':'model-a','artifact_admission_ref':'admission.json','revision':'rev1','digest':'c'*64,'license':'Apache-2.0','provider_id':'local-llama','role':'advisory-router','lifecycle_status':'WATCH','use_scope':'LOCAL_PILOT','authority_mode':'ADVISORY','secret_values_allowed':False,'personal_data_allowed':False,'personal_data_policy_ref':None,'evidence_refs':['eval.json']}],'inventory_status':'COMPLETE','governance':{'read_only_snapshot':True,'grants_activation':False,'grants_execution':False,'grants_release':False,'unknown_data_boundary_blocks_activation':True},'evidence':['inventory-source'],'known_unknowns':[]}
    def validate(self,payload):
        with tempfile.TemporaryDirectory() as tmp:
            p=Path(tmp)/'i.json'; p.write_text(json.dumps(payload),encoding='utf-8')
            return subprocess.run([sys.executable,str(VALIDATOR),'--kind','ai-dependency-inventory','--file',str(p)],cwd=ROOT,text=True,capture_output=True,check=False)
    def test_complete_local_inventory_passes(self):
        r=self.validate(self.base()); self.assertEqual(r.returncode,0,msg=r.stdout+r.stderr)
    def test_unknown_provider_reference_fails(self):
        d=self.base(); d['models'][0]['provider_id']='missing'; self.assertNotEqual(self.validate(d).returncode,0)
    def test_complete_inventory_cannot_hide_unknown_boundary(self):
        d=self.base(); d['providers'][0]['retention_mode']='UNKNOWN'; self.assertNotEqual(self.validate(d).returncode,0)
        d['inventory_status']='BLOCKED'; d['known_unknowns']=['provider retention unknown']; self.assertEqual(self.validate(d).returncode,0)
    def test_inventory_never_grants_authority_or_secret_values(self):
        for field in ('grants_activation','grants_execution','grants_release'):
            d=self.base(); d['governance'][field]=True; self.assertNotEqual(self.validate(d).returncode,0)
        d=self.base(); d['models'][0]['secret_values_allowed']=True; self.assertNotEqual(self.validate(d).returncode,0)
    def test_personal_data_requires_explicit_policy_reference(self):
        d=self.base(); d['models'][0]['personal_data_allowed']=True; self.assertNotEqual(self.validate(d).returncode,0)
        d['models'][0]['personal_data_policy_ref']='privacy-policy.md'; self.assertEqual(self.validate(d).returncode,0)
if __name__=='__main__': unittest.main()
