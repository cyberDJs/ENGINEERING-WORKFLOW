from __future__ import annotations
import hashlib, importlib.util, json, sqlite3, subprocess, sys, tempfile, unittest
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]; SCRIPT=ROOT/'scripts/verify_external_authority_adoption.py'; VALIDATOR=ROOT/'scripts/validate_ai_control_plane.py'
SPEC=importlib.util.spec_from_file_location('verify_external_authority_adoption',SCRIPT); MODULE=importlib.util.module_from_spec(SPEC); SPEC.loader.exec_module(MODULE)
def dump(path:Path,obj): path.write_text(json.dumps(obj,indent=2,sort_keys=True)+'\n')
def sha(path:Path): return hashlib.sha256(path.read_bytes()).hexdigest()
class NormalizeRepoSecurityTest(unittest.TestCase):
    def test_accepts_canonical_github_remotes(self):
        cases={
            "https://github.com/eimyroot/OATHDO.git":"eimyroot/OATHDO",
            "https://github.com:443/eimyroot/OATHDO.git":"eimyroot/OATHDO",
            "git@github.com:eimyroot/OATHDO.git":"eimyroot/OATHDO",
            "ssh://git@github.com/eimyroot/OATHDO.git":"eimyroot/OATHDO",
            "ssh://git@github.com:22/eimyroot/OATHDO":"eimyroot/OATHDO",
        }
        for remote,expected in cases.items():
            with self.subTest(remote=remote):
                self.assertEqual(MODULE.normalize_repo(remote),expected)

    def test_rejects_github_substring_and_authority_confusion(self):
        cases=[
            "https://evil.example/github.com/eimyroot/OATHDO.git",
            "https://github.com.evil.example/eimyroot/OATHDO.git",
            "https://github.com@evil.example/github.com/eimyroot/OATHDO.git",
            "https://evil.example/?next=https://github.com/eimyroot/OATHDO.git",
            "https://github.com/eimyroot/OATHDO.git?redirect=evil",
            "https://user@github.com/eimyroot/OATHDO.git",
            "http://github.com/eimyroot/OATHDO.git",
            "git://github.com/eimyroot/OATHDO.git",
            "eimyroot/OATHDO",
        ]
        for remote in cases:
            with self.subTest(remote=remote):
                with self.assertRaises(ValueError):
                    MODULE.normalize_repo(remote)

    def test_rejects_non_repository_github_paths(self):
        for remote in [
            "https://github.com/eimyroot",
            "https://github.com/eimyroot/OATHDO/issues",
            "https://github.com/../OATHDO",
            "ssh://other@github.com/eimyroot/OATHDO.git",
        ]:
            with self.subTest(remote=remote):
                with self.assertRaises(ValueError):
                    MODULE.normalize_repo(remote)

class ExternalAuthorityAdoptionTest(unittest.TestCase):
    def fixture(self,td:Path):
        projection=td/'projection.json'; dump(projection,{"evidence":"x"})
        descriptor=td/'descriptor.json'; dump(descriptor,{"schema":"voodoo.project-descriptor.v1","project_id":"engineering-workflow","canonical_repository":"nulleimy/ENGINEERING-WORKFLOW","canonical_ref":"refs/heads/main","aliases":[]})
        binding=td/'binding.json'; dump(binding,{"schema_version":"1.0.0","record_id":"EAB-test","subject":{"project_id":"engineering-workflow","repository":"nulleimy/ENGINEERING-WORKFLOW","head":"1"*40},"goverdocs":{"schema_ref":"schema","schema_digest":"a"*64,"projection_ref":str(projection),"projection_digest":sha(projection),"verification_status":"UNVERIFIED","ingest_ref":None},"voodoo_project_registry":{"contract_ref":"contract","contract_digest":"b"*64,"descriptor_ref":str(descriptor),"descriptor_digest":sha(descriptor),"binding_status":"UNBOUND","registry_ref":None},"integration_status":"PROJECTION_READY","governance":{"record_grants_authority":False,"external_write_performed":False,"external_write_requires_separate_authorization":True,"canonical_truth_remains_external":True},"evidence":[str(projection)]})
        return binding,projection,descriptor
    def test_missing_external_authorities_blocks(self):
        with tempfile.TemporaryDirectory() as t:
            td=Path(t); binding,_,_=self.fixture(td); out=td/'out.json'
            cp=subprocess.run([sys.executable,str(SCRIPT),'--binding',str(binding),'--output',str(out)],capture_output=True,text=True)
            self.assertEqual(cp.returncode,2); data=json.loads(out.read_text()); self.assertEqual(data['adoption_status'],'BLOCKED'); self.assertFalse(data['governance']['record_grants_execution'])
    def test_bound_requires_git_workspace_registry_row_and_audit(self):
        with tempfile.TemporaryDirectory() as t:
            td=Path(t); binding,projection,descriptor=self.fixture(td); gd=td/'goverdocs'; gd.mkdir(); subprocess.run(['git','init','-q',str(gd)],check=True); subprocess.run(['git','-C',str(gd),'config','user.email','test@example.com'],check=True); subprocess.run(['git','-C',str(gd),'config','user.name','test'],check=True); (gd/'seed').write_text('x'); subprocess.run(['git','-C',str(gd),'add','seed'],check=True); subprocess.run(['git','-C',str(gd),'commit','-qm','seed'],check=True); subprocess.run(['git','-C',str(gd),'remote','add','origin','https://github.com/eimyroot/OATHDO.git'],check=True); head=subprocess.check_output(['git','-C',str(gd),'rev-parse','HEAD'],text=True).strip()
            target='evidence/engineering-workflow.json'; tp=gd/target; tp.parent.mkdir(parents=True); tp.write_bytes(projection.read_bytes()); post=sha(tp)
            subject={'repository':'eimyroot/OATHDO','pull_request':7,'head_sha':head,'change_digest':'c'*64}; grant=td/'grant.json'; receipt=td/'receipt.json'; dump(grant,{'grant_id':'g1','subject':subject}); dump(receipt,{'grant_id':'g1','subject':subject,'payload_sha256':sha(projection),'target':target,'post_state':{'sha256':post}})
            db=td/'v.sqlite3'; con=sqlite3.connect(db); con.executescript('create table runtime_flags(key text primary key,value text); create table audit_events(action text,target_id text);'); desc=json.loads(descriptor.read_text()); con.execute('insert into runtime_flags values(?,?)',(f"control_plane.project.v1:{desc['project_id']}",json.dumps(desc,sort_keys=True,separators=(',',':')))); con.execute('insert into audit_events values(?,?)',('control_plane.registry.project.registered',desc['project_id'])); con.commit(); con.close()
            out=td/'out.json'; cp=subprocess.run([sys.executable,str(SCRIPT),'--binding',str(binding),'--output',str(out),'--goverdocs-root',str(gd),'--goverdocs-write-grant',str(grant),'--goverdocs-write-receipt',str(receipt),'--voodoo-db',str(db)],capture_output=True,text=True)
            self.assertEqual(cp.returncode,0,cp.stdout+cp.stderr); data=json.loads(out.read_text()); self.assertEqual(data['adoption_status'],'BOUND'); self.assertEqual(data['blockers'],[])
            valid=subprocess.run([sys.executable,str(VALIDATOR),'--kind','external-authority-adoption','--file',str(out)],cwd=ROOT,capture_output=True,text=True); self.assertEqual(valid.returncode,0,valid.stdout+valid.stderr)
    def test_unrelated_goverdocs_workspace_drift_blocks(self):
        with tempfile.TemporaryDirectory() as t:
            td=Path(t); binding,projection,_=self.fixture(td); gd=td/'g'; gd.mkdir(); subprocess.run(['git','init','-q',str(gd)],check=True); subprocess.run(['git','-C',str(gd),'config','user.email','t@x'],check=True); subprocess.run(['git','-C',str(gd),'config','user.name','t'],check=True); (gd/'seed').write_text('x'); subprocess.run(['git','-C',str(gd),'add','seed'],check=True); subprocess.run(['git','-C',str(gd),'commit','-qm','x'],check=True); subprocess.run(['git','-C',str(gd),'remote','add','origin','https://github.com/eimyroot/OATHDO.git'],check=True); head=subprocess.check_output(['git','-C',str(gd),'rev-parse','HEAD'],text=True).strip(); target='evidence/item.json'; tp=gd/target; tp.parent.mkdir(parents=True); tp.write_bytes(projection.read_bytes()); (gd/'unrelated.txt').write_text('drift'); subject={'repository':'eimyroot/OATHDO','pull_request':1,'head_sha':head,'change_digest':'e'*64}; grant=td/'grant'; receipt=td/'receipt'; dump(grant,{'grant_id':'g','subject':subject}); dump(receipt,{'grant_id':'g','subject':subject,'payload_sha256':sha(projection),'target':target,'post_state':{'sha256':sha(tp)}}); out=td/'out'
            cp=subprocess.run([sys.executable,str(SCRIPT),'--binding',str(binding),'--output',str(out),'--goverdocs-root',str(gd),'--goverdocs-write-grant',str(grant),'--goverdocs-write-receipt',str(receipt)],capture_output=True,text=True); self.assertEqual(cp.returncode,2); self.assertIn('outside the authorized target',out.read_text())
    def test_wrong_goverdocs_workspace_subject_blocks(self):
        with tempfile.TemporaryDirectory() as t:
            td=Path(t); binding,projection,_=self.fixture(td); gd=td/'g'; gd.mkdir(); subprocess.run(['git','init','-q',str(gd)],check=True); subprocess.run(['git','-C',str(gd),'config','user.email','t@x'],check=True); subprocess.run(['git','-C',str(gd),'config','user.name','t'],check=True); (gd/'x').write_text('x'); subprocess.run(['git','-C',str(gd),'add','x'],check=True); subprocess.run(['git','-C',str(gd),'commit','-qm','x'],check=True); subprocess.run(['git','-C',str(gd),'remote','add','origin','https://github.com/eimyroot/OATHDO.git'],check=True); head=subprocess.check_output(['git','-C',str(gd),'rev-parse','HEAD'],text=True).strip(); target='e.json'; (gd/target).write_bytes(projection.read_bytes()); subject={'repository':'wrong/repo','pull_request':1,'head_sha':head,'change_digest':'d'*64}; grant=td/'grant'; receipt=td/'receipt'; dump(grant,{'grant_id':'g','subject':subject}); dump(receipt,{'grant_id':'g','subject':subject,'payload_sha256':sha(projection),'target':target,'post_state':{'sha256':sha(gd/target)}}); out=td/'out'
            cp=subprocess.run([sys.executable,str(SCRIPT),'--binding',str(binding),'--output',str(out),'--goverdocs-root',str(gd),'--goverdocs-write-grant',str(grant),'--goverdocs-write-receipt',str(receipt)],capture_output=True,text=True); self.assertEqual(cp.returncode,2); self.assertIn('write subject does not bind',out.read_text())
if __name__=='__main__': unittest.main()
