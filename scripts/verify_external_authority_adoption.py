#!/usr/bin/env python3
from __future__ import annotations
import argparse, hashlib, json, re, sqlite3, subprocess
from pathlib import Path

HEX40=re.compile(r"^[0-9a-f]{40}$")

def load(path: Path): return json.loads(path.read_text(encoding="utf-8"))
def digest(path: Path): return hashlib.sha256(path.read_bytes()).hexdigest()
def file_digest(path: Path): return hashlib.sha256(path.read_bytes()).hexdigest()
def run_git(root: Path, *args: str) -> str:
    cp=subprocess.run(["git","-C",str(root),*args],text=True,capture_output=True,check=False)
    if cp.returncode: raise ValueError(cp.stderr.strip() or "git command failed")
    return cp.stdout.strip()
def normalize_repo(url: str) -> str:
    value=url.strip()
    if value.startswith("git@github.com:"): value=value.split(":",1)[1]
    elif "github.com/" in value: value=value.split("github.com/",1)[1]
    if value.endswith(".git"): value=value[:-4]
    if not re.fullmatch(r"[^/\s]+/[^/\s]+",value): raise ValueError("origin is not a GitHub owner/repository identity")
    return value

def verify_goverdocs(binding: dict, root: Path|None, grant_path: Path|None, receipt_path: Path|None):
    blockers=[]; evidence=[]
    result={"status":"BLOCKED","authority_repository":None,"authority_head":None,"target":None,"write_grant_ref":None,"write_receipt_ref":None}
    if root is None or grant_path is None or receipt_path is None:
        blockers.append("GOVERDOCS_WRITE_AUTHORITY_MISSING")
        return result,blockers,evidence
    try:
        grant=load(grant_path); receipt=load(receipt_path)
        repo=normalize_repo(run_git(root,"remote","get-url","origin")); head=run_git(root,"rev-parse","HEAD")
        if not HEX40.fullmatch(head): raise ValueError("GOVERDOCS head is invalid")
        subject=grant.get("subject"); rsubject=receipt.get("subject")
        if not isinstance(subject,dict) or subject != rsubject: raise ValueError("grant/receipt subject mismatch")
        if subject.get("repository") != repo or subject.get("head_sha") != head: raise ValueError("write subject does not bind GOVERDOCS workspace repository/head")
        if receipt.get("grant_id") != grant.get("grant_id"): raise ValueError("receipt grant_id mismatch")
        if receipt.get("payload_sha256") != binding["goverdocs"]["projection_digest"]: raise ValueError("receipt payload does not match projected evidence")
        target=receipt.get("target")
        if not isinstance(target,str) or not target or target.startswith("/") or ".." in Path(target).parts: raise ValueError("receipt target is unsafe")
        target_path=(root/target).resolve()
        if root.resolve() not in target_path.parents: raise ValueError("receipt target escapes GOVERDOCS workspace")
        if not target_path.is_file(): raise ValueError("GOVERDOCS target file is missing")
        if file_digest(target_path) != receipt.get("post_state",{}).get("sha256"): raise ValueError("GOVERDOCS target hash does not match receipt")
        raw_status=run_git(root,"status","--porcelain=v1","--untracked-files=all")
        changed=set()
        for line in raw_status.splitlines():
            if not line.strip(): continue
            path=line[3:].strip()
            if " -> " in path: path=path.split(" -> ",1)[1]
            changed.add(path)
        if changed != {target}: raise ValueError("GOVERDOCS workspace contains changes outside the authorized target")
        result={"status":"INGESTED","authority_repository":repo,"authority_head":head,"target":target,"write_grant_ref":str(grant_path),"write_receipt_ref":str(receipt_path)}
        evidence += [str(grant_path),str(receipt_path),str(target_path)]
    except (OSError,ValueError,KeyError,json.JSONDecodeError) as exc:
        blockers.append("GOVERDOCS_VERIFICATION_FAILED:"+str(exc))
    return result,blockers,evidence

def verify_voodoo(binding: dict, db_path: Path|None):
    blockers=[]; evidence=[]
    result={"status":"BLOCKED","database_ref":None,"registry_key":None,"audit_action":None}
    if db_path is None or not db_path.is_file():
        blockers.append("VOODOO_CANONICAL_DATABASE_MISSING")
        return result,blockers,evidence
    try:
        descriptor_path=Path(binding["voodoo_project_registry"]["descriptor_ref"])
        if digest(descriptor_path) != binding["voodoo_project_registry"]["descriptor_digest"]: raise ValueError("Voodoo descriptor digest drift")
        descriptor=load(descriptor_path); project_id=descriptor["project_id"]
        key=f"control_plane.project.v1:{project_id}"
        con=sqlite3.connect(f"file:{db_path.resolve()}?mode=ro",uri=True)
        row=con.execute("select value from runtime_flags where key=?",(key,)).fetchone()
        if row is None or json.loads(row[0]) != descriptor: raise ValueError("Voodoo registry row missing or mismatched")
        cols={r[1] for r in con.execute("pragma table_info(audit_events)").fetchall()}
        required={"action","target_id"}
        if not required.issubset(cols): raise ValueError("Voodoo audit schema lacks required fields")
        audit=con.execute("select action,target_id from audit_events where action=? and target_id=? order by rowid desc limit 1",("control_plane.registry.project.registered",project_id)).fetchone()
        con.close()
        if audit is None: raise ValueError("Voodoo project registration audit event missing")
        result={"status":"REGISTERED","database_ref":str(db_path),"registry_key":key,"audit_action":audit[0]}
        evidence.append(str(db_path))
    except (OSError,ValueError,KeyError,json.JSONDecodeError,sqlite3.Error) as exc:
        blockers.append("VOODOO_VERIFICATION_FAILED:"+str(exc))
    return result,blockers,evidence

def main()->int:
    p=argparse.ArgumentParser()
    p.add_argument("--binding",type=Path,required=True); p.add_argument("--output",type=Path,required=True)
    p.add_argument("--goverdocs-root",type=Path); p.add_argument("--goverdocs-write-grant",type=Path); p.add_argument("--goverdocs-write-receipt",type=Path)
    p.add_argument("--voodoo-db",type=Path)
    a=p.parse_args(); binding=load(a.binding)
    if binding.get("schema_version")!="1.0.0": raise SystemExit("unsupported binding schema")
    g,gb,ge=verify_goverdocs(binding,a.goverdocs_root,a.goverdocs_write_grant,a.goverdocs_write_receipt)
    v,vb,ve=verify_voodoo(binding,a.voodoo_db)
    blockers=gb+vb; status="BOUND" if g["status"]=="INGESTED" and v["status"]=="REGISTERED" else "BLOCKED"
    if status=="BOUND": blockers=[]
    record={"schema_version":"1.0.0","record_id":"EAA-"+digest(a.binding)[:16],"binding_ref":str(a.binding),"binding_digest":digest(a.binding),"subject":binding["subject"],"goverdocs":g,"voodoo_project_registry":v,"adoption_status":status,"blockers":blockers,"governance":{"fail_closed":True,"record_grants_execution":False,"record_grants_release":False,"external_authorities_remain_canonical":True},"evidence":[str(a.binding),*ge,*ve]}
    a.output.parent.mkdir(parents=True,exist_ok=True); a.output.write_text(json.dumps(record,indent=2,sort_keys=True)+"\n",encoding="utf-8")
    print("EXTERNAL_AUTHORITY_ADOPTION="+status)
    for item in blockers: print("BLOCKER="+item)
    return 0 if status=="BOUND" else 2
if __name__=="__main__": raise SystemExit(main())
