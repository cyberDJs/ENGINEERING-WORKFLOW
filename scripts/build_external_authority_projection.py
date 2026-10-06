#!/usr/bin/env python3
"""Build read-only GOVERDOCS and Voodoo project-registry projections."""
from __future__ import annotations
import argparse, hashlib, json, re
from datetime import datetime, timezone
from pathlib import Path
HEX64=re.compile(r"^[0-9a-f]{64}$")
REPO=re.compile(r"^[^/\s]+/[^/\s]+$")

def digest(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()

def write_json(path: Path, value: object) -> None:
    path.write_text(json.dumps(value, indent=2, sort_keys=True)+"\n", encoding="utf-8")

def main() -> int:
    p=argparse.ArgumentParser()
    p.add_argument("--project-context", type=Path, required=True)
    p.add_argument("--source-record", type=Path, required=True)
    p.add_argument("--change-digest", required=True)
    p.add_argument("--repository", required=True)
    p.add_argument("--goverdocs-schema", type=Path, required=True)
    p.add_argument("--voodoo-contract", type=Path, required=True)
    p.add_argument("--output-dir", type=Path, required=True)
    p.add_argument("--producer-id", default="ai-engineering-control-plane")
    a=p.parse_args()
    if not HEX64.match(a.change_digest): raise SystemExit("change-digest must be lowercase sha256")
    if not REPO.match(a.repository): raise SystemExit("repository must use owner/repository form")
    packet=json.loads(a.project_context.read_text())
    source=json.loads(a.source_record.read_text())
    if not isinstance(source, dict): raise SystemExit("source-record must be a JSON object")
    project=packet.get("project") if isinstance(packet,dict) else None
    if not isinstance(project,dict): raise SystemExit("project context missing project")
    if project.get("dirty") is not False: raise SystemExit("project context must bind a clean project state")
    project_id=str(project.get("id") or "").strip(); head=str(project.get("head") or ""); branch=str(project.get("branch") or "").strip()
    if not project_id or not re.fullmatch(r"[0-9a-f]{40}",head) or not branch: raise SystemExit("project context identity is incomplete")
    if not a.goverdocs_schema.is_file() or not a.voodoo_contract.is_file(): raise SystemExit("upstream contract file missing")
    a.output_dir.mkdir(parents=True, exist_ok=True)
    now=datetime.now(timezone.utc).isoformat().replace("+00:00","Z")
    evidence_item={"schema_version":1,"evidence_id":f"EW-AI-{digest(a.source_record)[:16]}","rule_id":"AI-CONTROL-PLANE-EXTERNAL-PROJECTION","requirement":"Preserve attributable AI control-plane evidence without granting authority","subject":{"change_digest":a.change_digest,"repository":a.repository,"head_sha":head},"source":{"ref":str(a.source_record),"digest":digest(a.source_record)},"producer":{"id":a.producer_id,"type":"tool"},"verification":{"status":"unverified","verifier_id":"external-authority-review-required","method":"read-only projection; no GOVERDOCS ingest performed","verified_at":now,"valid_until":None}}
    project_descriptor={"schema":"voodoo.project-descriptor.v1","project_id":project_id,"canonical_repository":a.repository,"canonical_ref":f"refs/heads/{branch}","aliases":[]}
    ev_path=a.output_dir/'goverdocs-evidence-item.json'; vd_path=a.output_dir/'voodoo-project-descriptor.json'
    write_json(ev_path,evidence_item); write_json(vd_path,project_descriptor)
    binding={"schema_version":"1.0.0","record_id":f"EAB-{digest(a.source_record)[:16]}","subject":{"project_id":project_id,"repository":a.repository,"head":head},"goverdocs":{"schema_ref":str(a.goverdocs_schema),"schema_digest":digest(a.goverdocs_schema),"projection_ref":str(ev_path),"projection_digest":digest(ev_path),"verification_status":"UNVERIFIED","ingest_ref":None},"voodoo_project_registry":{"contract_ref":str(a.voodoo_contract),"contract_digest":digest(a.voodoo_contract),"descriptor_ref":str(vd_path),"descriptor_digest":digest(vd_path),"binding_status":"UNBOUND","registry_ref":None},"integration_status":"PROJECTION_READY","governance":{"record_grants_authority":False,"external_write_performed":False,"external_write_requires_separate_authorization":True,"canonical_truth_remains_external":True},"evidence":[str(a.project_context),str(a.source_record),str(a.goverdocs_schema),str(a.voodoo_contract)]}
    write_json(a.output_dir/'external-authority-binding.json',binding)
    print("AUTHORITY_PROJECTION=PASSED"); print(f"PROJECT={project_id}"); print("GOVERDOCS=UNVERIFIED_PROJECTION"); print("VOODOO_PROJECT_REGISTRY=UNBOUND"); print("EXTERNAL_WRITE_PERFORMED=false")
    return 0
if __name__=="__main__": raise SystemExit(main())
