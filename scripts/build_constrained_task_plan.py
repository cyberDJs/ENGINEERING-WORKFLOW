#!/usr/bin/env python3
from __future__ import annotations
import argparse, hashlib, json
from pathlib import Path

PROTECTED={"write","shell","git","network","deploy","release"}
DENIED={"secrets"}

def load(p): return json.loads(Path(p).read_text())
def main():
 p=argparse.ArgumentParser(); p.add_argument("--context",required=True); p.add_argument("--mapping",required=True); p.add_argument("--effect",action="append",default=[]); p.add_argument("--authority",action="append",default=[]); p.add_argument("--output",required=True); a=p.parse_args()
 ctx=load(a.context); mapping=load(a.mapping); auth=set(a.authority)
 allowed=set(ctx.get("constraints",{}).get("allowed_effects",[])); prohibited=set(ctx.get("constraints",{}).get("prohibited_effects",[]))
 decisions=[]; blocked=False; approval=False
 for effect in sorted(set(a.effect)):
  if effect in DENIED or effect in prohibited or effect not in allowed:
   d="DENY"; ref=None; blocked=True
  elif effect in PROTECTED:
   ref=next((x for x in auth if x.startswith(effect+":")),None); d="ALLOW" if ref else "APPROVAL_REQUIRED"; approval |= ref is None
  else:
   d="ALLOW"; ref="context-policy"
  decisions.append({"effect":effect,"decision":d,"authority_ref":ref})
 status="BLOCKED" if blocked else ("APPROVAL_REQUIRED" if approval else "PLANNED")
 raw=(str(a.context)+str(a.mapping)+json.dumps(decisions,sort_keys=True)).encode(); pid="CTP-"+hashlib.sha256(raw).hexdigest()[:16]
 out={"schema_version":"1.0.0","plan_id":pid,"project_context_ref":str(a.context),"capability_mapping_ref":str(a.mapping),"task":ctx.get("task",{}),"requested_effects":sorted(set(a.effect)),"effect_decisions":decisions,"status":status,"governance":{"plan_only":True,"execution_performed":False,"plan_grants_execution":False,"fail_closed":True},"evidence":[str(a.context),str(a.mapping)]}
 Path(a.output).write_text(json.dumps(out,indent=2)+"\n"); print(f"PLAN_STATUS={status}"); print(f"PLAN_ID={pid}")
if __name__=="__main__": main()
