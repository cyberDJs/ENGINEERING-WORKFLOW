#!/usr/bin/env python3
from __future__ import annotations
import argparse, hashlib, json, shutil, tempfile, threading, time, urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

class ServiceState:
    def __init__(self, version: str, state_file: Path):
        self.version=version; self.state_file=state_file; self.requests=0; self.errors=0; self.latencies_ms=[]

class Handler(BaseHTTPRequestHandler):
    state: ServiceState
    def log_message(self, fmt, *args): return
    def _send(self, code, payload):
        body=(json.dumps(payload,sort_keys=True)+'\n').encode()
        self.send_response(code); self.send_header('Content-Type','application/json'); self.send_header('Content-Length',str(len(body))); self.end_headers(); self.wfile.write(body)
    def do_GET(self):
        start=time.perf_counter(); self.state.requests+=1
        try:
            if self.path=='/healthz': self._send(200,{'status':'ok','version':self.state.version})
            elif self.path=='/readyz': self._send(200,{'status':'ready','version':self.state.version})
            elif self.path=='/work': self._send(200,{'ok':True,'request_id':f'req-{self.state.requests:04d}','version':self.state.version})
            elif self.path=='/metrics': self._send(200,{'requests_total':self.state.requests,'errors_total':self.state.errors})
            else: self.state.errors+=1; self._send(404,{'error':'not_found'})
        finally: self.state.latencies_ms.append((time.perf_counter()-start)*1000)

def sha256(path: Path) -> str:
    h=hashlib.sha256();
    with path.open('rb') as f:
        for chunk in iter(lambda:f.read(1024*1024),b''): h.update(chunk)
    return h.hexdigest()

def get_json(url: str) -> dict:
    with urllib.request.urlopen(url,timeout=2) as r:
        if r.status!=200: raise RuntimeError(f'HTTP {r.status}')
        return json.loads(r.read())

def percentile(values, q):
    xs=sorted(values); idx=max(0,min(len(xs)-1,int(round((len(xs)-1)*q))))
    return xs[idx]

def run(output: Path, probes: int=20) -> dict:
    with tempfile.TemporaryDirectory(prefix='ew-reference-service-') as td:
        lab=Path(td); state_file=lab/'state.json'; backup=lab/'backup.json'
        version='reference-service-rehearsal-v1'
        state_file.write_text(json.dumps({'version':version,'value':'baseline'},sort_keys=True)+'\n')
        baseline_sha=sha256(state_file); shutil.copy2(state_file,backup); backup_sha=sha256(backup)
        state=ServiceState(version,state_file); Handler.state=state
        server=ThreadingHTTPServer(('127.0.0.1',0),Handler); port=server.server_address[1]
        t=threading.Thread(target=server.serve_forever,daemon=True); t.start(); base=f'http://127.0.0.1:{port}'
        started=time.perf_counter(); health=get_json(base+'/healthz'); ready=get_json(base+'/readyz')
        ok=0
        for _ in range(probes): ok += bool(get_json(base+'/work').get('ok'))
        metrics=get_json(base+'/metrics')
        state_file.write_text(json.dumps({'version':version,'value':'corrupted-synthetic-state'},sort_keys=True)+'\n')
        corruption_sha=sha256(state_file); restore_start=time.perf_counter(); shutil.copy2(backup,state_file); restore_ms=(time.perf_counter()-restore_start)*1000
        restored_sha=sha256(state_file); server.shutdown(); server.server_close(); t.join(timeout=2)
        success_ratio=ok/probes; p95=percentile(state.latencies_ms,0.95)
        receipt={'schema':'ReferenceOperatedServiceRehearsal/v1','status':'VERIFIED' if (health.get('status')=='ok' and ready.get('status')=='ready' and success_ratio==1.0 and restored_sha==baseline_sha) else 'FAILED','environment':'LOCAL_ISOLATED_REHEARSAL','service':{'id':'engineering-workflow-reference-service','tier':'TIER-3','owner':'Operator','production_service':False,'external_network':False},'slo_spec':{'claim_scope':'rehearsal-only','availability_sli':'successful_work_probes / total_work_probes','success_target':0.99,'latency_sli':'local handler response p95 ms','p95_target_ms':250.0,'restore_target_ms':2000.0,'production_slo_claimed':False},'measurements':{'probe_count':probes,'successful_work_probes':ok,'success_ratio':success_ratio,'p95_latency_ms':round(p95,3),'requests_total':metrics['requests_total'],'errors_total':metrics['errors_total'],'restore_ms':round(restore_ms,3),'elapsed_ms':round((time.perf_counter()-started)*1000,3)},'recovery':{'baseline_sha256':baseline_sha,'backup_sha256':backup_sha,'corruption_sha256':corruption_sha,'restored_sha256':restored_sha,'restore_identity_verified':restored_sha==baseline_sha},'checks':{'health':health,'readiness':ready,'success_target_met':success_ratio>=0.99,'latency_target_met':p95<=250.0,'restore_target_met':restore_ms<=2000.0},'governance':{'production_effects':False,'release_performed':False,'deployment_performed':False,'network_scope':'127.0.0.1 only','operational_readiness_claimed':False},'remaining_blockers':['REAL_OPERATED_SERVICE_MISSING','PRODUCTION_MEASUREMENT_WINDOW_MISSING','INDEPENDENT_OPERATIONAL_READINESS_REVIEW_PENDING']}
        output.parent.mkdir(parents=True,exist_ok=True); output.write_text(json.dumps(receipt,indent=2,sort_keys=True)+'\n')
        return receipt

def main():
    p=argparse.ArgumentParser(); p.add_argument('--output',required=True); p.add_argument('--probes',type=int,default=20); a=p.parse_args(); r=run(Path(a.output),a.probes)
    print('REFERENCE_SERVICE_REHEARSAL='+r['status']); print('SUCCESS_RATIO='+str(r['measurements']['success_ratio'])); print('P95_LATENCY_MS='+str(r['measurements']['p95_latency_ms'])); print('RESTORE_VERIFIED='+str(r['recovery']['restore_identity_verified']).lower()); print('PRODUCTION_EFFECTS=false')
    raise SystemExit(0 if r['status']=='VERIFIED' else 1)
if __name__=='__main__': main()
