"""Hardened EW project operations."""
from __future__ import annotations

import json
import os
import shutil
import tempfile
import uuid
from pathlib import Path

from ew_runtime import *
from ew_scan import scan_project
from ew_records import project_record, render_records
from ew_doctor import doctor, safe_control_file

def publish_control(target: Path, files: dict[str, bytes]) -> Path:
    control = target / CONTROL
    stage: Path | None = None
    try:
        stage = Path(tempfile.mkdtemp(prefix=CONTROL_STAGING_PREFIX, dir=target))
        for relative, content in files.items():
            output = stage / relative
            output.parent.mkdir(parents=True, exist_ok=True)
            output.write_bytes(content)
        if any((item.is_symlink() for item in stage.rglob('*'))):
            raise Blocked('generated state contains symlink')
        if control.exists():
            raise Blocked('controlled state appeared during write')
        os.replace(stage, control)
        stage = None
        return control
    except Exception:
        if stage is not None:
            shutil.rmtree(stage, ignore_errors=True)
        raise

def init(target: Path, name: str, profile: str, risk: str, reversibility: str, dry_run: bool=False) -> dict[str, object]:
    if not SAFE_NAME.fullmatch(name):
        raise Blocked('unsafe project name')
    assurance, effective = selection(profile, risk, reversibility)
    target = resolved_target(target, must_exist=False)
    control = target / CONTROL
    if os.path.lexists(control):
        if control.is_symlink() or not control.is_dir():
            raise Blocked('existing control state is unsafe')
        try:
            existing = read_json_regular(safe_control_file(control, 'project.json'))['project']
            requested = {'name': name, 'profile': profile, 'risk': risk, 'reversibility': reversibility}
            current = {'name': existing['name'], 'profile': existing['profile'], 'risk': existing['requested_risk'], 'reversibility': existing['reversibility']}
        except Exception as exc:
            raise Blocked(f'existing control state is invalid: {exc}') from exc
        if current != requested or existing.get('bootstrap_mode', 'init') != 'init':
            raise Blocked(f'controlled state differs: {current}')
        if doctor(target)['status'] != 'PASS':
            raise Blocked('existing controlled project failed doctor')
        return {'status': 'NOOP', 'operation': 'init', 'project_dir': str(target), 'details': {'reason': 'identical controlled state exists'}}
    plan = {'control_directory': str(control), 'profile': profile, 'assurance_level': assurance, 'requested_risk': risk, 'effective_risk': effective, 'reversibility': reversibility}
    if dry_run:
        return {'status': 'PLANNED', 'operation': 'init', 'project_dir': str(target), 'details': plan}
    target_created = False
    try:
        if not target.exists():
            target.mkdir(parents=True)
            target_created = True
        if not target.is_dir() or not os.access(target, os.W_OK):
            raise Blocked('project target is not a writable directory')
        created = now()
        record = project_record(name, profile, risk, effective, reversibility, created, mode='init')
        publish_control(target, render_records(record, created, mode='init'))
        if doctor(target)['status'] != 'PASS':
            shutil.rmtree(control, ignore_errors=True)
            raise Blocked('post-write doctor failed')
        plan['manifest_digest'] = sha((control / 'manifest.json').read_bytes())
        return {'status': 'CREATED', 'operation': 'init', 'project_dir': str(target), 'details': plan}
    except Exception:
        if target_created and target.exists() and (not any(target.iterdir())):
            target.rmdir()
        raise

def adopt(target: Path, name: str, profile: str, risk: str, reversibility: str, *, apply: bool, acknowledge_sensitive_paths: bool, acknowledge_symlinks: bool=False, symlink_rationale: str | None=None) -> dict[str, object]:
    if not SAFE_NAME.fullmatch(name):
        raise Blocked('unsafe project name')
    target = resolved_target(target, must_exist=True)
    control = target / CONTROL
    audit = scan_project(target)
    rationale = (symlink_rationale or '').strip()
    if audit['symlink_records']:
        audit['symlink_acknowledgement'] = {'acknowledged': bool(acknowledge_symlinks), 'rationale': rationale if acknowledge_symlinks else None, 'rationale_sha256': sha(rationale.encode()) if acknowledge_symlinks else None}
    observed = str(audit['observed_minimum_risk'])
    blockers: list[str] = []
    try:
        assurance, effective = selection(profile, risk, reversibility, observed)
    except Blocked as exc:
        assurance = PROFILES[profile][0] if profile in PROFILES else 'UNKNOWN'
        effective = highest_risk(risk, REV_MIN.get(reversibility, 'R3'), observed)
        blockers.append(str(exc))
    if audit['sensitive_paths_content_not_read'] and (not acknowledge_sensitive_paths):
        blockers.append('sensitive path indicators require --acknowledge-sensitive-paths')
    if audit['symlink_records']:
        if not acknowledge_symlinks:
            blockers.append('symlink paths require --acknowledge-symlinks')
        if len(rationale) < 20:
            blockers.append('symlink acknowledgement requires --symlink-rationale with at least 20 characters')
    if os.path.lexists(control):
        if control.is_symlink() or not control.is_dir():
            raise Blocked('existing control state is unsafe')
        try:
            existing = read_json_regular(safe_control_file(control, 'project.json'))['project']
        except Exception as exc:
            raise Blocked(f'existing control state is invalid: {exc}') from exc
        requested = {'name': name, 'profile': profile, 'risk': risk, 'reversibility': reversibility, 'fingerprint': audit['fingerprint']}
        current = {'name': existing['name'], 'profile': existing['profile'], 'risk': existing['requested_risk'], 'reversibility': existing['reversibility'], 'fingerprint': existing.get('source_fingerprint')}
        if existing.get('bootstrap_mode') != 'adopt' or current != requested:
            raise Blocked(f'controlled state differs: {current}')
        if doctor(target)['status'] != 'PASS':
            raise Blocked('existing adopted project failed doctor')
        return {'status': 'NOOP', 'operation': 'adopt', 'project_dir': str(target), 'details': {'reason': 'identical adoption state exists'}}
    plan = {'control_directory': str(control), 'profile': profile, 'assurance_level': assurance, 'requested_risk': risk, 'observed_minimum_risk': observed, 'effective_risk': effective, 'reversibility': reversibility, 'source_fingerprint': audit['fingerprint'], 'files_scanned': audit['files_scanned'], 'bytes_scanned': audit['bytes_scanned'], 'detected_technologies': audit['detected_technologies'], 'sensitive_paths_content_not_read': audit['sensitive_paths_content_not_read'], 'symlinks_not_followed': audit['symlinks_not_followed'], 'symlink_acknowledgement': audit['symlink_acknowledgement'], 'blockers': blockers, 'product_source_changes': []}
    if not apply:
        return {'status': 'PLANNED', 'operation': 'adopt', 'project_dir': str(target), 'details': plan}
    if blockers:
        raise Blocked('; '.join(blockers))
    if not os.access(target, os.W_OK):
        raise Blocked('project target is not writable')
    before_publish = scan_project(target)
    if before_publish['fingerprint'] != audit['fingerprint']:
        raise Blocked('project changed between audit and apply')
    created = now()
    record = project_record(name, profile, risk, effective, reversibility, created, mode='adopt', audit=audit)
    publish_control(target, render_records(record, created, mode='adopt', audit=audit))
    try:
        after_publish = scan_project(target)
        if after_publish['fingerprint'] != audit['fingerprint']:
            raise Blocked('project source fingerprint changed during adoption')
        if doctor(target)['status'] != 'PASS':
            raise Blocked('post-adoption doctor failed')
    except Exception:
        shutil.rmtree(control, ignore_errors=True)
        raise
    plan['manifest_digest'] = sha((control / 'manifest.json').read_bytes())
    return {'status': 'ADOPTED', 'operation': 'adopt', 'project_dir': str(target), 'details': plan}

def rollback(target: Path, *, apply: bool) -> dict[str, object]:
    target = resolved_target(target, must_exist=True)
    control = target / CONTROL
    if not control.is_dir() or control.is_symlink():
        raise Blocked('owned control directory is missing or unsafe')
    if doctor(target)['status'] != 'PASS':
        raise Blocked('rollback requires a passing doctor result')
    record = read_json_regular(safe_control_file(control, 'project.json'))
    project = record['project']
    if project.get('bootstrap_mode') != 'adopt':
        raise Blocked('this rollback slice supports adopted projects only')
    if project.get('status') != 'discovery':
        raise Blocked('accepted or advanced projects require a migration-specific rollback')
    if os.path.lexists(control / 'acceptance.json'):
        raise Blocked('acceptance marker prevents bootstrap rollback')
    rollback_record = read_json_regular(safe_control_file(control, 'rollback.json'))
    if rollback_record.get('owned_scope') != CONTROL or rollback_record.get('action') != 'remove-owned-control-directory':
        raise Blocked('rollback record does not authorize this operation')
    before = scan_project(target)
    plan = {'owned_scope': str(control), 'action': 'remove-owned-control-directory', 'source_fingerprint_before': before['fingerprint'], 'product_source_changes': []}
    if not apply:
        return {'status': 'PLANNED', 'operation': 'rollback', 'project_dir': str(target), 'details': plan}
    quarantine = target / f'{CONTROL_ROLLBACK_PREFIX}{uuid.uuid4().hex}'
    os.replace(control, quarantine)
    try:
        after_rename = scan_project(target)
        if after_rename['fingerprint'] != before['fingerprint']:
            os.replace(quarantine, control)
            raise Blocked('project source changed during rollback')
        shutil.rmtree(quarantine)
    except Exception:
        if quarantine.exists() and (not control.exists()):
            os.replace(quarantine, control)
        raise
    after = scan_project(target)
    if after['fingerprint'] != before['fingerprint']:
        raise Blocked('project source fingerprint changed after rollback')
    plan['source_fingerprint_after'] = after['fingerprint']
    return {'status': 'ROLLED_BACK', 'operation': 'rollback', 'project_dir': str(target), 'details': plan}

def selftest() -> dict[str, object]:
    with tempfile.TemporaryDirectory(prefix='ew-self-test-') as directory:
        root = Path(directory)
        initialized = root / 'initialized'
        init_args = ('EW Init Self Test', 'standard-product', 'R2', 'REV-2')
        dry = init(initialized, *init_args, dry_run=True)
        dry_no_write = not initialized.exists()
        created = init(initialized, *init_args)
        init_doctor = doctor(initialized)
        init_noop = init(initialized, *init_args)
        adopted = root / 'existing'
        adopted.mkdir()
        (adopted / 'pyproject.toml').write_text("[project]\nname='sample'\n", encoding='utf-8')
        (adopted / 'app.py').write_text("print('ok')\n", encoding='utf-8')
        source_before = scan_project(adopted)['fingerprint']
        adoption_plan = adopt(adopted, 'EW Adopt Self Test', 'standard-product', 'R2', 'REV-2', apply=False, acknowledge_sensitive_paths=False)
        plan_no_write = not (adopted / CONTROL).exists()
        adopted_result = adopt(adopted, 'EW Adopt Self Test', 'standard-product', 'R2', 'REV-2', apply=True, acknowledge_sensitive_paths=False)
        adopt_doctor = doctor(adopted)
        source_after = scan_project(adopted)['fingerprint']
        adopt_noop = adopt(adopted, 'EW Adopt Self Test', 'standard-product', 'R2', 'REV-2', apply=True, acknowledge_sensitive_paths=False)
        product = adopted / CONTROL / 'PRODUCT_DEFINITION.md'
        original = product.read_bytes()
        product.write_bytes(original + b'\ntamper\n')
        tampered = doctor(adopted)
        product.write_bytes(original)
        restored = doctor(adopted)
        rollback_plan = rollback(adopted, apply=False)
        rollback_no_write = (adopted / CONTROL).is_dir()
        rolled_back = rollback(adopted, apply=True)
        source_after_rollback = scan_project(adopted)['fingerprint']
        assertions = {'init_dry_run': dry['status'] == 'PLANNED' and dry_no_write, 'init_created': created['status'] == 'CREATED', 'init_doctor': init_doctor['status'] == 'PASS', 'init_noop': init_noop['status'] == 'NOOP', 'adopt_read_only_plan': adoption_plan['status'] == 'PLANNED' and plan_no_write, 'adopt_applied': adopted_result['status'] == 'ADOPTED', 'adopt_doctor': adopt_doctor['status'] == 'PASS', 'adopt_source_unchanged': source_before == source_after, 'adopt_noop': adopt_noop['status'] == 'NOOP', 'tamper_detected': tampered['status'] == 'FAIL', 'tamper_restored': restored['status'] == 'PASS', 'rollback_read_only_plan': rollback_plan['status'] == 'PLANNED' and rollback_no_write, 'rollback_applied': rolled_back['status'] == 'ROLLED_BACK' and (not (adopted / CONTROL).exists()), 'rollback_source_unchanged': source_before == source_after_rollback}
        if not all(assertions.values()):
            raise RuntimeError(assertions)
        return {'status': 'PASS', 'operation': 'self-test', 'project_dir': str(root), 'details': {'assertions': assertions}}
