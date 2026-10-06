"""Fail-closed validation of an EW-controlled project."""
from __future__ import annotations

import os
import stat
from pathlib import Path

from ew_runtime import *

def _failed_doctor(target: Path, mode: str, checks: list[dict[str, object]]) -> dict[str, object]:
    return {'status': 'FAIL', 'operation': 'doctor', 'project_dir': str(target), 'details': {'bootstrap_mode': mode, 'control_plane_ready': False, 'project_ready': False, 'readiness_reason': 'control records failed validation', 'checks': checks}}

def _control_inventory(control: Path) -> tuple[set[str], list[str], list[str]]:
    files: set[str] = set()
    links: list[str] = []
    special: list[str] = []
    for current, dirnames, filenames in os.walk(control, topdown=True, followlinks=False):
        current_path = Path(current)
        kept: list[str] = []
        for dirname in sorted(dirnames):
            child = current_path / dirname
            relative = child.relative_to(control).as_posix()
            metadata = child.lstat()
            if stat.S_ISLNK(metadata.st_mode):
                links.append(relative)
            elif stat.S_ISDIR(metadata.st_mode):
                kept.append(dirname)
            else:
                special.append(relative)
        dirnames[:] = kept
        for filename in sorted(filenames):
            child = current_path / filename
            relative = child.relative_to(control).as_posix()
            metadata = child.lstat()
            if stat.S_ISLNK(metadata.st_mode):
                links.append(relative)
            elif stat.S_ISREG(metadata.st_mode):
                files.add(relative)
            else:
                special.append(relative)
    return (files, links, special)

def safe_control_file(control: Path, relative: str) -> Path:
    candidate = Path(relative)
    if candidate.is_absolute() or '..' in candidate.parts or (not candidate.parts):
        raise Blocked(f'unsafe manifest path: {relative!r}')
    current = control
    for index, part in enumerate(candidate.parts):
        current = current / part
        metadata = current.lstat()
        if stat.S_ISLNK(metadata.st_mode):
            raise Blocked(f'control path contains symlink: {relative!r}')
        final = index == len(candidate.parts) - 1
        if final and (not stat.S_ISREG(metadata.st_mode)):
            raise Blocked(f'control path is not a regular file: {relative!r}')
        if not final and (not stat.S_ISDIR(metadata.st_mode)):
            raise Blocked(f'control path parent is not a directory: {relative!r}')
    return current

def doctor(target: Path) -> dict[str, object]:
    target = resolved_target(target, must_exist=False)
    control = target / CONTROL
    checks: list[dict[str, object]] = []

    def check(name: str, passed: bool, detail: object) -> None:
        checks.append({'name': name, 'passed': bool(passed), 'detail': str(detail)})
    check('python-version', tuple(os.sys.version_info[:2]) >= (3, 11), os.sys.version.split()[0])
    project_safe = target.is_dir() and (not target.is_symlink())
    check('project-directory', project_safe, target)
    control_exists = os.path.lexists(control)
    control_safe = project_safe and control_exists and (not control.is_symlink()) and control.is_dir()
    check('control-directory', control_safe, control)
    if not control_safe:
        check('content-read-boundary', False, 'stopped before reading unsafe control directory')
        return _failed_doctor(target, 'unknown', checks)
    try:
        actual, links, special = _control_inventory(control)
        check('no-symlinks', not links, links or 'none')
        check('regular-files-only', not special, special or 'none')
    except Exception as exc:
        check('control-inventory', False, exc)
        return _failed_doctor(target, 'unknown', checks)
    if links or special:
        check('content-read-boundary', False, 'stopped before reading unsafe control contents')
        return _failed_doctor(target, 'unknown', checks)
    record: dict[str, object] = {}
    project: dict[str, object] = {}
    mode = 'init'
    try:
        record = read_json_regular(safe_control_file(control, 'project.json'))
        project = record['project']
        assert isinstance(project, dict)
        mode = str(project.get('bootstrap_mode', 'init'))
        check('project-json', True, f'mode={mode}')
    except Exception as exc:
        check('project-json', False, exc)
    required = {'project.json', 'PRODUCT_DEFINITION.md', 'WORK_PACKAGE.md', 'DECISION_REGISTER.md', 'lifecycle.json', 'manifest.json'}
    required.add('evidence/init.json' if mode == 'init' else 'evidence/adopt.json')
    if mode == 'adopt':
        required.update({'ADOPTION_PLAN.md', 'evidence/adoption-audit.json', 'snapshots/pre-adoption.json', 'rollback.json'})
    missing = sorted((item for item in required if item not in actual))
    check('required-records', not missing, missing or 'all present')
    try:
        manifest = read_json_regular(safe_control_file(control, 'manifest.json'))
        check('manifest-json', True, 'valid')
    except Exception as exc:
        manifest = {}
        check('manifest-json', False, exc)
    declared = manifest.get('files', {})
    integrity_errors: list[str] = []
    if not isinstance(declared, dict):
        declared = {}
        integrity_errors.append('files:not-object')
    if manifest.get('content_digest') != sha(canon(declared)):
        integrity_errors.append('content-digest:mismatch')
    for relative, expected in declared.items():
        if not isinstance(relative, str):
            integrity_errors.append('path:not-string')
            continue
        try:
            path = safe_control_file(control, relative)
        except (Blocked, OSError) as exc:
            integrity_errors.append(str(exc))
            continue
        if not isinstance(expected, str) or not SAFE_HASH.fullmatch(expected):
            integrity_errors.append(f'{relative}:invalid-hash')
            continue
        try:
            actual_hash, _ = sha_file(path)
        except Blocked as exc:
            integrity_errors.append(str(exc))
            continue
        if actual_hash != expected:
            integrity_errors.append(f'{relative}:hash-mismatch')
    undeclared = actual - set(declared) - {'manifest.json'}
    if undeclared:
        integrity_errors.append('undeclared:' + ','.join(sorted(undeclared)))
    check('manifest-integrity', bool(declared) and (not integrity_errors), integrity_errors or f'{len(declared)} files')
    try:
        requested = str(project['requested_risk'])
        observed = str(project.get('observed_minimum_risk', 'R0'))
        _, effective = selection(str(project['profile']), requested, str(project['reversibility']), observed)
        schema_ok = str(record['schema_version']) in SUPPORTED_CONTROL_VERSIONS
        check('project-selection', effective == project['effective_risk'] and schema_ok and (mode in {'init', 'adopt'}), f"{project['profile']} {project['effective_risk']} {project['reversibility']} mode={mode}")
    except Exception as exc:
        check('project-selection', False, exc)
    try:
        graph = read_json_regular(safe_control_file(control, 'lifecycle.json'))
        identities = [node['id'] for node in graph['nodes']]
        references = {value for edge in graph['edges'] for value in (edge['from'], edge['to'])}
        graph_ok = len(identities) == len(set(identities)) and references <= set(identities) and (graph['git_history_is_authoritative'] is False)
        check('lifecycle-graph', graph_ok, f"nodes={len(identities)} edges={len(graph['edges'])}")
    except Exception as exc:
        check('lifecycle-graph', False, exc)
    if mode == 'adopt':
        try:
            audit = read_json_regular(safe_control_file(control, 'evidence/adoption-audit.json'))
            snapshot = read_json_regular(safe_control_file(control, 'snapshots/pre-adoption.json'))
            receipt = read_json_regular(safe_control_file(control, 'evidence/adopt.json'))
            rollback_record = read_json_regular(safe_control_file(control, 'rollback.json'))
            fingerprint = str(project['source_fingerprint'])
            claims = receipt['claims']
            acknowledgement = audit['symlink_acknowledgement']
            symlinks = audit['symlink_records']
            symlink_ok = not symlinks or (acknowledgement['acknowledged'] is True and isinstance(acknowledgement['rationale'], str) and (len(acknowledgement['rationale'].strip()) >= 20) and (acknowledgement['rationale_sha256'] == sha(acknowledgement['rationale'].strip().encode())) and (audit['observed_minimum_risk'] == 'R3') and (project['effective_risk'] == 'R3'))
            adoption_ok = audit['fingerprint'] == fingerprint and snapshot['fingerprint'] == fingerprint and (snapshot['symlink_records'] == symlinks) and (snapshot['symlink_acknowledgement'] == acknowledgement) and (project.get('symlink_policy_digest') == sha(canon(acknowledgement))) and (claims['pre_fingerprint'] == fingerprint) and (claims['post_fingerprint'] == fingerprint) and (claims['product_source_modified'] is False) and (rollback_record['owned_scope'] == CONTROL) and (rollback_record['action'] == 'remove-owned-control-directory') and symlink_ok
            check('adoption-evidence', adoption_ok, fingerprint)
        except Exception as exc:
            check('adoption-evidence', False, exc)
    passed = all((bool(item['passed']) for item in checks))
    return {'status': 'PASS' if passed else 'FAIL', 'operation': 'doctor', 'project_dir': str(target), 'details': {'bootstrap_mode': mode, 'control_plane_ready': passed, 'project_ready': False, 'readiness_reason': 'product definition and authorities remain PROPOSED' if passed else 'control records failed validation', 'checks': checks}}
