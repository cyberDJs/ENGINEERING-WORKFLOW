"""Bounded, no-follow existing-project scanner."""
from __future__ import annotations

import os
import stat
from pathlib import Path

from ew_runtime import *

def scan_project(target: Path) -> dict[str, object]:
    target = resolved_target(target, must_exist=True)
    entries: list[dict[str, object]] = []
    symlink_records: list[dict[str, str]] = []
    special_files: list[str] = []
    sensitive_paths: list[str] = []
    scan_errors: list[str] = []
    total_bytes = 0

    def onerror(error: OSError) -> None:
        scan_errors.append(str(error))
    for current, dirnames, filenames in os.walk(target, topdown=True, followlinks=False, onerror=onerror):
        current_path = Path(current)
        retained: list[str] = []
        for dirname in sorted(dirnames):
            child = current_path / dirname
            relative = child.relative_to(target).as_posix()
            try:
                metadata = child.lstat()
            except OSError as exc:
                scan_errors.append(f'{relative}: {exc}')
                continue
            if stat.S_ISLNK(metadata.st_mode):
                symlink_records.append(symlink_record(child, relative))
                continue
            if dirname in IGNORE_DIRS or dirname.startswith(CONTROL_STAGING_PREFIX) or dirname.startswith(CONTROL_ROLLBACK_PREFIX):
                continue
            retained.append(dirname)
        dirnames[:] = retained
        for filename in sorted(filenames):
            path = current_path / filename
            relative = path.relative_to(target).as_posix()
            try:
                metadata = path.lstat()
            except OSError as exc:
                scan_errors.append(f'{relative}: {exc}')
                continue
            if stat.S_ISLNK(metadata.st_mode):
                symlink_records.append(symlink_record(path, relative))
                continue
            if not stat.S_ISREG(metadata.st_mode):
                special_files.append(relative)
                continue
            if len(entries) + 1 > MAX_SCAN_FILES:
                raise Blocked(f'audit exceeds file limit {MAX_SCAN_FILES}')
            if metadata.st_size > MAX_SCAN_BYTES - total_bytes:
                raise Blocked(f'audit exceeds byte limit {MAX_SCAN_BYTES}')
            sensitive = is_sensitive_path(relative)
            digest: str | None = None
            stable_metadata = metadata
            if sensitive:
                sensitive_paths.append(relative)
            else:
                digest, stable_metadata = sha_file(path, expected=metadata, max_bytes=MAX_SCAN_BYTES - total_bytes)
            total_bytes += int(stable_metadata.st_size)
            entries.append({'path': relative, 'size': int(stable_metadata.st_size), 'mode': stat.S_IMODE(stable_metadata.st_mode), 'mtime_ns': int(stable_metadata.st_mtime_ns), 'sha256': digest, 'content_read': not sensitive})
    if scan_errors:
        raise Blocked('project audit could not read all paths: ' + '; '.join(scan_errors[:5]))
    if special_files:
        raise Blocked('project contains unsupported special files: ' + ', '.join(special_files[:5]))
    if not entries and (not symlink_records):
        raise Blocked('existing project is empty; use ew init instead')
    paths = {str(item['path']) for item in entries}
    technologies = detect_technologies(paths)
    observed_risk = 'R3' if {'terraform', 'kubernetes'} & set(technologies) or sensitive_paths or symlink_records else 'R2'
    recommended_profile = 'production-service' if observed_risk == 'R3' else 'standard-product'
    fingerprint = sha(canon({'inventory': entries, 'symlinks': symlink_records}))
    findings: list[dict[str, object]] = []
    if symlink_records:
        findings.append({'id': 'symlink-paths', 'severity': 'high', 'count': len(symlink_records)})
    if sensitive_paths:
        findings.append({'id': 'sensitive-path-indicators', 'severity': 'high', 'count': len(sensitive_paths)})
    return {'schema_version': CONTROL_SCHEMA_VERSION, 'type': 'ew-adoption-audit', 'status': 'VERIFIED', 'project_dir': str(target), 'fingerprint': fingerprint, 'files_scanned': len(entries), 'bytes_scanned': total_bytes, 'limits': {'max_files': MAX_SCAN_FILES, 'max_bytes': MAX_SCAN_BYTES}, 'ignored_directories': sorted(IGNORE_DIRS), 'inventory': entries, 'symlinks_not_followed': [item['path'] for item in symlink_records], 'symlink_records': symlink_records, 'symlink_acknowledgement': {'acknowledged': False, 'rationale': None, 'rationale_sha256': None}, 'sensitive_paths_content_not_read': sorted(sensitive_paths), 'detected_technologies': technologies, 'observed_minimum_risk': observed_risk, 'recommended_profile': recommended_profile, 'findings': findings, 'git_history_is_authoritative': False}
