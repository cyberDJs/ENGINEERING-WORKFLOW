"""Shared runtime contract for hardened EW CLI modules."""
from __future__ import annotations

import os
from pathlib import Path

import ew_core as core
import ew_fs as fs

CLI_VERSION = "0.3.0"
CONTROL_SCHEMA_VERSION = "0.3.0"
SUPPORTED_CONTROL_VERSIONS = {"0.1.0", "0.2.0", CONTROL_SCHEMA_VERSION}
CONTROL = core.CONTROL
CONTROL_STAGING_PREFIX = f"{CONTROL}.staging-"
CONTROL_ROLLBACK_PREFIX = f"{CONTROL}.rollback-"
MAX_SCAN_FILES = core.MAX_SCAN_FILES
MAX_SCAN_BYTES = core.MAX_SCAN_BYTES
IGNORE_DIRS = core.IGNORE_DIRS
RISKS = core.RISKS
REV_MIN = core.REV_MIN
PROFILES = core.PROFILES
SAFE_NAME = core.SAFE_NAME
SAFE_HASH = core.SAFE_HASH
SUCCESS = core.SUCCESS
Blocked = core.Blocked
canon = core.canon
sha = core.sha
now = core.now
slug = core.slug
emit = core.emit
highest_risk = core.highest_risk
selection = core.selection
resolved_target = core.resolved_target
is_sensitive_path = core.is_sensitive_path
detect_technologies = core.detect_technologies


def read_stable_file(path: Path, *, expected: os.stat_result | None = None, max_bytes: int = fs.MAX_CONTROL_FILE_BYTES):
    try:
        return fs.read_stable_file(path, expected=expected, max_bytes=max_bytes)
    except fs.SafeFileError as exc:
        raise Blocked(str(exc)) from exc


def sha_file(path: Path, *, expected: os.stat_result | None = None, max_bytes: int = fs.MAX_CONTROL_FILE_BYTES):
    try:
        return fs.sha_file(path, expected=expected, max_bytes=max_bytes)
    except fs.SafeFileError as exc:
        raise Blocked(str(exc)) from exc


def read_json_regular(path: Path) -> dict[str, object]:
    try:
        return fs.read_json_regular(path)
    except fs.SafeFileError as exc:
        raise Blocked(str(exc)) from exc


def symlink_record(path: Path, relative: str) -> dict[str, str]:
    try:
        return fs.symlink_record(path, relative)
    except fs.SafeFileError as exc:
        raise Blocked(str(exc)) from exc
