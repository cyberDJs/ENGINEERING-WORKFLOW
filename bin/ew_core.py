#!/usr/bin/env python3
"""Dependency-free ENGINEERING-WORKFLOW bootstrap and adoption CLI."""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import shutil
import stat
import tempfile
import uuid
from datetime import datetime, timezone
from pathlib import Path

CLI_VERSION = "0.2.0"
CONTROL_SCHEMA_VERSION = "0.2.0"
SUPPORTED_CONTROL_VERSIONS = {"0.1.0", CONTROL_SCHEMA_VERSION}
CONTROL = ".engineering-workflow"
MAX_SCAN_FILES = 10_000
MAX_SCAN_BYTES = 256 * 1024 * 1024
IGNORE_DIRS = {
    ".git", ".hg", ".svn", CONTROL, "node_modules", ".venv", "venv", "dist", "build",
    ".next", ".nuxt", ".cache", ".pytest_cache", ".mypy_cache", ".ruff_cache", "__pycache__",
    "target", "coverage", ".terraform",
}
RISKS = {"R0": 0, "R1": 1, "R2": 2, "R3": 3}
REV_MIN = {"REV-0": "R0", "REV-1": "R1", "REV-2": "R2", "REV-3": "R3", "REV-4": "R3"}
PROFILES = {
    "experiment": ("A1-professional-foundation", "R1"),
    "internal-tool": ("A2-controlled-engineering", "R2"),
    "standard-product": ("A3-high-assurance-product", "R2"),
    "production-service": ("A4-production-assurance", "R3"),
    "security-critical": ("A5-critical-trust", "R3"),
}
SAFE_NAME = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._ -]{0,127}$")
SAFE_HASH = re.compile(r"^[0-9a-f]{64}$")
SENSITIVE_NAMES = {".env", "id_rsa", "id_dsa", "id_ecdsa", "id_ed25519"}
SENSITIVE_SUFFIXES = {".pem", ".key", ".p12", ".pfx"}
SUCCESS = {"PASS", "PLANNED", "CREATED", "ADOPTED", "NOOP", "ROLLED_BACK"}


class Blocked(RuntimeError):
    """Operation must stop without changing controlled state."""


def canon(value: object) -> bytes:
    return (json.dumps(value, indent=2, sort_keys=True, ensure_ascii=False) + "\n").encode()


def sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def sha_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def slug(value: str) -> str:
    result = re.sub(r"[^a-z0-9]+", "-", value.lower()).strip("-")[:80]
    if not result:
        raise Blocked("project name does not produce a safe identifier")
    return result


def emit(value: dict[str, object], as_json: bool) -> None:
    if as_json:
        print(json.dumps(value, indent=2, sort_keys=True))
        return
    for key, item in value.items():
        rendered = json.dumps(item, sort_keys=True) if isinstance(item, (dict, list)) else item
        print(f"{key.upper()}={rendered}")


def highest_risk(*values: str) -> str:
    for value in values:
        if value not in RISKS:
            raise Blocked(f"invalid risk: {value!r}")
    return max(values, key=RISKS.get)


def selection(profile: str, risk: str, reversibility: str, observed_risk: str = "R0") -> tuple[str, str]:
    if profile not in PROFILES or risk not in RISKS or reversibility not in REV_MIN:
        raise Blocked("invalid profile, risk or reversibility")
    effective = highest_risk(risk, REV_MIN[reversibility], observed_risk)
    assurance, maximum = PROFILES[profile]
    if RISKS[effective] > RISKS[maximum]:
        raise Blocked(
            f"{profile} permits {maximum}, but observed/reversibility requirements require {effective}; "
            "choose a stronger profile"
        )
    return assurance, effective


def resolved_target(target: Path, *, must_exist: bool) -> Path:
    expanded = target.expanduser()
    if expanded.exists() and expanded.is_symlink():
        raise Blocked("project directory may not be a symlink")
    resolved = expanded.resolve(strict=False)
    if must_exist and (not resolved.is_dir() or resolved.is_symlink()):
        raise Blocked("existing project directory is required")
    return resolved


def safe_path(root: Path, relative: str) -> Path:
    candidate = Path(relative)
    if candidate.is_absolute() or ".." in candidate.parts:
        raise Blocked(f"unsafe manifest path: {relative!r}")
    output = (root / candidate).resolve(strict=False)
    try:
        output.relative_to(root.resolve())
    except ValueError as exc:
        raise Blocked(f"manifest path escapes control directory: {relative!r}") from exc
    return output


def is_sensitive_path(relative: str) -> bool:
    path = Path(relative)
    name = path.name.lower()
    if name in SENSITIVE_NAMES or any(name.startswith(f"{item}.") for item in SENSITIVE_NAMES):
        return not name.endswith((".example", ".sample", ".template"))
    return path.suffix.lower() in SENSITIVE_SUFFIXES


def detect_technologies(paths: set[str]) -> list[str]:
    technologies: set[str] = set()
    names = {Path(item).name for item in paths}
    if names & {"pyproject.toml", "requirements.txt", "setup.py", "Pipfile"}:
        technologies.add("python")
    if "package.json" in names:
        technologies.add("nodejs")
    if names & {"Dockerfile", "docker-compose.yml", "docker-compose.yaml", "compose.yml", "compose.yaml"}:
        technologies.add("containers")
    if any(item.endswith(".tf") for item in paths):
        technologies.add("terraform")
    if any(item.startswith(("k8s/", "kubernetes/", "helm/", "charts/")) for item in paths):
        technologies.add("kubernetes")
    if any(item.startswith(".github/workflows/") for item in paths):
        technologies.add("github-actions")
    if ".gitlab-ci.yml" in paths:
        technologies.add("gitlab-ci")
    if "go.mod" in names:
        technologies.add("go")
    if "Cargo.toml" in names:
        technologies.add("rust")
    if names & {"pom.xml", "build.gradle", "build.gradle.kts"}:
        technologies.add("jvm")
    return sorted(technologies)


def scan_project(target: Path) -> dict[str, object]:
    target = resolved_target(target, must_exist=True)
    entries: list[dict[str, object]] = []
    symlinks: list[str] = []
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
            if child.is_symlink():
                symlinks.append(relative)
                continue
            if dirname in IGNORE_DIRS or dirname.startswith(f".{CONTROL}.staging-") or dirname.startswith(f".{CONTROL}.rollback-"):
                continue
            retained.append(dirname)
        dirnames[:] = retained

        for filename in sorted(filenames):
            path = current_path / filename
            relative = path.relative_to(target).as_posix()
            try:
                metadata = path.lstat()
            except OSError as exc:
                scan_errors.append(f"{relative}: {exc}")
                continue
            if stat.S_ISLNK(metadata.st_mode):
                symlinks.append(relative)
                continue
            if not stat.S_ISREG(metadata.st_mode):
                special_files.append(relative)
                continue
            if len(entries) + 1 > MAX_SCAN_FILES:
                raise Blocked(f"audit exceeds file limit {MAX_SCAN_FILES}")
            total_bytes += metadata.st_size
            if total_bytes > MAX_SCAN_BYTES:
                raise Blocked(f"audit exceeds byte limit {MAX_SCAN_BYTES}")
            sensitive = is_sensitive_path(relative)
            if sensitive:
                sensitive_paths.append(relative)
            entries.append(
                {
                    "path": relative,
                    "size": metadata.st_size,
                    "mode": stat.S_IMODE(metadata.st_mode),
                    "mtime_ns": metadata.st_mtime_ns,
                    "sha256": None if sensitive else sha_file(path),
                    "content_read": not sensitive,
                }
            )

    if scan_errors:
        raise Blocked("project audit could not read all paths: " + "; ".join(scan_errors[:5]))
    if special_files:
        raise Blocked("project contains unsupported special files: " + ", ".join(special_files[:5]))
    if not entries:
        raise Blocked("existing project is empty; use ew init instead")

    paths = {str(item["path"]) for item in entries}
    technologies = detect_technologies(paths)
    observed_risk = "R3" if ({"terraform", "kubernetes"} & set(technologies) or sensitive_paths) else "R2"
    recommended_profile = "production-service" if observed_risk == "R3" else "standard-product"
    fingerprint = sha(canon(entries))
    findings: list[dict[str, object]] = []
    if symlinks:
        findings.append({"id": "symlink-paths", "severity": "review", "count": len(symlinks)})
    if sensitive_paths:
        findings.append({"id": "sensitive-path-indicators", "severity": "high", "count": len(sensitive_paths)})
    return {
        "schema_version": CONTROL_SCHEMA_VERSION,
        "type": "ew-adoption-audit",
        "status": "VERIFIED",
        "project_dir": str(target),
        "fingerprint": fingerprint,
        "files_scanned": len(entries),
        "bytes_scanned": total_bytes,
        "limits": {"max_files": MAX_SCAN_FILES, "max_bytes": MAX_SCAN_BYTES},
        "ignored_directories": sorted(IGNORE_DIRS),
        "inventory": entries,
        "symlinks_not_followed": sorted(symlinks),
        "sensitive_paths_content_not_read": sorted(sensitive_paths),
        "detected_technologies": technologies,
        "observed_minimum_risk": observed_risk,
        "recommended_profile": recommended_profile,
        "findings": findings,
        "git_history_is_authoritative": False,
    }


def project_record(name: str, profile: str, risk: str, effective: str, reversibility: str, created: str, *, mode: str, audit: dict[str, object] | None = None) -> dict[str, object]:
    assurance, _ = PROFILES[profile]
    project: dict[str, object] = {
        "id": slug(name), "name": name, "status": "discovery", "bootstrap_mode": mode,
        "profile": profile, "assurance_level": assurance, "requested_risk": risk,
        "effective_risk": effective, "reversibility": reversibility, "created_at": created,
    }
    if audit is not None:
        project.update({"source_fingerprint": audit["fingerprint"], "observed_minimum_risk": audit["observed_minimum_risk"], "detected_technologies": audit["detected_technologies"]})
    return {
        "$schema": "https://github.com/nulleimy/ENGINEERING-WORKFLOW/schemas/ew-project.schema.json",
        "schema_version": CONTROL_SCHEMA_VERSION,
        "project": project,
        "governance": {
            "primary_invariant": ["simple", "purposeful", "automated", "secure", "measurable", "reversible", "evidence-verifiable"],
            "protected_operation_authority": "explicit-operator-authorization-required",
            "git_required": False,
            "owned_scope": CONTROL,
        },
    }


def render_records(record: dict[str, object], created: str, *, mode: str, audit: dict[str, object] | None = None) -> dict[str, bytes]:
    project = record["project"]
    assert isinstance(project, dict)
    project_id = str(project["id"])
    files: dict[str, bytes] = {
        "project.json": canon(record),
        "PRODUCT_DEFINITION.md": f"""# Product Definition
- Record ID: `PD-{project_id}-001`
- Status: `PROPOSED`
- Product Authority: `UNASSIGNED`
- Engineering Authority: `UNASSIGNED`
- Target user: `TO_BE_DEFINED`
- Problem: `TO_BE_DEFINED`
- Primary value: `TO_BE_DEFINED`
- Success metrics: `TO_BE_DEFINED`
- Boundaries and non-goals: `TO_BE_DEFINED`
- Security/data classification: `TO_BE_CLASSIFIED`
- Operational profile: `{project['profile']}`
""".encode(),
        "WORK_PACKAGE.md": f"""# Work Package
- ID: `WP-{project_id}-{mode}-001`
- Mode: `DISCOVER`
- Risk: `{project['effective_risk']}`
- Reversibility: `{project['reversibility']}`
- Owner/Authority: `UNASSIGNED`
- Target: accept product definition, authorities and first vertical slice.
- Allowed scope: `.engineering-workflow/`
- Prohibited scope: product code, secrets, Git history and production.
- Verify: `ew doctor .`
- Recovery: `ew rollback .` before acceptance when bootstrap mode is adopt.
- Status: `PROPOSED`
""".encode(),
        "DECISION_REGISTER.md": f"""# Decision Register
| ID | Class | Status | Decision |
|---|---|---|---|
| `DR-{project_id}-001` | D2 | PROPOSED | Use `{project['profile']}`, `{project['effective_risk']}`, `{project['reversibility']}` through `{mode}`. |
""".encode(),
        "lifecycle.json": canon({
            "schema_version": CONTROL_SCHEMA_VERSION, "project_id": project_id, "created_at": created,
            "nodes": [
                {"id": f"problem:{project_id}:001", "type": "product-problem", "status": "PROPOSED"},
                {"id": f"decision:{project_id}:001", "type": "decision", "status": "PROPOSED"},
                {"id": f"work:{project_id}:001", "type": "work-package", "status": "IMPLEMENTED"},
                {"id": f"evidence:{project_id}:001", "type": "evidence", "status": "VERIFIED"},
            ],
            "edges": [
                {"from": f"problem:{project_id}:001", "to": f"decision:{project_id}:001", "relation": "informs"},
                {"from": f"decision:{project_id}:001", "to": f"work:{project_id}:001", "relation": "authorizes"},
                {"from": f"work:{project_id}:001", "to": f"evidence:{project_id}:001", "relation": "produces"},
            ],
            "git_history_is_authoritative": False,
        }),
    }
    if mode == "init":
        files["evidence/init.json"] = canon({
            "schema_version": CONTROL_SCHEMA_VERSION, "type": "ew-init", "status": "VERIFIED",
            "created_at": created, "project_id": project_id,
            "claims": {"controlled_records_generated": True, "product_ready": False, "release_ready": False, "operational_ready": False},
        })
    elif mode == "adopt" and audit is not None:
        fingerprint = str(audit["fingerprint"])
        files["ADOPTION_PLAN.md"] = f"""# Adoption Plan
- Status: `PROPOSED`
- Project: `{project['name']}`
- Detected technologies: `{', '.join(audit['detected_technologies']) or 'none'}`
- Observed minimum risk: `{audit['observed_minimum_risk']}`
- Selected profile: `{project['profile']}`
- Source fingerprint: `{fingerprint}`
- Product source changes performed by adoption: `NONE`
- Next action: assign authorities, complete Product Definition and authorize the first vertical slice.
""".encode()
        files["evidence/adoption-audit.json"] = canon(audit)
        files["snapshots/pre-adoption.json"] = canon({
            "schema_version": CONTROL_SCHEMA_VERSION, "type": "pre-adoption-snapshot", "status": "VERIFIED",
            "created_at": created, "project_id": project_id, "fingerprint": fingerprint,
            "inventory": audit["inventory"], "sensitive_paths_content_not_read": audit["sensitive_paths_content_not_read"],
        })
        files["evidence/adopt.json"] = canon({
            "schema_version": CONTROL_SCHEMA_VERSION, "type": "ew-adopt", "status": "VERIFIED",
            "created_at": created, "project_id": project_id,
            "claims": {"audit_was_read_only": True, "product_source_modified": False, "pre_fingerprint": fingerprint, "post_fingerprint": fingerprint, "control_plane_ready": True, "product_ready": False, "release_ready": False, "operational_ready": False},
        })
        files["rollback.json"] = canon({
            "schema_version": CONTROL_SCHEMA_VERSION, "type": "bootstrap-rollback", "status": "AVAILABLE",
            "created_at": created, "project_id": project_id, "owned_scope": CONTROL,
            "action": "remove-owned-control-directory", "precondition": "project-status-discovery-and-manifest-integrity-pass",
            "acceptance_marker_must_be_absent": True,
        })
    else:
        raise Blocked(f"unsupported render mode: {mode}")

    hashes = {name: sha(content) for name, content in sorted(files.items())}
    files["manifest.json"] = canon({
        "schema_version": CONTROL_SCHEMA_VERSION, "project_id": project_id, "generator": "ew",
        "generator_version": CLI_VERSION, "bootstrap_mode": mode, "files": hashes,
        "content_digest": sha(canon(hashes)),
    })
    return files


def doctor(target: Path) -> dict[str, object]:
    target = resolved_target(target, must_exist=False)
    control = target / CONTROL
    checks: list[dict[str, object]] = []
    def check(name: str, passed: bool, detail: object) -> None:
        checks.append({"name": name, "passed": bool(passed), "detail": str(detail)})

    check("python-version", tuple(os.sys.version_info[:2]) >= (3, 11), os.sys.version.split()[0])
    check("project-directory", target.is_dir() and not target.is_symlink(), target)
    check("control-directory", control.is_dir() and not control.is_symlink(), control)
    record: dict[str, object] = {}
    project: dict[str, object] = {}
    mode = "init"
    try:
        record = json.loads((control / "project.json").read_text(encoding="utf-8"))
        project = record["project"]
        assert isinstance(project, dict)
        mode = str(project.get("bootstrap_mode", "init"))
        check("project-json", True, f"mode={mode}")
    except Exception as exc:
        check("project-json", False, exc)

    required = {"project.json", "PRODUCT_DEFINITION.md", "WORK_PACKAGE.md", "DECISION_REGISTER.md", "lifecycle.json", "manifest.json"}
    required.add("evidence/init.json" if mode == "init" else "evidence/adopt.json")
    if mode == "adopt":
        required.update({"ADOPTION_PLAN.md", "evidence/adoption-audit.json", "snapshots/pre-adoption.json", "rollback.json"})
    if control.is_dir():
        links = [str(item.relative_to(control)) for item in control.rglob("*") if item.is_symlink()]
        check("no-symlinks", not links, links or "none")
        missing = sorted(item for item in required if not (control / item).is_file())
        check("required-records", not missing, missing or "all present")
    else:
        check("no-symlinks", False, "control directory missing")
        check("required-records", False, "control directory missing")

    try:
        manifest = json.loads((control / "manifest.json").read_text(encoding="utf-8"))
        check("manifest-json", True, "valid")
    except Exception as exc:
        manifest = {}
        check("manifest-json", False, exc)
    declared = manifest.get("files", {})
    integrity_errors: list[str] = []
    if not isinstance(declared, dict):
        declared = {}
        integrity_errors.append("files:not-object")
    if manifest.get("content_digest") != sha(canon(declared)):
        integrity_errors.append("content-digest:mismatch")
    for relative, expected in declared.items():
        try:
            path = safe_path(control, relative)
        except Blocked as exc:
            integrity_errors.append(str(exc))
            continue
        if not isinstance(expected, str) or not SAFE_HASH.fullmatch(expected):
            integrity_errors.append(f"{relative}:invalid-hash")
        elif not path.is_file():
            integrity_errors.append(f"{relative}:missing")
        elif sha(path.read_bytes()) != expected:
            integrity_errors.append(f"{relative}:hash-mismatch")
    actual = {str(item.relative_to(control)) for item in control.rglob("*") if item.is_file() and item.name != "manifest.json"} if control.is_dir() else set()
    undeclared = actual - set(declared)
    if undeclared:
        integrity_errors.append("undeclared:" + ",".join(sorted(undeclared)))
    check("manifest-integrity", bool(declared) and not integrity_errors, integrity_errors or f"{len(declared)} files")

    try:
        requested = str(project["requested_risk"])
        observed = str(project.get("observed_minimum_risk", "R0"))
        _, effective = selection(str(project["profile"]), requested, str(project["reversibility"]), observed)
        schema_ok = str(record["schema_version"]) in SUPPORTED_CONTROL_VERSIONS
        check("project-selection", effective == project["effective_risk"] and schema_ok and mode in {"init", "adopt"}, f"{project['profile']} {project['effective_risk']} {project['reversibility']} mode={mode}")
    except Exception as exc:
        check("project-selection", False, exc)

    try:
        graph = json.loads((control / "lifecycle.json").read_text(encoding="utf-8"))
        identities = [node["id"] for node in graph["nodes"]]
        references = {value for edge in graph["edges"] for value in (edge["from"], edge["to"])}
        graph_ok = len(identities) == len(set(identities)) and references <= set(identities) and graph["git_history_is_authoritative"] is False
        check("lifecycle-graph", graph_ok, f"nodes={len(identities)} edges={len(graph['edges'])}")
    except Exception as exc:
        check("lifecycle-graph", False, exc)

    if mode == "adopt":
        try:
            audit = json.loads((control / "evidence/adoption-audit.json").read_text(encoding="utf-8"))
            snapshot = json.loads((control / "snapshots/pre-adoption.json").read_text(encoding="utf-8"))
            receipt = json.loads((control / "evidence/adopt.json").read_text(encoding="utf-8"))
            rollback_record = json.loads((control / "rollback.json").read_text(encoding="utf-8"))
            fingerprint = str(project["source_fingerprint"])
            claims = receipt["claims"]
            adoption_ok = audit["fingerprint"] == fingerprint and snapshot["fingerprint"] == fingerprint and claims["pre_fingerprint"] == fingerprint and claims["post_fingerprint"] == fingerprint and claims["product_source_modified"] is False and rollback_record["owned_scope"] == CONTROL and rollback_record["action"] == "remove-owned-control-directory"
            check("adoption-evidence", adoption_ok, fingerprint)
        except Exception as exc:
            check("adoption-evidence", False, exc)

    passed = all(bool(item["passed"]) for item in checks)
    return {
        "status": "PASS" if passed else "FAIL", "operation": "doctor", "project_dir": str(target),
        "details": {"bootstrap_mode": mode, "control_plane_ready": passed, "project_ready": False,
        "readiness_reason": "product definition and authorities remain PROPOSED" if passed else "control records failed validation",
        "checks": checks},
    }


def publish_control(target: Path, files: dict[str, bytes]) -> Path:
    control = target / CONTROL
    stage: Path | None = None
    try:
        stage = Path(tempfile.mkdtemp(prefix=f".{CONTROL}.staging-", dir=target))
        for relative, content in files.items():
            output = stage / relative
            output.parent.mkdir(parents=True, exist_ok=True)
            output.write_bytes(content)
        if any(item.is_symlink() for item in stage.rglob("*")):
            raise Blocked("generated state contains symlink")
        if control.exists():
            raise Blocked("controlled state appeared during write")
        os.replace(stage, control)
        stage = None
        return control
    except Exception:
        if stage is not None:
            shutil.rmtree(stage, ignore_errors=True)
        raise


def init(target: Path, name: str, profile: str, risk: str, reversibility: str, dry_run: bool = False) -> dict[str, object]:
    if not SAFE_NAME.fullmatch(name):
        raise Blocked("unsafe project name")
    assurance, effective = selection(profile, risk, reversibility)
    target = resolved_target(target, must_exist=False)
    control = target / CONTROL
    if control.exists():
        try:
            existing = json.loads((control / "project.json").read_text(encoding="utf-8"))["project"]
            requested = {"name": name, "profile": profile, "risk": risk, "reversibility": reversibility}
            current = {"name": existing["name"], "profile": existing["profile"], "risk": existing["requested_risk"], "reversibility": existing["reversibility"]}
        except Exception as exc:
            raise Blocked(f"existing control state is invalid: {exc}") from exc
        if current != requested or existing.get("bootstrap_mode", "init") != "init":
            raise Blocked(f"controlled state differs: {current}")
        if doctor(target)["status"] != "PASS":
            raise Blocked("existing controlled project failed doctor")
        return {"status": "NOOP", "operation": "init", "project_dir": str(target), "details": {"reason": "identical controlled state exists"}}
    plan = {"control_directory": str(control), "profile": profile, "assurance_level": assurance, "requested_risk": risk, "effective_risk": effective, "reversibility": reversibility}
    if dry_run:
        return {"status": "PLANNED", "operation": "init", "project_dir": str(target), "details": plan}
    target_created = False
    try:
        if not target.exists():
            target.mkdir(parents=True)
            target_created = True
        if not target.is_dir() or not os.access(target, os.W_OK):
            raise Blocked("project target is not a writable directory")
        created = now()
        record = project_record(name, profile, risk, effective, reversibility, created, mode="init")
        publish_control(target, render_records(record, created, mode="init"))
        if doctor(target)["status"] != "PASS":
            shutil.rmtree(control, ignore_errors=True)
            raise Blocked("post-write doctor failed")
        plan["manifest_digest"] = sha((control / "manifest.json").read_bytes())
        return {"status": "CREATED", "operation": "init", "project_dir": str(target), "details": plan}
    except Exception:
        if target_created and target.exists() and not any(target.iterdir()):
            target.rmdir()
        raise


def adopt(target: Path, name: str, profile: str, risk: str, reversibility: str, *, apply: bool, acknowledge_sensitive_paths: bool) -> dict[str, object]:
    if not SAFE_NAME.fullmatch(name):
        raise Blocked("unsafe project name")
    target = resolved_target(target, must_exist=True)
    control = target / CONTROL
    audit = scan_project(target)
    observed = str(audit["observed_minimum_risk"])
    blockers: list[str] = []
    try:
        assurance, effective = selection(profile, risk, reversibility, observed)
    except Blocked as exc:
        assurance = PROFILES[profile][0] if profile in PROFILES else "UNKNOWN"
        effective = highest_risk(risk, REV_MIN.get(reversibility, "R3"), observed)
        blockers.append(str(exc))
    if audit["sensitive_paths_content_not_read"] and not acknowledge_sensitive_paths:
        blockers.append("sensitive path indicators require --acknowledge-sensitive-paths")
    if control.exists():
        try:
            existing = json.loads((control / "project.json").read_text(encoding="utf-8"))["project"]
        except Exception as exc:
            raise Blocked(f"existing control state is invalid: {exc}") from exc
        requested = {"name": name, "profile": profile, "risk": risk, "reversibility": reversibility, "fingerprint": audit["fingerprint"]}
        current = {"name": existing["name"], "profile": existing["profile"], "risk": existing["requested_risk"], "reversibility": existing["reversibility"], "fingerprint": existing.get("source_fingerprint")}
        if existing.get("bootstrap_mode") != "adopt" or current != requested:
            raise Blocked(f"controlled state differs: {current}")
        if doctor(target)["status"] != "PASS":
            raise Blocked("existing adopted project failed doctor")
        return {"status": "NOOP", "operation": "adopt", "project_dir": str(target), "details": {"reason": "identical adoption state exists"}}

    plan = {"control_directory": str(control), "profile": profile, "assurance_level": assurance, "requested_risk": risk, "observed_minimum_risk": observed, "effective_risk": effective, "reversibility": reversibility, "source_fingerprint": audit["fingerprint"], "files_scanned": audit["files_scanned"], "bytes_scanned": audit["bytes_scanned"], "detected_technologies": audit["detected_technologies"], "sensitive_paths_content_not_read": audit["sensitive_paths_content_not_read"], "symlinks_not_followed": audit["symlinks_not_followed"], "blockers": blockers, "product_source_changes": []}
    if not apply:
        return {"status": "PLANNED", "operation": "adopt", "project_dir": str(target), "details": plan}
    if blockers:
        raise Blocked("; ".join(blockers))
    if not os.access(target, os.W_OK):
        raise Blocked("project target is not writable")

    before_publish = scan_project(target)
    if before_publish["fingerprint"] != audit["fingerprint"]:
        raise Blocked("project changed between audit and apply")
    created = now()
    record = project_record(name, profile, risk, effective, reversibility, created, mode="adopt", audit=audit)
    publish_control(target, render_records(record, created, mode="adopt", audit=audit))
    try:
        after_publish = scan_project(target)
        if after_publish["fingerprint"] != audit["fingerprint"]:
            raise Blocked("project source fingerprint changed during adoption")
        if doctor(target)["status"] != "PASS":
            raise Blocked("post-adoption doctor failed")
    except Exception:
        shutil.rmtree(control, ignore_errors=True)
        raise
    plan["manifest_digest"] = sha((control / "manifest.json").read_bytes())
    return {"status": "ADOPTED", "operation": "adopt", "project_dir": str(target), "details": plan}


def rollback(target: Path, *, apply: bool) -> dict[str, object]:
    target = resolved_target(target, must_exist=True)
    control = target / CONTROL
    if not control.is_dir() or control.is_symlink():
        raise Blocked("owned control directory is missing or unsafe")
    if doctor(target)["status"] != "PASS":
        raise Blocked("rollback requires a passing doctor result")
    record = json.loads((control / "project.json").read_text(encoding="utf-8"))
    project = record["project"]
    if project.get("bootstrap_mode") != "adopt":
        raise Blocked("this rollback slice supports adopted projects only")
    if project.get("status") != "discovery":
        raise Blocked("accepted or advanced projects require a migration-specific rollback")
    if (control / "acceptance.json").exists():
        raise Blocked("acceptance marker prevents bootstrap rollback")
    rollback_record = json.loads((control / "rollback.json").read_text(encoding="utf-8"))
    if rollback_record.get("owned_scope") != CONTROL or rollback_record.get("action") != "remove-owned-control-directory":
        raise Blocked("rollback record does not authorize this operation")

    before = scan_project(target)
    plan = {"owned_scope": str(control), "action": "remove-owned-control-directory", "source_fingerprint_before": before["fingerprint"], "product_source_changes": []}
    if not apply:
        return {"status": "PLANNED", "operation": "rollback", "project_dir": str(target), "details": plan}

    quarantine = target / f".{CONTROL}.rollback-{uuid.uuid4().hex}"
    os.replace(control, quarantine)
    try:
        after_rename = scan_project(target)
        if after_rename["fingerprint"] != before["fingerprint"]:
            os.replace(quarantine, control)
            raise Blocked("project source changed during rollback")
        shutil.rmtree(quarantine)
    except Exception:
        if quarantine.exists() and not control.exists():
            os.replace(quarantine, control)
        raise
    after = scan_project(target)
    if after["fingerprint"] != before["fingerprint"]:
        raise Blocked("project source fingerprint changed after rollback")
    plan["source_fingerprint_after"] = after["fingerprint"]
    return {"status": "ROLLED_BACK", "operation": "rollback", "project_dir": str(target), "details": plan}


def selftest() -> dict[str, object]:
    with tempfile.TemporaryDirectory(prefix="ew-self-test-") as directory:
        root = Path(directory)
        initialized = root / "initialized"
        init_args = ("EW Init Self Test", "standard-product", "R2", "REV-2")
        dry = init(initialized, *init_args, dry_run=True)
        dry_no_write = not initialized.exists()
        created = init(initialized, *init_args)
        init_doctor = doctor(initialized)
        init_noop = init(initialized, *init_args)

        adopted = root / "existing"
        adopted.mkdir()
        (adopted / "pyproject.toml").write_text("[project]\nname='sample'\n", encoding="utf-8")
        (adopted / "app.py").write_text("print('ok')\n", encoding="utf-8")
        source_before = scan_project(adopted)["fingerprint"]
        adoption_plan = adopt(adopted, "EW Adopt Self Test", "standard-product", "R2", "REV-2", apply=False, acknowledge_sensitive_paths=False)
        plan_no_write = not (adopted / CONTROL).exists()
        adopted_result = adopt(adopted, "EW Adopt Self Test", "standard-product", "R2", "REV-2", apply=True, acknowledge_sensitive_paths=False)
        adopt_doctor = doctor(adopted)
        source_after = scan_project(adopted)["fingerprint"]
        adopt_noop = adopt(adopted, "EW Adopt Self Test", "standard-product", "R2", "REV-2", apply=True, acknowledge_sensitive_paths=False)
        product = adopted / CONTROL / "PRODUCT_DEFINITION.md"
        original = product.read_bytes()
        product.write_bytes(original + b"\ntamper\n")
        tampered = doctor(adopted)
        product.write_bytes(original)
        restored = doctor(adopted)
        rollback_plan = rollback(adopted, apply=False)
        rollback_no_write = (adopted / CONTROL).is_dir()
        rolled_back = rollback(adopted, apply=True)
        source_after_rollback = scan_project(adopted)["fingerprint"]

        assertions = {
            "init_dry_run": dry["status"] == "PLANNED" and dry_no_write,
            "init_created": created["status"] == "CREATED",
            "init_doctor": init_doctor["status"] == "PASS",
            "init_noop": init_noop["status"] == "NOOP",
            "adopt_read_only_plan": adoption_plan["status"] == "PLANNED" and plan_no_write,
            "adopt_applied": adopted_result["status"] == "ADOPTED",
            "adopt_doctor": adopt_doctor["status"] == "PASS",
            "adopt_source_unchanged": source_before == source_after,
            "adopt_noop": adopt_noop["status"] == "NOOP",
            "tamper_detected": tampered["status"] == "FAIL",
            "tamper_restored": restored["status"] == "PASS",
            "rollback_read_only_plan": rollback_plan["status"] == "PLANNED" and rollback_no_write,
            "rollback_applied": rolled_back["status"] == "ROLLED_BACK" and not (adopted / CONTROL).exists(),
            "rollback_source_unchanged": source_before == source_after_rollback,
        }
        if not all(assertions.values()):
            raise RuntimeError(assertions)
        return {"status": "PASS", "operation": "self-test", "project_dir": str(root), "details": {"assertions": assertions}}


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="ew")
    parser.add_argument("--version", action="version", version=f"%(prog)s {CLI_VERSION}")
    commands = parser.add_subparsers(dest="command", required=True)

    init_parser = commands.add_parser("init")
    init_parser.add_argument("project_dir", type=Path)
    init_parser.add_argument("--name", required=True)
    init_parser.add_argument("--profile", choices=sorted(PROFILES), default="standard-product")
    init_parser.add_argument("--risk", choices=RISKS, default="R2")
    init_parser.add_argument("--reversibility", choices=REV_MIN, default="REV-2")
    init_parser.add_argument("--dry-run", action="store_true")
    init_parser.add_argument("--json", action="store_true")

    adopt_parser = commands.add_parser("adopt")
    adopt_parser.add_argument("project_dir", type=Path)
    adopt_parser.add_argument("--name", required=True)
    adopt_parser.add_argument("--profile", choices=sorted(PROFILES), default="standard-product")
    adopt_parser.add_argument("--risk", choices=RISKS, default="R2")
    adopt_parser.add_argument("--reversibility", choices=REV_MIN, default="REV-2")
    adopt_parser.add_argument("--apply", action="store_true")
    adopt_parser.add_argument("--acknowledge-sensitive-paths", action="store_true")
    adopt_parser.add_argument("--json", action="store_true")

    doctor_parser = commands.add_parser("doctor")
    doctor_parser.add_argument("project_dir", type=Path, nargs="?", default=Path("."))
    doctor_parser.add_argument("--json", action="store_true")

    rollback_parser = commands.add_parser("rollback")
    rollback_parser.add_argument("project_dir", type=Path, nargs="?", default=Path("."))
    rollback_parser.add_argument("--apply", action="store_true")
    rollback_parser.add_argument("--json", action="store_true")

    selftest_parser = commands.add_parser("self-test")
    selftest_parser.add_argument("--json", action="store_true")

    arguments = parser.parse_args(argv)
    try:
        if arguments.command == "init":
            output = init(arguments.project_dir, arguments.name, arguments.profile, arguments.risk, arguments.reversibility, arguments.dry_run)
        elif arguments.command == "adopt":
            output = adopt(arguments.project_dir, arguments.name, arguments.profile, arguments.risk, arguments.reversibility, apply=arguments.apply, acknowledge_sensitive_paths=arguments.acknowledge_sensitive_paths)
        elif arguments.command == "doctor":
            output = doctor(arguments.project_dir)
        elif arguments.command == "rollback":
            output = rollback(arguments.project_dir, apply=arguments.apply)
        else:
            output = selftest()
        emit(output, arguments.json)
        return 0 if output["status"] in SUCCESS else 1
    except Blocked as exc:
        emit({"status": "BLOCKED", "operation": arguments.command, "project_dir": str(getattr(arguments, "project_dir", "")), "details": {"error": str(exc)}}, getattr(arguments, "json", False))
        return 2
    except Exception as exc:
        emit({"status": "FAILED", "operation": arguments.command, "project_dir": str(getattr(arguments, "project_dir", "")), "details": {"error": str(exc)}}, getattr(arguments, "json", False))
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
