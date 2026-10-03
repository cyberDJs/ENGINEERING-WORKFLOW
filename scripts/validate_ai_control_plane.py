#!/usr/bin/env python3
"""Dependency-free validation for AI Engineering Control Plane contracts."""
from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
HEX40 = re.compile(r"^[a-f0-9]{40}$")
HEX64 = re.compile(r"^[a-f0-9]{64}$")
RECORD_KINDS = {"artifact-admission", "project-context", "eval-receipt"}


def load(path: Path) -> object:
    return json.loads(path.read_text(encoding="utf-8"))


def require_mapping(value: object, label: str, errors: list[str]) -> dict:
    if not isinstance(value, dict):
        errors.append(f"{label}: expected object")
        return {}
    return value


def require_fields(value: dict, fields: tuple[str, ...], label: str, errors: list[str]) -> None:
    for field in fields:
        if field not in value:
            errors.append(f"{label}: missing {field}")


def validate_sha256(value: object, label: str, errors: list[str]) -> None:
    if not isinstance(value, str) or not HEX64.match(value):
        errors.append(f"{label}: expected lowercase sha256 hex")


def validate_artifact_record(data: object) -> list[str]:
    errors: list[str] = []
    record = require_mapping(data, "record", errors)
    require_fields(record, ("schema_version", "record_id", "artifact", "ownership", "security", "runtime", "governance", "evidence"), "record", errors)
    if record.get("schema_version") != "1.0.0":
        errors.append("record.schema_version must be 1.0.0")
    artifact = require_mapping(record.get("artifact"), "artifact", errors)
    require_fields(artifact, ("id", "type", "source", "revision", "digest", "license", "format"), "artifact", errors)
    digest = require_mapping(artifact.get("digest"), "artifact.digest", errors)
    if digest.get("algorithm") != "sha256":
        errors.append("artifact.digest.algorithm must be sha256")
    validate_sha256(digest.get("value"), "artifact.digest.value", errors)
    security = require_mapping(record.get("security"), "security", errors)
    if security.get("risk_class") not in {"LOW", "MEDIUM", "HIGH", "CRITICAL", "UNKNOWN"}:
        errors.append("security.risk_class is invalid")
    if not isinstance(security.get("trust_remote_code"), bool):
        errors.append("security.trust_remote_code must be boolean")
    governance = require_mapping(record.get("governance"), "governance", errors)
    if governance.get("status") not in {"CANDIDATE", "QUARANTINED", "PILOT", "ADMITTED", "WATCH", "REJECTED", "DEPRECATED"}:
        errors.append("governance.status is invalid")
    if not governance.get("rollback_ref"):
        errors.append("governance.rollback_ref is required")
    if not isinstance(record.get("evidence"), list) or not record.get("evidence"):
        errors.append("evidence must be a non-empty array")
    return errors


def validate_context_packet(data: object) -> list[str]:
    errors: list[str] = []
    packet = require_mapping(data, "packet", errors)
    require_fields(packet, ("schema_version", "packet_id", "project", "task", "authority_sources", "context_sources", "constraints", "build"), "packet", errors)
    if packet.get("schema_version") != "1.0.0":
        errors.append("packet.schema_version must be 1.0.0")
    project = require_mapping(packet.get("project"), "project", errors)
    require_fields(project, ("id", "path", "branch", "head", "dirty"), "project", errors)
    if not isinstance(project.get("head"), str) or not HEX40.match(project.get("head", "")):
        errors.append("project.head must be a 40-character git SHA")
    if not isinstance(project.get("dirty"), bool):
        errors.append("project.dirty must be boolean")
    task = require_mapping(packet.get("task"), "task", errors)
    if task.get("mode") not in {"AUDIT", "DESIGN", "IMPLEMENT", "VERIFY", "RELEASE", "VALIDATE", "INCIDENT"}:
        errors.append("task.mode is invalid")
    if not isinstance(task.get("scope_in"), list) or not task.get("scope_in"):
        errors.append("task.scope_in must be non-empty")
    authorities = packet.get("authority_sources")
    if not isinstance(authorities, list) or not authorities:
        errors.append("authority_sources must be non-empty")
    else:
        for index, source in enumerate(authorities):
            source = require_mapping(source, f"authority_sources[{index}]", errors)
            require_fields(source, ("path", "sha256", "content"), f"authority_sources[{index}]", errors)
            validate_sha256(source.get("sha256"), f"authority_sources[{index}].sha256", errors)
    constraints = require_mapping(packet.get("constraints"), "constraints", errors)
    if constraints.get("secret_policy") != "no-secret-values":
        errors.append("constraints.secret_policy must be no-secret-values")
    return errors


def validate_eval_receipt(data: object) -> list[str]:
    errors: list[str] = []
    receipt = require_mapping(data, "receipt", errors)
    require_fields(receipt, ("schema_version", "receipt_id", "evaluation_kind", "subject", "comparison", "change_scope", "corpus", "metrics", "thresholds", "verdict", "evidence", "environment", "evaluated_at"), "receipt", errors)
    if receipt.get("schema_version") != "1.0.0":
        errors.append("receipt.schema_version must be 1.0.0")
    kind = receipt.get("evaluation_kind")
    if kind not in {"CHANGE_REGRESSION", "ARCHITECTURE_CHALLENGER", "MODEL_CANDIDATE", "RETRIEVAL_CANDIDATE", "WORKER_CANDIDATE"}:
        errors.append("evaluation_kind is invalid")
    comparison = require_mapping(receipt.get("comparison"), "comparison", errors)
    if not comparison.get("champion_ref") or not comparison.get("challenger_ref"):
        errors.append("comparison requires champion_ref and challenger_ref")
    scope = require_mapping(receipt.get("change_scope"), "change_scope", errors)
    changed = scope.get("changed_dimensions")
    if not isinstance(changed, list) or not changed:
        errors.append("change_scope.changed_dimensions must be non-empty")
    elif len(changed) != len(set(changed)):
        errors.append("change_scope.changed_dimensions must be unique")
    if kind == "ARCHITECTURE_CHALLENGER" and isinstance(changed, list) and len(changed) > 1 and not scope.get("multi_dimension_exception_ref"):
        errors.append("architecture challenger changes one dimension by default; multi_dimension_exception_ref is required")
    corpus = require_mapping(receipt.get("corpus"), "corpus", errors)
    validate_sha256(corpus.get("digest"), "corpus.digest", errors)
    if receipt.get("verdict") not in {"PASS", "FAIL", "BLOCKED", "INCONCLUSIVE"}:
        errors.append("verdict is invalid")
    if not isinstance(receipt.get("metrics"), list) or not receipt.get("metrics"):
        errors.append("metrics must be non-empty")
    if not isinstance(receipt.get("thresholds"), list) or not receipt.get("thresholds"):
        errors.append("thresholds must be non-empty")
    if not isinstance(receipt.get("evidence"), list) or not receipt.get("evidence"):
        errors.append("evidence must be non-empty")
    return errors


def validate_policy(data: object) -> list[str]:
    errors: list[str] = []
    policy = require_mapping(data, "policy", errors)
    if policy.get("schema_version") != "1.0.0":
        errors.append("policy.schema_version must be 1.0.0")
    stable = require_mapping(policy.get("stable_lane"), "stable_lane", errors)
    lab = require_mapping(policy.get("lab_lane"), "lab_lane", errors)
    promotion = require_mapping(policy.get("promotion_policy"), "promotion_policy", errors)
    if stable.get("production_eligible") is not True:
        errors.append("stable lane must be production eligible")
    if lab.get("production_eligible") is not False or lab.get("production_mutation_allowed") is not False:
        errors.append("lab lane must be isolated from production effects")
    for key in ("champion_challenger", "single_dimension_default", "multi_dimension_change_requires_exception", "security_review_required", "regression_required", "rollback_required"):
        if promotion.get(key) is not True:
            errors.append(f"promotion_policy.{key} must be true")
    if promotion.get("production_mutation_from_lab") is not False:
        errors.append("promotion_policy.production_mutation_from_lab must be false")
    expected_fields = {"why", "evidence", "benchmark", "risk", "migration", "rollback"}
    if set(policy.get("architecture_release_fields", [])) != expected_fields:
        errors.append("architecture_release_fields must contain WHY/EVIDENCE/BENCHMARK/RISK/MIGRATION/ROLLBACK")
    return errors


def validate_record(kind: str, data: object) -> list[str]:
    if kind == "artifact-admission":
        return validate_artifact_record(data)
    if kind == "project-context":
        return validate_context_packet(data)
    if kind == "eval-receipt":
        return validate_eval_receipt(data)
    return [f"unknown record kind: {kind}"]


def validate_repository_contract() -> list[str]:
    errors: list[str] = []
    required = [
        "architecture/AI_ENGINEERING_CONTROL_PLANE.md",
        "config/ai-engineering-control-plane.json",
        "schemas/ai-engineering-control-plane.schema.json",
        "schemas/artifact-admission-record.schema.json",
        "schemas/project-context-packet.schema.json",
        "schemas/eval-receipt.schema.json",
        "scripts/build_project_context_packet.py",
        "scripts/validate_ai_control_plane.py",
    ]
    for rel in required:
        if not (ROOT / rel).is_file():
            errors.append(f"missing required AI control-plane file: {rel}")
    if errors:
        return errors
    for rel in required[2:6]:
        schema = load(ROOT / rel)
        if not isinstance(schema, dict) or schema.get("type") != "object" or "$schema" not in schema:
            errors.append(f"{rel}: invalid schema envelope")
    errors.extend(validate_policy(load(ROOT / "config/ai-engineering-control-plane.json")))
    control = load(ROOT / "project-control.json")
    expected_control = {
        "ai_engineering_control_plane": "config/ai-engineering-control-plane.json",
        "artifact_admission_schema": "schemas/artifact-admission-record.schema.json",
        "project_context_packet_schema": "schemas/project-context-packet.schema.json",
        "eval_receipt_schema": "schemas/eval-receipt.schema.json",
    }
    control_section = control.get("control", {}) if isinstance(control, dict) else {}
    for key, expected in expected_control.items():
        if control_section.get(key) != expected:
            errors.append(f"project-control.json control.{key} must equal {expected!r}")
    quality = control.get("quality", {}) if isinstance(control, dict) else {}
    if quality.get("ai_control_plane_validator") != "python3 scripts/validate_ai_control_plane.py":
        errors.append("project-control.json quality.ai_control_plane_validator is missing")
    return errors


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--kind", choices=sorted(RECORD_KINDS))
    parser.add_argument("--file", type=Path)
    args = parser.parse_args()
    if bool(args.kind) != bool(args.file):
        parser.error("--kind and --file must be provided together")
    if args.kind:
        errors = validate_record(args.kind, load(args.file))
        label = "RECORD_VALIDATION"
    else:
        errors = validate_repository_contract()
        label = "AI_CONTROL_PLANE_VALIDATION"
    if errors:
        print(f"{label}=FAILED")
        for message in errors:
            print(f"ERROR: {message}")
        return 1
    print(f"{label}=PASSED")
    return 0


if __name__ == "__main__":
    sys.exit(main())
