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
RECORD_KINDS = {"artifact-admission", "project-context", "eval-receipt", "capability-mapping"}
ARTIFACT_TYPES = {"model", "dataset", "skill", "tool", "runtime", "adapter", "benchmark", "library", "other"}
SECRET_PATTERNS = [
    re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----"),
    re.compile(r"\bgh[pousr]_[A-Za-z0-9]{30,}\b"),
    re.compile(r"\bsk-(?:proj-)?[A-Za-z0-9_-]{20,}\b"),
]


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
    if artifact.get("type") not in ARTIFACT_TYPES:
        errors.append("artifact.type is invalid")
    for field in ("id", "source", "revision", "license", "format"):
        if not isinstance(artifact.get(field), str) or not artifact.get(field, "").strip():
            errors.append(f"artifact.{field} must be a non-empty string")
    digest = require_mapping(artifact.get("digest"), "artifact.digest", errors)
    if digest.get("algorithm") != "sha256":
        errors.append("artifact.digest.algorithm must be sha256")
    validate_sha256(digest.get("value"), "artifact.digest.value", errors)
    ownership = require_mapping(record.get("ownership"), "ownership", errors)
    require_fields(ownership, ("owner", "project_scope"), "ownership", errors)
    if not isinstance(ownership.get("owner"), str) or not ownership.get("owner", "").strip():
        errors.append("ownership.owner must be a non-empty string")
    if not isinstance(ownership.get("project_scope"), list) or not ownership.get("project_scope"):
        errors.append("ownership.project_scope must be non-empty")
    security = require_mapping(record.get("security"), "security", errors)
    require_fields(security, ("risk_class", "executable_surface", "trust_remote_code"), "security", errors)
    if security.get("risk_class") not in {"LOW", "MEDIUM", "HIGH", "CRITICAL", "UNKNOWN"}:
        errors.append("security.risk_class is invalid")
    if not isinstance(security.get("executable_surface"), list):
        errors.append("security.executable_surface must be an array")
    if not isinstance(security.get("trust_remote_code"), bool):
        errors.append("security.trust_remote_code must be boolean")
    runtime = require_mapping(record.get("runtime"), "runtime", errors)
    require_fields(runtime, ("engine", "hardware_fit"), "runtime", errors)
    engine = runtime.get("engine")
    if engine is not None and (not isinstance(engine, str) or not engine.strip()):
        errors.append("runtime.engine must be a non-empty string or null")
    if runtime.get("hardware_fit") not in {"FIT", "CONSTRAINED", "RESEARCH_ONLY", "UNSUPPORTED", "NOT_APPLICABLE", "UNKNOWN"}:
        errors.append("runtime.hardware_fit is invalid")
    governance = require_mapping(record.get("governance"), "governance", errors)
    require_fields(governance, ("status", "allowed_use", "prohibited_use", "eval_baseline_ref", "rollback_ref"), "governance", errors)
    if governance.get("status") not in {"CANDIDATE", "QUARANTINED", "PILOT", "ADMITTED", "WATCH", "REJECTED", "DEPRECATED"}:
        errors.append("governance.status is invalid")
    if not isinstance(governance.get("allowed_use"), list) or not isinstance(governance.get("prohibited_use"), list):
        errors.append("governance allowed_use/prohibited_use must be arrays")
    if governance.get("eval_baseline_ref") is not None and not isinstance(governance.get("eval_baseline_ref"), str):
        errors.append("governance.eval_baseline_ref must be string or null")
    if not isinstance(governance.get("rollback_ref"), str) or not governance.get("rollback_ref", "").strip():
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
    require_fields(task, ("objective", "mode", "scope_in", "scope_out"), "task", errors)
    if not isinstance(task.get("objective"), str) or len(task.get("objective", "").strip()) < 3:
        errors.append("task.objective must be a meaningful string")
    if task.get("mode") not in {"AUDIT", "DESIGN", "IMPLEMENT", "VERIFY", "RELEASE", "VALIDATE", "INCIDENT"}:
        errors.append("task.mode is invalid")
    if not isinstance(task.get("scope_in"), list) or not task.get("scope_in"):
        errors.append("task.scope_in must be non-empty")
    if not isinstance(task.get("scope_out"), list):
        errors.append("task.scope_out must be an array")
    for field, non_empty in (("authority_sources", True), ("context_sources", False)):
        sources = packet.get(field)
        if not isinstance(sources, list) or (non_empty and not sources):
            errors.append(f"{field} must be {'non-empty ' if non_empty else ''}array")
            continue
        for index, source in enumerate(sources):
            source = require_mapping(source, f"{field}[{index}]", errors)
            require_fields(source, ("path", "sha256", "content"), f"{field}[{index}]", errors)
            validate_sha256(source.get("sha256"), f"{field}[{index}].sha256", errors)
            content = source.get("content")
            if not isinstance(content, str):
                errors.append(f"{field}[{index}].content must be a string")
            elif any(pattern.search(content) for pattern in SECRET_PATTERNS):
                errors.append(f"{field}[{index}].content contains possible secret material")
    constraints = require_mapping(packet.get("constraints"), "constraints", errors)
    require_fields(constraints, ("allowed_effects", "prohibited_effects", "secret_policy"), "constraints", errors)
    if not isinstance(constraints.get("allowed_effects"), list) or not isinstance(constraints.get("prohibited_effects"), list):
        errors.append("constraints effects must be arrays")
    if constraints.get("secret_policy") != "no-secret-values":
        errors.append("constraints.secret_policy must be no-secret-values")
    build = require_mapping(packet.get("build"), "build", errors)
    require_fields(build, ("builder", "built_at", "content_included"), "build", errors)
    if not isinstance(build.get("content_included"), bool):
        errors.append("build.content_included must be boolean")
    elif build.get("content_included") is False:
        for field in ("authority_sources", "context_sources"):
            for index, source in enumerate(packet.get(field, []) if isinstance(packet.get(field), list) else []):
                if isinstance(source, dict) and source.get("content") not in ("", None):
                    errors.append(f"{field}[{index}].content must be empty when content_included is false")
    return errors


def validate_eval_receipt(data: object) -> list[str]:
    errors: list[str] = []
    receipt = require_mapping(data, "receipt", errors)
    require_fields(receipt, ("schema_version", "receipt_id", "evaluation_kind", "subject", "comparison", "change_scope", "corpus", "metrics", "thresholds", "security_review", "regression", "rollback", "verdict", "evidence", "environment", "evaluated_at"), "receipt", errors)
    if receipt.get("schema_version") != "1.0.0":
        errors.append("receipt.schema_version must be 1.0.0")
    kind = receipt.get("evaluation_kind")
    if kind not in {"CHANGE_REGRESSION", "ARCHITECTURE_CHALLENGER", "MODEL_CANDIDATE", "RETRIEVAL_CANDIDATE", "WORKER_CANDIDATE"}:
        errors.append("evaluation_kind is invalid")
    comparison = require_mapping(receipt.get("comparison"), "comparison", errors)
    if not comparison.get("champion_ref") or not comparison.get("challenger_ref"):
        errors.append("comparison requires champion_ref and challenger_ref")
    elif comparison.get("champion_ref") == comparison.get("challenger_ref"):
        errors.append("comparison champion_ref and challenger_ref must differ")
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
    if corpus.get("validation_strategy") not in {"HOLDOUT", "DISJOINT"}:
        errors.append("corpus.validation_strategy must be HOLDOUT or DISJOINT")
    metrics = receipt.get("metrics")
    metric_values: dict[str, float] = {}
    if not isinstance(metrics, list) or not metrics:
        errors.append("metrics must be non-empty")
    else:
        metric_names: list[str] = []
        for index, metric in enumerate(metrics):
            metric = require_mapping(metric, f"metrics[{index}]", errors)
            require_fields(metric, ("name", "baseline", "candidate", "delta"), f"metrics[{index}]", errors)
            values = (metric.get("baseline"), metric.get("candidate"), metric.get("delta"))
            if not all(isinstance(value, (int, float)) and not isinstance(value, bool) for value in values):
                errors.append(f"metrics[{index}] baseline/candidate/delta must be numeric")
            elif abs((values[1] - values[0]) - values[2]) > 1e-9:
                errors.append(f"metrics[{index}].delta must equal candidate - baseline")
            name = metric.get("name")
            if not isinstance(name, str) or not name.strip():
                errors.append(f"metrics[{index}].name must be non-empty")
            else:
                metric_names.append(name)
                if isinstance(metric.get("candidate"), (int, float)) and not isinstance(metric.get("candidate"), bool):
                    metric_values[name] = float(metric["candidate"])
        if len(metric_names) != len(set(metric_names)):
            errors.append("metric names must be unique")
    thresholds = receipt.get("thresholds")
    if not isinstance(thresholds, list) or not thresholds:
        errors.append("thresholds must be non-empty")
    else:
        threshold_names: list[str] = []
        for index, threshold in enumerate(thresholds):
            threshold = require_mapping(threshold, f"thresholds[{index}]", errors)
            require_fields(threshold, ("name", "operator", "value"), f"thresholds[{index}]", errors)
            name = threshold.get("name")
            if isinstance(name, str):
                threshold_names.append(name)
            if threshold.get("operator") not in {">=", "<=", ">", "<", "=="}:
                errors.append(f"thresholds[{index}].operator is invalid")
            if not isinstance(threshold.get("value"), (int, float)) or isinstance(threshold.get("value"), bool):
                errors.append(f"thresholds[{index}].value must be numeric")
        if len(threshold_names) != len(set(threshold_names)):
            errors.append("threshold names must be unique")
    security = require_mapping(receipt.get("security_review"), "security_review", errors)
    if security.get("status") not in {"PASS", "FAIL", "BLOCKED", "NOT_APPLICABLE"}:
        errors.append("security_review.status is invalid")
    if security.get("status") != "NOT_APPLICABLE" and not security.get("evidence_ref"):
        errors.append("security_review.evidence_ref is required unless NOT_APPLICABLE")
    regression = require_mapping(receipt.get("regression"), "regression", errors)
    if regression.get("status") not in {"PASS", "FAIL", "BLOCKED"} or not regression.get("evidence_ref"):
        errors.append("regression requires valid status and evidence_ref")
    rollback = require_mapping(receipt.get("rollback"), "rollback", errors)
    if not rollback.get("plan_ref") or not isinstance(rollback.get("verified"), bool):
        errors.append("rollback requires plan_ref and boolean verified")
    verdict = receipt.get("verdict")
    if verdict not in {"PASS", "FAIL", "BLOCKED", "INCONCLUSIVE"}:
        errors.append("verdict is invalid")
    if verdict == "PASS":
        if kind == "ARCHITECTURE_CHALLENGER" and security.get("status") != "PASS":
            errors.append("PASS architecture challenger requires security_review PASS")
        if regression.get("status") != "PASS":
            errors.append("PASS requires regression PASS")
        if rollback.get("verified") is not True:
            errors.append("PASS requires verified rollback")
        operators = {
            ">=": lambda a, b: a >= b, "<=": lambda a, b: a <= b,
            ">": lambda a, b: a > b, "<": lambda a, b: a < b, "==": lambda a, b: a == b,
        }
        if isinstance(thresholds, list):
            for index, threshold in enumerate(thresholds):
                if not isinstance(threshold, dict):
                    continue
                name, operator, value = threshold.get("name"), threshold.get("operator"), threshold.get("value")
                if name not in metric_values:
                    errors.append(f"PASS threshold {name!r} has no matching metric")
                elif operator in operators and isinstance(value, (int, float)) and not isinstance(value, bool) and not operators[operator](metric_values[name], float(value)):
                    errors.append(f"PASS threshold {name!r} is not satisfied by candidate metric")
    if not isinstance(receipt.get("evidence"), list) or not receipt.get("evidence"):
        errors.append("evidence must be non-empty")
    return errors


def validate_capability_mapping(data: object) -> list[str]:
    errors: list[str] = []
    record = require_mapping(data, "mapping", errors)
    require_fields(record, ("schema_version", "record_id", "capability", "admission_refs", "evaluation_refs", "registry_binding", "project_mappings", "governance", "evidence"), "mapping", errors)
    if record.get("schema_version") != "1.0.0":
        errors.append("mapping.schema_version must be 1.0.0")
    capability = require_mapping(record.get("capability"), "capability", errors)
    require_fields(capability, ("id", "class", "authority_mode", "lifecycle_status"), "capability", errors)
    if not isinstance(capability.get("id"), str) or not capability.get("id", "").strip():
        errors.append("capability.id must be non-empty")
    if capability.get("class") not in {"decision-routing", "retrieval", "memory", "skill", "tool", "worker", "model-runtime", "evaluator", "other"}:
        errors.append("capability.class is invalid")
    if capability.get("authority_mode") not in {"EVALUATION_ONLY", "ADVISORY", "READ_ONLY", "BOUNDED_EXECUTION"}:
        errors.append("capability.authority_mode is invalid")
    if capability.get("lifecycle_status") not in {"CANDIDATE", "PILOT", "WATCH", "ADMITTED", "DEPRECATED", "REJECTED"}:
        errors.append("capability.lifecycle_status is invalid")
    for field in ("admission_refs", "evaluation_refs", "evidence"):
        value = record.get(field)
        if not isinstance(value, list) or not value or not all(isinstance(item, str) and item.strip() for item in value):
            errors.append(f"{field} must be a non-empty string array")
        elif len(value) != len(set(value)):
            errors.append(f"{field} must contain unique entries")
    binding = require_mapping(record.get("registry_binding"), "registry_binding", errors)
    require_fields(binding, ("authority_type", "registry_ref", "capability_ref", "binding_status"), "registry_binding", errors)
    if binding.get("authority_type") not in {"VOODOO_ONE_EXECUTION_CAPABILITY", "CYBERSKILLS_DISCOVERY", "SKILLS_RUNTIME", "PROJECT_NATIVE", "NONE"}:
        errors.append("registry_binding.authority_type is invalid")
    if binding.get("binding_status") not in {"UNBOUND", "DISCOVERED", "REGISTERED", "ACTIVATED", "REVOKED"}:
        errors.append("registry_binding.binding_status is invalid")
    if binding.get("binding_status") in {"REGISTERED", "ACTIVATED", "REVOKED"}:
        if not isinstance(binding.get("registry_ref"), str) or not binding.get("registry_ref", "").strip():
            errors.append("bound registry state requires registry_ref")
        if not isinstance(binding.get("capability_ref"), str) or not binding.get("capability_ref", "").strip():
            errors.append("bound registry state requires capability_ref")
    mappings = record.get("project_mappings")
    if not isinstance(mappings, list) or not mappings:
        errors.append("project_mappings must be non-empty")
    else:
        seen: set[str] = set()
        for index, item in enumerate(mappings):
            item = require_mapping(item, f"project_mappings[{index}]", errors)
            require_fields(item, ("project_id", "project_ref", "status", "allowed_use", "prohibited_use", "environments", "execution_authority_ref", "production_eligible", "evidence_refs"), f"project_mappings[{index}]", errors)
            project_id = item.get("project_id")
            if not isinstance(project_id, str) or not project_id.strip():
                errors.append(f"project_mappings[{index}].project_id must be non-empty")
            elif project_id in seen:
                errors.append("project_mappings project_id values must be unique")
            else:
                seen.add(project_id)
            if item.get("status") not in {"CANDIDATE", "PILOT", "WATCH", "ENABLED", "REJECTED", "REVOKED"}:
                errors.append(f"project_mappings[{index}].status is invalid")
            for field in ("allowed_use", "prohibited_use", "environments", "evidence_refs"):
                if not isinstance(item.get(field), list):
                    errors.append(f"project_mappings[{index}].{field} must be an array")
            if type(item.get("production_eligible")) is not bool:
                errors.append(f"project_mappings[{index}].production_eligible must be boolean")
            authority_ref = item.get("execution_authority_ref")
            if item.get("status") == "ENABLED" and (not isinstance(authority_ref, str) or not authority_ref.strip()):
                errors.append(f"project_mappings[{index}] ENABLED requires external execution_authority_ref")
            if item.get("production_eligible") is True and item.get("status") != "ENABLED":
                errors.append(f"project_mappings[{index}] production_eligible requires ENABLED status")
    governance = require_mapping(record.get("governance"), "governance", errors)
    if governance.get("mapping_grants_execution") is not False:
        errors.append("capability mapping must never grant execution authority")
    if governance.get("project_authority_required") is not True:
        errors.append("capability mapping requires project authority")
    if governance.get("fail_closed_on_missing_binding") is not True:
        errors.append("capability mapping must fail closed on missing binding")
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
    for key in ("requires_governance", "requires_regression", "requires_evidence", "requires_rollback"):
        if stable.get(key) is not True:
            errors.append(f"stable_lane.{key} must be true")
    if lab.get("production_eligible") is not False or lab.get("production_mutation_allowed") is not False:
        errors.append("lab lane must be isolated from production effects")
    if lab.get("isolation_required") is not True:
        errors.append("lab_lane.isolation_required must be true")
    if not isinstance(lab.get("candidate_dimensions"), list) or not lab.get("candidate_dimensions"):
        errors.append("lab_lane.candidate_dimensions must be non-empty")
    for key in ("champion_challenger", "single_dimension_default", "multi_dimension_change_requires_exception", "holdout_or_disjoint_validation_required", "security_review_required", "regression_required", "rollback_required"):
        if promotion.get(key) is not True:
            errors.append(f"promotion_policy.{key} must be true")
    if promotion.get("production_mutation_from_lab") is not False:
        errors.append("promotion_policy.production_mutation_from_lab must be false")
    expected_pipeline = ["IDEA", "RESEARCH", "ISOLATED_PROTOTYPE", "BENCHMARK", "SECURITY_REVIEW", "CHAMPION_CHALLENGER", "REGRESSION", "ADOPT_OR_REJECT", "VERSIONED_ARCHITECTURE_RELEASE"]
    if policy.get("promotion_pipeline") != expected_pipeline:
        errors.append("promotion_pipeline must preserve the governed champion/challenger sequence")
    expected_fields = {"why", "evidence", "benchmark", "risk", "migration", "rollback"}
    if set(policy.get("architecture_release_fields", [])) != expected_fields:
        errors.append("architecture_release_fields must contain WHY/EVIDENCE/BENCHMARK/RISK/MIGRATION/ROLLBACK")
    expected_contracts = {
        "artifact_admission": "../schemas/artifact-admission-record.schema.json",
        "project_context_packet": "../schemas/project-context-packet.schema.json",
        "eval_receipt": "../schemas/eval-receipt.schema.json",
        "capability_mapping": "../schemas/capability-mapping-record.schema.json",
    }
    if policy.get("contracts") != expected_contracts:
        errors.append("policy.contracts must bind the canonical portable schemas")
    return errors


def validate_record(kind: str, data: object) -> list[str]:
    if kind == "artifact-admission":
        return validate_artifact_record(data)
    if kind == "project-context":
        return validate_context_packet(data)
    if kind == "eval-receipt":
        return validate_eval_receipt(data)
    if kind == "capability-mapping":
        return validate_capability_mapping(data)
    return [f"unknown record kind: {kind}"]


def validate_repository_contract() -> list[str]:
    errors: list[str] = []
    required = [
        "architecture/AI_ENGINEERING_CONTROL_PLANE_ARCHITECTURE.md",
        "config/ai-engineering-control-plane.json",
        "schemas/ai-engineering-control-plane.schema.json",
        "schemas/artifact-admission-record.schema.json",
        "schemas/project-context-packet.schema.json",
        "schemas/eval-receipt.schema.json",
        "schemas/capability-mapping-record.schema.json",
        "scripts/build_project_context_packet.py",
        "scripts/build_project_context_packet_from_session.py",
        "scripts/validate_ai_control_plane.py",
    ]
    for rel in required:
        if not (ROOT / rel).is_file():
            errors.append(f"missing required AI control-plane file: {rel}")
    if errors:
        return errors
    for rel in required[2:7]:
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
        "capability_mapping_schema": "schemas/capability-mapping-record.schema.json",
    }
    control_section = control.get("control", {}) if isinstance(control, dict) else {}
    for key, expected in expected_control.items():
        if control_section.get(key) != expected:
            errors.append(f"project-control.json control.{key} must equal {expected!r}")
    quality = control.get("quality", {}) if isinstance(control, dict) else {}
    if quality.get("ai_control_plane_validator") != "python3 scripts/validate_ai_control_plane.py":
        errors.append("project-control.json quality.ai_control_plane_validator is missing")
    if quality.get("trusted_context_builder") != "python3 scripts/build_project_context_packet_from_session.py":
        errors.append("project-control.json quality.trusted_context_builder is missing")
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
