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
RECORD_KINDS = {"artifact-admission", "project-context", "eval-receipt", "capability-mapping", "evaluation-suite", "architecture-promotion", "adversarial-review-suite", "ai-dependency-inventory", "constrained-task-plan", "external-authority-binding"}
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


def validate_architecture_promotion(data: object) -> list[str]:
    errors: list[str] = []
    record = require_mapping(data, "promotion", errors)
    require_fields(record, ("schema_version", "record_id", "architecture", "decision", "gates", "release", "governance", "evidence", "residual_risks"), "promotion", errors)
    if record.get("schema_version") != "1.0.0":
        errors.append("promotion.schema_version must be 1.0.0")
    if not isinstance(record.get("record_id"), str) or len(record.get("record_id", "").strip()) < 3:
        errors.append("promotion.record_id must be meaningful")

    architecture = require_mapping(record.get("architecture"), "architecture", errors)
    require_fields(architecture, ("family", "current_champion_ref", "candidate_ref", "changed_dimensions"), "architecture", errors)
    for field in ("family", "current_champion_ref", "candidate_ref"):
        if not isinstance(architecture.get(field), str) or not architecture.get(field, "").strip():
            errors.append(f"architecture.{field} must be non-empty")
    if architecture.get("current_champion_ref") == architecture.get("candidate_ref"):
        errors.append("architecture current champion and candidate must differ")
    changed = architecture.get("changed_dimensions")
    if not isinstance(changed, list) or not changed or not all(isinstance(item, str) and item.strip() for item in changed):
        errors.append("architecture.changed_dimensions must be non-empty strings")
    elif len(changed) != len(set(changed)):
        errors.append("architecture.changed_dimensions must be unique")

    decision = require_mapping(record.get("decision"), "decision", errors)
    require_fields(decision, ("outcome", "decision_record_ref", "decision_authority_type", "decision_authority_ref", "decided_at"), "decision", errors)
    outcome = decision.get("outcome")
    if outcome not in {"ADOPT", "REJECT", "WATCH"}:
        errors.append("decision.outcome is invalid")
    if decision.get("decision_authority_type") not in {"POLICY", "OPERATOR", "PROJECT_AUTHORITY"}:
        errors.append("decision.decision_authority_type is invalid")
    for field in ("decision_record_ref", "decision_authority_ref", "decided_at"):
        if not isinstance(decision.get(field), str) or not decision.get(field, "").strip():
            errors.append(f"decision.{field} must be non-empty")

    gates = require_mapping(record.get("gates"), "gates", errors)
    require_fields(gates, ("eval_receipt_ref", "eval_verdict", "security_status", "security_evidence_ref", "regression_status", "regression_evidence_ref", "rollback_verified", "rollback_ref"), "gates", errors)
    for field in ("eval_receipt_ref", "regression_evidence_ref", "rollback_ref"):
        if not isinstance(gates.get(field), str) or not gates.get(field, "").strip():
            errors.append(f"gates.{field} must be non-empty")
    if gates.get("eval_verdict") not in {"PASS", "FAIL", "BLOCKED", "INCONCLUSIVE"}:
        errors.append("gates.eval_verdict is invalid")
    security_status = gates.get("security_status")
    if security_status not in {"PASS", "FAIL", "BLOCKED", "NOT_APPLICABLE"}:
        errors.append("gates.security_status is invalid")
    if security_status != "NOT_APPLICABLE" and (not isinstance(gates.get("security_evidence_ref"), str) or not gates.get("security_evidence_ref", "").strip()):
        errors.append("gates.security_evidence_ref is required unless security is NOT_APPLICABLE")
    if gates.get("regression_status") not in {"PASS", "FAIL", "BLOCKED"}:
        errors.append("gates.regression_status is invalid")
    if type(gates.get("rollback_verified")) is not bool:
        errors.append("gates.rollback_verified must be boolean")

    release = require_mapping(record.get("release"), "release", errors)
    require_fields(release, ("architecture_version", "release_record_ref", "release_authority_ref", "production_eligible"), "release", errors)
    if type(release.get("production_eligible")) is not bool:
        errors.append("release.production_eligible must be boolean")
    for field in ("architecture_version", "release_record_ref", "release_authority_ref"):
        value = release.get(field)
        if value is not None and (not isinstance(value, str) or not value.strip()):
            errors.append(f"release.{field} must be non-empty string or null")

    governance = require_mapping(record.get("governance"), "governance", errors)
    if governance.get("record_grants_execution") is not False:
        errors.append("architecture promotion record must never grant execution")
    if governance.get("record_grants_release") is not False:
        errors.append("architecture promotion record must never grant release authority")
    if governance.get("protected_operations_require_separate_authorization") is not True:
        errors.append("protected operations require separate authorization")

    for field in ("evidence", "residual_risks"):
        value = record.get(field)
        if not isinstance(value, list) or not all(isinstance(item, str) and item.strip() for item in value):
            errors.append(f"{field} must be a string array")
        elif field == "evidence" and not value:
            errors.append("evidence must be non-empty")
        elif len(value) != len(set(value)):
            errors.append(f"{field} must contain unique entries")

    if outcome == "ADOPT":
        if decision.get("decision_authority_type") not in {"OPERATOR", "PROJECT_AUTHORITY"}:
            errors.append("ADOPT requires non-policy decision authority")
        if gates.get("eval_verdict") != "PASS":
            errors.append("ADOPT requires eval_verdict PASS")
        if security_status != "PASS":
            errors.append("ADOPT requires security_status PASS")
        if gates.get("regression_status") != "PASS":
            errors.append("ADOPT requires regression_status PASS")
        if gates.get("rollback_verified") is not True:
            errors.append("ADOPT requires verified rollback")
        for field in ("architecture_version", "release_record_ref", "release_authority_ref"):
            if not isinstance(release.get(field), str) or not release.get(field, "").strip():
                errors.append(f"ADOPT requires release.{field}")
        if release.get("production_eligible") is not True:
            errors.append("ADOPT requires production_eligible true")
    elif outcome in {"WATCH", "REJECT"}:
        for field in ("architecture_version", "release_record_ref", "release_authority_ref"):
            if release.get(field) is not None:
                errors.append(f"{outcome} requires release.{field} null")
        if release.get("production_eligible") is not False:
            errors.append(f"{outcome} requires production_eligible false")
    return errors


def validate_adversarial_review_suite(data: object) -> list[str]:
    errors: list[str] = []
    suite = require_mapping(data, "adversarial_suite", errors)
    require_fields(
        suite,
        (
            "schema_version", "suite_id", "security_scope", "executor",
            "threat_model_ref", "case_set", "blocking_policy",
            "independent_review", "governance",
        ),
        "adversarial_suite",
        errors,
    )
    if suite.get("schema_version") != "1.0.0":
        errors.append("adversarial_suite.schema_version must be 1.0.0")
    if not isinstance(suite.get("suite_id"), str) or not suite.get("suite_id", "").strip():
        errors.append("adversarial_suite.suite_id must be non-empty")
    scope = suite.get("security_scope")
    if (
        not isinstance(scope, list)
        or not scope
        or not all(isinstance(item, str) and item.strip() for item in scope)
        or len(scope) != len(set(scope))
    ):
        errors.append("security_scope must be unique non-empty strings")

    executor = require_mapping(suite.get("executor"), "executor", errors)
    if executor.get("authority_type") not in {"APPSEC_CANONICAL", "AI_RED_TEAM_OVERLAY", "SPECIALIZED_HARNESS"}:
        errors.append("executor.authority_type is invalid")
    if not isinstance(executor.get("ref"), str) or not executor.get("ref", "").strip():
        errors.append("executor.ref must be non-empty")
    if not isinstance(suite.get("threat_model_ref"), str) or not suite.get("threat_model_ref", "").strip():
        errors.append("threat_model_ref must be non-empty")

    case_set = require_mapping(suite.get("case_set"), "case_set", errors)
    if not isinstance(case_set.get("id"), str) or not case_set.get("id", "").strip():
        errors.append("case_set.id must be non-empty")
    validate_sha256(case_set.get("digest"), "case_set.digest", errors)
    case_ids = case_set.get("case_ids")
    if (
        not isinstance(case_ids, list)
        or not case_ids
        or not all(isinstance(item, str) and item.strip() for item in case_ids)
        or len(case_ids) != len(set(case_ids))
    ):
        errors.append("case_set.case_ids must be unique non-empty strings")
    if case_set.get("data_class") not in {"SYNTHETIC", "APPROVED_TEST_DATA"}:
        errors.append("case_set.data_class is invalid")
    if case_set.get("environment") not in {"LOCAL_ISOLATED", "CI_ISOLATED", "APPROVED_STAGING"}:
        errors.append("case_set.environment is invalid")

    policy = require_mapping(suite.get("blocking_policy"), "blocking_policy", errors)
    severities = policy.get("blocking_severities")
    allowed_severities = {"critical", "high", "medium", "low"}
    if (
        not isinstance(severities, list)
        or not severities
        or len(severities) != len(set(severities))
        or any(item not in allowed_severities for item in severities)
    ):
        errors.append("blocking_policy.blocking_severities is invalid")
    else:
        if "critical" not in severities or "high" not in severities:
            errors.append("blocking_policy.blocking_severities must include critical and high")
    for field in (
        "block_on_unauthorized_effect",
        "block_on_secret_exposure",
        "block_on_privilege_escalation",
        "block_on_external_effect",
    ):
        if policy.get(field) is not True:
            errors.append(f"blocking_policy.{field} must be true")

    independent = require_mapping(suite.get("independent_review"), "independent_review", errors)
    if independent.get("required") is not True:
        errors.append("independent_review.required must be true")

    governance = require_mapping(suite.get("governance"), "governance", errors)
    if governance.get("security_only") is not True:
        errors.append("governance.security_only must be true")
    if governance.get("functional_eval_separate") is not True:
        errors.append("governance.functional_eval_separate must be true")
    if governance.get("promotion_authority") is not False:
        errors.append("adversarial review suite must not have promotion authority")
    if governance.get("production_effects_allowed") is not False:
        errors.append("adversarial review suite must not allow production effects")
    return errors


def validate_ai_dependency_inventory(data: object) -> list[str]:
    errors: list[str] = []
    inventory = require_mapping(data, "inventory", errors)
    require_fields(inventory, ("schema_version", "snapshot_id", "project", "providers", "models", "inventory_status", "governance", "evidence", "known_unknowns"), "inventory", errors)
    if inventory.get("schema_version") != "1.0.0": errors.append("inventory.schema_version must be 1.0.0")
    if not isinstance(inventory.get("snapshot_id"), str) or not inventory.get("snapshot_id", "").strip(): errors.append("inventory.snapshot_id must be non-empty")
    project = require_mapping(inventory.get("project"), "project", errors)
    require_fields(project, ("id", "path", "branch", "head", "dirty"), "project", errors)
    for field in ("id", "path", "branch"):
        if not isinstance(project.get(field), str) or not project.get(field, "").strip(): errors.append(f"project.{field} must be non-empty")
    if not isinstance(project.get("head"), str) or not HEX40.match(project.get("head", "")): errors.append("project.head must be a 40-character git SHA")
    if type(project.get("dirty")) is not bool: errors.append("project.dirty must be boolean")
    providers = inventory.get("providers")
    provider_ids: set[str] = set(); unknown_boundary = False
    if not isinstance(providers, list) or not providers: errors.append("providers must be non-empty")
    else:
        for index, raw in enumerate(providers):
            provider = require_mapping(raw, f"providers[{index}]", errors)
            require_fields(provider, ("provider_id", "provider_type", "identity_ref", "digest", "endpoint_scope", "external_data_transfer", "retention_mode", "training_use", "credentials_required", "data_policy_ref", "evidence_refs"), f"providers[{index}]", errors)
            pid = provider.get("provider_id")
            if not isinstance(pid, str) or not pid.strip() or pid in provider_ids: errors.append(f"providers[{index}].provider_id must be unique non-empty")
            else: provider_ids.add(pid)
            if provider.get("provider_type") not in {"LOCAL_RUNTIME", "EXTERNAL_API", "REMOTE_MANAGED"}: errors.append(f"providers[{index}].provider_type is invalid")
            if not isinstance(provider.get("identity_ref"), str) or not provider.get("identity_ref", "").strip(): errors.append(f"providers[{index}].identity_ref must be non-empty")
            validate_sha256(provider.get("digest"), f"providers[{index}].digest", errors)
            if provider.get("endpoint_scope") not in {"NONE", "LOCALHOST_ONLY", "EXTERNAL"}: errors.append(f"providers[{index}].endpoint_scope is invalid")
            if type(provider.get("external_data_transfer")) is not bool or type(provider.get("credentials_required")) is not bool: errors.append(f"providers[{index}] boolean fields are invalid")
            if provider.get("provider_type") == "LOCAL_RUNTIME" and (provider.get("endpoint_scope") == "EXTERNAL" or provider.get("external_data_transfer") is True): errors.append(f"providers[{index}] local runtime cannot claim external data transfer")
            if provider.get("retention_mode") not in {"NONE", "PROCESS_EPHEMERAL", "LOCAL_EVIDENCE_ONLY", "PROVIDER_POLICY", "UNKNOWN"}: errors.append(f"providers[{index}].retention_mode is invalid")
            if provider.get("training_use") not in {"NOT_APPLICABLE", "DISABLED", "ENABLED", "UNKNOWN"}: errors.append(f"providers[{index}].training_use is invalid")
            if provider.get("retention_mode") == "UNKNOWN" or provider.get("training_use") == "UNKNOWN": unknown_boundary = True
            if provider.get("data_policy_ref") is not None and (not isinstance(provider.get("data_policy_ref"), str) or not provider.get("data_policy_ref", "").strip()): errors.append(f"providers[{index}].data_policy_ref must be non-empty string or null")
            ev = provider.get("evidence_refs")
            if not isinstance(ev, list) or not ev or not all(isinstance(x, str) and x.strip() for x in ev) or len(ev) != len(set(ev)): errors.append(f"providers[{index}].evidence_refs must be unique non-empty strings")
    models = inventory.get("models"); model_ids: set[str] = set()
    if not isinstance(models, list) or not models: errors.append("models must be non-empty")
    else:
        for index, raw in enumerate(models):
            model = require_mapping(raw, f"models[{index}]", errors)
            require_fields(model, ("model_id", "artifact_admission_ref", "revision", "digest", "license", "provider_id", "role", "lifecycle_status", "use_scope", "authority_mode", "secret_values_allowed", "personal_data_allowed", "personal_data_policy_ref", "evidence_refs"), f"models[{index}]", errors)
            mid=model.get("model_id")
            if not isinstance(mid,str) or not mid.strip() or mid in model_ids: errors.append(f"models[{index}].model_id must be unique non-empty")
            else: model_ids.add(mid)
            for field in ("artifact_admission_ref","revision","license","role"):
                if not isinstance(model.get(field),str) or not model.get(field,"").strip(): errors.append(f"models[{index}].{field} must be non-empty")
            validate_sha256(model.get("digest"), f"models[{index}].digest", errors)
            if model.get("provider_id") not in provider_ids: errors.append(f"models[{index}].provider_id references unknown provider")
            if model.get("lifecycle_status") not in {"BASELINE","PILOT","WATCH","ADMITTED","REJECTED","DEPRECATED"}: errors.append(f"models[{index}].lifecycle_status is invalid")
            if model.get("use_scope") not in {"RESEARCH_ONLY","LOCAL_PILOT","APPROVED_INTERNAL","PRODUCTION_ELIGIBLE"}: errors.append(f"models[{index}].use_scope is invalid")
            if model.get("authority_mode") not in {"ADVISORY","NON_AUTHORITATIVE"}: errors.append(f"models[{index}].authority_mode is invalid")
            if model.get("secret_values_allowed") is not False: errors.append(f"models[{index}] must prohibit secret values")
            if type(model.get("personal_data_allowed")) is not bool: errors.append(f"models[{index}].personal_data_allowed must be boolean")
            if model.get("personal_data_allowed") is True and (not isinstance(model.get("personal_data_policy_ref"),str) or not model.get("personal_data_policy_ref","").strip()): errors.append(f"models[{index}] personal data requires policy ref")
            ev=model.get("evidence_refs")
            if not isinstance(ev,list) or not ev or not all(isinstance(x,str) and x.strip() for x in ev) or len(ev)!=len(set(ev)): errors.append(f"models[{index}].evidence_refs must be unique non-empty strings")
    status=inventory.get("inventory_status"); unknowns=inventory.get("known_unknowns")
    if status not in {"COMPLETE","BLOCKED"}: errors.append("inventory_status is invalid")
    if not isinstance(unknowns,list) or not all(isinstance(x,str) and x.strip() for x in unknowns) or len(unknowns)!=len(set(unknowns)): errors.append("known_unknowns must be unique strings")
    elif status == "COMPLETE" and (unknowns or unknown_boundary): errors.append("COMPLETE inventory cannot contain unknown data boundaries")
    elif status == "BLOCKED" and not unknowns: errors.append("BLOCKED inventory requires known_unknowns")
    governance=require_mapping(inventory.get("governance"),"governance",errors)
    expected={"read_only_snapshot":True,"grants_activation":False,"grants_execution":False,"grants_release":False,"unknown_data_boundary_blocks_activation":True}
    for key,value in expected.items():
        if governance.get(key) is not value: errors.append(f"governance.{key} must be {value}")
    evidence=inventory.get("evidence")
    if not isinstance(evidence,list) or not evidence or not all(isinstance(x,str) and x.strip() for x in evidence) or len(evidence)!=len(set(evidence)): errors.append("evidence must be unique non-empty strings")
    return errors


def validate_constrained_task_plan(data: object) -> list[str]:
    errors: list[str] = []
    plan = require_mapping(data, "plan", errors)
    require_fields(plan, ("schema_version","plan_id","project_context_ref","capability_mapping_ref","task","requested_effects","effect_decisions","status","governance","evidence"), "plan", errors)
    if plan.get("schema_version") != "1.0.0": errors.append("plan.schema_version must be 1.0.0")
    if plan.get("status") not in {"PLANNED","APPROVAL_REQUIRED","BLOCKED"}: errors.append("plan.status is invalid")
    requested = plan.get("requested_effects")
    if not isinstance(requested, list) or not all(isinstance(x,str) and x for x in requested) or len(requested)!=len(set(requested)): errors.append("requested_effects must be unique strings")
    decisions = plan.get("effect_decisions")
    seen=set(); has_deny=False; has_approval=False
    if not isinstance(decisions,list): errors.append("effect_decisions must be an array")
    else:
        for i,item in enumerate(decisions):
            item=require_mapping(item,f"effect_decisions[{i}]",errors); require_fields(item,("effect","decision","authority_ref"),f"effect_decisions[{i}]",errors)
            effect=item.get("effect"); decision=item.get("decision")
            if not isinstance(effect,str) or not effect or effect in seen: errors.append(f"effect_decisions[{i}].effect must be unique non-empty")
            else: seen.add(effect)
            if decision not in {"ALLOW","APPROVAL_REQUIRED","DENY"}: errors.append(f"effect_decisions[{i}].decision is invalid")
            if decision=="ALLOW" and effect in {"write","shell","git","network","deploy","release"} and (not isinstance(item.get("authority_ref"),str) or not item.get("authority_ref","").strip()): errors.append(f"effect_decisions[{i}] protected ALLOW requires authority_ref")
            if decision=="DENY": has_deny=True
            if decision=="APPROVAL_REQUIRED": has_approval=True
    if isinstance(requested,list) and seen != set(requested): errors.append("effect_decisions must exactly cover requested_effects")
    if has_deny and plan.get("status") != "BLOCKED": errors.append("DENY effect requires BLOCKED status")
    if (not has_deny) and has_approval and plan.get("status") != "APPROVAL_REQUIRED": errors.append("approval-required effects require APPROVAL_REQUIRED status")
    gov=require_mapping(plan.get("governance"),"governance",errors)
    expected={"plan_only":True,"execution_performed":False,"plan_grants_execution":False,"fail_closed":True}
    for k,v in expected.items():
        if gov.get(k) is not v: errors.append(f"governance.{k} must be {v}")
    ev=plan.get("evidence")
    if not isinstance(ev,list) or not ev or not all(isinstance(x,str) and x.strip() for x in ev): errors.append("evidence must be non-empty strings")
    return errors

def validate_external_authority_binding(data: object) -> list[str]:
    errors: list[str] = []
    record = require_mapping(data, "external_authority_binding", errors)
    require_fields(record, ("schema_version", "record_id", "subject", "goverdocs", "voodoo_project_registry", "integration_status", "governance", "evidence"), "external_authority_binding", errors)
    if record.get("schema_version") != "1.0.0": errors.append("external_authority_binding.schema_version must be 1.0.0")
    if not isinstance(record.get("record_id"), str) or len(record.get("record_id", "").strip()) < 3: errors.append("external_authority_binding.record_id must be meaningful")
    subject = require_mapping(record.get("subject"), "subject", errors)
    require_fields(subject, ("project_id", "repository", "head"), "subject", errors)
    if not isinstance(subject.get("project_id"), str) or not subject.get("project_id", "").strip(): errors.append("subject.project_id must be non-empty")
    repository = subject.get("repository")
    if not isinstance(repository, str) or repository.count("/") != 1 or any(c.isspace() for c in repository): errors.append("subject.repository must use owner/repository form")
    if not isinstance(subject.get("head"), str) or not HEX40.match(subject.get("head", "")): errors.append("subject.head must be a 40-character git SHA")
    gd = require_mapping(record.get("goverdocs"), "goverdocs", errors)
    require_fields(gd, ("schema_ref", "schema_digest", "projection_ref", "projection_digest", "verification_status", "ingest_ref"), "goverdocs", errors)
    validate_sha256(gd.get("schema_digest"), "goverdocs.schema_digest", errors); validate_sha256(gd.get("projection_digest"), "goverdocs.projection_digest", errors)
    if gd.get("verification_status") not in {"UNVERIFIED", "VERIFIED", "REJECTED"}: errors.append("goverdocs.verification_status is invalid")
    if gd.get("verification_status") == "VERIFIED" and (not isinstance(gd.get("ingest_ref"), str) or not gd.get("ingest_ref", "").strip()): errors.append("VERIFIED GOVERDOCS projection requires ingest_ref")
    vr = require_mapping(record.get("voodoo_project_registry"), "voodoo_project_registry", errors)
    require_fields(vr, ("contract_ref", "contract_digest", "descriptor_ref", "descriptor_digest", "binding_status", "registry_ref"), "voodoo_project_registry", errors)
    validate_sha256(vr.get("contract_digest"), "voodoo_project_registry.contract_digest", errors); validate_sha256(vr.get("descriptor_digest"), "voodoo_project_registry.descriptor_digest", errors)
    if vr.get("binding_status") not in {"UNBOUND", "REGISTERED", "REVOKED"}: errors.append("voodoo_project_registry.binding_status is invalid")
    if vr.get("binding_status") == "REGISTERED" and (not isinstance(vr.get("registry_ref"), str) or not vr.get("registry_ref", "").strip()): errors.append("REGISTERED project binding requires registry_ref")
    status = record.get("integration_status")
    if status not in {"PROJECTION_READY", "BOUND", "BLOCKED"}: errors.append("integration_status is invalid")
    if status == "BOUND" and not (gd.get("verification_status") == "VERIFIED" and vr.get("binding_status") == "REGISTERED"): errors.append("BOUND requires verified GOVERDOCS ingest and registered Voodoo project binding")
    gov = require_mapping(record.get("governance"), "governance", errors)
    expected = {"record_grants_authority": False, "external_write_performed": False, "external_write_requires_separate_authorization": True, "canonical_truth_remains_external": True}
    for key, value in expected.items():
        if gov.get(key) is not value: errors.append(f"governance.{key} must be {value}")
    evidence = record.get("evidence")
    if not isinstance(evidence, list) or not evidence or not all(isinstance(x, str) and x.strip() for x in evidence) or len(evidence) != len(set(evidence)): errors.append("evidence must be unique non-empty strings")
    return errors

def validate_evaluation_suite(data: object) -> list[str]:
    errors: list[str] = []
    suite = require_mapping(data, "suite", errors)
    require_fields(suite, ("schema_version", "suite_id", "capability_class", "executor", "case_set", "comparison", "metrics", "regression_policy", "governance"), "suite", errors)
    if suite.get("schema_version") != "1.0.0":
        errors.append("suite.schema_version must be 1.0.0")
    for field in ("suite_id", "capability_class"):
        if not isinstance(suite.get(field), str) or not suite.get(field, "").strip():
            errors.append(f"suite.{field} must be non-empty")
    executor = require_mapping(suite.get("executor"), "executor", errors)
    if executor.get("authority_type") not in {"SKILLS_CAPABILITY_EVALUATOR", "SPECIALIZED_HARNESS", "PROJECT_NATIVE", "OTHER"}:
        errors.append("executor.authority_type is invalid")
    if not isinstance(executor.get("ref"), str) or not executor.get("ref", "").strip():
        errors.append("executor.ref must be non-empty")
    case_set = require_mapping(suite.get("case_set"), "case_set", errors)
    validate_sha256(case_set.get("digest"), "case_set.digest", errors)
    case_ids = case_set.get("case_ids")
    if not isinstance(case_ids, list) or not case_ids or not all(isinstance(x, str) and x for x in case_ids) or len(case_ids) != len(set(case_ids)):
        errors.append("case_set.case_ids must be unique non-empty strings")
    if case_set.get("validation_strategy") not in {"REGRESSION", "HOLDOUT", "DISJOINT"}:
        errors.append("case_set.validation_strategy is invalid")
    comparison = require_mapping(suite.get("comparison"), "comparison", errors)
    for key in ("paired_case_ids", "baseline_required", "fail_on_case_set_mismatch"):
        if comparison.get(key) is not True:
            errors.append(f"comparison.{key} must be true")
    metrics = suite.get("metrics")
    if not isinstance(metrics, list) or not metrics:
        errors.append("metrics must be non-empty")
    else:
        names: list[str] = []
        for index, metric in enumerate(metrics):
            metric = require_mapping(metric, f"metrics[{index}]", errors)
            require_fields(metric, ("name", "field", "aggregation", "direction", "threshold"), f"metrics[{index}]", errors)
            name = metric.get("name")
            field = metric.get("field")
            if not isinstance(name, str) or not name or not isinstance(field, str) or not field:
                errors.append(f"metrics[{index}] name/field are required")
            elif isinstance(name, str):
                names.append(name)
            if metric.get("aggregation") not in {"mean", "sum"}:
                errors.append(f"metrics[{index}].aggregation is invalid")
            if metric.get("direction") not in {"higher_is_better", "lower_is_better"}:
                errors.append(f"metrics[{index}].direction is invalid")
            threshold = require_mapping(metric.get("threshold"), f"metrics[{index}].threshold", errors)
            if threshold.get("operator") not in {">=", "<=", ">", "<", "=="}:
                errors.append(f"metrics[{index}].threshold.operator is invalid")
            if not isinstance(threshold.get("value"), (int, float)) or isinstance(threshold.get("value"), bool):
                errors.append(f"metrics[{index}].threshold.value must be numeric")
        if len(names) != len(set(names)):
            errors.append("metric names must be unique")
    policy = require_mapping(suite.get("regression_policy"), "regression_policy", errors)
    if policy.get("fail_on_candidate_critical") is not True:
        errors.append("regression_policy.fail_on_candidate_critical must be true")
    severities = policy.get("critical_severities")
    if not isinstance(severities, list) or not severities or any(x not in {"critical", "high", "medium", "low", "info"} for x in severities):
        errors.append("regression_policy.critical_severities is invalid")
    if not isinstance(policy.get("max_new_failures"), int) or isinstance(policy.get("max_new_failures"), bool) or policy.get("max_new_failures", -1) < 0:
        errors.append("regression_policy.max_new_failures must be non-negative integer")
    if not isinstance(policy.get("no_pass_rate_regression"), bool):
        errors.append("regression_policy.no_pass_rate_regression must be boolean")
    governance = require_mapping(suite.get("governance"), "governance", errors)
    if governance.get("functional_only") is not True:
        errors.append("governance.functional_only must be true")
    if governance.get("security_evaluation_separate") is not True:
        errors.append("governance.security_evaluation_separate must be true")
    if governance.get("promotion_authority") is not False:
        errors.append("evaluation suite must not have promotion authority")
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
        "evaluation_suite": "../schemas/evaluation-suite.schema.json",
        "architecture_promotion": "../schemas/architecture-promotion-record.schema.json",
        "adversarial_review_suite": "../schemas/adversarial-review-suite.schema.json",
        "ai_dependency_inventory": "../schemas/ai-dependency-inventory.schema.json",
        "constrained_task_plan": "../schemas/constrained-task-plan.schema.json",
        "external_authority_binding": "../schemas/external-authority-binding.schema.json",
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
    if kind == "evaluation-suite":
        return validate_evaluation_suite(data)
    if kind == "architecture-promotion":
        return validate_architecture_promotion(data)
    if kind == "adversarial-review-suite":
        return validate_adversarial_review_suite(data)
    if kind == "ai-dependency-inventory":
        return validate_ai_dependency_inventory(data)
    if kind == "constrained-task-plan":
        return validate_constrained_task_plan(data)
    if kind == "external-authority-binding":
        return validate_external_authority_binding(data)
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
        "schemas/evaluation-suite.schema.json",
        "schemas/architecture-promotion-record.schema.json",
        "schemas/adversarial-review-suite.schema.json",
        "schemas/ai-dependency-inventory.schema.json",
        "schemas/constrained-task-plan.schema.json",
        "schemas/external-authority-binding.schema.json",
        "scripts/build_project_context_packet.py",
        "scripts/build_project_context_packet_from_session.py",
        "scripts/compare_evaluation_runs.py",
        "scripts/build_constrained_task_plan.py",
        "scripts/build_external_authority_projection.py",
        "scripts/validate_ai_control_plane.py",
    ]
    for rel in required:
        if not (ROOT / rel).is_file():
            errors.append(f"missing required AI control-plane file: {rel}")
    if errors:
        return errors
    for rel in required[2:13]:
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
        "evaluation_suite_schema": "schemas/evaluation-suite.schema.json",
        "architecture_promotion_schema": "schemas/architecture-promotion-record.schema.json",
        "adversarial_review_suite_schema": "schemas/adversarial-review-suite.schema.json",
        "ai_dependency_inventory_schema": "schemas/ai-dependency-inventory.schema.json",
        "constrained_task_plan_schema": "schemas/constrained-task-plan.schema.json",
        "external_authority_binding_schema": "schemas/external-authority-binding.schema.json",
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
    if quality.get("eval_comparator") != "python3 scripts/compare_evaluation_runs.py":
        errors.append("project-control.json quality.eval_comparator is missing")
    if quality.get("adversarial_review_gate") != "python3 scripts/evaluate_adversarial_results.py":
        errors.append("project-control.json quality.adversarial_review_gate is missing")
    if quality.get("constrained_task_planner") != "python3 scripts/build_constrained_task_plan.py":
        errors.append("project-control.json quality.constrained_task_planner is missing")
    if quality.get("external_authority_projection") != "python3 scripts/build_external_authority_projection.py":
        errors.append("project-control.json quality.external_authority_projection is missing")
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
