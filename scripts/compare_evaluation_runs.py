#!/usr/bin/env python3
"""Deterministically compare paired baseline/candidate evaluation JSONL runs."""
from __future__ import annotations

import argparse
import hashlib
import json
import math
import sys
from pathlib import Path

SEVERITIES = {"critical", "high", "medium", "low", "info"}
OPERATORS = {
    ">=": lambda a, b: a >= b,
    "<=": lambda a, b: a <= b,
    ">": lambda a, b: a > b,
    "<": lambda a, b: a < b,
    "==": lambda a, b: a == b,
}


def sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def load_json(path: Path) -> dict:
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise ValueError(f"{path}: expected JSON object")
    return value


def load_jsonl(path: Path) -> list[dict]:
    rows: list[dict] = []
    for line_no, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
        if not line.strip():
            continue
        value = json.loads(line)
        if not isinstance(value, dict):
            raise ValueError(f"{path}:{line_no}: expected JSON object")
        rows.append(value)
    if not rows:
        raise ValueError(f"{path}: no evaluation rows")
    return rows


def suite_errors(suite: dict) -> list[str]:
    errors: list[str] = []
    if suite.get("schema_version") != "1.0.0":
        errors.append("schema_version must be 1.0.0")
    if not isinstance(suite.get("suite_id"), str) or not suite.get("suite_id", "").strip():
        errors.append("suite_id is required")
    if not isinstance(suite.get("capability_class"), str) or not suite.get("capability_class", "").strip():
        errors.append("capability_class is required")
    executor = suite.get("executor")
    if not isinstance(executor, dict) or executor.get("authority_type") not in {"SKILLS_CAPABILITY_EVALUATOR", "SPECIALIZED_HARNESS", "PROJECT_NATIVE", "OTHER"} or not executor.get("ref"):
        errors.append("executor authority_type/ref is invalid")
    case_set = suite.get("case_set")
    if not isinstance(case_set, dict):
        errors.append("case_set is required")
    else:
        digest = case_set.get("digest")
        ids = case_set.get("case_ids")
        if not isinstance(digest, str) or len(digest) != 64 or any(c not in "0123456789abcdef" for c in digest):
            errors.append("case_set.digest must be lowercase sha256")
        if not isinstance(ids, list) or not ids or not all(isinstance(x, str) and x for x in ids) or len(ids) != len(set(ids)):
            errors.append("case_set.case_ids must be unique non-empty strings")
        if case_set.get("validation_strategy") not in {"REGRESSION", "HOLDOUT", "DISJOINT"}:
            errors.append("case_set.validation_strategy is invalid")
    comparison = suite.get("comparison")
    if not isinstance(comparison, dict) or any(comparison.get(k) is not True for k in ("paired_case_ids", "baseline_required", "fail_on_case_set_mismatch")):
        errors.append("comparison must require paired baseline/candidate case IDs")
    metrics = suite.get("metrics")
    if not isinstance(metrics, list) or not metrics:
        errors.append("metrics must be non-empty")
    else:
        names: list[str] = []
        for index, metric in enumerate(metrics):
            if not isinstance(metric, dict):
                errors.append(f"metrics[{index}] must be an object")
                continue
            name, field = metric.get("name"), metric.get("field")
            if not isinstance(name, str) or not name or not isinstance(field, str) or not field:
                errors.append(f"metrics[{index}] name/field are required")
            else:
                names.append(name)
            if metric.get("aggregation") not in {"mean", "sum"}:
                errors.append(f"metrics[{index}].aggregation is invalid")
            if metric.get("direction") not in {"higher_is_better", "lower_is_better"}:
                errors.append(f"metrics[{index}].direction is invalid")
            threshold = metric.get("threshold")
            if not isinstance(threshold, dict) or threshold.get("operator") not in OPERATORS or not isinstance(threshold.get("value"), (int, float)) or isinstance(threshold.get("value"), bool):
                errors.append(f"metrics[{index}].threshold is invalid")
        if len(names) != len(set(names)):
            errors.append("metric names must be unique")
    policy = suite.get("regression_policy")
    if not isinstance(policy, dict):
        errors.append("regression_policy is required")
    else:
        if policy.get("fail_on_candidate_critical") is not True:
            errors.append("regression_policy.fail_on_candidate_critical must be true")
        severities = policy.get("critical_severities")
        if not isinstance(severities, list) or not severities or any(x not in SEVERITIES for x in severities):
            errors.append("regression_policy.critical_severities is invalid")
        if not isinstance(policy.get("max_new_failures"), int) or isinstance(policy.get("max_new_failures"), bool) or policy.get("max_new_failures", -1) < 0:
            errors.append("regression_policy.max_new_failures must be non-negative integer")
        if not isinstance(policy.get("no_pass_rate_regression"), bool):
            errors.append("regression_policy.no_pass_rate_regression must be boolean")
    governance = suite.get("governance")
    if not isinstance(governance, dict) or governance.get("functional_only") is not True or governance.get("security_evaluation_separate") is not True or governance.get("promotion_authority") is not False:
        errors.append("governance must keep functional evaluation separate and non-authoritative")
    return errors


def index_rows(rows: list[dict], label: str, metric_fields: list[str]) -> dict[str, dict]:
    indexed: dict[str, dict] = {}
    for index, row in enumerate(rows):
        case_id = row.get("case_id")
        if not isinstance(case_id, str) or not case_id:
            raise ValueError(f"{label}[{index}]: case_id is required")
        if case_id in indexed:
            raise ValueError(f"{label}: duplicate case_id {case_id}")
        if type(row.get("pass")) is not bool:
            raise ValueError(f"{label}/{case_id}: pass must be boolean")
        severity = row.get("severity_if_failed")
        if severity not in SEVERITIES:
            raise ValueError(f"{label}/{case_id}: severity_if_failed is invalid")
        for field in metric_fields:
            value = row.get(field)
            if not isinstance(value, (int, float)) or isinstance(value, bool) or not math.isfinite(float(value)):
                raise ValueError(f"{label}/{case_id}: metric field {field!r} must be finite numeric")
        indexed[case_id] = row
    return indexed


def aggregate(rows: dict[str, dict], field: str, method: str) -> float:
    values = [float(row[field]) for row in rows.values()]
    return sum(values) / len(values) if method == "mean" else sum(values)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--suite", type=Path, required=True)
    parser.add_argument("--case-manifest", type=Path, required=True)
    parser.add_argument("--baseline", type=Path, required=True)
    parser.add_argument("--candidate", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    try:
        suite = load_json(args.suite)
        errors = suite_errors(suite)
        if errors:
            raise ValueError("; ".join(errors))
        manifest_digest = sha256(args.case_manifest)
        if manifest_digest != suite["case_set"]["digest"]:
            raise ValueError("case manifest digest does not match frozen suite")
        metric_fields = [metric["field"] for metric in suite["metrics"]]
        baseline = index_rows(load_jsonl(args.baseline), "baseline", metric_fields)
        candidate = index_rows(load_jsonl(args.candidate), "candidate", metric_fields)
        expected_ids = suite["case_set"]["case_ids"]
        if set(baseline) != set(expected_ids) or set(candidate) != set(expected_ids):
            raise ValueError("baseline/candidate case IDs must exactly match frozen suite case IDs")
        for case_id in expected_ids:
            if baseline[case_id]["severity_if_failed"] != candidate[case_id]["severity_if_failed"]:
                raise ValueError(f"severity drift for case {case_id}")

        baseline_passed = sum(1 for row in baseline.values() if row["pass"])
        candidate_passed = sum(1 for row in candidate.values() if row["pass"])
        case_count = len(expected_ids)
        baseline_rate = baseline_passed / case_count
        candidate_rate = candidate_passed / case_count
        regressions = [case_id for case_id in expected_ids if baseline[case_id]["pass"] and not candidate[case_id]["pass"]]
        improvements = [case_id for case_id in expected_ids if not baseline[case_id]["pass"] and candidate[case_id]["pass"]]
        critical_set = set(suite["regression_policy"]["critical_severities"])
        critical_failures = [case_id for case_id in expected_ids if not candidate[case_id]["pass"] and candidate[case_id]["severity_if_failed"] in critical_set]
        new_critical_failures = [case_id for case_id in regressions if candidate[case_id]["severity_if_failed"] in critical_set]

        metric_results = []
        threshold_failures = []
        for metric in suite["metrics"]:
            base_value = aggregate(baseline, metric["field"], metric["aggregation"])
            cand_value = aggregate(candidate, metric["field"], metric["aggregation"])
            threshold = metric["threshold"]
            satisfied = OPERATORS[threshold["operator"]](cand_value, float(threshold["value"]))
            if not satisfied:
                threshold_failures.append(metric["name"])
            metric_results.append({
                "name": metric["name"], "field": metric["field"], "aggregation": metric["aggregation"],
                "direction": metric["direction"], "baseline": base_value, "candidate": cand_value,
                "delta": cand_value - base_value, "threshold": threshold, "threshold_satisfied": satisfied,
            })

        blockers = []
        policy = suite["regression_policy"]
        if critical_failures and policy["fail_on_candidate_critical"]:
            blockers.append("candidate-critical-failure")
        if len(regressions) > policy["max_new_failures"]:
            blockers.append("new-regression-budget-exceeded")
        if policy["no_pass_rate_regression"] and candidate_rate < baseline_rate:
            blockers.append("pass-rate-regression")
        if threshold_failures:
            blockers.append("metric-threshold-failure")
        verdict = "PASS" if not blockers else "FAIL"
        output = {
            "schema_version": "1.0.0",
            "suite_id": suite["suite_id"],
            "functional_verdict": verdict,
            "blockers": blockers,
            "promotion_authority": False,
            "security_evaluation": "NOT_EVALUATED",
            "inputs": {
                "suite_sha256": sha256(args.suite),
                "case_manifest_sha256": manifest_digest,
                "baseline_sha256": sha256(args.baseline),
                "candidate_sha256": sha256(args.candidate),
            },
            "cases": {
                "count": case_count,
                "baseline_passed": baseline_passed,
                "candidate_passed": candidate_passed,
                "baseline_pass_rate": baseline_rate,
                "candidate_pass_rate": candidate_rate,
                "regressions": regressions,
                "improvements": improvements,
                "candidate_critical_failures": critical_failures,
                "new_critical_failures": new_critical_failures,
            },
            "metrics": metric_results,
            "threshold_failures": threshold_failures,
            "executor": suite["executor"],
            "case_set": suite["case_set"],
            "governance": suite["governance"],
        }
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(json.dumps(output, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        print("EVAL_COMPARISON=" + verdict)
        print(f"CASES={case_count}")
        print(f"REGRESSIONS={len(regressions)}")
        print(f"CRITICAL_FAILURES={len(critical_failures)}")
        print(f"PROMOTION_AUTHORITY={str(output['promotion_authority']).lower()}")
        return 0 if verdict == "PASS" else 1
    except Exception as exc:
        print("EVAL_COMPARISON=INVALID", file=sys.stderr)
        print(f"ERROR: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
