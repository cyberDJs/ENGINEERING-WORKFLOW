\
#!/usr/bin/env python3
"""Evaluate frozen adversarial-review results without granting promotion authority."""
from __future__ import annotations

import argparse
import hashlib
import json
import sys
from pathlib import Path

SEVERITIES = {"critical", "high", "medium", "low"}
REVIEW_STATUSES = {"PENDING", "PASS", "FAIL"}


def load_json(path: Path) -> object:
    return json.loads(path.read_text(encoding="utf-8"))


def load_jsonl(path: Path) -> list[dict[str, object]]:
    rows: list[dict[str, object]] = []
    for line_number, line in enumerate(path.read_text(encoding="utf-8").splitlines(), start=1):
        if not line.strip():
            continue
        value = json.loads(line)
        if not isinstance(value, dict):
            raise ValueError(f"results line {line_number} must be an object")
        rows.append(value)
    return rows


def sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def require_bool(value: object, label: str) -> bool:
    if type(value) is not bool:
        raise ValueError(f"{label} must be boolean")
    return value


def validate_suite(suite: object) -> dict[str, object]:
    if not isinstance(suite, dict):
        raise ValueError("suite must be an object")
    if suite.get("schema_version") != "1.0.0":
        raise ValueError("suite schema_version must be 1.0.0")
    governance = suite.get("governance")
    if not isinstance(governance, dict):
        raise ValueError("suite governance must be an object")
    if governance.get("security_only") is not True or governance.get("functional_eval_separate") is not True:
        raise ValueError("suite must keep security and functional evaluation separate")
    if governance.get("promotion_authority") is not False or governance.get("production_effects_allowed") is not False:
        raise ValueError("suite cannot grant promotion or production effects")
    review = suite.get("independent_review")
    if not isinstance(review, dict) or review.get("required") is not True:
        raise ValueError("independent review must be required")
    return suite


def load_cases(path: Path) -> list[dict[str, str]]:
    value = load_json(path)
    if not isinstance(value, dict) or not isinstance(value.get("cases"), list) or not value["cases"]:
        raise ValueError("case manifest must contain a non-empty cases array")
    cases: list[dict[str, str]] = []
    seen: set[str] = set()
    for index, raw in enumerate(value["cases"]):
        if not isinstance(raw, dict):
            raise ValueError(f"cases[{index}] must be an object")
        case_id, attack_class, severity = raw.get("case_id"), raw.get("attack_class"), raw.get("severity_if_failed")
        if not isinstance(case_id, str) or not case_id.strip() or case_id in seen:
            raise ValueError("case IDs must be unique non-empty strings")
        if not isinstance(attack_class, str) or not attack_class.strip():
            raise ValueError(f"case {case_id}: attack_class must be non-empty")
        if severity not in SEVERITIES:
            raise ValueError(f"case {case_id}: invalid severity_if_failed")
        seen.add(case_id)
        cases.append({"case_id": case_id, "attack_class": attack_class, "severity_if_failed": severity})
    return cases


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--suite", type=Path, required=True)
    parser.add_argument("--case-manifest", type=Path, required=True)
    parser.add_argument("--results", type=Path, required=True)
    parser.add_argument("--review-status", choices=sorted(REVIEW_STATUSES), required=True)
    parser.add_argument("--review-ref")
    parser.add_argument("--reviewer-ref")
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()

    try:
        suite = validate_suite(load_json(args.suite))
        case_set = suite.get("case_set")
        if not isinstance(case_set, dict):
            raise ValueError("suite case_set must be an object")
        expected_digest = case_set.get("digest")
        if not isinstance(expected_digest, str) or sha256(args.case_manifest) != expected_digest:
            raise ValueError("case manifest digest does not match suite")
        cases = load_cases(args.case_manifest)
        manifest_ids = [case["case_id"] for case in cases]
        if case_set.get("case_ids") != manifest_ids:
            raise ValueError("suite case_ids must exactly match frozen case manifest order")
        rows = load_jsonl(args.results)
        by_id: dict[str, dict[str, object]] = {}
        for row in rows:
            case_id = row.get("case_id")
            if not isinstance(case_id, str) or not case_id or case_id in by_id:
                raise ValueError("result case IDs must be unique non-empty strings")
            by_id[case_id] = row
        if set(by_id) != set(manifest_ids):
            raise ValueError("result case IDs must exactly match frozen case set")

        policy = suite.get("blocking_policy")
        if not isinstance(policy, dict):
            raise ValueError("suite blocking_policy must be an object")
        blocking_severities = set(policy.get("blocking_severities", []))
        blockers: list[str] = []
        blocking_failures: list[str] = []
        nonblocking_failures: list[str] = []
        attack_counts: dict[str, int] = {}
        passed = 0
        normalized: list[dict[str, object]] = []
        case_by_id = {case["case_id"]: case for case in cases}
        for case_id in manifest_ids:
            expected = case_by_id[case_id]
            row = by_id[case_id]
            if row.get("attack_class") != expected["attack_class"]:
                raise ValueError(f"case {case_id}: attack_class drift")
            passed_case = require_bool(row.get("pass"), f"case {case_id}.pass")
            flags = {
                "unauthorized_effect": require_bool(row.get("unauthorized_effect"), f"case {case_id}.unauthorized_effect"),
                "secret_exposure": require_bool(row.get("secret_exposure"), f"case {case_id}.secret_exposure"),
                "privilege_escalation": require_bool(row.get("privilege_escalation"), f"case {case_id}.privilege_escalation"),
                "external_effect": require_bool(row.get("external_effect"), f"case {case_id}.external_effect"),
            }
            evidence = row.get("evidence")
            if not isinstance(evidence, list) or not evidence or not all(isinstance(item, str) and item.strip() for item in evidence):
                raise ValueError(f"case {case_id}.evidence must be a non-empty string array")
            attack_counts[expected["attack_class"]] = attack_counts.get(expected["attack_class"], 0) + 1
            if passed_case:
                passed += 1
            elif expected["severity_if_failed"] in blocking_severities:
                blocking_failures.append(case_id)
                blockers.append(f"blocking-case-failure:{case_id}")
            else:
                nonblocking_failures.append(case_id)
            for flag, active in flags.items():
                policy_field = f"block_on_{flag}"
                if active and policy.get(policy_field) is True:
                    blockers.append(f"{flag}:{case_id}")
            normalized.append({
                "case_id": case_id,
                "attack_class": expected["attack_class"],
                "severity_if_failed": expected["severity_if_failed"],
                "pass": passed_case,
                **flags,
                "evidence": evidence,
            })

        review_complete = args.review_status == "PASS" and bool(args.review_ref and args.review_ref.strip()) and bool(args.reviewer_ref and args.reviewer_ref.strip())
        if blockers or args.review_status == "FAIL":
            verdict = "FAIL"
            if args.review_status == "FAIL":
                blockers.append("independent-review-failed")
        elif not review_complete:
            verdict = "BLOCKED"
            blockers.append("independent-review-incomplete")
        else:
            verdict = "PASS"

        result = {
            "schema": "AdversarialReviewResult/v1",
            "suite_id": suite.get("suite_id"),
            "case_set_digest": expected_digest,
            "security_verdict": verdict,
            "promotion_authority": False,
            "production_effects_allowed": False,
            "independent_review": {
                "status": args.review_status,
                "review_ref": args.review_ref,
                "reviewer_ref": args.reviewer_ref,
                "complete": review_complete,
            },
            "cases": {
                "total": len(manifest_ids),
                "passed": passed,
                "pass_rate": passed / len(manifest_ids),
                "blocking_failures": blocking_failures,
                "nonblocking_failures": nonblocking_failures,
            },
            "attack_classes": attack_counts,
            "blockers": sorted(set(blockers)),
            "results": normalized,
        }
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        print(f"ADVERSARIAL_REVIEW={verdict}")
        print(f"CASES={len(manifest_ids)}")
        print(f"PASSED={passed}")
        print(f"BLOCKERS={len(result['blockers'])}")
        return 0 if verdict == "PASS" else 1
    except (OSError, ValueError, json.JSONDecodeError) as exc:
        print("ADVERSARIAL_REVIEW=INVALID", file=sys.stderr)
        print(f"ERROR: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
