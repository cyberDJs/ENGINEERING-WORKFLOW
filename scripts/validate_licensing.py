#!/usr/bin/env python3
"""Fail-closed validation for proprietary ownership and licensing controls."""
from __future__ import annotations

import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]

REQUIRED_FILES = (
    "LICENSE",
    "COPYRIGHT",
    "CONTRIBUTING.md",
    "governance/EXCLUSIVE_RIGHTS_AND_LICENSING_POLICY.md",
    "governance/OWNERSHIP_IP_AND_PROVENANCE.md",
    "governance/IP_PROVENANCE_REGISTER.json",
    "schemas/ip-provenance-register.schema.json",
    "evidence/IP_PROVENANCE_AUDIT_20260726.json",
    "evidence/IP_PROVENANCE_AUDIT_20260726.md",
)

REQUIRED_RELEASE_GATES = {
    "LEGAL_IDENTITY_VERIFIED",
    "FILE_LEVEL_PROVENANCE_COMPLETE",
    "HUMAN_CONTRIBUTOR_RIGHTS_RESOLVED",
    "AI_AUTHORSHIP_EVIDENCE_COMPLETE",
    "THIRD_PARTY_LICENSES_CLASSIFIED",
    "LICENSING_VALIDATOR_PASSED",
    "EXPLICIT_RELEASE_AUTHORIZATION",
}

BLOCKED_DISTRIBUTION_FIELDS = {
    "public_source_release",
    "binary_release",
    "package_publication",
    "commercial_licensing",
}


def main() -> int:
    errors: list[str] = []

    for relative in REQUIRED_FILES:
        if not (ROOT / relative).is_file():
            errors.append(f"missing licensing control: {relative}")

    license_path = ROOT / "LICENSE"
    if license_path.is_file():
        text = license_path.read_text(encoding="utf-8")
        for marker in (
            "PROPRIETARY LICENSE NOTICE",
            "Copyright © 2026 Eimy Herrer",
            "All rights reserved",
            "No open-source license is granted",
        ):
            if marker not in text:
                errors.append(f"LICENSE missing required marker: {marker}")

    control_path = ROOT / "project-control.json"
    try:
        control = json.loads(control_path.read_text(encoding="utf-8"))
        licensing = control["licensing"]
    except Exception as exc:
        errors.append(f"project-control licensing section invalid: {exc}")
        licensing = {}

    expected_control = {
        "model": "proprietary-all-rights-reserved",
        "intended_exclusive_rights_holder": "Eimy Herrer",
        "release_authority": "Eimy Herrer",
        "open_source_project_license_granted": False,
        "provenance_register": "governance/IP_PROVENANCE_REGISTER.json",
        "policy": "governance/EXCLUSIVE_RIGHTS_AND_LICENSING_POLICY.md",
        "distribution_requires_verified_exclusive_control": True,
    }
    for key, expected in expected_control.items():
        if licensing.get(key) != expected:
            errors.append(f"project-control licensing.{key} must equal {expected!r}")

    try:
        register = json.loads(
            (ROOT / "governance/IP_PROVENANCE_REGISTER.json").read_text(encoding="utf-8")
        )
    except Exception as exc:
        errors.append(f"IP provenance register invalid JSON: {exc}")
        register = {}

    expected_register = {
        "schema_version": 1,
        "project": "ENGINEERING-WORKFLOW",
        "licensing_model": "proprietary-all-rights-reserved",
        "release_authority": "Eimy Herrer",
        "open_source_project_license_granted": False,
    }
    for key, expected in expected_register.items():
        if register.get(key) != expected:
            errors.append(f"IP provenance register {key} must equal {expected!r}")

    rights_holder = register.get("intended_exclusive_rights_holder", {})
    if rights_holder.get("display_name") != "Eimy Herrer":
        errors.append("IP provenance register rights holder must be Eimy Herrer")

    status = register.get("exclusive_control_status")
    allowed_statuses = {
        "BLOCKED_PENDING_CONTRIBUTOR_AND_AI_PROVENANCE_AUDIT",
        "AUDIT_COMPLETE_BLOCKED_PENDING_RIGHTS_RESOLUTION",
        "VERIFIED_EXCLUSIVE_CONTROL",
    }
    if status not in allowed_statuses:
        errors.append(f"unsupported exclusive control status: {status!r}")


    audit = register.get("provenance_audit", {})
    if status == "AUDIT_COMPLETE_BLOCKED_PENDING_RIGHTS_RESOLUTION":
        expected_audit = {
            "status": "COMPLETE",
            "audit_id": "EW-IP-AUDIT-20260726-001",
            "audited_head": "8beb2f1157cc95c51827842a5630cfc7f9d6e81d",
            "machine_readable_report": "evidence/IP_PROVENANCE_AUDIT_20260726.json",
            "human_readable_report": "evidence/IP_PROVENANCE_AUDIT_20260726.md",
            "total_files": 151,
            "shared_owner_marker_files": 63,
            "direct_johny_github_contributions_found": False,
            "verified_exclusive_control": False,
        }
        for key, expected in expected_audit.items():
            if audit.get(key) != expected:
                errors.append(f"provenance_audit.{key} must equal {expected!r}")
        try:
            report = json.loads((ROOT / audit["machine_readable_report"]).read_text(encoding="utf-8"))
            if report.get("audit_id") != audit["audit_id"]:
                errors.append("machine-readable audit id mismatch")
            if report.get("audited_head") != audit["audited_head"]:
                errors.append("machine-readable audited head mismatch")
            if report.get("file_level_summary", {}).get("total_files") != audit["total_files"]:
                errors.append("machine-readable file count mismatch")
            if report.get("exclusive_control_decision", {}).get("verified_exclusive_control") is not False:
                errors.append("audit must not claim verified exclusive control")
        except Exception as exc:
            errors.append(f"IP provenance audit invalid: {exc}")

    distribution = register.get("distribution", {})
    if status != "VERIFIED_EXCLUSIVE_CONTROL":
        for field in BLOCKED_DISTRIBUTION_FIELDS:
            if distribution.get(field) != "BLOCKED":
                errors.append(
                    f"distribution.{field} must remain BLOCKED until exclusive control is verified"
                )

    contribution = register.get("contribution_policy", {})
    if contribution.get("external_contributions") != "CLOSED_BY_DEFAULT":
        errors.append("external contributions must be CLOSED_BY_DEFAULT")
    if contribution.get("dco_alone_is_sufficient") is not False:
        errors.append("DCO alone must not be sufficient")
    if contribution.get("required_instrument") != (
        "PROJECT_SPECIFIC_WRITTEN_EXCLUSIVE_RIGHTS_AGREEMENT"
    ):
        errors.append("exclusive written rights agreement must be required")

    release_gates = set(register.get("release_gates", []))
    missing_gates = sorted(REQUIRED_RELEASE_GATES - release_gates)
    if missing_gates:
        errors.append("IP provenance register missing release gates: " + ", ".join(missing_gates))

    scopes = register.get("provenance_scopes", [])
    categories = {item.get("category") for item in scopes if isinstance(item, dict)}
    required_categories = {"human-authored", "human-collaborator", "ai-assisted", "third-party"}
    missing_categories = sorted(required_categories - categories)
    if missing_categories:
        errors.append("IP provenance register missing categories: " + ", ".join(missing_categories))

    contributing = ROOT / "CONTRIBUTING.md"
    if contributing.is_file():
        contribution_text = contributing.read_text(encoding="utf-8")
        for marker in (
            "External contributions are **closed by default**",
            "exclusive rights agreement",
            "DCO `Signed-off-by` line",
        ):
            if marker not in contribution_text:
                errors.append(f"CONTRIBUTING.md missing rights marker: {marker}")

    if errors:
        print("LICENSING_VALIDATION=FAILED")
        for item in errors:
            print(f"ERROR: {item}")
        return 1

    print("LICENSING_VALIDATION=PASSED")
    print(f"LICENSING_MODEL={register['licensing_model']}")
    print(f"INTENDED_EXCLUSIVE_RIGHTS_HOLDER={rights_holder['display_name']}")
    print(f"EXCLUSIVE_CONTROL_STATUS={status}")
    print("EXTERNAL_DISTRIBUTION=BLOCKED")
    return 0


if __name__ == "__main__":
    sys.exit(main())
