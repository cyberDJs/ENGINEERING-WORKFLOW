#!/usr/bin/env python3
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path

from validate_ai_control_plane import validate_capability_mapping

PROTECTED = {"write", "shell", "git", "network", "deploy", "release"}
DENIED = {"secrets"}
TERMINAL_CAPABILITY_STATES = {"DEPRECATED", "REJECTED"}
TERMINAL_PROJECT_STATES = {"REJECTED", "REVOKED"}


def load(path: str) -> object:
    return json.loads(Path(path).read_text(encoding="utf-8"))


def fail(message: str) -> None:
    raise SystemExit(message)


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--context", required=True)
    parser.add_argument("--mapping", required=True)
    parser.add_argument("--effect", action="append", default=[])
    parser.add_argument("--authority", action="append", default=[])
    parser.add_argument("--output", required=True)
    args = parser.parse_args()

    ctx = load(args.context)
    mapping = load(args.mapping)
    if not isinstance(ctx, dict):
        fail("project context must be an object")

    mapping_errors = validate_capability_mapping(mapping)
    if mapping_errors:
        fail("invalid capability mapping: " + "; ".join(mapping_errors))
    assert isinstance(mapping, dict)

    project = ctx.get("project")
    if not isinstance(project, dict) or not isinstance(project.get("id"), str) or not project["id"].strip():
        fail("project context must contain a non-empty project.id")
    project_id = project["id"]

    project_mappings = mapping["project_mappings"]
    matches = [item for item in project_mappings if item.get("project_id") == project_id]
    if len(matches) != 1:
        fail(f"capability mapping must contain exactly one mapping for project {project_id!r}")
    project_mapping = matches[0]

    capability = mapping["capability"]
    if capability.get("lifecycle_status") in TERMINAL_CAPABILITY_STATES:
        fail("capability lifecycle state is not eligible for task planning")
    if project_mapping.get("status") in TERMINAL_PROJECT_STATES:
        fail("project capability mapping state is not eligible for task planning")

    auth = set(args.authority)
    allowed = set(ctx.get("constraints", {}).get("allowed_effects", []))
    prohibited = set(ctx.get("constraints", {}).get("prohibited_effects", []))
    decisions = []
    blocked = False
    approval = False
    for effect in sorted(set(args.effect)):
        if effect in DENIED or effect in prohibited or effect not in allowed:
            decision = "DENY"
            ref = None
            blocked = True
        elif effect in PROTECTED:
            ref = next((item for item in auth if item.startswith(effect + ":")), None)
            decision = "ALLOW" if ref else "APPROVAL_REQUIRED"
            approval |= ref is None
        else:
            decision = "ALLOW"
            ref = "context-policy"
        decisions.append({"effect": effect, "decision": decision, "authority_ref": ref})

    status = "BLOCKED" if blocked else ("APPROVAL_REQUIRED" if approval else "PLANNED")
    raw = (str(args.context) + str(args.mapping) + json.dumps(decisions, sort_keys=True)).encode()
    plan_id = "CTP-" + hashlib.sha256(raw).hexdigest()[:16]
    out = {
        "schema_version": "1.0.0",
        "plan_id": plan_id,
        "project_context_ref": str(args.context),
        "capability_mapping_ref": str(args.mapping),
        "task": ctx.get("task", {}),
        "requested_effects": sorted(set(args.effect)),
        "effect_decisions": decisions,
        "status": status,
        "governance": {
            "plan_only": True,
            "execution_performed": False,
            "plan_grants_execution": False,
            "fail_closed": True,
        },
        "evidence": [str(args.context), str(args.mapping)],
    }
    Path(args.output).write_text(json.dumps(out, indent=2) + "\n", encoding="utf-8")
    print(f"PLAN_STATUS={status}")
    print(f"PLAN_ID={plan_id}")


if __name__ == "__main__":
    main()
