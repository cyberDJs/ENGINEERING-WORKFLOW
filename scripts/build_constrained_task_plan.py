#!/usr/bin/env python3
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path

from validate_ai_control_plane import validate_capability_mapping, validate_context_packet

PROTECTED = {"write", "shell", "git", "network", "deploy", "release"}
DENIED = {"secrets"}
KNOWN_EFFECTS = {"read", "plan", *PROTECTED, *DENIED}
PRODUCTION_EFFECTS = {"deploy", "release"}
PRODUCTION_USE_MARKERS = {"production", "production-authority"}
TERMINAL_CAPABILITY_STATES = {"DEPRECATED", "REJECTED"}
TERMINAL_PROJECT_STATES = {"REJECTED", "REVOKED"}
TERMINAL_BINDING_STATES = {"REVOKED"}
AUTHORITY_MODE_EFFECTS = {
    "EVALUATION_ONLY": {"read", "plan"},
    "ADVISORY": {"read", "plan"},
    "READ_ONLY": {"read", "plan"},
    "BOUNDED_EXECUTION": KNOWN_EFFECTS - DENIED,
}


def load(path: str) -> object:
    return json.loads(Path(path).read_text(encoding="utf-8"))


def fail(message: str) -> None:
    raise SystemExit(message)


def string_set(value: object, label: str) -> set[str]:
    if not isinstance(value, list) or not all(isinstance(item, str) and item.strip() for item in value):
        fail(f"{label} must be an array of non-empty strings")
    return set(value)


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
    context_errors = validate_context_packet(ctx)
    if context_errors:
        fail("invalid project context: " + "; ".join(context_errors))

    mapping_errors = validate_capability_mapping(mapping)
    if mapping_errors:
        fail("invalid capability mapping: " + "; ".join(mapping_errors))
    assert isinstance(mapping, dict)

    project = ctx.get("project")
    if not isinstance(project, dict) or not isinstance(project.get("id"), str) or not project["id"].strip():
        fail("project context must contain a non-empty project.id")
    project_id = project["id"]

    task = ctx.get("task")
    if not isinstance(task, dict):
        fail("project context task must be an object")
    environment = task.get("environment")
    if environment is not None and (not isinstance(environment, str) or not environment.strip()):
        fail("project context task.environment must be a non-empty string when present")

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

    binding = mapping["registry_binding"]
    if binding.get("binding_status") in TERMINAL_BINDING_STATES:
        fail("registry binding state is revoked and not eligible for task planning")

    allowed_use = string_set(project_mapping.get("allowed_use"), "project mapping allowed_use")
    prohibited_use = string_set(project_mapping.get("prohibited_use"), "project mapping prohibited_use")
    environments = string_set(project_mapping.get("environments"), "project mapping environments")
    explicit_effect_allowlist = allowed_use & KNOWN_EFFECTS
    authority_mode = capability.get("authority_mode")
    mode_effects = AUTHORITY_MODE_EFFECTS[authority_mode]

    auth = set(args.authority)
    constraints = ctx["constraints"]
    allowed = string_set(constraints.get("allowed_effects"), "project context allowed_effects")
    prohibited = string_set(constraints.get("prohibited_effects"), "project context prohibited_effects")
    decisions = []
    blocked = False
    approval = False

    for effect in sorted(set(args.effect)):
        decision = "DENY"
        ref = None

        if effect not in KNOWN_EFFECTS:
            blocked = True
        elif effect in DENIED or effect in prohibited or effect not in allowed:
            blocked = True
        elif effect in prohibited_use:
            blocked = True
        elif effect in PRODUCTION_EFFECTS and prohibited_use & PRODUCTION_USE_MARKERS:
            blocked = True
        elif explicit_effect_allowlist and effect not in explicit_effect_allowlist:
            blocked = True
        elif effect not in mode_effects:
            blocked = True
        elif effect in PROTECTED:
            if project_mapping.get("status") != "ENABLED":
                blocked = True
            elif binding.get("binding_status") != "ACTIVATED":
                blocked = True
            elif environment is None or environment not in environments:
                blocked = True
            elif effect in PRODUCTION_EFFECTS and project_mapping.get("production_eligible") is not True:
                blocked = True
            else:
                authority_ref = project_mapping.get("execution_authority_ref")
                if not isinstance(authority_ref, str) or not authority_ref.strip():
                    blocked = True
                else:
                    expected_ref = f"{effect}:{authority_ref}"
                    if expected_ref in auth:
                        decision = "ALLOW"
                        ref = expected_ref
                    else:
                        decision = "APPROVAL_REQUIRED"
                        ref = expected_ref
                        approval = True
        else:
            decision = "ALLOW"
            ref = "context-and-mapping-policy"

        if decision == "DENY":
            blocked = True
        decisions.append({"effect": effect, "decision": decision, "authority_ref": ref})

    status = "BLOCKED" if blocked else ("APPROVAL_REQUIRED" if approval else "PLANNED")
    raw = (str(args.context) + str(args.mapping) + json.dumps(decisions, sort_keys=True)).encode()
    plan_id = "CTP-" + hashlib.sha256(raw).hexdigest()[:16]
    out = {
        "schema_version": "1.0.0",
        "plan_id": plan_id,
        "project_context_ref": str(args.context),
        "capability_mapping_ref": str(args.mapping),
        "task": task,
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
