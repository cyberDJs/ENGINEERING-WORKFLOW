from __future__ import annotations

import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
BUILDER = ROOT / "scripts/build_constrained_task_plan.py"
VALIDATOR = ROOT / "scripts/validate_ai_control_plane.py"


class ConstrainedTaskPlanTest(unittest.TestCase):
    def fixture(self, root: Path) -> tuple[Path, Path]:
        context = {
            "schema_version": "1.0.0",
            "packet_id": "PCP-test",
            "project": {"id": "p", "path": "/tmp/p", "branch": "main", "head": "a" * 40, "dirty": False},
            "task": {
                "objective": "bounded change",
                "mode": "IMPLEMENT",
                "scope_in": ["x"],
                "scope_out": [],
                "environment": "local",
            },
            "authority_sources": [{"path": "README.md", "sha256": "b" * 64, "content": ""}],
            "context_sources": [],
            "constraints": {
                "allowed_effects": ["read", "plan", "write", "git", "network", "deploy", "release"],
                "prohibited_effects": ["secrets"],
                "secret_policy": "no-secret-values",
            },
            "build": {"builder": "test", "built_at": "2026-10-04T00:00:00Z", "content_included": False},
        }
        mapping = {
            "schema_version": "1.0.0",
            "record_id": "CMR-test",
            "capability": {
                "id": "x/y",
                "class": "tool",
                "authority_mode": "BOUNDED_EXECUTION",
                "lifecycle_status": "ADMITTED",
            },
            "admission_refs": ["a"],
            "evaluation_refs": ["e"],
            "registry_binding": {
                "authority_type": "PROJECT_NATIVE",
                "registry_ref": "registry://capabilities",
                "capability_ref": "capability://x/y",
                "binding_status": "ACTIVATED",
            },
            "project_mappings": [
                {
                    "project_id": "p",
                    "project_ref": "p",
                    "status": "ENABLED",
                    "allowed_use": ["read", "plan", "write", "git", "network", "deploy", "release"],
                    "prohibited_use": [],
                    "environments": ["local"],
                    "execution_authority_ref": "AUTH-123",
                    "production_eligible": False,
                    "evidence_refs": ["e"],
                }
            ],
            "governance": {
                "mapping_grants_execution": False,
                "project_authority_required": True,
                "fail_closed_on_missing_binding": True,
            },
            "evidence": ["e"],
        }
        context_path = root / "context.json"
        mapping_path = root / "mapping.json"
        context_path.write_text(json.dumps(context), encoding="utf-8")
        mapping_path.write_text(json.dumps(mapping), encoding="utf-8")
        return context_path, mapping_path

    def run_plan(
        self,
        effects: list[str],
        authorities: tuple[str, ...] = (),
        *,
        mutate_context=None,
        mutate_mapping=None,
    ):
        temp = tempfile.TemporaryDirectory()
        root = Path(temp.name)
        context_path, mapping_path = self.fixture(root)
        if mutate_context is not None:
            context = json.loads(context_path.read_text(encoding="utf-8"))
            mutate_context(context)
            context_path.write_text(json.dumps(context), encoding="utf-8")
        if mutate_mapping is not None:
            mapping = json.loads(mapping_path.read_text(encoding="utf-8"))
            mutate_mapping(mapping)
            mapping_path.write_text(json.dumps(mapping), encoding="utf-8")
        output = root / "plan.json"
        command = [
            sys.executable,
            str(BUILDER),
            "--context",
            str(context_path),
            "--mapping",
            str(mapping_path),
            "--output",
            str(output),
        ]
        for effect in effects:
            command += ["--effect", effect]
        for authority in authorities:
            command += ["--authority", authority]
        result = subprocess.run(command, cwd=ROOT, text=True, capture_output=True, check=False)
        payload = json.loads(output.read_text(encoding="utf-8")) if output.exists() else None
        return temp, output, result, payload

    def test_protected_effect_requires_mapped_authority(self):
        temp, _, result, plan = self.run_plan(["read", "write"])
        self.addCleanup(temp.cleanup)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertEqual(plan["status"], "APPROVAL_REQUIRED")
        write = next(item for item in plan["effect_decisions"] if item["effect"] == "write")
        self.assertEqual(write["authority_ref"], "write:AUTH-123")
        self.assertFalse(plan["governance"]["execution_performed"])

    def test_attributable_mapped_authority_allows_plan_not_execution(self):
        temp, output, result, plan = self.run_plan(["write"], ("write:AUTH-123",))
        self.addCleanup(temp.cleanup)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertEqual(plan["status"], "PLANNED")
        self.assertFalse(plan["governance"]["plan_grants_execution"])
        valid = subprocess.run(
            [sys.executable, str(VALIDATOR), "--kind", "constrained-task-plan", "--file", str(output)],
            cwd=ROOT,
            text=True,
            capture_output=True,
            check=False,
        )
        self.assertEqual(valid.returncode, 0, valid.stdout + valid.stderr)

    def test_wrong_authority_reference_does_not_satisfy_mapping(self):
        temp, _, result, plan = self.run_plan(["write"], ("write:OTHER",))
        self.addCleanup(temp.cleanup)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertEqual(plan["status"], "APPROVAL_REQUIRED")
        self.assertEqual(plan["effect_decisions"][0]["authority_ref"], "write:AUTH-123")

    def test_invalid_mapping_is_rejected_before_planning(self):
        def mutate(mapping):
            mapping.clear()

        temp, output, result, plan = self.run_plan(["write"], ("write:AUTH-123",), mutate_mapping=mutate)
        self.addCleanup(temp.cleanup)
        self.assertNotEqual(result.returncode, 0)
        self.assertIsNone(plan)
        self.assertFalse(output.exists())
        self.assertIn("invalid capability mapping", result.stderr)

    def test_mapping_for_another_project_is_rejected(self):
        def mutate(mapping):
            mapping["project_mappings"][0]["project_id"] = "other"

        temp, output, result, plan = self.run_plan(["write"], ("write:AUTH-123",), mutate_mapping=mutate)
        self.addCleanup(temp.cleanup)
        self.assertNotEqual(result.returncode, 0)
        self.assertIsNone(plan)
        self.assertFalse(output.exists())
        self.assertIn("exactly one mapping for project", result.stderr)

    def test_terminal_mapping_lifecycle_is_rejected(self):
        def mutate(mapping):
            mapping["capability"]["lifecycle_status"] = "REJECTED"

        temp, output, result, plan = self.run_plan(["read"], mutate_mapping=mutate)
        self.addCleanup(temp.cleanup)
        self.assertNotEqual(result.returncode, 0)
        self.assertIsNone(plan)
        self.assertFalse(output.exists())
        self.assertIn("lifecycle state", result.stderr)

    def test_revoked_registry_binding_is_rejected_before_planning(self):
        def mutate(mapping):
            mapping["registry_binding"]["binding_status"] = "REVOKED"

        temp, output, result, plan = self.run_plan(["read"], mutate_mapping=mutate)
        self.addCleanup(temp.cleanup)
        self.assertNotEqual(result.returncode, 0)
        self.assertIsNone(plan)
        self.assertFalse(output.exists())
        self.assertIn("registry binding state is revoked", result.stderr)

    def test_read_only_authority_mode_blocks_write_even_with_authority(self):
        def mutate(mapping):
            mapping["capability"]["authority_mode"] = "READ_ONLY"

        temp, _, result, plan = self.run_plan(["write"], ("write:AUTH-123",), mutate_mapping=mutate)
        self.addCleanup(temp.cleanup)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertEqual(plan["status"], "BLOCKED")
        self.assertEqual(plan["effect_decisions"][0]["decision"], "DENY")

    def test_non_enabled_project_mapping_blocks_protected_effect(self):
        def mutate(mapping):
            mapping["project_mappings"][0]["status"] = "WATCH"
            mapping["project_mappings"][0]["execution_authority_ref"] = None

        temp, _, result, plan = self.run_plan(["write"], ("write:AUTH-123",), mutate_mapping=mutate)
        self.addCleanup(temp.cleanup)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertEqual(plan["status"], "BLOCKED")

    def test_non_activated_registry_binding_blocks_protected_effect(self):
        def mutate(mapping):
            mapping["registry_binding"]["binding_status"] = "REGISTERED"

        temp, _, result, plan = self.run_plan(["write"], ("write:AUTH-123",), mutate_mapping=mutate)
        self.addCleanup(temp.cleanup)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertEqual(plan["status"], "BLOCKED")

    def test_project_prohibited_use_blocks_effect(self):
        def mutate(mapping):
            mapping["project_mappings"][0]["prohibited_use"] = ["write"]

        temp, _, result, plan = self.run_plan(["write"], ("write:AUTH-123",), mutate_mapping=mutate)
        self.addCleanup(temp.cleanup)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertEqual(plan["status"], "BLOCKED")

    def test_explicit_effect_allowlist_blocks_unlisted_effect(self):
        def mutate(mapping):
            mapping["project_mappings"][0]["allowed_use"] = ["read", "plan"]

        temp, _, result, plan = self.run_plan(["write"], ("write:AUTH-123",), mutate_mapping=mutate)
        self.addCleanup(temp.cleanup)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertEqual(plan["status"], "BLOCKED")

    def test_mapping_environment_must_match_context(self):
        def mutate(context):
            context["task"]["environment"] = "staging"

        temp, _, result, plan = self.run_plan(["write"], ("write:AUTH-123",), mutate_context=mutate)
        self.addCleanup(temp.cleanup)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertEqual(plan["status"], "BLOCKED")

    def test_missing_environment_blocks_protected_effect(self):
        def mutate(context):
            context["task"].pop("environment")

        temp, _, result, plan = self.run_plan(["write"], ("write:AUTH-123",), mutate_context=mutate)
        self.addCleanup(temp.cleanup)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertEqual(plan["status"], "BLOCKED")

    def test_production_effect_requires_production_eligibility(self):
        temp, _, result, plan = self.run_plan(["deploy"], ("deploy:AUTH-123",))
        self.addCleanup(temp.cleanup)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertEqual(plan["status"], "BLOCKED")

    def test_production_use_marker_blocks_production_effect(self):
        def mutate(mapping):
            mapping["project_mappings"][0]["production_eligible"] = True
            mapping["project_mappings"][0]["prohibited_use"] = ["production"]

        temp, _, result, plan = self.run_plan(["deploy"], ("deploy:AUTH-123",), mutate_mapping=mutate)
        self.addCleanup(temp.cleanup)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertEqual(plan["status"], "BLOCKED")

    def test_context_prohibited_effect_blocks(self):
        def mutate(context):
            context["constraints"]["prohibited_effects"].append("git")

        temp, _, result, plan = self.run_plan(["git"], ("git:AUTH-123",), mutate_context=mutate)
        self.addCleanup(temp.cleanup)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertEqual(plan["status"], "BLOCKED")

    def test_unknown_effect_fails_closed(self):
        def mutate(context):
            context["constraints"]["allowed_effects"].append("teleport")

        temp, _, result, plan = self.run_plan(["teleport"], mutate_context=mutate)
        self.addCleanup(temp.cleanup)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertEqual(plan["status"], "BLOCKED")


if __name__ == "__main__":
    unittest.main()
