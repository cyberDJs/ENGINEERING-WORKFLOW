from __future__ import annotations

import hashlib
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
VALIDATOR = ROOT / "scripts/validate_ai_control_plane.py"
BUILDER = ROOT / "scripts/build_project_context_packet.py"
SESSION_BUILDER = ROOT / "scripts/build_project_context_packet_from_session.py"


class AIControlPlaneTest(unittest.TestCase):
    def run_record_validation(self, kind: str, payload: dict) -> subprocess.CompletedProcess[str]:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "record.json"
            path.write_text(json.dumps(payload), encoding="utf-8")
            return subprocess.run([sys.executable, str(VALIDATOR), "--kind", kind, "--file", str(path)], cwd=ROOT, text=True, capture_output=True, check=False)

    def test_repository_contract_validator_passes(self) -> None:
        result = subprocess.run([sys.executable, str(VALIDATOR)], cwd=ROOT, text=True, capture_output=True, check=False)
        self.assertEqual(result.returncode, 0, msg=result.stdout + result.stderr)
        self.assertIn("AI_CONTROL_PLANE_VALIDATION=PASSED", result.stdout)

    def test_artifact_admission_supports_non_runtime_artifacts_and_requires_digest(self) -> None:
        payload = {
            "schema_version": "1.0.0",
            "record_id": "AAR-test",
            "artifact": {"id": "example/benchmark", "type": "benchmark", "source": "https://example.invalid/benchmark", "revision": "abc", "digest": {"algorithm": "sha256", "value": "a" * 64}, "license": "Apache-2.0", "format": "JSON"},
            "ownership": {"owner": "Technical Steward", "project_scope": ["example"]},
            "security": {"risk_class": "LOW", "executable_surface": [], "trust_remote_code": False},
            "runtime": {"engine": None, "hardware_fit": "NOT_APPLICABLE"},
            "governance": {"status": "CANDIDATE", "allowed_use": ["evaluation"], "prohibited_use": ["production-authority"], "eval_baseline_ref": None, "rollback_ref": "remove-artifact-and-registry-entry"},
            "evidence": ["source-review"]
        }
        result = self.run_record_validation("artifact-admission", payload)
        self.assertEqual(result.returncode, 0, msg=result.stdout + result.stderr)
        payload["artifact"]["digest"]["value"] = "bad"
        result = self.run_record_validation("artifact-admission", payload)
        self.assertNotEqual(result.returncode, 0)

    def test_architecture_challenger_is_single_dimension_by_default(self) -> None:
        payload = {
            "schema_version": "1.0.0", "receipt_id": "EVAL-1", "evaluation_kind": "ARCHITECTURE_CHALLENGER", "subject": "retrieval challenger",
            "comparison": {"champion_ref": "arch-1.0", "challenger_ref": "arch-1.1-candidate"},
            "change_scope": {"changed_dimensions": ["retrieval"], "controlled_dimensions": ["decision-routing", "memory"]},
            "corpus": {"id": "retrieval-corpus-v1", "digest": "b" * 64, "validation_strategy": "DISJOINT"},
            "metrics": [{"name": "recall_at_10", "baseline": 0.7, "candidate": 0.8, "delta": 0.1}],
            "thresholds": [{"name": "recall_at_10", "operator": ">=", "value": 0.75}],
            "security_review": {"status": "PASS", "evidence_ref": "security-review.json"},
            "regression": {"status": "PASS", "evidence_ref": "regression.json"},
            "rollback": {"plan_ref": "rollback.md", "verified": True},
            "verdict": "PASS", "evidence": ["results.json"], "environment": {"runtime": "cpu"}, "evaluated_at": "2026-10-03T20:00:00Z"
        }
        result = self.run_record_validation("eval-receipt", payload)
        self.assertEqual(result.returncode, 0, msg=result.stdout + result.stderr)
        payload["metrics"][0]["delta"] = 0.2
        result = self.run_record_validation("eval-receipt", payload)
        self.assertNotEqual(result.returncode, 0)
        payload["metrics"][0]["delta"] = 0.1
        payload["change_scope"]["changed_dimensions"] = ["retrieval", "decision-routing"]
        result = self.run_record_validation("eval-receipt", payload)
        self.assertNotEqual(result.returncode, 0)
        payload["change_scope"]["multi_dimension_exception_ref"] = "ADR-EXPLICIT-COMBINED-CHANGE"
        result = self.run_record_validation("eval-receipt", payload)
        self.assertEqual(result.returncode, 0, msg=result.stdout + result.stderr)
        payload["thresholds"][0]["value"] = 0.95
        result = self.run_record_validation("eval-receipt", payload)
        self.assertNotEqual(result.returncode, 0)
        payload["thresholds"][0]["value"] = 0.75
        payload["security_review"]["evidence_ref"] = None
        result = self.run_record_validation("eval-receipt", payload)
        self.assertNotEqual(result.returncode, 0)

    def test_capability_mapping_never_grants_execution_and_enabled_requires_external_authority(self) -> None:
        payload = {
            "schema_version": "1.0.0",
            "record_id": "CMR-test",
            "capability": {"id": "decision-routing/jebadiah-native", "class": "decision-routing", "authority_mode": "ADVISORY", "lifecycle_status": "WATCH"},
            "admission_refs": ["artifact-admission.json"],
            "evaluation_refs": ["eval-receipt.json"],
            "registry_binding": {"authority_type": "VOODOO_ONE_EXECUTION_CAPABILITY", "registry_ref": "Voodoo-One:ImmutableCapabilityRegistry", "capability_ref": None, "binding_status": "UNBOUND"},
            "project_mappings": [{"project_id": "Voodoo-One", "project_ref": "PROJECT_CONSTITUTION.md", "status": "WATCH", "allowed_use": ["isolated-evaluation"], "prohibited_use": ["production-authority"], "environments": ["local-eval"], "execution_authority_ref": None, "production_eligible": False, "evidence_refs": ["eval-receipt.json"]}],
            "governance": {"mapping_grants_execution": False, "project_authority_required": True, "fail_closed_on_missing_binding": True},
            "evidence": ["promotion-decision.json"]
        }
        result = self.run_record_validation("capability-mapping", payload)
        self.assertEqual(result.returncode, 0, msg=result.stdout + result.stderr)
        payload["governance"]["mapping_grants_execution"] = True
        result = self.run_record_validation("capability-mapping", payload)
        self.assertNotEqual(result.returncode, 0)
        payload["governance"]["mapping_grants_execution"] = False
        payload["project_mappings"][0]["status"] = "ENABLED"
        payload["project_mappings"][0]["production_eligible"] = True
        result = self.run_record_validation("capability-mapping", payload)
        self.assertNotEqual(result.returncode, 0)

    def test_session_context_builder_excludes_experimental_and_rejects_git_drift(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            project = tmp_path / "project"
            project.mkdir()
            (project / "README.md").write_text("authority\n", encoding="utf-8")
            (project / "SECURITY.md").write_text("security\n", encoding="utf-8")
            supporting = project / "architecture.md"
            supporting.write_text("supporting\n", encoding="utf-8")
            experimental = project / "experimental.md"
            experimental.write_text("experimental\n", encoding="utf-8")
            subprocess.run(["git", "init", "-q", str(project)], check=True)
            subprocess.run(["git", "-C", str(project), "config", "user.email", "test@example.com"], check=True)
            subprocess.run(["git", "-C", str(project), "config", "user.name", "test"], check=True)
            subprocess.run(["git", "-C", str(project), "add", "."], check=True)
            subprocess.run(["git", "-C", str(project), "commit", "-qm", "seed"], check=True)
            head = subprocess.check_output(["git", "-C", str(project), "rev-parse", "HEAD"], text=True).strip()
            branch = subprocess.check_output(["git", "-C", str(project), "branch", "--show-current"], text=True).strip()
            session = {
                "status": "READY",
                "task": "assemble trusted context",
                "project": {
                    "path": str(project),
                    "authority_files": [str(project / "README.md"), str(project / "SECURITY.md")],
                    "git": {"root": str(project), "head": head, "branch": branch, "dirty": False},
                },
                "architecture_retrieval": {"load_set": [
                    {"path": str(supporting), "status": "CURRENT_SUPPORTING", "source": "project", "title": "AI control plane", "reasons": ["project-truth-priority"]},
                    {"path": str(experimental), "status": "EXPERIMENTAL", "source": "workflow_graph", "title": "experimental", "reasons": ["test"]},
                ]},
            }
            session_path = tmp_path / "session.json"
            output = tmp_path / "packet.json"
            session_path.write_text(json.dumps(session), encoding="utf-8")
            result = subprocess.run([sys.executable, str(SESSION_BUILDER), "--session", str(session_path), "--task-mode", "VERIFY", "--environment", "local-eval", "--scope-in", "trusted context", "--output", str(output)], cwd=ROOT, text=True, capture_output=True, check=False)
            self.assertEqual(result.returncode, 0, msg=result.stdout + result.stderr)
            packet = json.loads(output.read_text(encoding="utf-8"))
            self.assertEqual(packet["task"]["environment"], "local-eval")
            self.assertFalse(packet["build"]["content_included"])
            self.assertEqual(packet["build"]["excluded_status_counts"], {"EXPERIMENTAL": 1})
            self.assertEqual(len(packet["context_sources"]), 1)
            self.assertEqual(packet["context_sources"][0]["source_status"], "CURRENT_SUPPORTING")
            valid = subprocess.run([sys.executable, str(VALIDATOR), "--kind", "project-context", "--file", str(output)], cwd=ROOT, text=True, capture_output=True, check=False)
            self.assertEqual(valid.returncode, 0, msg=valid.stdout + valid.stderr)
            session["project"]["git"]["head"] = "0" * 40
            session_path.write_text(json.dumps(session), encoding="utf-8")
            drift = subprocess.run([sys.executable, str(SESSION_BUILDER), "--session", str(session_path), "--task-mode", "VERIFY", "--environment", "local-eval", "--scope-in", "trusted context", "--output", str(output)], cwd=ROOT, text=True, capture_output=True, check=False)
            self.assertNotEqual(drift.returncode, 0)
            self.assertIn("HEAD drifted", drift.stderr)

    def test_session_context_builder_rejects_dirty_runtime_session(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            head = subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=ROOT, text=True).strip()
            branch = subprocess.check_output(["git", "branch", "--show-current"], cwd=ROOT, text=True).strip()
            session = {
                "status": "READY",
                "task": "reject unbound dirty context",
                "project": {
                    "path": str(ROOT),
                    "authority_files": [str(ROOT / "README.md"), str(ROOT / "SECURITY.md")],
                    "git": {
                        "root": str(ROOT),
                        "head": head,
                        "branch": branch,
                        "dirty": True,
                        "status": [f"## {branch}", " M README.md"],
                    },
                },
                "architecture_retrieval": {"load_set": []},
            }
            session_path = tmp_path / "session.json"
            output = tmp_path / "packet.json"
            session_path.write_text(json.dumps(session), encoding="utf-8")
            result = subprocess.run(
                [sys.executable, str(SESSION_BUILDER), "--session", str(session_path), "--task-mode", "VERIFY", "--scope-in", "trusted context", "--output", str(output)],
                cwd=ROOT, text=True, capture_output=True, check=False,
            )
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("requires a clean runtime session worktree", result.stderr)
            self.assertFalse(output.exists())

    def test_context_builder_binds_git_state_and_authority_digest(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            output = Path(tmp) / "context.json"
            result = subprocess.run([
                sys.executable, str(BUILDER), "--project", str(ROOT), "--objective", "test context packet", "--mode", "VERIFY", "--environment", "local-eval",
                "--scope-in", "AI control-plane contracts", "--authority", str(ROOT / "README.md"), "--authority", str(ROOT / "SECURITY.md"),
                "--output", str(output)
            ], cwd=ROOT, text=True, capture_output=True, check=False)
            self.assertEqual(result.returncode, 0, msg=result.stdout + result.stderr)
            packet = json.loads(output.read_text(encoding="utf-8"))
            head = subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=ROOT, text=True).strip()
            self.assertEqual(packet["project"]["head"], head)
            self.assertEqual(packet["task"]["environment"], "local-eval")
            self.assertFalse(packet["build"]["content_included"])
            self.assertEqual(packet["authority_sources"][0]["content"], "")
            self.assertEqual(packet["authority_sources"][0]["sha256"], hashlib.sha256((ROOT / "README.md").read_bytes()).hexdigest())
            valid = subprocess.run([sys.executable, str(VALIDATOR), "--kind", "project-context", "--file", str(output)], cwd=ROOT, text=True, capture_output=True, check=False)
            self.assertEqual(valid.returncode, 0, msg=valid.stdout + valid.stderr)


if __name__ == "__main__":
    unittest.main()
