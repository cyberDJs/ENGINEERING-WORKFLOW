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

    def test_artifact_admission_requires_digest_and_rollback(self) -> None:
        payload = {
            "schema_version": "1.0.0",
            "record_id": "AAR-test",
            "artifact": {"id": "example/model", "type": "model", "source": "https://example.invalid/model", "revision": "abc", "digest": {"algorithm": "sha256", "value": "a" * 64}, "license": "Apache-2.0", "format": "GGUF"},
            "ownership": {"owner": "Technical Steward", "project_scope": ["example"]},
            "security": {"risk_class": "LOW", "executable_surface": [], "trust_remote_code": False},
            "runtime": {"engine": "llama.cpp", "hardware_fit": "FIT"},
            "governance": {"status": "CANDIDATE", "allowed_use": ["evaluation"], "prohibited_use": ["production-authority"], "eval_baseline_ref": None, "rollback_ref": "remove-artifact-and-registry-entry"},
            "evidence": ["model-card"]
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
            "corpus": {"id": "retrieval-corpus-v1", "digest": "b" * 64},
            "metrics": [{"name": "recall_at_10", "baseline": 0.7, "candidate": 0.8}],
            "thresholds": [{"name": "recall_at_10", "operator": ">=", "value": 0.75}],
            "verdict": "PASS", "evidence": ["results.json"], "environment": {"runtime": "cpu"}, "evaluated_at": "2026-10-03T20:00:00Z"
        }
        result = self.run_record_validation("eval-receipt", payload)
        self.assertEqual(result.returncode, 0, msg=result.stdout + result.stderr)
        payload["change_scope"]["changed_dimensions"] = ["retrieval", "decision-routing"]
        result = self.run_record_validation("eval-receipt", payload)
        self.assertNotEqual(result.returncode, 0)
        payload["change_scope"]["multi_dimension_exception_ref"] = "ADR-EXPLICIT-COMBINED-CHANGE"
        result = self.run_record_validation("eval-receipt", payload)
        self.assertEqual(result.returncode, 0, msg=result.stdout + result.stderr)

    def test_context_builder_binds_git_state_and_authority_digest(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            output = Path(tmp) / "context.json"
            result = subprocess.run([
                sys.executable, str(BUILDER), "--project", str(ROOT), "--objective", "test context packet", "--mode", "VERIFY",
                "--scope-in", "AI control-plane contracts", "--authority", str(ROOT / "README.md"), "--authority", str(ROOT / "SECURITY.md"),
                "--reference-only", "--output", str(output)
            ], cwd=ROOT, text=True, capture_output=True, check=False)
            self.assertEqual(result.returncode, 0, msg=result.stdout + result.stderr)
            packet = json.loads(output.read_text(encoding="utf-8"))
            head = subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=ROOT, text=True).strip()
            self.assertEqual(packet["project"]["head"], head)
            self.assertEqual(packet["authority_sources"][0]["sha256"], hashlib.sha256((ROOT / "README.md").read_bytes()).hexdigest())
            valid = subprocess.run([sys.executable, str(VALIDATOR), "--kind", "project-context", "--file", str(output)], cwd=ROOT, text=True, capture_output=True, check=False)
            self.assertEqual(valid.returncode, 0, msg=valid.stdout + valid.stderr)


if __name__ == "__main__":
    unittest.main()
