from __future__ import annotations

import copy
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
VALIDATOR = ROOT / "scripts/validate_ai_control_plane.py"


class ArchitecturePromotionTest(unittest.TestCase):
    def run_validation(self, payload: dict) -> subprocess.CompletedProcess[str]:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "promotion.json"
            path.write_text(json.dumps(payload), encoding="utf-8")
            return subprocess.run(
                [sys.executable, str(VALIDATOR), "--kind", "architecture-promotion", "--file", str(path)],
                cwd=ROOT,
                text=True,
                capture_output=True,
                check=False,
            )

    def base_record(self, outcome: str = "ADOPT") -> dict:
        adopt = outcome == "ADOPT"
        return {
            "schema_version": "1.0.0",
            "record_id": f"APR-{outcome.lower()}-test",
            "architecture": {
                "family": "ai-engineering-control-plane",
                "current_champion_ref": "arch-1.0.0",
                "candidate_ref": "arch-1.1.0-candidate",
                "changed_dimensions": ["decision-routing"],
            },
            "decision": {
                "outcome": outcome,
                "decision_record_ref": "DECISION-123",
                "decision_authority_type": "PROJECT_AUTHORITY" if adopt else "POLICY",
                "decision_authority_ref": "Technical-Steward:approval-123" if adopt else "ENGINEERING_CONSTITUTION#truth-over-appearance",
                "decided_at": "2026-10-04T12:00:00Z",
            },
            "gates": {
                "eval_receipt_ref": "EVAL-123",
                "eval_verdict": "PASS" if adopt else "INCONCLUSIVE",
                "security_status": "PASS" if adopt else "BLOCKED",
                "security_evidence_ref": "security-review.json",
                "regression_status": "PASS" if adopt else "BLOCKED",
                "regression_evidence_ref": "regression.json",
                "rollback_verified": adopt,
                "rollback_ref": "rollback.md",
            },
            "release": {
                "architecture_version": "1.1.0" if adopt else None,
                "release_record_ref": "RELEASE-1.1.0" if adopt else None,
                "release_authority_ref": "Release-Authority:approval-456" if adopt else None,
                "production_eligible": adopt,
            },
            "governance": {
                "record_grants_execution": False,
                "record_grants_release": False,
                "protected_operations_require_separate_authorization": True,
            },
            "evidence": ["eval-receipt.json", "decision-record.md"],
            "residual_risks": [],
        }

    def test_adopt_requires_all_independent_gates_and_authorities(self) -> None:
        record = self.base_record("ADOPT")
        result = self.run_validation(record)
        self.assertEqual(result.returncode, 0, msg=result.stdout + result.stderr)

        for mutation in ("eval", "security", "regression", "rollback", "decision_authority", "policy_self_approval", "release_authority"):
            broken = copy.deepcopy(record)
            if mutation == "eval":
                broken["gates"]["eval_verdict"] = "INCONCLUSIVE"
            elif mutation == "security":
                broken["gates"]["security_status"] = "BLOCKED"
            elif mutation == "regression":
                broken["gates"]["regression_status"] = "FAIL"
            elif mutation == "rollback":
                broken["gates"]["rollback_verified"] = False
            elif mutation == "decision_authority":
                broken["decision"]["decision_authority_ref"] = ""
            elif mutation == "policy_self_approval":
                broken["decision"]["decision_authority_type"] = "POLICY"
            else:
                broken["release"]["release_authority_ref"] = None
            failed = self.run_validation(broken)
            self.assertNotEqual(failed.returncode, 0, msg=mutation)

    def test_watch_allows_blocked_gates_but_never_release_eligibility(self) -> None:
        record = self.base_record("WATCH")
        result = self.run_validation(record)
        self.assertEqual(result.returncode, 0, msg=result.stdout + result.stderr)

        broken = copy.deepcopy(record)
        broken["release"]["production_eligible"] = True
        failed = self.run_validation(broken)
        self.assertNotEqual(failed.returncode, 0)

        broken = copy.deepcopy(record)
        broken["release"]["architecture_version"] = "1.1.0"
        failed = self.run_validation(broken)
        self.assertNotEqual(failed.returncode, 0)

    def test_reject_is_terminal_without_release_record(self) -> None:
        record = self.base_record("REJECT")
        record["gates"]["eval_verdict"] = "FAIL"
        record["gates"]["security_status"] = "FAIL"
        record["gates"]["regression_status"] = "FAIL"
        result = self.run_validation(record)
        self.assertEqual(result.returncode, 0, msg=result.stdout + result.stderr)

    def test_record_never_grants_execution_or_release(self) -> None:
        record = self.base_record("WATCH")
        record["governance"]["record_grants_execution"] = True
        self.assertNotEqual(self.run_validation(record).returncode, 0)

        record = self.base_record("WATCH")
        record["governance"]["record_grants_release"] = True
        self.assertNotEqual(self.run_validation(record).returncode, 0)

        record = self.base_record("WATCH")
        record["architecture"]["candidate_ref"] = record["architecture"]["current_champion_ref"]
        self.assertNotEqual(self.run_validation(record).returncode, 0)


if __name__ == "__main__":
    unittest.main()
