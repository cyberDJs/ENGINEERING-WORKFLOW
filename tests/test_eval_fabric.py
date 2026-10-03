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
COMPARATOR = ROOT / "scripts/compare_evaluation_runs.py"


class EvalFabricTest(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.work = Path(self.tmp.name)
        self.case_manifest = self.work / "cases.json"
        self.case_manifest.write_text(
            json.dumps({"cases": ["case-a", "case-b", "case-c"]}, sort_keys=True) + "\n",
            encoding="utf-8",
        )
        digest = hashlib.sha256(self.case_manifest.read_bytes()).hexdigest()
        self.suite = {
            "schema_version": "1.0.0",
            "suite_id": "router-regression-v1",
            "capability_class": "decision-routing",
            "executor": {
                "authority_type": "SKILLS_CAPABILITY_EVALUATOR",
                "ref": "SKILLS/capability-evaluator",
            },
            "case_set": {
                "id": "router-cases-v1",
                "digest": digest,
                "case_ids": ["case-a", "case-b", "case-c"],
                "validation_strategy": "REGRESSION",
            },
            "comparison": {
                "paired_case_ids": True,
                "baseline_required": True,
                "fail_on_case_set_mismatch": True,
            },
            "metrics": [
                {
                    "name": "task_success",
                    "field": "task_success",
                    "aggregation": "mean",
                    "direction": "higher_is_better",
                    "threshold": {"operator": ">=", "value": 0.8},
                }
            ],
            "regression_policy": {
                "fail_on_candidate_critical": True,
                "critical_severities": ["critical", "high"],
                "max_new_failures": 0,
                "no_pass_rate_regression": True,
            },
            "governance": {
                "functional_only": True,
                "security_evaluation_separate": True,
                "promotion_authority": False,
            },
        }
        self.suite_path = self.work / "suite.json"
        self._write_suite()
        self.baseline = [
            {"case_id": "case-a", "pass": True, "severity_if_failed": "critical", "task_success": 1.0},
            {"case_id": "case-b", "pass": False, "severity_if_failed": "low", "task_success": 0.5},
            {"case_id": "case-c", "pass": True, "severity_if_failed": "high", "task_success": 1.0},
        ]
        self.candidate = [
            {"case_id": "case-a", "pass": True, "severity_if_failed": "critical", "task_success": 1.0},
            {"case_id": "case-b", "pass": True, "severity_if_failed": "low", "task_success": 1.0},
            {"case_id": "case-c", "pass": True, "severity_if_failed": "high", "task_success": 1.0},
        ]

    def tearDown(self) -> None:
        self.tmp.cleanup()

    def _write_suite(self) -> None:
        self.suite_path.write_text(json.dumps(self.suite, sort_keys=True) + "\n", encoding="utf-8")

    @staticmethod
    def _write_jsonl(path: Path, rows: list[dict]) -> None:
        path.write_text(
            "".join(json.dumps(row, sort_keys=True) + "\n" for row in rows),
            encoding="utf-8",
        )

    def _run_comparator(self, candidate: list[dict]) -> tuple[subprocess.CompletedProcess[str], Path]:
        baseline_path = self.work / "baseline.jsonl"
        candidate_path = self.work / "candidate.jsonl"
        output_path = self.work / "comparison.json"
        self._write_jsonl(baseline_path, self.baseline)
        self._write_jsonl(candidate_path, candidate)
        result = subprocess.run(
            [
                sys.executable,
                str(COMPARATOR),
                "--suite", str(self.suite_path),
                "--case-manifest", str(self.case_manifest),
                "--baseline", str(baseline_path),
                "--candidate", str(candidate_path),
                "--output", str(output_path),
            ],
            cwd=ROOT,
            text=True,
            capture_output=True,
            check=False,
        )
        return result, output_path

    def test_suite_validation_rejects_promotion_authority(self) -> None:
        valid = subprocess.run(
            [sys.executable, str(VALIDATOR), "--kind", "evaluation-suite", "--file", str(self.suite_path)],
            cwd=ROOT, text=True, capture_output=True, check=False,
        )
        self.assertEqual(valid.returncode, 0, msg=valid.stdout + valid.stderr)
        self.suite["governance"]["promotion_authority"] = True
        self._write_suite()
        invalid = subprocess.run(
            [sys.executable, str(VALIDATOR), "--kind", "evaluation-suite", "--file", str(self.suite_path)],
            cwd=ROOT, text=True, capture_output=True, check=False,
        )
        self.assertNotEqual(invalid.returncode, 0)

    def test_comparator_passes_improvement_without_regression(self) -> None:
        result, output_path = self._run_comparator(self.candidate)
        self.assertEqual(result.returncode, 0, msg=result.stdout + result.stderr)
        comparison = json.loads(output_path.read_text(encoding="utf-8"))
        self.assertEqual(comparison["functional_verdict"], "PASS")
        self.assertFalse(comparison["promotion_authority"])
        self.assertEqual(comparison["security_evaluation"], "NOT_EVALUATED")
        self.assertEqual(comparison["cases"]["new_critical_failures"], [])
        self.assertEqual(comparison["cases"]["improvements"], ["case-b"])

    def test_comparator_blocks_critical_failure_even_when_average_is_acceptable(self) -> None:
        candidate = [dict(row) for row in self.candidate]
        candidate[0]["pass"] = False
        candidate[0]["task_success"] = 0.5
        result, output_path = self._run_comparator(candidate)
        self.assertEqual(result.returncode, 1, msg=result.stdout + result.stderr)
        comparison = json.loads(output_path.read_text(encoding="utf-8"))
        self.assertEqual(comparison["functional_verdict"], "FAIL")
        self.assertIn("candidate-critical-failure", comparison["blockers"])
        self.assertEqual(comparison["cases"]["new_critical_failures"], ["case-a"])

    def test_comparator_rejects_case_set_drift(self) -> None:
        result, _ = self._run_comparator(self.candidate[:2])
        self.assertEqual(result.returncode, 2)
        self.assertIn("case IDs must exactly match", result.stderr)


if __name__ == "__main__":
    unittest.main()
