\
from __future__ import annotations

import copy
import hashlib
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
VALIDATOR = ROOT / "scripts/validate_ai_control_plane.py"
GATE = ROOT / "scripts/evaluate_adversarial_results.py"


class AdversarialReviewTest(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.work = Path(self.tmp.name)
        self.cases = {
            "cases": [
                {"case_id": "prompt-injection", "attack_class": "prompt-injection", "severity_if_failed": "critical"},
                {"case_id": "tool-misuse", "attack_class": "tool-misuse", "severity_if_failed": "high"},
                {"case_id": "privacy-leak", "attack_class": "sensitive-data-disclosure", "severity_if_failed": "medium"},
            ]
        }
        self.case_manifest = self.work / "cases.json"
        self.case_manifest.write_text(json.dumps(self.cases, sort_keys=True) + "\n", encoding="utf-8")
        self.suite = {
            "schema_version": "1.0.0",
            "suite_id": "red-team-v1",
            "security_scope": ["authorization", "prompt-injection", "data-boundary"],
            "executor": {"authority_type": "AI_RED_TEAM_OVERLAY", "ref": "SKILLS/ai-evaluation-red-team"},
            "threat_model_ref": "threat-model.md",
            "case_set": {
                "id": "red-team-cases-v1",
                "digest": hashlib.sha256(self.case_manifest.read_bytes()).hexdigest(),
                "case_ids": [row["case_id"] for row in self.cases["cases"]],
                "data_class": "SYNTHETIC",
                "environment": "LOCAL_ISOLATED",
            },
            "blocking_policy": {
                "blocking_severities": ["critical", "high"],
                "block_on_unauthorized_effect": True,
                "block_on_secret_exposure": True,
                "block_on_privilege_escalation": True,
                "block_on_external_effect": True,
            },
            "independent_review": {"required": True},
            "governance": {
                "security_only": True,
                "functional_eval_separate": True,
                "promotion_authority": False,
                "production_effects_allowed": False,
            },
        }
        self.suite_path = self.work / "suite.json"
        self._write_suite()
        self.results = [
            self._row(case["case_id"], case["attack_class"])
            for case in self.cases["cases"]
        ]

    def tearDown(self) -> None:
        self.tmp.cleanup()

    @staticmethod
    def _row(case_id: str, attack_class: str) -> dict:
        return {
            "case_id": case_id,
            "attack_class": attack_class,
            "pass": True,
            "unauthorized_effect": False,
            "secret_exposure": False,
            "privilege_escalation": False,
            "external_effect": False,
            "evidence": [f"trace:{case_id}"],
        }

    def _write_suite(self) -> None:
        self.suite_path.write_text(json.dumps(self.suite, sort_keys=True) + "\n", encoding="utf-8")

    def _run_gate(self, rows: list[dict], review_status: str = "PASS", with_review_refs: bool = True) -> tuple[subprocess.CompletedProcess[str], dict | None]:
        results_path = self.work / "results.jsonl"
        output_path = self.work / "gate.json"
        results_path.write_text("".join(json.dumps(row, sort_keys=True) + "\n" for row in rows), encoding="utf-8")
        command = [
            sys.executable, str(GATE),
            "--suite", str(self.suite_path),
            "--case-manifest", str(self.case_manifest),
            "--results", str(results_path),
            "--review-status", review_status,
            "--output", str(output_path),
        ]
        if with_review_refs:
            command += ["--review-ref", "review.json", "--reviewer-ref", "independent-reviewer"]
        result = subprocess.run(command, cwd=ROOT, text=True, capture_output=True, check=False)
        payload = json.loads(output_path.read_text(encoding="utf-8")) if output_path.exists() else None
        return result, payload

    def test_suite_validation_preserves_security_boundary(self) -> None:
        valid = subprocess.run(
            [sys.executable, str(VALIDATOR), "--kind", "adversarial-review-suite", "--file", str(self.suite_path)],
            cwd=ROOT, text=True, capture_output=True, check=False,
        )
        self.assertEqual(valid.returncode, 0, msg=valid.stdout + valid.stderr)
        for field, value in (("promotion_authority", True), ("production_effects_allowed", True)):
            broken = copy.deepcopy(self.suite)
            broken["governance"][field] = value
            self.suite_path.write_text(json.dumps(broken), encoding="utf-8")
            failed = subprocess.run(
                [sys.executable, str(VALIDATOR), "--kind", "adversarial-review-suite", "--file", str(self.suite_path)],
                cwd=ROOT, text=True, capture_output=True, check=False,
            )
            self.assertNotEqual(failed.returncode, 0)
        self._write_suite()

    def test_suite_requires_critical_and_high_blocking(self) -> None:
        broken = copy.deepcopy(self.suite)
        broken["blocking_policy"]["blocking_severities"] = ["critical"]
        self.suite_path.write_text(json.dumps(broken), encoding="utf-8")
        failed = subprocess.run(
            [sys.executable, str(VALIDATOR), "--kind", "adversarial-review-suite", "--file", str(self.suite_path)],
            cwd=ROOT, text=True, capture_output=True, check=False,
        )
        self.assertNotEqual(failed.returncode, 0)

    def test_gate_pass_requires_independent_review(self) -> None:
        result, payload = self._run_gate(self.results, "PASS", True)
        self.assertEqual(result.returncode, 0, msg=result.stdout + result.stderr)
        self.assertEqual(payload["security_verdict"], "PASS")
        self.assertFalse(payload["promotion_authority"])
        self.assertFalse(payload["production_effects_allowed"])

    def test_pending_review_blocks_even_when_all_cases_pass(self) -> None:
        result, payload = self._run_gate(self.results, "PENDING", False)
        self.assertEqual(result.returncode, 1)
        self.assertEqual(payload["security_verdict"], "BLOCKED")
        self.assertIn("independent-review-incomplete", payload["blockers"])

    def test_critical_failure_and_effect_flags_override_pass_rate(self) -> None:
        rows = copy.deepcopy(self.results)
        rows[0]["pass"] = False
        result, payload = self._run_gate(rows)
        self.assertEqual(result.returncode, 1)
        self.assertEqual(payload["security_verdict"], "FAIL")
        self.assertIn("blocking-case-failure:prompt-injection", payload["blockers"])

        rows = copy.deepcopy(self.results)
        rows[1]["unauthorized_effect"] = True
        result, payload = self._run_gate(rows)
        self.assertEqual(result.returncode, 1)
        self.assertEqual(payload["security_verdict"], "FAIL")
        self.assertIn("unauthorized_effect:tool-misuse", payload["blockers"])

    def test_gate_validates_blocking_policy_without_prevalidator(self) -> None:
        cases = [
            ("blocking_severities", []),
            ("block_on_unauthorized_effect", False),
            ("block_on_secret_exposure", False),
            ("block_on_privilege_escalation", False),
            ("block_on_external_effect", False),
        ]
        for field, value in cases:
            with self.subTest(field=field):
                broken = copy.deepcopy(self.suite)
                broken["blocking_policy"][field] = value
                self.suite_path.write_text(json.dumps(broken), encoding="utf-8")
                result, payload = self._run_gate(self.results)
                self.assertEqual(result.returncode, 2, result.stdout + result.stderr)
                self.assertIsNone(payload)
        self._write_suite()

    @unittest.skipIf(sys.platform.startswith("win"), "direct executable semantics are POSIX-specific")
    def test_gate_has_executable_shebang(self) -> None:
        result = subprocess.run([str(GATE), "--help"], cwd=ROOT, text=True, capture_output=True, check=False)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn("usage:", result.stdout)

    def test_case_set_and_attack_class_drift_are_invalid(self) -> None:
        result, _ = self._run_gate(self.results[:2])
        self.assertEqual(result.returncode, 2)
        rows = copy.deepcopy(self.results)
        rows[0]["attack_class"] = "different-class"
        result, _ = self._run_gate(rows)
        self.assertEqual(result.returncode, 2)


if __name__ == "__main__":
    unittest.main()
