from __future__ import annotations

import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
EW = ROOT / "bin/ew"
CONTROL = ".engineering-workflow"


def run_ew(*args: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run([sys.executable, str(EW), *args], cwd=ROOT, text=True, capture_output=True, check=False)


class EWAdoptTest(unittest.TestCase):
    def project(self, root: Path) -> Path:
        target = root / "existing"
        target.mkdir()
        (target / "pyproject.toml").write_text("[project]\nname='sample'\n", encoding="utf-8")
        (target / "app.py").write_text("print('ok')\n", encoding="utf-8")
        return target

    def args(self, target: Path) -> tuple[str, ...]:
        return (
            "adopt", str(target), "--name", "Existing", "--profile", "standard-product",
            "--risk", "R2", "--reversibility", "REV-2", "--json",
        )

    def test_adopt_defaults_to_read_only_plan(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            target = self.project(Path(temp))
            result = run_ew(*self.args(target))
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            payload = json.loads(result.stdout)
            self.assertEqual(payload["status"], "PLANNED")
            self.assertFalse((target / CONTROL).exists())
            self.assertEqual(payload["details"]["product_source_changes"], [])

    def test_apply_doctor_noop_and_snapshot(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            target = self.project(Path(temp))
            source_before = (target / "app.py").read_bytes()
            result = run_ew(*self.args(target), "--apply")
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            self.assertEqual(json.loads(result.stdout)["status"], "ADOPTED")
            self.assertEqual((target / "app.py").read_bytes(), source_before)
            self.assertTrue((target / CONTROL / "snapshots/pre-adoption.json").is_file())
            doctor = run_ew("doctor", str(target), "--json")
            self.assertEqual(json.loads(doctor.stdout)["status"], "PASS")
            noop = run_ew(*self.args(target), "--apply")
            self.assertEqual(json.loads(noop.stdout)["status"], "NOOP")

    def test_sensitive_paths_require_acknowledgement_and_are_not_read(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            target = self.project(Path(temp))
            (target / ".env").write_text("PASSWORD=secret\n", encoding="utf-8")
            plan = json.loads(run_ew(*self.args(target)).stdout)
            self.assertIn(".env", plan["details"]["sensitive_paths_content_not_read"])
            blocked = run_ew(*self.args(target), "--apply")
            self.assertEqual(blocked.returncode, 2)
            self.assertFalse((target / CONTROL).exists())
            applied = run_ew(
                "adopt", str(target), "--name", "Existing", "--profile", "production-service",
                "--risk", "R3", "--reversibility", "REV-2", "--acknowledge-sensitive-paths", "--apply", "--json",
            )
            self.assertEqual(applied.returncode, 0, applied.stdout + applied.stderr)
            audit = json.loads((target / CONTROL / "evidence/adoption-audit.json").read_text(encoding="utf-8"))
            entry = next(item for item in audit["inventory"] if item["path"] == ".env")
            self.assertIsNone(entry["sha256"])
            self.assertFalse(entry["content_read"])

    def test_infrastructure_forces_r3_capable_profile(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            target = self.project(Path(temp))
            (target / "main.tf").write_text("terraform {}\n", encoding="utf-8")
            plan = run_ew(*self.args(target))
            self.assertEqual(plan.returncode, 0, plan.stdout + plan.stderr)
            payload = json.loads(plan.stdout)
            self.assertEqual(payload["status"], "PLANNED")
            self.assertTrue(payload["details"]["blockers"])
            applied = run_ew(*self.args(target), "--apply")
            self.assertEqual(applied.returncode, 2)
            self.assertEqual(json.loads(applied.stdout)["status"], "BLOCKED")

    def test_rollback_is_preview_first_and_removes_only_owned_scope(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            target = self.project(Path(temp))
            source_before = (target / "app.py").read_bytes()
            run_ew(*self.args(target), "--apply")
            plan = run_ew("rollback", str(target), "--json")
            self.assertEqual(json.loads(plan.stdout)["status"], "PLANNED")
            self.assertTrue((target / CONTROL).is_dir())
            result = run_ew("rollback", str(target), "--apply", "--json")
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            self.assertEqual(json.loads(result.stdout)["status"], "ROLLED_BACK")
            self.assertFalse((target / CONTROL).exists())
            self.assertEqual((target / "app.py").read_bytes(), source_before)

    def test_rollback_blocks_tampered_control_state(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            target = self.project(Path(temp))
            run_ew(*self.args(target), "--apply")
            product = target / CONTROL / "PRODUCT_DEFINITION.md"
            product.write_text(product.read_text(encoding="utf-8") + "\ntamper\n", encoding="utf-8")
            result = run_ew("rollback", str(target), "--apply", "--json")
            self.assertEqual(result.returncode, 2)
            self.assertTrue((target / CONTROL).is_dir())


if __name__ == "__main__":
    unittest.main()
