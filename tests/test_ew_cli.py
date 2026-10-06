from __future__ import annotations

import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
EW = ROOT / "bin/ew"


def run_ew(*args: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run([sys.executable, str(EW), *args], cwd=ROOT, text=True, capture_output=True, check=False)


class EWCLITest(unittest.TestCase):
    def test_self_test(self) -> None:
        result = run_ew("self-test", "--json")
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        payload = json.loads(result.stdout)
        self.assertEqual(payload["status"], "PASS")
        self.assertTrue(all(payload["details"]["assertions"].values()))

    def test_dry_run_does_not_write(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            target = Path(temp) / "project"
            result = run_ew("init", str(target), "--name", "Example", "--profile", "standard-product", "--risk", "R2", "--reversibility", "REV-2", "--dry-run", "--json")
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            self.assertEqual(json.loads(result.stdout)["status"], "PLANNED")
            self.assertFalse(target.exists())

    def test_init_doctor_and_noop(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            target = Path(temp) / "project"
            args = ("init", str(target), "--name", "Example", "--profile", "standard-product", "--risk", "R2", "--reversibility", "REV-2", "--json")
            self.assertEqual(json.loads(run_ew(*args).stdout)["status"], "CREATED")
            payload = json.loads(run_ew("doctor", str(target), "--json").stdout)
            self.assertEqual(payload["status"], "PASS")
            self.assertTrue(payload["details"]["control_plane_ready"])
            self.assertFalse(payload["details"]["project_ready"])
            self.assertEqual(json.loads(run_ew(*args).stdout)["status"], "NOOP")

    def test_profile_downgrade_is_blocked(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            result = run_ew("init", str(Path(temp) / "project"), "--name", "Unsafe", "--profile", "experiment", "--risk", "R1", "--reversibility", "REV-4", "--dry-run", "--json")
            self.assertEqual(result.returncode, 2)
            self.assertEqual(json.loads(result.stdout)["status"], "BLOCKED")

    def test_tampering_is_detected(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            target = Path(temp) / "project"
            run_ew("init", str(target), "--name", "Example", "--profile", "standard-product", "--risk", "R2", "--reversibility", "REV-2", "--json")
            product = target / ".engineering-workflow/PRODUCT_DEFINITION.md"
            product.write_text(product.read_text(encoding="utf-8") + "\ntamper\n", encoding="utf-8")
            result = run_ew("doctor", str(target), "--json")
            self.assertEqual(result.returncode, 1)
            self.assertEqual(json.loads(result.stdout)["status"], "FAIL")

    def test_manifest_path_traversal_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            target = Path(temp) / "project"
            run_ew("init", str(target), "--name", "Example", "--profile", "standard-product", "--risk", "R2", "--reversibility", "REV-2", "--json")
            manifest_path = target / ".engineering-workflow/manifest.json"
            manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
            manifest["files"]["../outside.txt"] = "0" * 64
            canonical = json.dumps(manifest["files"], indent=2, sort_keys=True, ensure_ascii=False) + "\n"
            manifest["content_digest"] = __import__("hashlib").sha256(canonical.encode()).hexdigest()
            manifest_path.write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n")
            result = run_ew("doctor", str(target), "--json")
            self.assertEqual(result.returncode, 1)
            self.assertIn("unsafe", result.stdout)


if __name__ == "__main__":
    unittest.main()
