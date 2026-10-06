from __future__ import annotations

import json
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
VALIDATOR = ROOT / "scripts/validate_licensing.py"

CONTROL_FILES = (
    "LICENSE",
    "COPYRIGHT",
    "CONTRIBUTING.md",
    "project-control.json",
    "governance/EXCLUSIVE_RIGHTS_AND_LICENSING_POLICY.md",
    "governance/OWNERSHIP_IP_AND_PROVENANCE.md",
    "governance/IP_PROVENANCE_REGISTER.json",
    "schemas/ip-provenance-register.schema.json",
)


class LicensingValidationTest(unittest.TestCase):
    def copy_fixture(self, destination: Path) -> None:
        for relative in CONTROL_FILES:
            source = ROOT / relative
            target = destination / relative
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(source, target)
        script = destination / "scripts/validate_licensing.py"
        script.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(VALIDATOR, script)

    def run_validator(self, root: Path) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            ["python3", str(root / "scripts/validate_licensing.py")],
            cwd=root,
            text=True,
            capture_output=True,
            check=False,
        )

    def test_current_repository_passes(self) -> None:
        result = subprocess.run(
            ["python3", str(VALIDATOR)],
            cwd=ROOT,
            text=True,
            capture_output=True,
            check=False,
        )
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn("LICENSING_VALIDATION=PASSED", result.stdout)

    def test_open_source_flag_fails(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            self.copy_fixture(root)
            path = root / "governance/IP_PROVENANCE_REGISTER.json"
            data = json.loads(path.read_text(encoding="utf-8"))
            data["open_source_project_license_granted"] = True
            path.write_text(json.dumps(data, indent=2) + "\n", encoding="utf-8")
            result = self.run_validator(root)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("open_source_project_license_granted", result.stdout)

    def test_unverified_distribution_fails_open(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            self.copy_fixture(root)
            path = root / "governance/IP_PROVENANCE_REGISTER.json"
            data = json.loads(path.read_text(encoding="utf-8"))
            data["distribution"]["commercial_licensing"] = "ALLOWED"
            path.write_text(json.dumps(data, indent=2) + "\n", encoding="utf-8")
            result = self.run_validator(root)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("commercial_licensing", result.stdout)

    def test_dco_only_contribution_fails(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            self.copy_fixture(root)
            path = root / "governance/IP_PROVENANCE_REGISTER.json"
            data = json.loads(path.read_text(encoding="utf-8"))
            data["contribution_policy"]["dco_alone_is_sufficient"] = True
            path.write_text(json.dumps(data, indent=2) + "\n", encoding="utf-8")
            result = self.run_validator(root)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("DCO alone", result.stdout)

    def test_missing_human_collaborator_scope_fails(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            self.copy_fixture(root)
            path = root / "governance/IP_PROVENANCE_REGISTER.json"
            data = json.loads(path.read_text(encoding="utf-8"))
            data["provenance_scopes"] = [
                item
                for item in data["provenance_scopes"]
                if item["category"] != "human-collaborator"
            ]
            path.write_text(json.dumps(data, indent=2) + "\n", encoding="utf-8")
            result = self.run_validator(root)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("human-collaborator", result.stdout)


if __name__ == "__main__":
    unittest.main()
