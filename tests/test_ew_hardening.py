from __future__ import annotations

import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
EW = ROOT / "bin/ew"
CONTROL = ".engineering-workflow"


def run_ew(*args: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run([sys.executable, str(EW), *args], cwd=ROOT, text=True, capture_output=True, check=False)


def load_ew_module():
    bin_dir = str(ROOT / "bin")
    if bin_dir not in sys.path:
        sys.path.insert(0, bin_dir)
    import ew_runtime
    import ew_fs
    return ew_runtime, ew_fs


def make_symlink(target: Path, link: Path) -> None:
    try:
        link.symlink_to(target, target_is_directory=target.is_dir())
    except (OSError, NotImplementedError) as exc:
        raise unittest.SkipTest(f"symlink creation unavailable: {exc}")


class EWHardeningTest(unittest.TestCase):
    def test_doctor_stops_before_reading_linked_control_directory(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            project = root / "project"
            outside = root / "outside"
            project.mkdir()
            outside.mkdir()
            (outside / "project.json").write_text("not-json", encoding="utf-8")
            make_symlink(outside, project / CONTROL)
            result = run_ew("doctor", str(project), "--json")
            self.assertEqual(result.returncode, 1)
            payload = json.loads(result.stdout)
            self.assertEqual(payload["status"], "FAIL")
            details = " ".join(item["detail"] for item in payload["details"]["checks"])
            self.assertIn("stopped before reading unsafe control directory", details)

    def test_doctor_rejects_symlink_inside_manifest_scope(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            project = Path(temp) / "project"
            created = run_ew("init", str(project), "--name", "Hardening", "--json")
            self.assertEqual(created.returncode, 0, created.stdout + created.stderr)
            controlled = project / CONTROL / "PRODUCT_DEFINITION.md"
            outside = project / "outside.md"
            outside.write_text("outside", encoding="utf-8")
            controlled.unlink()
            make_symlink(outside, controlled)
            result = run_ew("doctor", str(project), "--json")
            self.assertEqual(result.returncode, 1)
            self.assertEqual(json.loads(result.stdout)["status"], "FAIL")

    def test_symlink_adoption_requires_r3_acknowledgement_and_rationale(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            project = Path(temp) / "existing"
            project.mkdir()
            target = project / "real.txt"
            target.write_text("real", encoding="utf-8")
            make_symlink(target, project / "linked.txt")
            preview = run_ew("adopt", str(project), "--name", "Linked", "--json")
            payload = json.loads(preview.stdout)
            self.assertEqual(payload["status"], "PLANNED")
            self.assertTrue(payload["details"]["blockers"])
            blocked = run_ew("adopt", str(project), "--name", "Linked", "--apply", "--json")
            self.assertEqual(blocked.returncode, 2)
            applied = run_ew(
                "adopt", str(project), "--name", "Linked", "--profile", "production-service",
                "--risk", "R3", "--acknowledge-symlinks",
                "--symlink-rationale", "Required local compatibility link",
                "--apply", "--json",
            )
            self.assertEqual(applied.returncode, 0, applied.stdout + applied.stderr)
            audit = json.loads((project / CONTROL / "evidence/adoption-audit.json").read_text(encoding="utf-8"))
            record = audit["symlink_records"][0]
            self.assertEqual(set(record), {"path", "target_sha256"})
            self.assertNotIn("target", record)
            self.assertTrue(audit["symlink_acknowledgement"]["acknowledged"])
            self.assertEqual(json.loads(run_ew("doctor", str(project), "--json").stdout)["status"], "PASS")

    @unittest.skipIf(os.name == "nt", "descriptor replacement semantics differ on Windows")
    def test_hash_rejects_replacement_between_lstat_and_open(self) -> None:
        module, filesystem = load_ew_module()
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            victim = root / "victim.txt"
            replacement = root / "replacement.txt"
            victim.write_bytes(b"original")
            replacement.write_bytes(b"replacement")
            expected = victim.lstat()
            real_open = filesystem.os.open
            triggered = False

            def replacing_open(path, flags):
                nonlocal triggered
                if not triggered and Path(path) == victim:
                    triggered = True
                    os.replace(replacement, victim)
                return real_open(path, flags)

            with mock.patch.object(filesystem.os, "open", side_effect=replacing_open):
                with self.assertRaises(module.Blocked):
                    module.sha_file(victim, expected=expected)

    @unittest.skipIf(os.name == "nt", "concurrent mutation semantics differ on Windows")
    def test_hash_rejects_mutation_during_read(self) -> None:
        module, filesystem = load_ew_module()
        with tempfile.TemporaryDirectory() as temp:
            victim = Path(temp) / "victim.bin"
            victim.write_bytes(b"a" * (2 * 1024 * 1024))
            real_read = filesystem.os.read
            triggered = False

            def mutating_read(fd, size):
                nonlocal triggered
                chunk = real_read(fd, size)
                if not triggered:
                    triggered = True
                    with victim.open("ab") as handle:
                        handle.write(b"mutation")
                return chunk

            with mock.patch.object(filesystem.os, "read", side_effect=mutating_read):
                with self.assertRaises(module.Blocked):
                    module.sha_file(victim, max_bytes=4 * 1024 * 1024)


if __name__ == "__main__":
    unittest.main()
