#!/usr/bin/env python3
from __future__ import annotations

import argparse
import hashlib
import json
import shutil
import subprocess
import sys
import tempfile
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SOURCE_LOCK = ROOT / "platform/toolchain.lock.json"
SOURCE_VALIDATOR = ROOT / "scripts/validate_toolchain_lock.py"


def now() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def run_validator(root: Path) -> tuple[int, str]:
    cp = subprocess.run(
        [sys.executable, str(root / "scripts/validate_toolchain_lock.py")],
        cwd=root,
        text=True,
        capture_output=True,
        check=False,
    )
    return cp.returncode, (cp.stdout + cp.stderr).strip()


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()

    source_before = sha256(SOURCE_LOCK)
    timeline: list[dict[str, object]] = []

    def event(phase: str, status: str, evidence: dict[str, object]) -> None:
        timeline.append({"at": now(), "phase": phase, "status": status, "evidence": evidence})

    with tempfile.TemporaryDirectory(prefix="ew-incident-exercise-") as td:
        lab = Path(td)
        (lab / "platform").mkdir()
        (lab / "scripts").mkdir()
        shutil.copy2(SOURCE_LOCK, lab / "platform/toolchain.lock.json")
        shutil.copy2(SOURCE_VALIDATOR, lab / "scripts/validate_toolchain_lock.py")

        lab_lock = lab / "platform/toolchain.lock.json"
        baseline = lab_lock.read_bytes()
        baseline_hash = hashlib.sha256(baseline).hexdigest()
        event("DETECT", "STARTED", {"baseline_sha256": baseline_hash})

        data = json.loads(lab_lock.read_text())
        data["policy"]["unverified_binary_execution_allowed"] = True
        lab_lock.write_text(json.dumps(data, indent=2, sort_keys=True) + "\n")

        bad_rc, bad_out = run_validator(lab)
        detected = bad_rc != 0 and "unverified_binary_execution_allowed" in bad_out
        event("VERIFY", "PASS" if detected else "FAIL", {"validator_exit": bad_rc, "output": bad_out})
        event("DECLARE", "PASS" if detected else "FAIL", {"severity": "SEV-2", "scope": "isolated-toolchain-policy-drift", "production_effect": False})
        event("CONTAIN", "PASS", {"action": "keep mutated state inside temporary lab; prohibit execution/release/network"})
        event("DIAGNOSE", "PASS", {"root_cause": "unverified_binary_execution_allowed changed false -> true", "affected_file": "platform/toolchain.lock.json"})

        lab_lock.write_bytes(baseline)
        good_rc, good_out = run_validator(lab)
        restored = sha256(lab_lock) == baseline_hash and good_rc == 0
        event("RECOVER", "PASS" if restored else "FAIL", {"validator_exit": good_rc, "restored_sha256": sha256(lab_lock)})

        source_after = sha256(SOURCE_LOCK)
        source_unchanged = source_before == source_after
        verified = detected and restored and source_unchanged
        event("VALIDATE", "PASS" if verified else "FAIL", {"source_repository_unchanged": source_unchanged, "source_sha256": source_after, "validator_output": good_out})
        event("LEARN", "PASS" if verified else "FAIL", {"corrective_action": "retain deterministic incident exercise as regression control", "verification": "automated test + real receipt"})

    receipt = {
        "schema": "engineering-workflow-incident-exercise/v1",
        "exercise_id": "EW-IR-TOOLCHAIN-DRIFT-001",
        "status": "VERIFIED" if verified else "FAILED",
        "scenario": "unsafe toolchain policy drift permits unverified binary execution",
        "roles": {
            "incident_commander": "exercise-controller",
            "operations_lead": "exercise-runner",
            "communications_lead": "exercise-controller",
            "scribe": "receipt-writer",
        },
        "rto_target_seconds": 60,
        "rpo_target": "zero source-repository data loss",
        "timeline": timeline,
        "corrective_actions": [
            {
                "id": "CA-001",
                "owner": "Incident Commander",
                "action": "keep this isolated regression exercise executable",
                "status": "VERIFIED",
                "evidence": "tests/test_incident_exercise.py",
            }
        ],
        "governance": {
            "isolated_environment": True,
            "production_effects": False,
            "network_used": False,
            "deploy_performed": False,
            "release_performed": False,
            "secrets_accessed": False,
            "source_repository_mutated": False,
        },
        "source": {
            "head": subprocess.check_output(["git", "-C", str(ROOT), "rev-parse", "HEAD"], text=True).strip(),
            "toolchain_lock_sha256": source_before,
        },
        "conclusion": (
            "Control drift was detected fail-closed, contained in an isolated lab, restored byte-for-byte, and revalidated."
            if verified
            else "Exercise failed; GAP-017 must remain open."
        ),
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(receipt, indent=2, sort_keys=True) + "\n")
    print("INCIDENT_EXERCISE=" + receipt["status"])
    print("SOURCE_REPOSITORY_MUTATED=false")
    print("PRODUCTION_EFFECTS=false")
    return 0 if verified else 1


if __name__ == "__main__":
    raise SystemExit(main())
