#!/usr/bin/env python3
"""Run a local, non-production release promotion and rollback rehearsal."""
from __future__ import annotations

import argparse
import hashlib
import io
import json
import os
import subprocess
import sys
import tarfile
import tempfile
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def git(*args: str) -> str:
    return subprocess.check_output(["git", "-C", str(ROOT), *args], text=True).strip()


def export_commit(commit: str, destination: Path) -> None:
    archive = subprocess.check_output(["git", "-C", str(ROOT), "archive", "--format=tar", commit])
    destination.mkdir(parents=True, exist_ok=True)
    with tarfile.open(fileobj=io.BytesIO(archive), mode="r:") as handle:
        handle.extractall(destination, filter="data")


def build_artifact(source: Path, output: Path, manifest: Path) -> dict:
    env = {**os.environ, "PYTHONDONTWRITEBYTECODE": "1"}
    result = subprocess.run(
        [sys.executable, str(source / "scripts/build_reference_artifact.py"), "--output", str(output), "--manifest", str(manifest)],
        cwd=source, text=True, capture_output=True, check=False, env=env,
    )
    if result.returncode != 0:
        raise RuntimeError(result.stdout + result.stderr)
    expected = manifest.read_text(encoding="utf-8").split()[0]
    actual = sha256(output)
    if expected != actual:
        raise RuntimeError("artifact digest does not match manifest")
    return {"sha256": actual, "build_output": result.stdout.strip()}


def validate_snapshot(source: Path) -> dict:
    env = {**os.environ, "PYTHONDONTWRITEBYTECODE": "1"}
    result = subprocess.run(
        [sys.executable, "scripts/validate_repository.py"], cwd=source,
        text=True, capture_output=True, check=False, env=env,
    )
    return {"exit_code": result.returncode, "output": (result.stdout + result.stderr).strip(), "pass": result.returncode == 0}


def atomic_state(path: Path, payload: dict) -> None:
    tmp = path.with_suffix(".tmp")
    tmp.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    tmp.replace(path)


def promote_and_rollback(state: Path, baseline: dict, candidate: dict) -> dict:
    atomic_state(state, {"slot": "baseline", **baseline})
    before = json.loads(state.read_text(encoding="utf-8"))
    atomic_state(state, {"slot": "candidate", **candidate})
    promoted = json.loads(state.read_text(encoding="utf-8"))
    promotion_ok = promoted["sha256"] == candidate["sha256"] and promoted["source_ref"] == candidate["source_ref"]
    atomic_state(state, before)
    rolled_back = json.loads(state.read_text(encoding="utf-8"))
    rollback_ok = rolled_back == before and rolled_back["sha256"] == baseline["sha256"]
    return {"promotion_ok": promotion_ok, "rollback_ok": rollback_ok, "initial": before, "promoted": promoted, "restored": rolled_back}


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    if git("status", "--porcelain"):
        print("RELEASE_REHEARSAL=BLOCKED\nERROR: repository must be clean", file=sys.stderr)
        return 2
    head = git("rev-parse", "HEAD")
    parent = git("rev-parse", "HEAD^")
    with tempfile.TemporaryDirectory(prefix="ew-release-rehearsal-") as td:
        lab = Path(td)
        base_src, cand_src = lab / "baseline-src", lab / "candidate-src"
        export_commit(parent, base_src)
        export_commit(head, cand_src)
        base_art, cand_art = lab / "baseline.tar.gz", lab / "candidate.tar.gz"
        base_manifest, cand_manifest = lab / "baseline.SHA256SUMS", lab / "candidate.SHA256SUMS"
        base_build = build_artifact(base_src, base_art, base_manifest)
        cand_build = build_artifact(cand_src, cand_art, cand_manifest)
        base_validation = validate_snapshot(base_src)
        cand_validation = validate_snapshot(cand_src)
        transition = promote_and_rollback(
            lab / "active-release.json",
            {"source_ref": parent, "sha256": base_build["sha256"]},
            {"source_ref": head, "sha256": cand_build["sha256"]},
        )
        verified = all([base_validation["pass"], cand_validation["pass"], transition["promotion_ok"], transition["rollback_ok"]])
        receipt = {
            "schema": "engineering-workflow-release-rehearsal/v1",
            "status": "VERIFIED" if verified else "FAILED",
            "rehearsal_kind": "OFFLINE_IMMUTABLE_PROMOTION_AND_ROLLBACK",
            "baseline": {"source_ref": parent, "artifact_sha256": base_build["sha256"], "validation": base_validation},
            "candidate": {"source_ref": head, "artifact_sha256": cand_build["sha256"], "validation": cand_validation},
            "promotion": {"same_candidate_identity_preserved": transition["promotion_ok"], "active_state": transition["promoted"]},
            "rollback": {"restored_baseline_identity": transition["rollback_ok"], "active_state": transition["restored"]},
            "governance": {
                "production_effects": False, "network_used": False, "deploy_performed": False,
                "release_performed": False, "tag_created": False, "push_performed": False,
                "release_authority_exercised": False,
            },
            "blockers": [
                "REAL_RELEASE_AUTHORITY_NOT_EXERCISED",
                "PRODUCTION_DEPLOYMENT_VERIFICATION_MISSING",
                "INDEPENDENT_RELEASE_REVIEW_PENDING",
            ],
            "recorded_at": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
        }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(receipt, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print("RELEASE_REHEARSAL=" + receipt["status"])
    print("CANDIDATE_SHA256=" + receipt["candidate"]["artifact_sha256"])
    print("ROLLBACK_VERIFIED=" + str(receipt["rollback"]["restored_baseline_identity"]).lower())
    print("PRODUCTION_EFFECTS=false")
    return 0 if verified else 1


if __name__ == "__main__":
    raise SystemExit(main())
