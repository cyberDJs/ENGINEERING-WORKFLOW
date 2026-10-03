#!/usr/bin/env python3
"""Build a deterministic, bounded Project Context Packet from explicit sources."""
from __future__ import annotations

import argparse
import hashlib
import json
import re
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path

SECRET_PATTERNS = [
    re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----"),
    re.compile(r"\bgh[pousr]_[A-Za-z0-9]{30,}\b"),
    re.compile(r"\bsk-(?:proj-)?[A-Za-z0-9_-]{20,}\b"),
]


def run_git(project: Path, *args: str) -> str:
    result = subprocess.run(["git", *args], cwd=project, text=True, capture_output=True, check=False)
    if result.returncode != 0:
        raise RuntimeError(result.stderr.strip() or f"git {' '.join(args)} failed")
    return result.stdout.strip()


def read_source(path: Path, include_content: bool) -> dict[str, object]:
    raw = path.read_bytes()
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise ValueError(f"context source is not UTF-8 text: {path}") from exc
    for pattern in SECRET_PATTERNS:
        if pattern.search(text):
            raise ValueError(f"possible secret material detected in context source: {path}")
    item: dict[str, object] = {
        "path": str(path.resolve()),
        "sha256": hashlib.sha256(raw).hexdigest(),
    }
    if include_content:
        item["content"] = text
    else:
        item["content"] = ""
    return item


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--project", type=Path, default=Path.cwd())
    parser.add_argument("--objective", required=True)
    parser.add_argument("--mode", choices=["AUDIT", "DESIGN", "IMPLEMENT", "VERIFY", "RELEASE", "VALIDATE", "INCIDENT"], default="IMPLEMENT")
    parser.add_argument("--scope-in", action="append", required=True)
    parser.add_argument("--scope-out", action="append", default=[])
    parser.add_argument("--authority", action="append", type=Path, required=True)
    parser.add_argument("--context", action="append", type=Path, default=[])
    parser.add_argument("--allowed-effect", action="append", default=[])
    parser.add_argument("--prohibited-effect", action="append", default=[])
    parser.add_argument("--reference-only", action="store_true", help="Store hashes but omit source contents")
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()

    project = Path(run_git(args.project, "rev-parse", "--show-toplevel")).resolve()
    branch = run_git(project, "branch", "--show-current")
    head = run_git(project, "rev-parse", "HEAD")
    dirty = bool(run_git(project, "status", "--porcelain"))
    project_id = project.name
    project_control = project / "project-control.json"
    if project_control.is_file():
        control = json.loads(project_control.read_text(encoding="utf-8"))
        project_id = control.get("project", {}).get("id", project_id)

    include_content = not args.reference_only
    authorities = [read_source(path, include_content) for path in args.authority]
    contexts = [read_source(path, include_content) for path in args.context]
    seed = "|".join([project_id, head, args.objective, *args.scope_in])
    packet_id = "PCP-" + hashlib.sha256(seed.encode("utf-8")).hexdigest()[:16]
    packet = {
        "schema_version": "1.0.0",
        "packet_id": packet_id,
        "project": {"id": project_id, "path": str(project), "branch": branch, "head": head, "dirty": dirty},
        "task": {"objective": args.objective, "mode": args.mode, "scope_in": args.scope_in, "scope_out": args.scope_out},
        "authority_sources": authorities,
        "context_sources": contexts,
        "constraints": {
            "allowed_effects": args.allowed_effect or ["read", "plan"],
            "prohibited_effects": args.prohibited_effect or ["secrets", "deploy", "release"],
            "secret_policy": "no-secret-values",
        },
        "build": {
            "builder": "scripts/build_project_context_packet.py",
            "built_at": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
            "content_included": include_content,
        },
    }
    output = json.dumps(packet, indent=2, sort_keys=True) + "\n"
    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(output, encoding="utf-8")
    else:
        sys.stdout.write(output)
    return 0


if __name__ == "__main__":
    sys.exit(main())
