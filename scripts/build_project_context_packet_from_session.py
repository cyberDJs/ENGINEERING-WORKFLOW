#!/usr/bin/env python3
"""Build a trust-aware Project Context Packet from a governed runtime session."""
from __future__ import annotations

import argparse
import hashlib
import json
import sys
from datetime import datetime, timezone
from pathlib import Path

# Trust verification must not dirty the repository by creating local __pycache__ files.
sys.dont_write_bytecode = True

from build_project_context_packet import read_source, run_git

TRUSTED_CONTEXT_STATUSES = {"CURRENT_CANONICAL", "CURRENT_SUPPORTING"}


def fail(message: str) -> int:
    print("CONTEXT_BUILD=FAILED", file=sys.stderr)
    print(f"ERROR: {message}", file=sys.stderr)
    return 1


def source_record(path: Path, *, include_content: bool, metadata: dict[str, object]) -> dict[str, object]:
    record = read_source(path, include_content)
    record.update(metadata)
    return record


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--session", type=Path, required=True)
    parser.add_argument("--task-mode", choices=["AUDIT", "DESIGN", "IMPLEMENT", "VERIFY", "RELEASE", "VALIDATE", "INCIDENT"], default="IMPLEMENT")
    parser.add_argument("--scope-in", action="append", required=True)
    parser.add_argument("--scope-out", action="append", default=[])
    parser.add_argument("--allowed-effect", action="append", default=[])
    parser.add_argument("--prohibited-effect", action="append", default=[])
    parser.add_argument("--include-content", action="store_true")
    parser.add_argument("--max-context-sources", type=int, default=12)
    parser.add_argument("--max-total-content-bytes", type=int, default=131072)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()

    if args.max_context_sources < 1 or args.max_total_content_bytes < 1:
        return fail("context bounds must be positive")
    try:
        session_raw = args.session.read_bytes()
        session = json.loads(session_raw.decode("utf-8"))
    except Exception as exc:
        return fail(f"invalid session file: {exc}")
    if session.get("status") != "READY":
        return fail("runtime session status must be READY")

    project = session.get("project")
    if not isinstance(project, dict):
        return fail("runtime session project is missing")
    session_git = project.get("git")
    if not isinstance(session_git, dict):
        return fail("runtime session git snapshot is missing")
    project_path = Path(str(project.get("path", ""))).resolve()
    try:
        git_root = Path(run_git(project_path, "rev-parse", "--show-toplevel")).resolve()
        current_head = run_git(git_root, "rev-parse", "HEAD")
        current_branch = run_git(git_root, "branch", "--show-current")
        current_dirty = bool(run_git(git_root, "status", "--porcelain"))
    except Exception as exc:
        return fail(f"cannot verify current Git state: {exc}")

    expected_root = Path(str(session_git.get("root", project_path))).resolve()
    if git_root != expected_root:
        return fail("project root drifted since runtime session")
    if current_head != session_git.get("head"):
        return fail("project HEAD drifted since runtime session")
    if current_branch != session_git.get("branch"):
        return fail("project branch drifted since runtime session")
    if current_dirty is not bool(session_git.get("dirty")):
        return fail("project dirty state drifted since runtime session")

    authority_paths = project.get("authority_files")
    if not isinstance(authority_paths, list) or not authority_paths:
        return fail("runtime session returned no authority files")
    authorities: list[dict[str, object]] = []
    authority_resolved: set[Path] = set()
    try:
        for raw_path in authority_paths:
            path = Path(str(raw_path)).resolve()
            authority_resolved.add(path)
            authorities.append(source_record(path, include_content=args.include_content, metadata={"role": "authority", "source_status": "CURRENT_CANONICAL", "source_class": "project-authority"}))
    except Exception as exc:
        return fail(str(exc))
    retrieval = session.get("architecture_retrieval")
    load_set = retrieval.get("load_set", []) if isinstance(retrieval, dict) else []
    if not isinstance(load_set, list):
        return fail("architecture retrieval load_set is invalid")
    contexts: list[dict[str, object]] = []
    excluded_status_counts: dict[str, int] = {}
    try:
        for item in load_set:
            if not isinstance(item, dict):
                continue
            status = str(item.get("status", "UNKNOWN"))
            path = Path(str(item.get("path", ""))).resolve()
            if status not in TRUSTED_CONTEXT_STATUSES:
                excluded_status_counts[status] = excluded_status_counts.get(status, 0) + 1
                continue
            if path in authority_resolved:
                continue
            if not path.is_file():
                return fail(f"selected context source is not a file: {path}")
            contexts.append(source_record(path, include_content=args.include_content, metadata={
                "role": "supporting-context",
                "source_status": status,
                "source_class": str(item.get("source", "unknown")),
                "title": str(item.get("title", path.name)),
                "reasons": item.get("reasons", []),
            }))
            if len(contexts) >= args.max_context_sources:
                break
    except Exception as exc:
        return fail(str(exc))

    if args.include_content:
        total_bytes = sum(len(str(item.get("content", "")).encode("utf-8")) for item in [*authorities, *contexts])
        if total_bytes > args.max_total_content_bytes:
            return fail(f"included context exceeds byte budget: {total_bytes} > {args.max_total_content_bytes}")
    project_id = git_root.name
    control_path = git_root / "project-control.json"
    if control_path.is_file():
        try:
            control = json.loads(control_path.read_text(encoding="utf-8"))
            project_id = str(control.get("project", {}).get("id", project_id))
        except Exception as exc:
            return fail(f"invalid project-control.json: {exc}")

    task = str(session.get("task", "")).strip()
    if not task:
        return fail("runtime session task is missing")
    session_sha = hashlib.sha256(session_raw).hexdigest()
    seed = "|".join([project_id, current_head, session_sha, task, *args.scope_in])
    packet = {
        "schema_version": "1.0.0",
        "packet_id": "PCP-" + hashlib.sha256(seed.encode("utf-8")).hexdigest()[:16],
        "project": {"id": project_id, "path": str(git_root), "branch": current_branch, "head": current_head, "dirty": current_dirty},
        "task": {"objective": task, "mode": args.task_mode, "scope_in": args.scope_in, "scope_out": args.scope_out},
        "authority_sources": authorities,
        "context_sources": contexts,
        "constraints": {
            "allowed_effects": args.allowed_effect or ["read", "plan"],
            "prohibited_effects": args.prohibited_effect or ["secrets", "deploy", "release"],
            "secret_policy": "no-secret-values",
        },
        "build": {
            "builder": "scripts/build_project_context_packet_from_session.py",
            "built_at": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
            "content_included": args.include_content,
            "session_sha256": session_sha,
            "session_source": str(args.session.resolve()),
            "trusted_context_statuses": sorted(TRUSTED_CONTEXT_STATUSES),
            "excluded_status_counts": excluded_status_counts,
            "selected_context_count": len(contexts),
            "source_policy": "project truth outranks supporting sources; experimental/historical/superseded/unknown excluded",
        },
    }
    output = json.dumps(packet, indent=2, sort_keys=True) + "\n"
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(output, encoding="utf-8")
    print("CONTEXT_BUILD=PASSED")
    print(f"PACKET_ID={packet['packet_id']}")
    print(f"AUTHORITY_SOURCES={len(authorities)}")
    print(f"CONTEXT_SOURCES={len(contexts)}")
    print(f"EXCLUDED_STATUSES={json.dumps(excluded_status_counts, sort_keys=True)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
