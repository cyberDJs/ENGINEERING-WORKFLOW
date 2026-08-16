#!/usr/bin/env python3
"""Dependency-free validation for the ENGINEERING-WORKFLOW repository."""
from __future__ import annotations

import json
import re
import sys
from pathlib import Path
from urllib.parse import urlparse

ROOT = Path(__file__).resolve().parents[1]
SEMVER = re.compile(r"^(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)(?:-[0-9A-Za-z.-]+)?(?:\+[0-9A-Za-z.-]+)?$")
LINK = re.compile(r"\[[^\]]+\]\(([^)]+)\)")
FRONT_MATTER_REQUIRED = ("governance", "operating-model", "documentation", "roadmap", "references", "templates", "platform")
FRONT_FIELDS = {"id", "title", "status", "owner", "version", "last-reviewed"}
ALLOWED_STATUS = {"draft", "proposed", "current", "deprecated", "archived", "superseded"}
SECRET_PATTERNS = [
    re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----"),
    re.compile(r"\bgh[pousr]_[A-Za-z0-9]{30,}\b"),
    re.compile(r"\bsk-(?:proj-)?[A-Za-z0-9_-]{20,}\b"),
]


def error(errors: list[str], message: str) -> None:
    errors.append(message)


def parse_front_matter(path: Path, text: str, errors: list[str]) -> dict[str, str]:
    if not text.startswith("---\n"):
        error(errors, f"{path.relative_to(ROOT)}: missing front matter")
        return {}
    end = text.find("\n---\n", 4)
    if end == -1:
        error(errors, f"{path.relative_to(ROOT)}: unterminated front matter")
        return {}
    values: dict[str, str] = {}
    for line in text[4:end].splitlines():
        if not line.strip() or line.lstrip().startswith("#"):
            continue
        if ":" not in line:
            error(errors, f"{path.relative_to(ROOT)}: invalid front matter line: {line}")
            continue
        key, value = line.split(":", 1)
        values[key.strip()] = value.strip()
    missing = sorted(FRONT_FIELDS - values.keys())
    if missing:
        error(errors, f"{path.relative_to(ROOT)}: missing metadata fields: {', '.join(missing)}")
    if values.get("status") and values["status"] not in ALLOWED_STATUS:
        error(errors, f"{path.relative_to(ROOT)}: unsupported status {values['status']!r}")
    if values.get("version") and not SEMVER.match(values["version"]):
        error(errors, f"{path.relative_to(ROOT)}: invalid document version {values['version']!r}")
    return values


def validate_links(path: Path, text: str, errors: list[str]) -> None:
    for target in LINK.findall(text):
        target = target.strip().split("#", 1)[0]
        if not target or target.startswith(("#", "mailto:")):
            continue
        parsed = urlparse(target)
        if parsed.scheme:
            continue
        resolved = (path.parent / target).resolve()
        try:
            resolved.relative_to(ROOT.resolve())
        except ValueError:
            error(errors, f"{path.relative_to(ROOT)}: link escapes repository: {target}")
            continue
        if not resolved.exists():
            error(errors, f"{path.relative_to(ROOT)}: broken relative link: {target}")


def main() -> int:
    errors: list[str] = []
    required = json.loads((ROOT / "config/required-paths.json").read_text(encoding="utf-8"))["required_paths"]
    for relative in required:
        if not (ROOT / relative).is_file():
            error(errors, f"missing required file: {relative}")

    version = (ROOT / "VERSION").read_text(encoding="utf-8").strip()
    if not SEMVER.match(version):
        error(errors, f"VERSION is not valid SemVer: {version!r}")

    for json_path in ROOT.rglob("*.json"):
        try:
            json.loads(json_path.read_text(encoding="utf-8"))
        except Exception as exc:
            error(errors, f"{json_path.relative_to(ROOT)}: invalid JSON: {exc}")

    document_ids: dict[str, Path] = {}
    for path in ROOT.rglob("*.md"):
        if ".git" in path.parts:
            continue
        text = path.read_text(encoding="utf-8")
        if not text.strip():
            error(errors, f"{path.relative_to(ROOT)}: empty document")
        if path.relative_to(ROOT).parts[0] in FRONT_MATTER_REQUIRED and path.name != "WORLD_CLASS_SOFTWARE_DEVOPS_OPERATING_MODE.md":
            metadata = parse_front_matter(path, text, errors)
            document_id = metadata.get("id")
            if document_id:
                if document_id in document_ids:
                    error(errors, f"duplicate document id {document_id}: {document_ids[document_id].relative_to(ROOT)} and {path.relative_to(ROOT)}")
                document_ids[document_id] = path
        validate_links(path, text, errors)
        for pattern in SECRET_PATTERNS:
            if pattern.search(text):
                error(errors, f"{path.relative_to(ROOT)}: possible secret/private key pattern")

    control = json.loads((ROOT / "project-control.json").read_text(encoding="utf-8"))
    if control.get("control", {}).get("version") != version:
        error(errors, "project-control.json version does not match VERSION")
    for key in (
        "governance_file",
        "technical_operating_mode",
        "product_decision_execution_constitution",
        "constitutional_authority",
        "constitutional_compatibility_report",
        "primary_engineering_invariant",
        "complexity_budget",
        "reversibility_classes",
        "manual_work_register",
        "lifecycle_evidence_graph",
    ):
        relative = control.get("control", {}).get(key)
        if not relative or not (ROOT / relative).is_file():
            error(errors, f"project-control.json references missing {key}: {relative!r}")

    quality = control.get("quality", {})
    expected_quality = {
        "validator": "python3 scripts/validate_repository.py",
        "constitutional_validator": "python3 scripts/validate_constitutions.py",
        "primary_invariant_validator": "python3 scripts/validate_primary_invariant.py",
        "supply_chain_validator": "python3 scripts/validate_supply_chain.py",
        "cli_self_test": "./bin/ew self-test --json",
        "portability": "python bin/ew self-test --json + CLI test matrix",
        "tests": "python3 -m unittest discover -s tests -v",
    }
    for key, expected in expected_quality.items():
        if quality.get(key) != expected:
            error(errors, f"project-control.json quality.{key} must equal {expected!r}")

    cli = control.get("cli", {})
    expected_cli = {
        "version": "0.3.0",
        "entrypoint": "bin/ew",
        "foundation_document": "platform/EW_CLI_FOUNDATION.md",
        "adoption_document": "platform/EW_ADOPT_FOUNDATION.md",
        "commands": ["init", "adopt", "doctor", "rollback", "self-test"],
        "git_required": False,
        "external_runtime_dependencies": [],
    }
    for key, expected in expected_cli.items():
        if cli.get(key) != expected:
            error(errors, f"project-control.json cli.{key} must equal {expected!r}")
    for key in ("entrypoint", "foundation_document", "adoption_document"):
        relative = cli.get(key)
        if not relative or not (ROOT / relative).is_file():
            error(errors, f"project-control.json references missing cli.{key}: {relative!r}")

    portability_workflow = ROOT / ".github/workflows/portability.yml"
    if not portability_workflow.is_file():
        error(errors, "missing portability workflow")
    else:
        workflow_text = portability_workflow.read_text(encoding="utf-8")
        for marker in ("ubuntu-24.04", "macos-14", "windows-2022", 'python-version: ["3.11", "3.12"]'):
            if marker not in workflow_text:
                error(errors, f"portability workflow missing matrix marker: {marker}")

    entrypoint = ROOT / str(cli.get("entrypoint", ""))
    cli_parser = ROOT / "bin/ew_cli.py"
    if entrypoint.is_file():
        text = entrypoint.read_text(encoding="utf-8")
        if 'CLI_VERSION = "0.3.0"' not in text:
            error(errors, "bin/ew CLI_VERSION does not match project-control.json")
        if entrypoint.stat().st_mode & 0o111 == 0:
            error(errors, "bin/ew must be executable")
    if not cli_parser.is_file():
        error(errors, "missing modular CLI parser: bin/ew_cli.py")
    else:
        parser_text = cli_parser.read_text(encoding="utf-8")
        for command in expected_cli["commands"]:
            if f"add_parser('{command}')" not in parser_text and f'add_parser("{command}")' not in parser_text:
                error(errors, f"bin/ew_cli.py does not register required command: {command}")

    if errors:
        print("VALIDATION=FAILED")
        for item in errors:
            print(f"ERROR: {item}")
        return 1
    print("VALIDATION=PASSED")
    print(f"VERSION={version}")
    print(f"REQUIRED_FILES={len(required)}")
    print(f"CONTROLLED_DOCUMENT_IDS={len(document_ids)}")
    print(f"CLI_COMMANDS={len(expected_cli['commands'])}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
