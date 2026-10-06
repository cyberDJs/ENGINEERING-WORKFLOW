---
id: EW-PLAT-ADOPT-001
title: EW Adopt Foundation
status: proposed
owner: Eimy Herrer and Johny
version: 0.9.0-rc.1
last-reviewed: 2026-07-26
---

# EW Adopt Foundation

## Purpose

`ew adopt` attaches the ENGINEERING-WORKFLOW control plane to an existing project without modifying product source, Git history, secrets, production infrastructure or public contracts.

## Safety contract

```text
AUDIT → CLASSIFY → PREVIEW → APPLY → VERIFY → ROLLBACK OR ACCEPT
```

The default command is read-only. Writing requires `--apply`.

The adoption process:

- requires an existing non-symlink directory;
- ignores common generated and dependency directories;
- never follows symlinks and stores only the SHA-256 of link-target text, never the target itself;
- rejects special files and unreadable paths;
- caps the audit at 10,000 files and 256 MiB;
- detects common language, CI, container and infrastructure markers;
- raises the minimum risk to R3 for Terraform, Kubernetes, sensitive-path indicators or any symlink;
- does not read or hash the content of `.env`, private-key or certificate-like paths;
- requires explicit acknowledgement before adopting a project with sensitive-path indicators;
- stages the complete control directory before atomic publication;
- compares source fingerprints before and after publication;
- writes only `.engineering-workflow/`;
- leaves product, release and operational readiness false.

## Preview

```bash
./bin/ew adopt ./existing-project \
  --name "Existing Project" \
  --profile standard-product \
  --risk R2 \
  --reversibility REV-2 \
  --json
```

Preview returns detected technologies, observed minimum risk, fingerprint, ignored paths and blockers. A blocker does not prevent the read-only report; it prevents `--apply`.

## Apply

```bash
./bin/ew adopt ./existing-project \
  --name "Existing Project" \
  --profile standard-product \
  --risk R2 \
  --reversibility REV-2 \
  --apply \
  --json
```

Generated adoption records include:

```text
.engineering-workflow/
├── project.json
├── PRODUCT_DEFINITION.md
├── WORK_PACKAGE.md
├── DECISION_REGISTER.md
├── ADOPTION_PLAN.md
├── lifecycle.json
├── rollback.json
├── evidence/
│   ├── adoption-audit.json
│   └── adopt.json
├── snapshots/
│   └── pre-adoption.json
└── manifest.json
```

## Sensitive paths

Sensitive-path metadata is reported but content is not read or hashed. Apply requires:

```bash
--acknowledge-sensitive-paths
```

Acknowledgement does not accept the security risk or expose a secret. It confirms that the operator reviewed the reported paths and selected an R3-capable profile.

## Symlink acknowledgement

A project containing symlinks can be previewed without writes. Apply requires all of:

```text
R3-CAPABLE PROFILE
--acknowledge-symlinks
--symlink-rationale "at least twenty characters"
```

The audit stores the path, a SHA-256 of the link-target text, the acknowledgement and its rationale digest. It never stores or follows the raw target.

## Rollback

Rollback is preview-first:

```bash
./bin/ew rollback ./existing-project --json
./bin/ew rollback ./existing-project --apply --json
```

Rollback is allowed only while:

- bootstrap mode is `adopt`;
- project state is `discovery`;
- no acceptance marker exists;
- `ew doctor` passes;
- the rollback record authorizes removal of `.engineering-workflow/`;
- no source fingerprint change occurs during the operation.

It removes only the owned control directory. It does not revert product code because adoption never changes product code.

## Explicit non-goals

This release candidate does not:

- understand application semantics;
- generate language or deployment golden paths;
- migrate existing CI or documentation;
- accept Product, Engineering, Security or Release authority;
- make a project production-ready;
- scan secret contents;
- claim certification, compliance or a SLSA level;
- support post-acceptance rollback or upgrade migrations.
