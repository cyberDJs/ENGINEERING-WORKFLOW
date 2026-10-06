---
id: EW-PLAT-003
title: EW CLI Foundation
status: proposed
owner: Eimy Herrer and Johny
version: 0.9.0-rc.1
last-reviewed: 2026-07-26
---

# EW CLI Foundation

`ew` is the portable, dependency-free bootstrap and adoption interface for ENGINEERING-WORKFLOW.

## Implemented commands

```text
ew init
ew adopt
ew doctor
ew rollback
ew self-test
```

`ew init` writes only `.engineering-workflow/`. It stages the complete controlled directory and atomically publishes it only when every record has been generated. It never overwrites an existing controlled project.

`ew adopt` performs a bounded read-only audit by default. `--apply` is required to add the control plane to an existing project. Product source is fingerprinted before and after publication and is not modified.

`ew doctor` verifies required records, profile/risk/reversibility consistency, manifest hashes, adoption evidence, undeclared files, symlinks and lifecycle graph references. It stops before reading content when the control directory itself or any controlled path is linked or unsafe.

`ew rollback` is preview-first and removes only an unaccepted, manifest-owned adoption control directory. It does not attempt semantic product migration or source rollback.

`ew self-test` proves init and adoption preview behavior, atomic creation, doctor success, idempotent re-execution, tamper detection, source-fingerprint stability and controlled rollback inside isolated temporary directories.

## Safety contract

- Git is not required.
- Product source files are never modified by init or adoption.
- Existing controlled state is never silently replaced.
- Adoption preview remains read-only even when blockers are detected.
- Apply is fail-closed for unresolved blockers.
- Profile downgrade is rejected when observed risk or reversibility requires a stronger profile.
- Terraform, Kubernetes and sensitive-path indicators raise the observed minimum risk to R3.
- Symlinks are recorded but never followed; adoption requires R3, explicit acknowledgement and a rationale of at least 20 characters.
- Regular files are opened with no-follow semantics where supported and are checked before open, on the descriptor, after read and again by path.
- Sensitive-path content is neither read nor hashed.
- Scans are capped at 10,000 files and 256 MiB.
- `REV-3` and `REV-4` require a profile supporting R3.
- Generated records do not claim product, release or operational readiness.
- Failed writes are cleaned up before returning.
- Existing inconsistent state returns `BLOCKED`.

## Execution

```bash
./bin/ew self-test --json
```

The repository-native script has no external runtime dependencies and does not require Git. Distribution packaging remains deferred until license and intellectual-property authority are accepted.

The detailed adoption and rollback contract is defined in [`EW_ADOPT_FOUNDATION.md`](EW_ADOPT_FOUNDATION.md).

## Deliberately deferred

Semantic migration, project-specific golden paths, upgrades, post-acceptance rollback, provider adapters, release signing and remote evidence storage are separate governed slices.

## Portability evidence

The CI matrix runs the CLI self-test and all CLI/adversarial tests on Ubuntu 24.04, macOS 14 and Windows 2022 with Python 3.11 and 3.12. Platform-specific symlink tests are skipped only when the runner cannot create symlinks.
