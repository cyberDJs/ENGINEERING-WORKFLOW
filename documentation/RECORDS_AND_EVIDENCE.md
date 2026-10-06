---
id: EW-DOC-004
title: Records and Evidence Standard
status: proposed
owner: Eimy Herrer and Johny
version: 0.7.0
last-reviewed: 2026-10-04
---

# Records and Evidence Standard

## Portable records

- Project Record;
- Work Package;
- Decision Record;
- Baseline Record;
- Change Set Record;
- Verification Record;
- Release Record;
- Incident and Postmortem Record;
- Handoff Record;
- Exception Record;
- Artifact Admission Record;
- Project Context Packet;
- Eval Receipt;
- Capability Mapping Record;
- Evaluation Suite Manifest and functional comparison result;
- Architecture Promotion Record;
- Adversarial Review Suite and security-gate result;
- AI Dependency Inventory Snapshot;
- External Authority Binding Record;
- External Authority Adoption Record.

The AI Engineering Control Plane records and Evaluation Suite Manifest are defined by JSON Schema in `../schemas/` and validated by `../scripts/validate_ai_control_plane.py`. Functional baseline/candidate comparisons are produced by `../scripts/compare_evaluation_runs.py`; they do not carry security or promotion authority. Architecture Promotion Records bind the final `ADOPT | REJECT | WATCH` state to existing Decision/Release authority without granting protected-operation permission. Adversarial Review evidence remains distinct from functional evaluation and requires independent review before it can support a passing security gate. AI Dependency Inventory snapshots bind model/provider identity and data-boundary evidence without becoming activation authority. External Authority Binding Records preserve read-only projections and exact upstream contract digests; they never substitute for authoritative GOVERDOCS ingest or Voodoo project-registry registration. External Authority Adoption Records verify those external states read-only against the actual GOVERDOCS Git workspace and Voodoo registry database; `BOUND` is evidence of registration/ingest only and grants no execution or release authority.

## Evidence properties

Evidence is attributable, timestamped, integrity-verifiable, linked to its subject, exportable and retained according to risk and obligation.

AI architecture experiments additionally preserve champion and challenger identity, the single primary changed dimension by default, corpus identity, metric thresholds, regression results, security review, migration and rollback evidence.

## Recommended evidence bundle

```text
EVIDENCE_BUNDLE/
├── manifest.json
├── project-record.json
├── work-package.md
├── baseline.json
├── change-set.json
├── verification/
├── ai/
│   ├── artifact-admission.json
│   ├── project-context-packet.json
│   ├── eval-receipt.json
│   ├── capability-mapping.json
│   ├── evaluation-suite.json
│   ├── evaluation-comparison.json
│   ├── architecture-promotion.json
│   ├── adversarial-review-suite.json
│   ├── adversarial-review-result.json
│   ├── ai-dependency-inventory.json
│   ├── goverdocs-evidence-item.json
│   ├── voodoo-project-descriptor.json
│   ├── external-authority-binding.json
│   └── external-authority-adoption.json
├── review/
├── release/
└── SHA256SUMS
```

## Storage

Git, CI artifacts, Drive, object storage and GOVERDOCS may store evidence. No single UI may be the only copy of critical long-term evidence. Closed evidence is immutable; corrections are additive and traceable.
