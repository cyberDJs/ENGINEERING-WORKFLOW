---
id: EW-DOC-004
title: Records and Evidence Standard
status: proposed
owner: Eimy Herrer and Johny
version: 0.3.0
last-reviewed: 2026-10-03
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
- Capability Mapping Record.

The four AI Engineering Control Plane records are defined by JSON Schema in `../schemas/` and validated by `../scripts/validate_ai_control_plane.py`.

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
│   └── capability-mapping.json
├── review/
├── release/
└── SHA256SUMS
```

## Storage

Git, CI artifacts, Drive, object storage and GOVERDOCS may store evidence. No single UI may be the only copy of critical long-term evidence. Closed evidence is immutable; corrections are additive and traceable.
