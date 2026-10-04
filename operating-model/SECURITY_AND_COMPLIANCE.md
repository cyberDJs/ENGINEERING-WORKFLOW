---
id: EW-OPS-004
title: Security and Compliance Operating Standard
status: proposed
owner: Eimy Herrer and Johny
version: 0.1.0
last-reviewed: 2026-07-24
---

# Security and Compliance Operating Standard

## Security outcomes

The system aligns its secure-development outcomes with NIST SSDF 1.1 and tracks the draft SSDF 1.2 without treating draft controls as final. AI model development additionally considers NIST SP 800-218A.

## Control families

1. **Prepare:** roles, policy, environment hardening, training and toolchain integrity.
2. **Protect:** source, credentials, build systems, artifacts and sensitive records.
3. **Produce:** secure design, threat modeling, reviewed dependencies, testing and provenance.
4. **Respond:** vulnerability intake, triage, remediation, disclosure and root-cause prevention.

## Required practices

- threat modeling for R2/R3 boundary changes;
- least privilege and separated identities;
- secret scanning and rotation procedure;
- input validation and output encoding;
- dependency, license and provenance review;
- logging with sensitive-data redaction;
- defined data classification, retention and deletion;
- vulnerability response ownership and service levels;
- supply-chain integrity targets using SLSA concepts;
- compliance evidence mapped to actual engineering controls, not duplicated paperwork.

## Compliance mapping

A compliance requirement must map to: control objective, implementation, owner, evidence source, frequency, exception process and retention. Evidence should be generated from normal delivery wherever possible.
## Current project threat model

`assurance/engineering-workflow-threat-model.json` is the canonical current threat model for this repository, with `assurance/ENGINEERING_WORKFLOW_THREAT_MODEL.md` as its human-readable summary. A locally implemented model is not independent acceptance; unresolved high residual risks remain blocking until the named authority and closure evidence exist.
