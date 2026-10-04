---
id: EW-RM-001
title: Implementation Roadmap
status: proposed
owner: Eimy Herrer and Johny
version: 0.1.0
last-reviewed: 2026-07-24
---

# Implementation Roadmap

## Phase 0 — Foundation (implemented in 0.1.0 RC)

- constitution, governance and lifecycle;
- risk lanes and quality gates;
- documentation architecture and templates;
- security, compliance, AI, release, SRE and incident standards;
- repository validator, tests and CI.

## Phase 1 — Repository hardening

- approve governance documents;
- choose repository license;
- configure protected `main`, review requirements and required CI;
- add CODEOWNERS and signed-release policy;
- publish 0.1.0.

## Phase 2 — Golden-path CLI

- `ej doctor`, `ej new`, `ej work`, `ej check`, `ej evidence`, `ej release`, `ej recover`;
- adapter contract and project manifest schema;
- deterministic scaffold templates for Python, Node and mixed-stack projects.

## Phase 3 — Project pilot

- adopt on a low-risk reference project;
- measure bootstrap time, lead time, review friction, rework and documentation freshness;
- remove unnecessary controls and automate repeated steps.

## Phase 4 — Real project adoption

- CyberCore pilot;
- APPLAYLIST and NoDrama adoption;
- V-One adoption only after compatibility audit due to its existing governance invariants.

## Phase 5 — Delivery platform

- reusable CI workflows;
- environment/deployment adapters;
- evidence builder, SBOM and provenance;
- policy-as-code and compliance mapping;
- progressive delivery and rollback automation.

## Phase 6 — AI-native control plane

- context packet builder;
- constrained task orchestrator;
- deterministic validator and adversarial reviewer;
- human authority gates;
- GOVERDOCS/VOODOO evidence and project registry integration through read-only contract projections; authoritative ingest/registration remains a separately governed adoption gate.

## Completion rule

A phase is complete only after implementation, validation, adoption evidence, rollback/recovery proof and updated documentation.
