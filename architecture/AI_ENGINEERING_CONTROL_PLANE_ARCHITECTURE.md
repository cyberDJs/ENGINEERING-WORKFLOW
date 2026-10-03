---
id: EW-ARCH-AI-001
title: AI Engineering Control Plane
status: proposed
owner: Eimy Herrer and Johny
version: 0.4.0
last-reviewed: 2026-10-04
---

# AI Engineering Control Plane

## Canonical principle

> Optimize the decision and evidence system, not a particular model. Models, harnesses, retrieval systems, skills and runtimes are replaceable capabilities under governance, evaluation and evidence.

Hugging Face and other external ecosystems are artifact and benchmark sources. They do not own architecture, governance or project truth.

## Two-lane operating model

### Stable architecture lane

The stable lane contains the currently accepted architecture baseline. It is the only lane eligible for production use and must preserve governance, security, regression coverage, evidence and rollback.

A stable architecture version is not claimed to be globally optimal. It is only the current champion with enough evidence to operate safely inside its approved scope.

### Architecture Lab lane

The lab is an isolated challenger lane for retrieval, decision models, memory, harnesses, skills, recovery strategies, inference runtimes and other architecture components.

Lab candidates have no production authority. They may not mutate production state or weaken stable-lane controls.

## Promotion path

```text
IDEA
-> RESEARCH
-> ISOLATED PROTOTYPE
-> BENCHMARK
-> SECURITY REVIEW
-> CHAMPION/CHALLENGER COMPARISON
-> REGRESSION SUITE
-> ADOPT | REJECT | WATCH
-> VERSIONED ARCHITECTURE RELEASE
```

Promotion requires an Eval Receipt bound to exact baseline and candidate identities. Architecture experiments change one primary dimension at a time by default. Multi-dimension changes require an explicit exception reference and stronger attribution evidence.

## Architecture version record

Every promoted architecture version records:

- WHY: problem or hypothesis that justified the change;
- EVIDENCE: attributable evidence and exact artifact identities;
- BENCHMARK: representative comparison against the current champion;
- RISK: security, reliability, operational and lock-in risk;
- MIGRATION: bounded transition plan and compatibility notes;
- ROLLBACK: tested rollback, disable or safe-forward path.

## Control-plane backbone

The first portable control-plane contracts are:

1. Artifact Admission Record: identity, provenance, license, executable surface, allowed use, evaluation and rollback.
2. Project Context Packet: project truth, authority, scoped context, constraints, Git baseline and provenance. A governed runtime session may be consumed by the trust-aware builder, which fails closed on Git drift and excludes experimental, historical, superseded and unknown architecture sources by default.
3. Eval Receipt: baseline, candidate, corpus, metrics, thresholds, delta, verdict and evidence.
4. Capability Mapping Record: evidence-backed mapping from an admitted capability to an existing registry authority and project-specific permission state. The mapping is a read model and never grants execution authority.
5. Evaluation Suite Manifest: frozen case-set identity, evaluator authority, paired baseline/candidate requirements, metric thresholds and regression policy. `scripts/compare_evaluation_runs.py` only produces a functional comparison; it has no promotion authority and never substitutes for a separate security evaluation or Eval Receipt.

Registry ownership stays with the existing domain authority. Voodoo-One owns its executable capability definitions and activations; CyberSKILLS owns skill discovery/trust/distribution state; SKILLS runtime owns skill/tool routing state. The AI Engineering Control Plane references those authorities rather than creating a competing registry.

The machine-readable operating policy is `../config/ai-engineering-control-plane.json`.

## Non-goals

This control plane does not create a new model runtime, memory database, agent framework, policy authority or deployment system. It standardizes the contracts that let existing and future components be compared and replaced without redefining governance.
