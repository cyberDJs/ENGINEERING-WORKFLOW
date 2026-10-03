---
id: EW-OPS-005
title: AI-Assisted Engineering Standard
status: proposed
owner: Eimy Herrer and Johny
version: 0.7.0
last-reviewed: 2026-10-04
---

# AI-Assisted Engineering Standard

AI is an accelerator and replaceable capability, not an authority.

## Canonical principle

> Optimize the decision and evidence system, not a particular model. Models, harnesses, retrieval systems, skills and runtimes remain replaceable under governance, evaluation and evidence.

## Required pipeline

```text
CONTEXT -> PLAN -> CONSTRAINED EXECUTION -> DETERMINISTIC VALIDATION -> ADVERSARIAL REVIEW -> HUMAN ACCEPTANCE -> EVIDENCE
```

## Project Context Packet

Every material AI task receives a bounded Project Context Packet containing project identity and Git baseline, exact objective and scope, authoritative sources, relevant supporting context, allowed and prohibited effects, validation expectations and secret boundaries.

The portable schema is `../schemas/project-context-packet.schema.json`. The reference builder is `../scripts/build_project_context_packet.py`.

The reference builder is provenance-only by default: it records paths and SHA-256 digests but omits source content. Source content is included only through explicit `--include-content`, and scanned inputs still fail closed on detected secret material.

For governed project work, `../scripts/build_project_context_packet_from_session.py` consumes a `READY` SKILLS runtime session instead of rediscovering context. It binds the packet to the session SHA-256 and exact Git root/branch/HEAD/dirty state, fails on drift, preserves source status/provenance, and admits only `CURRENT_CANONICAL` and `CURRENT_SUPPORTING` context by default. Project authority files remain a separate higher-priority source class.

## Artifact Admission

Models, datasets, Skills, tools, runtimes and adapters are untrusted until admitted. Admission records immutable revision and digest, license, owner, executable surface, runtime/hardware fit, allowed and prohibited use, evaluation baseline, evidence and rollback.

The portable schema is `../schemas/artifact-admission-record.schema.json`.

## Eval Receipt

Every material AI change compares an identified baseline with an identified candidate and records corpus identity, metrics, thresholds, delta, verdict, environment and evidence. Architecture challengers change one primary dimension at a time by default so improvement remains attributable.

The portable schema is `../schemas/eval-receipt.schema.json`.

## Eval Fabric

Functional evaluations use a frozen Evaluation Suite Manifest plus paired baseline/candidate JSONL results. The manifest binds the exact case-set digest, case IDs, evaluator authority, metrics, thresholds and regression policy. `../scripts/compare_evaluation_runs.py` rejects case-set drift, duplicate or missing cases, severity drift and malformed metrics before comparison. Critical candidate failures override averages, and new regressions remain explicit.

Eval Fabric is not a model runner and does not replace project-native QA or SKILLS evaluators. Existing harnesses produce the per-case evidence; the comparator normalizes their paired comparison. Its output is functional-only, records `promotion_authority=false`, and leaves security as `NOT_EVALUATED` until a separate security gate runs.

The portable manifest schema is `../schemas/evaluation-suite.schema.json`.

## Adversarial Review Gate

Security evaluation is separate from functional Eval Fabric. An Adversarial Review Suite binds an explicit threat model, a frozen case-set digest, approved isolated test environment and blocking policy. Existing project-native or SKILLS red-team harnesses execute the cases; `../scripts/evaluate_adversarial_results.py` verifies the result contract and fails closed on critical/high failures, unauthorized effects, secret exposure, privilege escalation or external effects.

A clean behavioral run is not sufficient by itself. Independent review is mandatory; until an attributable reviewer and review evidence are present, the security verdict is `BLOCKED`. The gate never grants promotion, release, deployment or production authority. The portable suite schema is `../schemas/adversarial-review-suite.schema.json`.

## Architecture Promotion Closure

A candidate leaves the Architecture Lab only through an Architecture Promotion Record. `WATCH` and `REJECT` may be closed by fail-closed project policy and remain non-production. `ADOPT` requires a passing Eval Receipt, passing security and regression gates, verified rollback, an attributable non-policy Decision Authority, a versioned architecture, and references to an existing Release Record and Release Authority.

The promotion record is evidence of closure, not permission to execute, merge, release, deploy or change activation state. Protected operations remain separately authorized under project governance. The portable schema is `../schemas/architecture-promotion-record.schema.json`.

## Capability Mapping

An admitted capability may be mapped to projects only through an evidence-backed Capability Mapping Record. The mapping points to the existing registry authority for that capability class and records project-specific allowed use, prohibited use, environments, lifecycle status and any external execution-authority reference.

A Capability Mapping Record is observational. It never creates or activates an executable capability and `mapping_grants_execution` is always false. Voodoo-One, CyberSKILLS, SKILLS runtime or a project-native registry remain authoritative for their own entity classes.

The portable schema is `../schemas/capability-mapping-record.schema.json`.

## Stable architecture and Architecture Lab

Stable architecture is the current evidence-backed champion. It is not assumed globally optimal. The Architecture Lab is an isolated challenger lane for retrieval, decision routing, memory, harnesses, Skills, recovery, inference/runtime variants and workers.

Lab candidates have no production authority. Promotion follows research, isolated prototype, benchmark, security review, champion/challenger comparison, regression and explicit adopt/reject decision. The machine policy is `../config/ai-engineering-control-plane.json`.

## Controls

- generated output is untrusted until validated;
- an AI must not claim tests or changes it did not execute;
- R2/R3 changes require human review and independent deterministic checks;
- sensitive data and secrets must not be placed into an unauthorized model context;
- source and license provenance must be reviewed for generated or suggested implementation;
- model/provider/harness/retrieval changes are dependency and risk changes;
- prompt, context and output retention follow project data policy;
- production governance and deterministic gates may not be weakened by a lab candidate;
- benchmark improvement without regression, security and rollback evidence is insufficient for promotion.

## Metrics

Measure accepted value, task success, regression retention, failure behavior, lead time, latency, cost, escaped defects, rework, review time and automation coverage. Do not use token count, generated lines or prompt count as primary performance metrics.
