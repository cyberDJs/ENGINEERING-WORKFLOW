---
id: EW-OPS-008
title: Incident Management Standard
status: proposed
owner: Eimy Herrer and Johny
version: 0.1.0
last-reviewed: 2026-07-24
---

# Incident Management Standard

## Priorities

1. protect people, data and legal obligations;
2. contain blast radius;
3. restore a safe level of service;
4. preserve evidence and timeline;
5. communicate verified status;
6. remove the root cause and systemic weakness.

## Severity

Projects define severity using user impact, data/security impact, duration, scope and recovery complexity.

## Roles

Incident Commander, Operations Lead, Communications Lead and Scribe. In a two-person team roles may be combined but must remain explicit.

## Timeline

Every incident records detection, declaration, containment, mitigation, recovery, validation and closure.

## Postmortem

Blameless does not mean accountability-free. The postmortem identifies contributing system conditions, missing controls, decision quality and corrective actions with owners and due states.

## Reference exercise

`scripts/run_incident_exercise.py` performs a bounded local rehearsal of unsafe toolchain-policy drift. It mutates only a temporary lab copy, requires fail-closed detection, restores the exact baseline bytes, re-runs validation, and emits a machine-readable timeline receipt. The exercise grants no emergency, execution, deployment or release authority.

## Emergency change

Emergency changes still require identity, baseline, limited scope, recovery plan and retrospective reconciliation.
