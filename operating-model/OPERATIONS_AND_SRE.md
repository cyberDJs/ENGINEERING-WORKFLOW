---
id: EW-OPS-007
title: Operations and SRE Standard
status: proposed
owner: Eimy Herrer and Johny
version: 0.1.0
last-reviewed: 2026-07-24
---

# Operations and SRE Standard

## Service ownership

Every operated service declares an owner, support status, critical dependencies, environments, runbook, recovery objectives and escalation path.

## Reliability model

Define user-centered service level indicators and objectives. Use error budgets to balance feature delivery and reliability work; do not promise 100% availability without a justified architecture and cost model.

## Observability minimum

- version and environment identity;
- health and readiness status;
- structured logs with stable event names;
- correlation/request identifiers;
- latency, error, traffic and saturation indicators as applicable;
- audit trail for privileged and security-sensitive actions;
- alerts tied to actionable runbooks;
- sensitive-data redaction.

## Recovery

Critical systems define RTO, RPO, backup ownership, restore procedure and rehearsal frequency. A backup is not considered valid until restore has been tested.

## Operational change freeze

When reliability or security risk exceeds the defined budget, feature delivery may be limited until the system is stabilized.

## Reference operated-service rehearsal

The repository includes a localhost-only synthetic reference-service rehearsal. It verifies health/readiness, bounded operational metrics, a rehearsal-only SLI/SLO contract, backup identity and restore recovery without claiming production operation or achieved production SLOs. The authoritative runner is `scripts/run_reference_service_rehearsal.py`.
