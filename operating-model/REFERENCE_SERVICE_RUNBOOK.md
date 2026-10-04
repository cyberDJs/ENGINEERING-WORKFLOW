---
id: EW-RUNBOOK-REFERENCE-SERVICE
title: Reference Service Rehearsal Runbook
status: current
owner: Operator
version: 1.0.0
last-reviewed: 2026-10-05
---

# Reference Service Rehearsal Runbook

## Scope

This runbook covers only the isolated localhost rehearsal implemented by `scripts/run_reference_service_rehearsal.py`. It is not a production-service runbook.

## Identity and start

Run `python3 scripts/run_reference_service_rehearsal.py --output <receipt.json>`. The service binds only to `127.0.0.1` on an ephemeral port and uses synthetic temporary state.

## Health and readiness

The rehearsal verifies `/healthz` and `/readyz`, then executes bounded `/work` probes and records request/error counters.

## Rehearsal SLI/SLO

Success SLI is successful synthetic work probes divided by total probes with a rehearsal target of 0.99. Local handler p95 latency has a rehearsal target of 250 ms. These are laboratory thresholds and are not production SLO claims.

## Recovery

The runner creates a SHA-256-bound backup, deliberately corrupts only temporary synthetic state, restores from backup, and requires restored state identity to match the original baseline. Rehearsal restore target is 2000 ms.

## Failure handling

Any failed health/readiness probe, missed rehearsal threshold, or restore identity mismatch makes the receipt `FAILED`. Do not reinterpret missing telemetry as success.

## Security

No external network, secrets, personal data, deployment credentials or production state are used.

## Remaining operational gap

A real operated service, real telemetry window, real backup/restore target and independent Operational Readiness Authority review remain required before `GAP-012` can close.
