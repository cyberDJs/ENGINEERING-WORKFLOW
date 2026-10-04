---
id: EW-TM-001
title: ENGINEERING-WORKFLOW Threat Model
status: implemented-awaiting-independent-review
owner: Security Authority
baseline-revision: fa61885bac99476bab3dfe7f54334bcd1755cb32
---

# ENGINEERING-WORKFLOW Threat Model

The canonical machine-readable model is `assurance/engineering-workflow-threat-model.json`. This assessment covers repository governance, GitHub/CI trust boundaries, verified tools, supply-chain evidence, AI-assisted engineering, release promotion and recovery controls. Active exploitation, production DAST, secret access and third-party target testing are explicitly out of scope.

## Current verdict

The threat model is **IMPLEMENTED** but not independently accepted. Critical residual risks remain around merge enforcement (`GAP-007`), independent security review (`GAP-008`), signed release evidence (`GAP-009`), production release verification (`GAP-011`), operational recovery evidence (`GAP-012`) and independent AI acceptance (`GAP-015`).

## Trust boundaries

1. untrusted contribution → repository and CI;
2. GitHub Actions → OIDC signing authority;
3. third-party actions/tools → repository evidence;
4. AI output → governed execution;
5. evidence producer → acceptance authority;
6. release candidate → deployment target.

## Security rule

No threat is considered accepted merely because a control exists or a local test passes. High residual risks remain blocking until their named authority and closure evidence exist. Independent review is required for `GAP-008`; this document does not self-approve that gate.
