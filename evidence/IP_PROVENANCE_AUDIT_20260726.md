---
id: EW-IP-AUDIT-20260726-001
title: IP Provenance Audit
status: verified-audit-blocked-rights-resolution
owner: Eimy Herrer
version: 1.0.0
last-reviewed: 2026-07-26
---

# ENGINEERING-WORKFLOW IP Provenance Audit

## Decision

```text
AUDIT                         COMPLETE
AUDITED HEAD                  8beb2f1157cc95c51827842a5630cfc7f9d6e81d
FILES CLASSIFIED              151
DIRECT JOHNY GITHUB COMMITS    NOT FOUND
DIRECT JOHNY PULL REQUESTS     NOT FOUND
SHARED-OWNER MARKER FILES      63
AI-ASSISTED FILES              150
THIRD-PARTY REFERENCE FILES    25
VERIFIED EXCLUSIVE CONTROL     NO
DISTRIBUTION                   BLOCKED
```

## What the audit proves

- the audited tree is bound to the verified PR #14 supply-chain artifact;
- every source file has a SHA-256 and origin classification;
- all reviewed pull requests were opened by `nulleimy`;
- no separate Johny commit, pull request, foundation review or foundation comment was found;
- the current repository does not contain an open-source project licence.

## What the audit does not prove

- a GitHub account name does not prove legal authorship;
- absence of a Johny commit does not prove absence of off-platform contribution;
- historical `owner: Eimy Herrer and Johny` markers cannot be silently treated as errors;
- AI-assisted creation does not automatically establish copyright in every generated fragment;
- references to open-source tools do not by themselves prove copied code or satisfy notice obligations.

## Blocking findings

1. Verify the legal identity of the contracting rights holder.
2. Obtain Johny's written no-contribution declaration or an exclusive rights instrument.
3. Document human selection, arrangement, modification and approval of AI-assisted material.
4. Review third-party notices and licence applicability.
5. Correct shared-owner metadata only after the rights question is resolved.
6. Obtain explicit release authorization and legal review.

## Safe release state

Until all blocking findings are closed:

```text
PUBLIC SOURCE RELEASE   BLOCKED
BINARY RELEASE          BLOCKED
PACKAGE PUBLICATION     BLOCKED
COMMERCIAL LICENSING    BLOCKED
PRIVATE INTERNAL USE    PROPOSED
```

The complete file-level manifest is stored in
`evidence/IP_PROVENANCE_AUDIT_20260726.json`.
