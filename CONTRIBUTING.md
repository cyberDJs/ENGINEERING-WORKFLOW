---
id: EW-CONTRIBUTING
title: Contributing
status: current
owner: Eimy Herrer
version: 0.9.3-rc.1
last-reviewed: 2026-07-26
---

# Contributing

## Contribution status

External contributions are **closed by default**.

A pull request may be opened for discussion or technical review, but it must
not be merged unless Eimy Herrer has approved the contribution in writing and
the contributor has completed the project-specific exclusive rights agreement.

## Mandatory rights gate

Before merge, every non-Eimy contribution requires:

1. verified contributor identity;
2. authorship and provenance declaration;
3. disclosure of AI assistance and third-party material;
4. a written exclusive licence or other legally sufficient rights instrument
   accepted by Eimy Herrer;
5. file-level registration in `governance/IP_PROVENANCE_REGISTER.json`;
6. successful licensing and repository validation.

A DCO `Signed-off-by` line, GitHub pull request, verbal agreement or technical
approval alone is not sufficient.

## Engineering contract

After the rights gate is satisfied, every contribution must:

1. establish the current baseline;
2. declare the intended outcome and allowed scope;
3. select a risk lane;
4. remain small and logically coherent;
5. run the applicable quality gates;
6. update documentation in the same change set;
7. record limitations honestly;
8. provide rollback or recovery instructions where applicable.

Use [`templates/WORK_PACKAGE.md`](templates/WORK_PACKAGE.md) for R1-R3 work and
[`templates/ADR.md`](templates/ADR.md) for significant or difficult-to-reverse
decisions.

R2 and R3 changes require independent technical review. Independent review
does not replace the exclusive rights gate.

## No implied licence

Submitting content does not grant the submitter any licence to the existing
project. The project does not accept a contribution until the required written
rights agreement has been executed and the contribution is explicitly merged
by an authorized maintainer.
