---
id: EW-GOV-IP-002
title: Exclusive Rights and Proprietary Licensing Policy
status: current
owner: Eimy Herrer
version: 0.9.3-rc.1
last-reviewed: 2026-07-26
---

# Exclusive Rights and Proprietary Licensing Policy

## Target state

ENGINEERING-WORKFLOW is intended to be controlled and commercially licensed
exclusively by **Eimy Herrer**.

The project uses a proprietary **All Rights Reserved** model. No Apache, MIT,
MPL, GPL or other open-source licence is granted for the project-owned material.

## Current truth status

```text
PROPRIETARY LICENSING MODEL          IMPLEMENTED
INTENDED EXCLUSIVE LICENSOR          EIMY HERRER
FILE-LEVEL IP PROVENANCE             INCOMPLETE
HUMAN CONTRIBUTOR RIGHTS             PENDING AUDIT
AI-ASSISTED AUTHORSHIP EVIDENCE       PENDING AUDIT
PUBLIC SOURCE DISTRIBUTION            BLOCKED
COMMERCIAL DISTRIBUTION               BLOCKED
```

The words “exclusive owner” or “exclusive licensor” may be used as an accepted
release claim only after every material scope is classified in
`IP_PROVENANCE_REGISTER.json` and all required written agreements are retained
as controlled evidence.

## Rights model

Only Eimy Herrer may authorize:

- copying or distribution outside GitHub's mandatory service functionality;
- modification or creation of derivative works;
- publication of source or binary releases;
- commercial licensing, OEM use or hosted-service use;
- sublicensing;
- disclosure to customers, auditors or contractors;
- use of the ENGINEERING-WORKFLOW name, official marks and release seals.

A third party receives no rights unless a separate written agreement explicitly
grants them.

## Existing collaborators

Technical contribution, review, discussion or stewardship does not silently
transfer ownership to Eimy Herrer and does not silently create joint ownership.

Any material contribution by Johny or another human contributor must be handled
through one of these evidence-backed paths:

1. written exclusive licence to Eimy Herrer;
2. valid assignment where applicable law permits it;
3. documented proof that the contribution is not copyrightable;
4. clean-room replacement by an authorized contributor;
5. removal before distribution.

Until resolved, the relevant scope remains `BLOCKED`.

## AI-assisted material

AI-assisted creation must record the human creative contribution, including
selection, arrangement, modification, review and final authorship decisions.

Prompting alone is not treated as sufficient proof of exclusive copyright.
Unreviewed or unclassified AI output cannot be part of an external release.

## Contributions

External contributions are closed by default.

A pull request may be reviewed for discussion, but it must not be merged unless:

- the contributor has signed the project-specific exclusive contributor
  agreement approved by Eimy Herrer;
- authorship and provenance are recorded;
- third-party material is identified;
- the contribution is compatible with the proprietary product model.

A DCO `Signed-off-by` line alone is insufficient.

## Third-party components

Third-party tools, standards and libraries remain governed by their original
licences. Their inclusion does not change ENGINEERING-WORKFLOW into an
open-source project and does not transfer ownership of those components.

The canonical dependency record remains
`config/open-source-components.json`.

## Repository visibility

A public GitHub repository permits viewing and GitHub-service forking under the
GitHub Terms. It does not grant a general software licence, but public copies,
forks and local clones may continue to exist after a later visibility change.

Therefore the recommended target is:

```text
PRIVATE REPOSITORY
→ IP AUDIT
→ CONTROLLED PRIVATE RELEASE
→ COMMERCIAL LICENCE
```

Changing repository visibility is a separate protected administrative action
and is not performed by this policy document.

## Release gate

No source release, package publication, binary release, customer deployment or
commercial licence may be marked `ACCEPTED` until:

- legal identity of the rights holder is verified;
- human contributor history is audited;
- required exclusive agreements are signed;
- AI-assisted scopes have human-authorship evidence;
- all third-party components are classified;
- the IP provenance validator passes;
- Release Authority explicitly authorizes distribution.

## Legal review

This policy is an engineering control, not a substitute for legal advice.
Before the first external or commercial release, the agreement templates and
ownership conclusions require review by a lawyer experienced in Czech software
copyright and licensing.
