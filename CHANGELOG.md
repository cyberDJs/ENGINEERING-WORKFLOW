---
id: EW-CHANGELOG
title: Changelog
status: current
owner: Eimy Herrer and Johny
version: 0.9.4-rc.1
last-reviewed: 2026-10-06
---

# Changelog

All notable changes are recorded here. Versions follow Semantic Versioning.

## [Unreleased]

- Record GAP-012 reference operated-service evidence and move operations from DESIGNED to IMPLEMENTED while keeping real operational readiness blocked.
- Add localhost-only reference operated-service rehearsal with health/readiness probes, rehearsal SLI/SLO measurements, backup identity and deterministic restore verification.
- Reclassify GAP-009 from design-only to implemented supply-chain controls while blocking closure on main/tag attestation, signing verification and independent acceptance.
- Record current GAP-015 AI context, permission, evaluation and red-team evidence; advance AI engineering to IMPLEMENTED while blocking closure on independent security and human acceptance.
- Record live GitHub verification for GAP-007 and mark policy enforcement BLOCKED until merge-level required checks or rulesets are active.
- Add deterministic isolated incident rehearsal for toolchain-policy drift, recovery, timeline evidence, and corrective-action verification.
- Add the current repository threat model and mark GAP-008 implemented but blocked on independent security review.
- Record GAP-011 as IMPLEMENTED/BLOCKED after a verified offline immutable promotion and rollback rehearsal; real release authority and deployment verification remain required.
- Add a deterministic offline release promotion/rollback rehearsal with immutable candidate identity and explicit no-production-authority boundaries.

### Added

- Add fail-closed External Authority Adoption verification that binds GOVERDOCS receipts to the real Git authority workspace and Voodoo project registration to the durable registry plus audit event without granting execution or release authority.
- AI Engineering Control Plane architecture with stable champion and isolated Architecture Lab lanes;
- portable Artifact Admission Record, Project Context Packet and Eval Receipt schemas;
- dependency-free AI control-plane validator, deterministic context-packet builder and regression tests;
- secure-by-default context packets with provenance-only output unless source content is explicitly requested;
- hardened eval receipts requiring disjoint/holdout validation, explicit deltas, security review, regression evidence and rollback state;
- portable Capability Mapping Record that binds admission/eval evidence to existing registry authorities without granting execution authority;
- trust-aware Project Context Packet assembly from governed runtime sessions with Git-drift rejection and experimental-source exclusion;
- deterministic Eval Fabric manifest and paired-run comparator with frozen case-set identity, critical-failure override, regression detection and no promotion authority;
- fail-closed Architecture Promotion Record linking `ADOPT | REJECT | WATCH` to evaluation, security, regression, rollback and existing Decision/Release authority without granting protected operations;
- deterministic adversarial-review suite and security gate with frozen threat/case identity, critical-effect hard stops, independent-review requirement and no promotion authority;
- read-only AI model/provider dependency inventory with exact admission identity, data/network/retention boundaries and no activation authority;
- read-only GOVERDOCS/Voodoo external-authority projections with exact upstream contract digests, fail-closed binding state and no implicit ingest, registration or authority;
- constrained task-plan contract and plan-only builder that fail closed on prohibited effects and require attributable external authority for protected effects;
- deterministic reference artifact packaging and SHA-256 manifests;
- CycloneDX SBOM generation and blocking vulnerability policy;
- supply-chain evidence, provenance, keyless signing and identity-verification workflow;
- Product, Decision and Execution Constitution bound to the exact technical constitution hash;
- Article 0 primary engineering invariant;
- machine-readable invariant, complexity budget and reversibility classes;
- manual-work register and lifecycle evidence graph beyond Git history;
- constitutional and primary-invariant validators with negative regression tests;
- Product Definition, Decision Record, Authority Assignment and Manual Work templates;
- independent constitutional CI gate alongside quality, policy and supply-chain gates.
- proprietary `LICENSE` and `COPYRIGHT` notices reserving project rights to Eimy Herrer;
- machine-readable IP provenance register and schema;
- exclusive-rights and proprietary-licensing governance policy;
- closed-by-default contribution policy requiring a project-specific written exclusive rights agreement;
- fail-closed distribution gates while contributor and AI provenance remain unresolved;
- licensing validator with negative regression tests;
- independent constitutional CI gate alongside quality, policy and supply-chain gates;
- dependency-free `ew init`, `ew doctor` and `ew self-test` foundation;
- atomic controlled-directory generation, manifest integrity and profile downgrade protection;
- preview-first `ew adopt` for existing projects;
- bounded read-only inventory, technology detection and source fingerprinting;
- sensitive-path content redaction and explicit acknowledgement gate;
- pre-adoption evidence snapshot and no-source-change proof;
- preview-first `ew rollback` limited to manifest-owned bootstrap state;
- CLI schemas, documentation and negative regression tests;
- race-aware no-follow file hashing with pre-open, descriptor and post-read identity checks;
- fail-closed doctor boundary for linked or unsafe control directories;
- R3 symlink acknowledgement with rationale evidence and hashed link targets;
- Linux, macOS and Windows portability matrix for Python 3.11 and 3.12;
- adversarial filesystem tests for link substitution and concurrent mutation.

### Planned

- repository rulesets and branch protection;
- project scaffolding CLI and adoption automation;
- reusable deployment adapters;
- compliance evidence generation;
- successful signed main/tag evidence execution;
- real new-project and existing-project pilots.
- legal identity verification for the exclusive rights holder;
- file-level contributor and AI authorship provenance audit;
- written exclusive rights resolution for any non-Eimy copyrightable contribution;
- repository visibility change to private as a separate protected action;
- semantic project migration and upgrade automation;
- language and deployment golden paths;

## [0.1.0] - 2026-07-24

### Added

- governance foundation and engineering constitution;
- tool-independent lifecycle and risk-based change lanes;
- documentation architecture, metadata and evidence standards;
- security, compliance, release, SRE, incident and AI engineering policies;
- reusable templates for projects, work, decisions, threats, releases and incidents;
- implementation roadmap, adoption playbook and maturity model;
- repository validator, unit tests and GitHub Actions quality gate.
