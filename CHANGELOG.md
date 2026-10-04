---
id: EW-CHANGELOG
title: Changelog
status: current
owner: Eimy Herrer and Johny
version: 0.7.0-rc.2
last-reviewed: 2026-10-04
---

# Changelog

All notable changes are recorded here. Versions follow Semantic Versioning.

## [Unreleased]

### Added

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

### Planned

- repository rulesets and branch protection;
- project scaffolding CLI and adoption automation;
- reusable deployment adapters;
- compliance evidence generation;
- successful signed main/tag evidence execution;
- real new-project and existing-project pilots.

## [0.1.0] - 2026-07-24

### Added

- governance foundation and engineering constitution;
- tool-independent lifecycle and risk-based change lanes;
- documentation architecture, metadata and evidence standards;
- security, compliance, release, SRE, incident and AI engineering policies;
- reusable templates for projects, work, decisions, threats, releases and incidents;
- implementation roadmap, adoption playbook and maturity model;
- repository validator, unit tests and GitHub Actions quality gate.
