# ADR 0009: Define the Whitebox Audit Engine product boundary

- Status: Accepted
- Date: 2026-08-14

## Context

The original GitHub repository name, `continuous-appsec`, suggested a broad platform spanning PR and CI events,
incremental scans, scheduled execution, cross-run finding state, risk acceptance, dashboards, and vulnerability
management. The implemented product identity and architecture are narrower: `Whitebox AI Audit`, the
`whitebox-ai-audit` distribution and repository, and the `whitebox-audit` CLI implement an evidence-driven
white-box audit harness.

Keeping the broader implication would make v1 ownership unclear and invite orchestration features before the
evidence pipeline and independent verifier are complete.

## Decision

Define this repository as the **Whitebox Audit Engine** and use these canonical names:

- product: `Whitebox AI Audit`,
- GitHub repository and Python distribution: `whitebox-ai-audit`,
- Python import package: `whitebox_audit`,
- CLI: `whitebox-audit`.

The engine owns target safety, deterministic evidence collection, focused navigation, invariant and hypothesis
records, falsification, independent verification, findings, reports, and regression artifacts for an audit run.

PR/CI event handling, changed-lines analysis, scheduling, baseline comparison, cross-run `new` / `fixed` /
`regressed` state, risk-acceptance expiry, dashboards, and vulnerability-management workflow are outside v1. A
future external Continuous AppSec Orchestrator may invoke the engine and consume canonical artifacts, but may not
weaken the evidence model or verifier boundary.

## Consequences

- v1 remains focused on proving the evidence-to-verifier vertical slice.
- CI may run fixture/evaluation audits, but CI product orchestration is not an engine responsibility.
- Cross-run lifecycle state is not added to the seven candidate-finding statuses.
- Future orchestration integrates through versioned machine-readable artifacts rather than internal LLM prose.
- The GitHub repository name now matches the existing product and distribution identity.
