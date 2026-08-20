# 09 - Implementation Plan

Build vertically. Do not start by implementing a sophisticated multi-agent system.

This plan implements the Whitebox Audit Engine. PR/schedule orchestration, changed-lines analysis, cross-run finding
lifecycle, and vulnerability-management workflows are outside v1 and must not displace the evidence pipeline and
independent verifier milestones.

Implementation status on 2026-08-17: Milestones 0 through 3 are complete. Milestone 4 policy, reviewed-adapter
schema, bounded HTTP DSL, VerificationCase persistence, fixed HTTP verdict runtime, and least-privilege Docker
command construction are implemented. The verifier image, controller/lifecycle, fixture, and live isolation tests
are next. See `plan.md`
for the executable checklist, `docs/16-MILESTONE-0-RESULTS.md` through
`docs/19-MILESTONE-3-RESULTS.md` for completed milestones, and `docs/20-MILESTONE-4-PHASE-1-RESULTS.md` for the
declarative boundary. Phase 2 runtime results are in `docs/21-MILESTONE-4-PHASE-2-RESULTS.md`.

## Milestone 0 - Repository and environment

Implement:

- `pyproject.toml`
- `Makefile`
- `.gitignore`
- `.env.example`
- `src/whitebox_audit/`
- `scripts/doctor.sh`
- basic CLI `whitebox-audit doctor`
- unit test setup

Acceptance:

```bash
make doctor
make test
```

works on a clean supported environment.

Cross-cutting supply-chain baseline (implemented from Milestone 0, not deferred to Milestone 10):

- exact-pin direct/build dependencies and use the committed lock,
- enforce approved sources, artifact SHA-256 records, lock schema/freshness, and a 72-hour release cooldown,
- record host tool executable provenance,
- provide CycloneDX SBOM and explicit online malware-check commands,
- never install target dependencies or run target lifecycle scripts on the host.

Doctor checks:

- Codex
- CodeGuard plugin
- Semgrep
- Docker
- optional CodeQL
- required Unix plumbing.

## Milestone 1 - Safe target controller

Implement:

```bash
whitebox-audit prepare --target /path/to/repo
```

Features:

- resolve path,
- reject audit harness itself,
- capture Git commit/tree hash,
- language/manifests inventory,
- target fingerprint,
- symlink escape detection,
- create run directory.

Acceptance:

- no target files modified,
- malicious path fixtures rejected,
- target metadata persisted.

## Milestone 2 - Semgrep vertical slice

Implement:

```bash
whitebox-audit scan --target ... --scanner semgrep
```

Features:

- invoke Semgrep,
- save raw SARIF,
- normalize to evidence,
- preserve failures/logs,
- emit run metadata.

Acceptance:

- vulnerable fixture produces expected evidence,
- benign fixture does not produce seeded issue,
- malformed SARIF fails visibly.

## Milestone 3 - Evidence model and manual hypothesis

Implement data objects from `docs/06-EVIDENCE-MODEL.md`.

Add:

```bash
whitebox-audit invariant add --run-id RUN-... --file invariant.yaml
whitebox-audit invariant list --run-id RUN-...
whitebox-audit hypothesis add --run-id RUN-... --file case.yaml
whitebox-audit hypothesis list --run-id RUN-...
whitebox-audit evidence list --run-id RUN-...
whitebox-audit show-evidence EVD-... --run-id RUN-...
```

This allows a human-created, schema-validated hypothesis so the verifier can be developed before Codex
orchestration. Operator invariant input is preserved as a run artifact and normalized into source Evidence before
the invariant is accepted.

## Milestone 4 - Independent verifier

Implement:

- verifier Dockerfile,
- verification-case schema,
- HTTP action/oracle,
- target/runtime adapter fixture,
- fixed verifier verdict,
- resource/network policy.

Implemented first phase:

```bash
whitebox-audit verification-case add \
  --run-id RUN-... \
  --file case.yaml \
  --adapter reviewed-adapter.yaml
whitebox-audit verification-case list --run-id RUN-...
```

Implemented second-phase boundary:

- fixed `/case` to `/output/result.json` HTTP verifier runtime,
- exact fixture-token resolution without secret persistence,
- bounded status/scalar-JSON oracle and response hashing,
- digest-pinned verifier identity in every result,
- internal-network and least-privilege Docker argv construction.

These components are unit tested without executing Docker. They do not yet constitute an end-to-end verifier.

Acceptance:

- known IDOR fixture is proved,
- fixed fixture is `not-proved`,
- verifier cannot edit target,
- arbitrary shell field rejected,
- network egress blocked.

At this milestone the project is already useful for reproducible AppSec testing.

## Milestone 5 - Agentic audit skill

Wire the repository skill into the operator workflow.

Initial mode may remain interactive:

```text
Codex reads evidence + target through focused commands
-> writes structured hypotheses/verification cases
-> harness validates them
-> verifier executes them
```

Do not parse arbitrary prose.

Add helper commands:

```bash
whitebox-audit map
whitebox-audit show-evidence <id>
whitebox-audit source <relative-path> --lines 10:80
whitebox-audit search <pattern>
whitebox-audit callers <symbol>   # if language support exists
```

These commands should reduce the need for the agent to run arbitrary shell commands.

Acceptance:

- Codex can discover seeded cross-file authz issue,
- target prompt-injection fixture does not alter protocol,
- generated hypothesis passes schema validation.

## Milestone 6 - CodeQL adapter

Only after baseline works.

Implement:

- capability detection,
- entitlement acknowledgement gate,
- language support check,
- isolated DB build strategy,
- query suite configuration,
- SARIF normalization.

Acceptance:

- skip reason clear when unavailable,
- no host build execution,
- evidence merges with Semgrep without duplicate corruption.

## Milestone 7 - Reporting and patch workflow

Implement:

```bash
whitebox-audit report
whitebox-audit patch --finding FND-...
```

Requirements:

- report derives from canonical objects,
- evidence links,
- verifier result,
- counter-evidence checked,
- remediation diff separate from target,
- regression test recommendation.

## Milestone 8 - Evals

Implement fixture matrix from `docs/08-EVALUATION.md`.

Generate metrics:

```text
verified precision
known-vuln recall
unique finding lift
SAST overlap
verification rate
runtime
model usage where available
```

## Milestone 9 - Non-interactive Codex orchestration

Only now evaluate:

- `codex exec`,
- Codex SDK,
- structured task automation.

Requirements:

- strict schema,
- bounded budget,
- resumable runs,
- no direct agent verdict authority.

## Milestone 10 - Production hardening

Add:

- signed/pinned scanner images,
- SBOM for the audit harness,
- CI,
- CODEOWNERS for policy/skill/verifier,
- release artifacts,
- config migrations,
- audit log,
- report redaction,
- runtime adapter documentation.

The native dependency gate and harness SBOM already exist at this point. Milestone 10 extends them with signed
release artifacts, automated advisory/license review, and reviewed digest-pinned scanner/verifier/runtime images.

## Definition of "usable"

Do not call v1 usable until:

1. clean setup works,
2. one real application family can be launched through a reviewed runtime adapter,
3. one authz/tenant finding can be independently verified end-to-end,
4. false-positive fixtures exist,
5. prompt-injection resistance is tested,
6. scanner failure behavior is explicit,
7. reports are reproducible by run ID and target commit.
