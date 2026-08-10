# 10 - Codex Prompts

These prompts are intended for development of the audit harness itself.

They are not a substitute for `AGENTS.md` or the audit skill.

Use one milestone at a time.

## Prompt 1 - Bootstrap the repository

```text
Read AGENTS.md and docs/01-SETUP.md through docs/09-IMPLEMENTATION-PLAN.md.

Implement Milestone 0 only.

Goals:
- Python 3.12+ project using a minimal dependency set.
- Add pyproject.toml, Makefile, package skeleton, tests, and a non-destructive doctor command.
- Doctor must check git, python, Docker, Codex, Project CodeGuard plugin, Semgrep, ripgrep, jq, and optional CodeQL.
- Print tool versions.
- Missing optional CodeQL is a warning; missing Docker/Semgrep/Codex is an error.
- Do not add an agent framework.
- Do not implement scanning yet.

Run all tests and show:
1. files changed,
2. commands executed,
3. test results,
4. remaining Milestone 0 limitations.
```

## Prompt 2 - Safe target controller

```text
Implement Milestone 1 from docs/09-IMPLEMENTATION-PLAN.md.

Treat the target repository as hostile input.

Requirements:
- target path is absolute/resolved,
- do not modify target,
- record Git commit/tree when available,
- detect obvious symlink escapes,
- inventory languages/manifests without executing target code,
- create a run directory in work/,
- target repository must never become the Codex project root,
- add malicious-path and prompt-injection fixture tests.

Do not implement Semgrep yet.

Run tests and provide the exact threat cases covered.
```

## Prompt 3 - Semgrep adapter

```text
Implement Milestone 2.

Read docs/04-DETERMINISTIC-ANALYSIS.md and docs/06-EVIDENCE-MODEL.md first.

Build a Semgrep adapter that:
- detects the installed version,
- invokes semgrep with shell=False,
- writes SARIF to the run directory,
- records argv/version/returncode/stdout/stderr/timestamps,
- normalizes SARIF into the internal Evidence model,
- preserves raw SARIF,
- handles scanner failures visibly,
- never modifies target.

Use fixture SARIF for parser unit tests and one local integration test that is skippable when Semgrep is unavailable.

Do not add CodeQL yet.
```

## Prompt 4 - Evidence model + hypothesis schema

```text
Implement Milestone 3.

Use docs/06-EVIDENCE-MODEL.md as the source of truth.

Add typed models and JSON serialization for:
Target, ScannerRun, SecurityInvariant, Evidence, Hypothesis,
VerificationCase, VerificationResult, Finding.

Enforce the finding state model.

Important:
- an LLM cannot directly construct a Finding with status=verified,
- only a valid VerificationResult(status=proved) can permit verified status,
- retain provenance and target fingerprint.

Add unit tests for invalid state transitions.
```

## Prompt 5 - Verifier

```text
Implement Milestone 4.

Read docs/05-VERIFIER-SANDBOX.md and docs/07-SECURITY-MODEL.md in full.

Start with an HTTP verification DSL, not arbitrary shell execution.

Implement a disposable fixture target with:
- tenant A,
- tenant B,
- one deliberately vulnerable cross-tenant endpoint,
- one fixed endpoint/version.

Verifier requirements:
- target/source read-only,
- no external network,
- cap-drop ALL,
- no-new-privileges,
- pid/memory/cpu/time limits,
- no Docker socket,
- separate output directory,
- verifier owns verdict.

Tests must prove:
- vulnerable case -> proved,
- fixed case -> not proved,
- target cannot be written,
- arbitrary command injection rejected,
- egress unavailable.

Do not involve Codex in the verdict.
```

## Prompt 6 - Agent-facing navigation interface

```text
Implement Milestone 5 helper interfaces, without autonomous orchestration yet.

Create safe CLI commands for:
- repository map/inventory,
- bounded source reads,
- ripgrep-based search,
- evidence lookup,
- invariant listing,
- hypothesis creation from validated JSON/YAML.

Commands must prevent paths escaping the target root.

The purpose is to let Codex navigate through narrow, auditable operations rather than dumping the full repository or running arbitrary target commands.

Update the whitebox-vulnerability-audit skill to use these commands when available.
```

## Prompt 7 - CodeQL

```text
Implement Milestone 6.

Read docs/01-SETUP.md and docs/04-DETERMINISTIC-ANALYSIS.md.

Requirements:
- CodeQL remains optional,
- require an explicit local entitlement acknowledgement before scanning private/internal targets,
- detect CodeQL and supported target language,
- record CodeQL/bundle/query versions,
- design database creation so target build commands do not execute directly on the host,
- normalize SARIF into the same evidence model,
- surface clear skip/failure reasons.

Do not weaken the scanner sandbox merely to make a fixture pass.

Document any language-specific build limitation explicitly.
```

## Prompt 8 - Codex integration

```text
Now implement the first Codex-assisted audit flow.

Do not ask Codex to scan the entire repository.

The agent receives:
- target metadata,
- threat model,
- invariants,
- normalized scanner evidence,
- safe navigation commands.

It must output validated Hypothesis and VerificationCase artifacts.

Follow:
Hypothesis -> focused trace -> counter-evidence -> falsification -> verification request.

The discovery agent must never write a verified finding.
Only the verifier can produce the evidence that permits verified status.

Use .agents/skills/whitebox-vulnerability-audit/SKILL.md as the workflow contract.
```

## Prompt 9 - Evals

```text
Implement the evaluation harness from docs/08-EVALUATION.md.

Compare at minimum:
A. Semgrep
B. deterministic evidence + Codex navigation
C. full pipeline with independent verifier

Measure:
- known-vuln recall,
- false positives,
- verified precision,
- SAST overlap,
- unique verified findings,
- verifier reproducibility,
- wall-clock time.

Do not optimize the model prompts until these metrics are produced.
```

## Prompt 10 - Production-readiness review

```text
Perform a production-readiness review of this repository.

Use AGENTS.md as policy.

Specifically try to break:
- target path confinement,
- prompt-injection handling,
- environment secret isolation,
- scanner invocation,
- CodeQL build isolation,
- verifier network/filesystem restrictions,
- evidence state transitions,
- report redaction.

Do not merely list theoretical risks.
Add tests for concrete weaknesses you identify and fix them where safe.
Return unresolved risks separately.
```
