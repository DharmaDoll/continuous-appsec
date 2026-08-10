# 11 - Tool Decisions

## Codex CLI - Required

Role:

- implementation agent,
- later: goal-directed audit navigator.

Why:

- repository-aware CLI workflow,
- reusable `AGENTS.md`,
- Agent Skills,
- sandbox and approval controls,
- script/CI integration path.

Do not use Codex as the sole scanner/verifier.

## Project CodeGuard - Required baseline knowledge

Role:

```text
secure coding/security knowledge
not vulnerability proof
```

Recommended install:

```bash
codex plugin marketplace add cosai-oasis/project-codeguard
codex plugin add codeguard-security@project-codeguard
```

Project CodeGuard currently ships Codex plugin support and security-oriented skills/rules.

Use it for:

- baseline security review knowledge,
- secure coding categories,
- remediation guidance.

Do not rely on it for:

- organization-specific tenant semantics,
- business state-machine rules,
- runtime proof.

Those belong in local invariants/policies.

### Pinning policy

Development workstation:

- managed plugin route acceptable.

Strict production/regulated workflow:

- record plugin/version in every audit run,
- evaluate pinning/vendor review policy,
- review updates before changing the audit baseline.

## Semgrep CE - Required baseline deterministic scanner

Role:

- fast SAST,
- local/custom rules,
- candidate evidence,
- lightweight baseline.

Why baseline:

- easy to deploy,
- useful across many languages,
- SARIF export,
- simple custom rule path.

It should work without a hosted Semgrep account for the CE baseline.

## CodeQL - Optional / recommended

Role:

- deeper semantic/data-flow analysis,
- reusable security queries,
- evidence enrichment.

Why optional:

- entitlement/licensing conditions vary by repository,
- supported languages/build extraction differ,
- build extraction can be operationally heavy,
- not every environment can safely execute target builds.

Policy:

```text
Do not make a user's entire audit unusable because CodeQL is unavailable.
```

The report should say whether CodeQL ran.

## Docker - Required verifier isolation

Docker is the initial portable isolation primitive.

It is not the ultimate security boundary for every adversarial workload.

Future high-risk mode may use:

- dedicated VM,
- Firecracker/microVM,
- gVisor/Kata,
- isolated CI runner.

Do not design around this before the basic verifier works.

## ripgrep - Required navigation helper

Use `rg` as a cheap, bounded navigation primitive.

Typical uses:

```text
route definition
symbol references
auth middleware usage
tenant_id propagation
repository methods
state constants
```

The agent should search, then open only relevant ranges.

## SARIF - Interchange format, not internal truth model

Use SARIF for scanner ingestion/export.

Do not force every agent/runtime concept into SARIF.

Internal JSON model should represent:

- invariants,
- hypotheses,
- counter-evidence,
- verification,
- attack chains.

Final export can map verified findings to SARIF.

## CodeGuard reviewer skill vs custom audit skill

Project CodeGuard includes a security review workflow.

Use it as useful knowledge/reference, but this repository's own skill is necessary because the intended process is stricter:

```text
map
-> invariant
-> deterministic evidence
-> focused navigation
-> falsification
-> independent verification
```

The local skill owns this protocol.

## Codex Security - Optional comparator, not dependency

As of 2026-08, OpenAI documents a Codex Security CLI/SDK for security scans for users with access.

Possible future use:

- benchmark this harness against another agentic scanner,
- compare findings,
- compare cost/coverage.

Do not make this project depend on product access or opaque behavior.

## SCA / dependency scanning

Not the focus of the first version.

If needed later, integrate existing outputs from:

- Dependabot,
- Trivy,
- other SCA scanners,

as evidence.

Do not let dependency CVE volume drown out the white-box logic-analysis goal.

## IaC

Checkov/Trivy config can be added later as deterministic evidence adapters.

Again, do not turn this repository into a generic "all scanners" wrapper before the white-box audit workflow is proven.
