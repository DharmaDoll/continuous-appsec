# 02 - Architecture

## Objective

Build a white-box audit harness where the LLM is a reasoning/navigation component, not the sole detector or verifier.

## Product boundary

This repository implements the **Whitebox Audit Engine**. It does not implement the surrounding Continuous AppSec
control plane in v1.

```text
Future external orchestration
  PR / CI / schedule / baseline comparison / finding lifecycle
                              |
                              | invokes audits and consumes canonical artifacts
                              v
Whitebox Audit Engine
  Target -> Evidence -> Hypothesis -> Falsification -> Verifier -> Finding / Report
```

The engine owns the safety and evidentiary integrity of one audit run. A future orchestrator may compare run
artifacts and manage `new` / `fixed` / `regressed` lifecycle state, but it must not weaken the engine's evidence
model or grant the discovery agent verifier authority.

## Components

### A. Target Controller

Responsibilities:

- validate target path,
- compute repository fingerprint,
- enumerate languages and manifests,
- create an audit run ID,
- expose target read-only to scanner/verifier components,
- prevent accidental writes.

Suggested object:

```python
@dataclass(frozen=True)
class Target:
    target_id: str
    root: Path
    git_commit: str | None
    tree_hash: str
    languages: tuple[str, ...]
```

The target is never the Codex project root.

### B. Deterministic Scanner Adapters

Initial adapters:

- Semgrep
- CodeQL

Each adapter must expose a common interface:

```python
class Scanner(Protocol):
    def doctor(self) -> ScannerCapability: ...
    def run(self, target: Target, run_dir: Path) -> ScannerRun: ...
    def normalize(self, output: Path) -> list[Evidence]: ...
```

The adapter owns:

- command invocation,
- timeout,
- resource policy,
- raw output preservation,
- normalization.

### C. Evidence Store

Canonical source of truth.

Directory example:

```text
work/<run-id>/
├── target.json
├── scanner-runs/
│   ├── semgrep/
│   │   ├── run.json
│   │   └── result.sarif
│   └── codeql/
├── evidence/
│   └── evidence.jsonl
├── invariants/
├── hypotheses/
├── verification/
│   ├── cases.jsonl
│   ├── policies/<policy-sha256>.json
│   └── adapters/<adapter-sha256>.json
└── reports/
```

Keep raw scanner output so normalization bugs can be diagnosed.

### D. Security Model Builder

Produces:

- trust boundaries,
- assets,
- identities/roles,
- entry points,
- state transitions,
- tenant dimensions,
- important background jobs,
- external trust relationships.

It should use:

- repository structure,
- config/routing files,
- scanner evidence,
- focused Codex navigation.

It must not ingest the repository wholesale.

### E. Invariant Engine

Transforms security expectations into explicit, testable statements.

Examples:

```yaml
id: INV-TENANT-INVOICE-READ
scope:
  resource: Invoice
source:
  derivation: declared
  origin: organization-policy
source_evidence:
  - EVD-POLICY-INVOICE-TENANCY
statement: >
  A non-admin principal may read an invoice only when
  principal.tenant_id == invoice.tenant_id.
counterexample:
  actor: authenticated_user_tenant_a
  request: GET /invoices/{tenant_b_invoice_id}
  forbidden_effect:
    - response_contains_tenant_b_invoice
```

Invariants are more useful than generic vulnerability categories because they describe what **must remain true**.
Every invariant must distinguish a declared requirement from an expectation inferred from implementation evidence.
An inferred invariant is a review hypothesis about intended behavior, not proof of the product's actual requirement.

### F. Agentic Navigator

Codex explores only the files required to prove or falsify hypotheses.

Input:

```text
target metadata
threat model
invariant
scanner evidence
current hypothesis
known traces
```

Output:

```text
new evidence references
counter-evidence
trace
next search step
candidate verification case
```

The output should be structured, not free-form-only.

### G. Discovery Agent vs Verifier

This is a hard architecture boundary.

Discovery agent:

- can reason,
- can search,
- can suggest a PoC/test,
- can propose a patch,
- cannot set final verification status.

Verifier:

- executes a predeclared verification case,
- has a fixed policy,
- produces machine-observable result,
- cannot change the target or verification oracle.

### H. Reporter

Report status must derive from structured objects.

Never infer `verified` because a Markdown sentence says so.

## Data flow

```text
target
  |
  +--> metadata
  |
  +--> Semgrep ----+
  |                |
  +--> CodeQL -----+--> Evidence Store
  |                |
  +--> prior SARIF-+
                   |
                   v
             Threat Model
                   |
                   v
              Invariants
                   |
                   v
              Hypotheses
                   |
           focused navigation
                   |
                   v
             Falsification
                   |
                   v
           Verification Case
                   |
                   v
          Independent Verifier
                   |
                   v
              Finding
```

## Target adapter strategy

A generic harness cannot automatically boot every application safely.

Implement three verification modes:

### Mode 1: Static-only

Use when runtime setup is not available.

Result can be:

- rejected,
- high-confidence-static,
- needs-verification.

Never `verified`.

### Mode 2: Operator-provided runtime adapter

The target team provides a reviewed adapter describing:

- build image,
- start command,
- health check,
- seed data,
- test identities,
- service ports,
- allowed dependencies.

This should become the primary production mode.

### Mode 3: Fixture / disposable target image

For CI/evals.

Fully automated and deterministic.

## Why not automatically infer and run arbitrary build commands?

Because target build files are untrusted code.

Automation must not turn source review into arbitrary code execution on the audit operator's host.

## Domain policy layer

Organization-specific knowledge lives separately:

```text
policies/
├── authz/
├── tenancy/
├── payments/
├── pii/
└── framework/
```

Do not fork CodeGuard to add business-specific rules unless necessary.

CodeGuard is baseline secure-coding knowledge; domain invariants are local policy.

## Integration with Codex

Phase 1 implementation should call Codex manually through the repository skill.

Later automation may use:

- `codex exec`, or
- Codex SDK,

only after the structured evidence interface is stable.

Do not build orchestration around fragile parsing of terminal prose.
