# 19 - Milestone 3 Results

## Scope completed

Milestone 3 implements the canonical record foundation and the manual hypothesis workflow required before an
independent verifier is built.

Implemented:

- `SecurityInvariant`, `Hypothesis`, `VerificationCase`, `VerificationResult`, and `Finding` dataclasses,
- enriched Evidence location, provenance, redaction, kind, and confidence fields,
- stable `INV-`, `HYP-`, `EVD-`, `VER-`, and `FND-` ID validation and content-derived generation,
- declared vs inferred invariant provenance with mandatory source Evidence,
- seven Finding states and centralized transition gates,
- proved-verifier requirement for `verified` and complete-trace gate for `high-confidence-static`,
- immutable run-relative Evidence, Invariant, and Hypothesis JSONL repositories,
- strict bounded JSON/YAML input with duplicate-key, unsafe-tag, recursive-alias, depth, node, and symlink controls,
- atomic file replacement, file and directory fsync, line-numbered corruption errors, and target fingerprint checks,
- operator input preservation under `evidence/operator-inputs/` and normalization into Evidence,
- strict compatibility reading for Milestone 2 schema-v1 Evidence records,
- human and JSON CLI operations for adding/listing invariants, adding/listing hypotheses, and inspecting Evidence.

## Commands exercised

```bash
whitebox-audit invariant add --run-id RUN-... --file invariant.yaml --format json
whitebox-audit invariant list --run-id RUN-... --format json
whitebox-audit hypothesis add --run-id RUN-... --file hypothesis.yaml --format json
whitebox-audit hypothesis list --run-id RUN-... --format json
whitebox-audit evidence list --run-id RUN-... --format json
whitebox-audit show-evidence EVD-... --run-id RUN-... --format json
```

JSON and YAML are parsed as untrusted data. YAML uses PyYAML `SafeLoader` with stricter duplicate-key and bounded
document checks; Python/object tags and symlinked input files are rejected.

Invariant import envelope:

```yaml
schema_version: 1
invariant:
  title: Invoice reads are tenant scoped
  scope: [invoice, read]
  statement: Tenant A cannot read tenant B invoices.
  source:
    derivation: declared
    origin: organization-policy
  confidence: high
  counterexample:
    actor: tenant-a-user
    forbidden_effect: tenant-b invoice returned
source_evidence:
  - kind: config
    claim: Organization policy requires tenant-scoped invoice reads.
    location:
      path: policies/tenancy.md
      start_line: 10
      end_line: 12
```

The harness derives the Evidence and Invariant IDs, injects the prepared target identity, and records the original
input artifact. An optional supplied `invariant_id` is accepted only when it equals the derived ID. Hypothesis input
similarly receives its target identity from `--run-id`; any supplied target fields must match the prepared run.

## Executed validation

- supply-chain policy and frozen lock validation,
- Ruff formatting and linting,
- strict mypy checking,
- 80+ unit, integration, and security tests,
- stable-ID reproduction,
- invalid ID and state transition rejection,
- dangling/cross-role Evidence rejection,
- unknown field/schema and target fingerprint rejection,
- malformed JSONL line reporting,
- strict JSON/YAML and CLI workflow coverage.

## Explicit limitations

- `VerificationCase`, `VerificationResult`, and `Finding` are model/state foundations only; verifier execution and
  their run artifact repositories begin in Milestone 4 and later reporting work.
- `high-confidence-static` currently requires an explicit trusted service gate; automatic completeness assessment
  is not implemented.
- no Discovery Agent creates hypotheses yet; manual import is the intentional bridge to Milestone 4.
- CodeQL remains optional and unimplemented.
- the current Semgrep host adapter detects target mutation after execution but does not enforce an OS-level
  read-only mount or network denial.
