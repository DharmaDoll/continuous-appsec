# 06 - Evidence Model

## Principle

LLM prose is not the source of truth.

Every decision should be derivable from structured records.

## Core entities

### SecurityInvariant

```json
{
  "schema_version": 1,
  "invariant_id": "INV-...",
  "target_id": "TGT-...",
  "target_tree_hash": "...",
  "title": "Tenant-owned invoice reads are scoped to trusted tenant context",
  "scope": ["invoice", "read"],
  "statement": "...",
  "source": {
    "derivation": "declared|inferred",
    "origin": "operator|product-requirement|organization-policy|framework-contract|source-analysis"
  },
  "source_evidence": ["EVD-..."],
  "confidence": "high",
  "counterexample": {
    "actor": "tenant-a-user",
    "forbidden_effect": "tenant-b invoice returned"
  }
}
```

`source.derivation` is the semantic boundary:

- `declared` means an authorized requirement exists independently of the implementation under review,
- `inferred` means the expected security property was derived from source, configuration, tests, or framework use.

`source.origin` records where that declaration or inference came from. `source_evidence` links the exact Evidence
records supporting it. Operator or policy material should be ingested as Evidence rather than copied into an
untraceable prose field. Reports must preserve this provenance and must not relabel a high-confidence inferred
invariant as declared.

### Evidence

```json
{
  "schema_version": 1,
  "evidence_id": "EVD-...",
  "kind": "source|static-analysis|runtime|config|test",
  "location": {
    "path": "src/invoice/repository.py",
    "start_line": 44,
    "end_line": 48,
    "symbol": "get_invoice",
    "path_safe": true,
    "snippet_hash": "..."
  },
  "claim": "Query filters by invoice id but not tenant id",
  "artifact_ref": "...",
  "fingerprint": "...",
  "content_hash": "...",
  "confidence": "direct-source-trace",
  "target_id": "TGT-...",
  "target_tree_hash": "...",
  "provenance": {
    "source_type": "source-read",
    "run_id": "RUN-...",
    "raw_uri": "..."
  },
  "redactions": [],
  "severity": null
}
```

### Hypothesis

```json
{
  "schema_version": 1,
  "hypothesis_id": "HYP-...",
  "target_id": "TGT-...",
  "target_tree_hash": "...",
  "invariant_id": "INV-...",
  "title": "Authenticated tenant user may read another tenant's invoice",
  "attacker_preconditions": [
    "valid low-privilege account",
    "knowledge/guess of another invoice id"
  ],
  "entry_point": {
    "path": "src/routes/invoices.ts",
    "path_safe": true,
    "start_line": 10,
    "end_line": 20,
    "snippet_hash": null,
    "symbol": "getInvoice"
  },
  "suspected_path": [
    {
      "path": "src/routes/invoices.ts",
      "path_safe": true,
      "start_line": 10,
      "end_line": 20,
      "snippet_hash": null,
      "symbol": "getInvoice"
    }
  ],
  "files_symbols_to_inspect": [
    {
      "path": "src/invoice/repository.py",
      "path_safe": true,
      "start_line": 44,
      "end_line": 48,
      "snippet_hash": null,
      "symbol": "get_invoice"
    }
  ],
  "supporting_evidence": ["EVD-1", "EVD-2"],
  "counter_evidence": [],
  "falsification_conditions": ["upstream tenant authorization exists"],
  "verification_plan": {"type": "http"},
  "status": "needs-verification"
}
```

### CounterEvidence

Counter-evidence is still normal evidence. It is linked by role.

Examples:

```text
auth middleware verifies role
repository wrapper always applies tenant filter
route cannot be reached by normal user
```

### VerificationCase

Declarative request for independent execution.

The serialized ID field is `verification_id`. A canonical HTTP case binds the request to `target_id`,
`target_tree_hash`, `hypothesis_id`, `policy_fingerprint`, `adapter_fingerprint`, a reviewed `runtime_profile`, and
a digest-pinned `runtime_image`. The v1 protocol accepts only a bounded HTTP method/path/header/body action and a
status and/or scalar JSON-path equality oracle. Policy and adapter fingerprints participate in the stable case ID.

Operator/Discovery input cannot supply shell commands, remote URLs, host paths, environment references, mutable
image tags, arbitrary fixture IDs, or resource limits above policy. The canonical case, normalized policy, and
normalized adapter are immutable run-relative artifacts.

### VerificationResult

Generated only by verifier.

The result reuses the case `verification_id` and records the verifier run, target fingerprint, status,
observations, oracle comparison, timestamps, verifier version, immutable verifier image identity, and policy
fingerprint. The fixed HTTP runtime stores bounded observations and a response-body hash, not fixture tokens or a
raw response body.

### Finding

```json
{
  "schema_version": 1,
  "finding_id": "FND-...",
  "target_tree_hash": "...",
  "hypothesis_id": "HYP-...",
  "invariant_id": "INV-...",
  "status": "verified",
  "title": "Cross-tenant invoice read",
  "severity": {"level": "high", "reason": "cross-tenant confidentiality"},
  "cwe": ["CWE-639"],
  "verification_result_id": "VER-...",
  "evidence": ["EVD-..."],
  "record_origin": "verifier",
  "remediation": {...},
  "regression": {...}
}
```

## Provenance

Every evidence item should preserve origin.

Examples:

```json
"provenance": {
  "type": "semgrep",
  "run_id": "SCAN-...",
  "raw_uri": "scanner-runs/semgrep/result.sarif"
}
```

or:

```json
"provenance": {
  "type": "source-read",
  "target_tree_hash": "...",
  "content_sha256": "..."
}
```

This allows the report to prove it refers to the exact audited version.

## Line numbers

Line numbers are useful but unstable across patches.

Store:

- relative path,
- symbol when known,
- line range,
- content hash or snippet hash,
- Git commit/tree hash.

## Evidence confidence

Avoid opaque numeric confidence generated by the model.

Prefer categories:

```text
observed-runtime
deterministic-static
direct-source-trace
inferred
operator-asserted
```

Reporting should distinguish them.

## Finding state machine

```text
hypothesis
   |
   +--> rejected
   |
   +--> needs-verification
           |
           +--> verified
           |
           +--> high-confidence-static
           |
           +--> rejected
```

Later triage:

```text
verified/high-confidence-static
   |
   +--> accepted-risk
   +--> duplicate
```

## Report rendering

Markdown should be generated from the structured objects.

Example:

```markdown
### [HIGH] Cross-tenant invoice read

- Status: VERIFIED
- CWE: CWE-639
- Violated invariant: INV-TENANT-INVOICE-READ
- Attacker: authenticated low-privilege tenant user
- Entry point: ...
- Sink/effect: ...
- Supporting evidence: ...
- Counter-evidence checked: ...
- Verification: VER-...
```

## Data retention

Treat reports/evidence as potentially sensitive source-derived artifacts.

The tool must support:

- local-only operation,
- configurable retention,
- redaction of tokens/secrets,
- deletion by run ID.

Do not put raw production secrets into SARIF/Markdown artifacts.
