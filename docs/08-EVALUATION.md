# 08 - Evaluation and Operational Quality

A usable system needs measured quality, not anecdotes.

## Primary metrics

### Verified Precision

```text
verified true positives / all surfaced verified findings
```

The system should prioritize precision over producing many plausible findings.

### Known Vulnerability Recall

Use fixture applications and intentionally vulnerable commits.

```text
known vulnerabilities rediscovered / known vulnerabilities in scope
```

### False Positive Rate

Track rejected findings after verification/review.

### Unique Finding Lift

Measure what agentic reasoning adds beyond deterministic scanners.

```text
verified findings not directly reported by baseline SAST
```

### SAST Overlap

How much the agent simply repeats scanner output.

### Verification Rate

```text
candidate findings with executable verifier case / candidate findings
```

### Reproduction Success

Can a second run reproduce the verifier result?

### Cost per Verified Finding

Track:

- model usage/tokens where available,
- wall-clock time,
- scanner time,
- verifier time.

Do not optimize token counts before quality is measurable.

## Comparison matrix

For a fixture set, compare:

```text
A. Semgrep only
B. CodeQL only
C. deterministic union
D. Codex navigation without scanner evidence
E. Codex + deterministic evidence
F. Codex + evidence + falsification
G. full pipeline + independent verifier
```

## Fixture taxonomy

Include:

- IDOR,
- tenant isolation,
- missing role check,
- state transition bypass,
- password reset misuse,
- cache isolation,
- background job privilege confusion,
- webhook trust boundary,
- SSRF chain,
- injection baseline,
- false-positive controls.

Each fixture should include:

```yaml
expected:
  vulnerabilities:
    - id: FIX-...
      cwe: ...
      expected_entry: ...
      expected_effect: ...
  non_vulnerabilities:
    - ...
```

## Backtesting

Support auditing both:

- vulnerable commit,
- fixed commit.

A high-quality audit should:

- report on vulnerable commit,
- stop reporting after fix,
- preserve regression test.

## Human triage feedback

Store:

```text
confirmed
rejected
duplicate
accepted-risk
needs-context
```

Keep the rationale.

Later runs should use prior triage as evidence, not opaque fine-tuning.

## Release quality gate

Before tagging a usable release:

- setup reproducible from clean environment,
- `make doctor` passes,
- all fixture tests pass,
- prompt-injection fixtures pass,
- verifier isolation tests pass,
- scanner failures are visible,
- no target writes,
- report generated from structured evidence,
- documentation matches commands.

## Minimum useful v1 target

A v1 does not need autonomous support for every framework.

A useful v1 should reliably support:

- Python/JS/TS target navigation,
- Semgrep SARIF ingestion,
- optional CodeQL when available,
- HTTP authorization/tenant verification for a demo/runtime adapter,
- evidence-backed Markdown report,
- known-vuln regression suite.
