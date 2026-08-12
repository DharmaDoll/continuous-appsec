# 18 - Milestone 2 Results

## Scope

Milestone 2 implements the first deterministic vertical slice: prepared target to Semgrep SARIF to normalized,
deduplicated Evidence. It also accepts operator-supplied SARIF through the same defensive normalization path.

## Implemented

- `Scanner` protocol with separated capability, execution, and normalization responsibilities
- immutable `ScannerRun`, `ScannerResourcePolicy`, `Evidence`, and SARIF normalization records
- Semgrep executable/version/hash provenance and explicit argument-array construction
- reviewed harness-local YAML rules, configurable exclusions, minimal environment, timeout, bounded/redacted logs
- distinct `succeeded`, `skipped`, `failed`, and `timed-out` states
- raw SARIF, scanner metadata, normalization summary, and canonical Evidence artifacts under each run
- defensive SARIF loading with a 100 MiB limit, multiple-run support, optional-field handling, and warnings
- safe URI normalization that does not follow SARIF paths or read target-external files
- stable `EVD-<hash>` IDs, content hashes, scanner provenance, and fingerprint deduplication
- atomic, mode-0600 Evidence JSONL merge with corruption and target-fingerprint rejection
- `scan` and `ingest-sarif` CLI commands plus `make scan TARGET=...`
- explicit exit/status policy: unavailable 3/degraded, execution failure 5/failed, malformed SARIF 6/failed
- vulnerable, benign, malformed, optional-field, multiple-run, fake failure, timeout, and mutation fixtures/tests

## Verification on 2026-08-12

```text
make check
whitebox-audit doctor --format json
```

Results:

```text
formatter/linter/typecheck: passed
tests: 70 passed
native supply-chain checks: passed
Semgrep capability: unavailable (real smoke test skipped by its conditional gate)
Docker daemon: unavailable in this environment
fake scanner success/finding, benign, failure, timeout, malformed-SARIF, and mutation paths: passed
```

The fake scanner integrations exercise the actual subprocess, log, run-state, SARIF, normalization, and Evidence
persistence paths without installing packages from a target. The realistic SARIF fixture produces one expected
Evidence record; the benign fixture produces none.

## Deliberate limitations

- No Semgrep executable is installed on the current host, so a real Semgrep execution is not claimed.
- The host adapter disables Semgrep network features but does not provide OS-level network isolation.
- Target immutability is checked after scanner execution; it is not yet enforced by a read-only mount. A detected
  mutation fails the run but cannot undo the mutation. Use only reviewed/trusted scanner binaries for this MVP.
- Ruleset validation is a trusted-path and top-level-structure precheck; Semgrep performs full rule validation.
- Raw SARIF is retained without rewriting and may contain sensitive source content. Run directories and files are
  restricted locally, and normalized messages/logs are redacted, but operators must apply retention policy.
- CodeQL, hypothesis creation, independent verification, and final reporting are later milestones.
