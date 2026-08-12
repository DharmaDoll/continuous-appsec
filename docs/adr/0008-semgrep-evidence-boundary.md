# ADR 0008: Semgrep execution and evidence boundary

- Status: Accepted
- Date: 2026-08-12

## Context

Semgrep provides deterministic scanner evidence, but the audit target and scanner output remain untrusted data.
Scanner availability, findings, execution failures, malformed SARIF, and incomplete SARIF must remain distinct.
The initial host adapter also needs to avoid claiming isolation controls it does not technically enforce.

## Decision

1. A scanner implements separate `doctor`, `run`, and `normalize` operations. Every attempt records a stable
   scanner-run ID, target fingerprint, executable identity, timestamps, status, return code, reason, argv, and
   artifact references.
2. Semgrep receives only reviewed harness-local YAML rules. The harness invokes it with an argument array,
   `shell=False`, a minimal environment, metrics/version checks disabled, bounded logs, and a timeout. Target
   package installation, build, tests, and lifecycle scripts are never invoked.
3. Exit codes 0 and 1 are accepted only when a SARIF file exists. Other exits and timeouts are persisted as
   failures. Missing Semgrep is persisted as `skipped`; the audit run becomes `degraded` and exits with code 3.
4. The host adapter requests offline behavior through Semgrep flags, but does not enforce network isolation at
   the operating-system boundary. It requests read-only target treatment, but currently enforces this only by
   comparing the independent target tree fingerprint after execution. These enforcement mechanisms are stored
   explicitly in `ScannerResourcePolicy`.
5. Raw SARIF is retained as restricted run evidence. Parsing supports multiple runs and optional fields, and
   represents target-external URIs as opaque hashes. It never follows a SARIF URI to read source.
6. Normalized `Evidence` is canonical for later phases. Stable fingerprints deduplicate records. JSONL merge and
   replacement are atomic, preserve evidence from other producers, and reject target-fingerprint mismatches or
   corrupt existing data.
7. Operator-supplied SARIF is copied atomically into the run, normalized through the same parser, and receives
   provenance metadata stating that the harness did not execute its producer.

## Consequences

- The Semgrep host adapter is useful for the deterministic MVP but is not an isolation boundary. OS-enforced
  read-only mounts and network denial remain required before scanning arbitrary hostile targets in a stronger
  execution profile.
- Scanner evidence is not a verified vulnerability and cannot directly create a `verified` finding.
- Raw SARIF can contain sensitive source snippets or scanner messages and must follow run-artifact access and
  retention policy even though normalized claims and logs receive common secret redaction.
- A real Semgrep smoke test is conditional on a trusted, operator-installed Semgrep executable. The harness does
  not automatically install scanner tooling or target dependencies.
