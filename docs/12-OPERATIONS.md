# 12 - Operating Procedure

This is the intended human workflow once v1 is implemented.

## Before an audit

Confirm:

- authorization to assess the target,
- target commit/tag,
- test environment/runtime adapter,
- allowed verification techniques,
- CodeQL entitlement if CodeQL will be used,
- report classification/retention,
- no production credentials are exposed to the harness.

## Step 1 - Doctor

```bash
make doctor
```

Do not continue if required isolation dependencies fail.

## Step 2 - Prepare target

```bash
make prepare TARGET=/absolute/path/to/target
```

Review:

- target path,
- independent content fingerprint and Git commit/tree/dirty metadata,
- languages,
- manifests,
- excluded directories and symlink inventory,
- effective configuration (`network_allowed=false`, `target_execution_allowed=false`).

Preparation rejects external/broken symlinks, nested mounts, special files, external Git worktree pointers, and
unsafe Git metadata. Do not bypass these failures by moving the harness into the target or running target setup
commands manually.

## Step 3 - Deterministic scan

```bash
make scan TARGET=/absolute/path/to/target
```

Review scanner coverage.

The current Semgrep adapter:

- uses reviewed rules stored in this harness and never installs target dependencies,
- stores raw SARIF, executable provenance, bounded/redacted logs, normalization counts, and Evidence under
  `work/<run-id>/`,
- exits 3 and records `skipped/degraded` when Semgrep is unavailable,
- exits 5 for scanner execution failure and 6 for malformed SARIF,
- requests offline Semgrep behavior but does not yet enforce network denial at the OS boundary,
- compares target fingerprints after execution but does not yet mount the target read-only.

For hostile real-world targets, treat the current host adapter as an MVP evidence collector, not an execution
sandbox. Use only a trusted Semgrep installation and review `scanner-runs/semgrep/run.json`. Raw SARIF may contain
sensitive source snippets and follows the same access/retention controls as other audit evidence.

Existing SARIF can be attached to a prepared run without executing its producer:

```bash
whitebox-audit ingest-sarif \
  --run-id RUN-YYYYMMDDTHHMMSSZ-012345abcdef \
  --tool-name reviewed-tool \
  --input /absolute/path/to/results.sarif
```

Do not treat scanner findings as the final report.

## Step 4 - Start Codex from audit harness

From the **whitebox-ai-audit repository root**:

```bash
codex --sandbox workspace-write --ask-for-approval on-request
```

Then request:

```text
Use the whitebox-vulnerability-audit skill.
Audit target <target-id> using the prepared evidence.
Do not execute target build/test/install commands on the host.
Start with threat model and invariants, then use focused navigation.
```

Never `cd` into the target and start Codex there.

## Step 5 - Review hypotheses before high-risk verification

Low-risk fixture verification can be automated.

For real application adapters, operator may require approval for:

- resource-intensive tests,
- state mutations,
- privileged test identities,
- any network exception.

## Step 6 - Verify

```bash
make verify TARGET=/absolute/path/to/target
```

Only independent verifier results can promote a hypothesis to verified.

## Step 7 - Report

```bash
make report TARGET=/absolute/path/to/target
```

Report must state:

- target fingerprint,
- tools/versions,
- scanner coverage,
- skipped tools,
- threat model scope,
- findings,
- rejected hypotheses count,
- verification limitations.

## Step 8 - Patch

Generate patch separately.

```bash
whitebox-audit patch --finding FND-...
```

Apply only after human review.

Then rerun:

```bash
whitebox-audit verify --finding FND-...
```

## Audit evidence retention

Default retention should be local.

Suggested:

```text
raw source: not copied unless needed
raw scanner output: retain per policy
runtime requests/responses: retain with redaction
PoC artifacts: retain
secrets/tokens: redact
final report: retain per org policy
```

## Incident boundary

If verification unexpectedly reaches:

- production systems,
- real customer data,
- real cloud metadata,
- external third-party services,

stop the verification path and preserve minimal evidence.

Do not continue exploitation merely to improve confidence.
