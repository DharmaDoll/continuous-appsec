# 17 - Milestone 1 Results

## Scope

Milestone 1 implements the safe target controller and `whitebox-audit prepare`. It validates and fingerprints
an untrusted repository, records a bounded code/manifest inventory, and persists canonical run metadata without
executing or modifying the target.

## Implemented

- immutable, schema-versioned `Target`, `Inventory`, `AuditRun`, and `PrepareResult` records
- safe run/target IDs and run-relative artifact references
- strict harness/target relationship validation
- directory-FD traversal with no-follow file opens and inode/device checks
- external/broken symlink, special-file, nested-mount, oversized target, and timeout rejection
- deterministic content fingerprint independent of root path, file order, and mtime
- language, manifest, route candidate, exclusion, and internal symlink inventory
- hardened Git commit/tree/dirty metadata collection for normal repositories
- rejection of external Git worktree pointers and redirecting Git metadata
- atomic JSON persistence through a staging directory with no implicit final-run overwrite
- allowlisted effective configuration with target execution and network disabled
- human and JSON `prepare` output plus `make prepare TARGET=...`
- benign and prompt-injection/lifecycle-script fixture repositories

## Verification on 2026-08-12

```text
make check UV=/home/calvet/.local/bin/uv
make prepare UV=/home/calvet/.local/bin/uv TARGET=<temporary-malicious-fixture-copy>
```

Results:

```text
formatter/linter/typecheck: passed
tests: 51 passed
native supply-chain checks: passed
prepare acceptance run: prepared
target content hashes before/after: identical
target lifecycle marker: absent
run.json/target.json schema and read_only assertions: passed
```

The acceptance run treated `AGENTS.md`, README instructions, a source-comment instruction, and a package
`postinstall` command strictly as data. Its four source-file hashes were identical before and after preparation.

## Deliberate limitations

- External Git worktrees are rejected by the default profile.
- Cross-filesystem target mounts are rejected.
- The source inventory is metadata only; framework mapping begins in Milestone 5.
- Scanner execution and SARIF normalization begin in Milestone 2.
- Crash-left staging directories are not automatically resumed or deleted; only completed final run directories
  are canonical.
