# ADR 0007: Fail-closed target preparation

- Status: Accepted
- Date: 2026-08-12

## Context

The target repository is adversarial input. Even a metadata-only preparation phase can accidentally follow a
symlink, cross a mount, execute a Git extension, write into the target, or publish partially written run state.

## Decision

The default preparation profile is deliberately strict:

1. Resolve the target and reject identity or containment in either direction with the harness.
2. Traverse through directory file descriptors. Files are opened relative to those descriptors with
   `O_NOFOLLOW`, and inode/device identity is rechecked to resist path replacement races.
3. Reject external and broken symlinks, special files, nested filesystem mounts, inventory limit overruns, and
   files larger than 128 MiB. Internal symlinks are recorded but never followed for content inventory.
4. Exclude VCS metadata, dependencies, caches, and generated output from the content fingerprint using the
   documented directory-name allow policy. Hash source/manifests and executable bits; ignore mtime and absolute
   target location.
5. Reject Git worktree pointer files in the default profile. For a normal `.git` directory, reject metadata
   symlinks, alternate object stores, config includes, worktree overrides, special files, and cross-device
   paths before invoking Git.
6. Git commands use argument arrays, no optional locks, a minimal environment, disabled hooks/fsmonitor/
   credentials/external diff, a fixed worktree, and a timeout. Git object IDs supplement rather than replace
   the independent working-tree fingerprint.
7. Persist JSON records atomically in a uniquely named staging directory and publish the run directory only
   after every record succeeds. Existing final runs are never intentionally overwritten. A caught failure
   deletes only its own validated staging directory; crash-left staging directories are non-canonical and are
   quarantined for operator inspection rather than automatically trusted or resumed.
8. Store only an allowlisted effective configuration. Artifact references are normalized run-relative POSIX
   paths. Target content and target-supplied profiles never influence configuration.

## Consequences

- Legitimate external Git worktrees and repositories containing cross-filesystem mounts require a future,
  explicit reviewed profile; they fail closed today.
- Dependency/vendor/generated directories are not part of the source fingerprint and are recorded as excluded.
  Their lock/manifests remain included and later scanner/runtime environments rebuild them independently.
- The preparation phase performs two source fingerprints around Git metadata collection and aborts if the target
  changes during that interval.
