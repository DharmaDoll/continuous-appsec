# ADR 0006: Native supply-chain baseline

- Status: Accepted
- Date: 2026-08-12

## Context

The audit harness processes adversarial repositories and is itself security-sensitive. Deferring dependency
integrity, tool provenance, and SBOM generation until final production hardening would leave the MVP bootstrap
path exposed to dependency confusion, compromised newly published packages, unreviewed direct references, and
non-reproducible host tooling.

## Decision

Supply-chain controls are a cross-cutting baseline from Milestone 0 onward:

1. All direct, development, and build requirements use exact `==` pins.
2. `uv.lock` is committed and installation uses `uv sync --locked`; normal execution uses the locked environment.
3. A project-local `uv.toml` applies a 72-hour `exclude-newer` cooldown and allows subprocesses to select the
   reviewed project configuration explicitly instead of discovering user configuration.
4. `whitebox-audit supply-chain check` rejects direct URL/VCS/file dependencies, alternate indexes, non-PyPI
   lock sources, missing exact versions, unapproved artifact hosts, missing SHA-256 records, lock schema drift,
   project-file symlink breakout, and stale lock files.
5. All Make-based uv operations select the reviewed `uv.toml` explicitly. `make check` always runs the native
   policy check; lock freshness is verified offline without cache or user configuration influence.
6. `make malware-check` explicitly enables uv's online OSV-backed malware check during trusted setup. This
   preview defense-in-depth signal does not replace pinning, hashes, review, or provenance checks, and its
   availability does not block offline audit operation.
7. `doctor --format json` records each resolved executable path and SHA-256 in addition to its version.
8. `make sbom` emits a CycloneDX 1.5 SBOM to `reports/whitebox-ai-audit.cdx.json`.
9. Target repositories remain untrusted data. The harness never installs a target's dependencies or runs its
   lifecycle/build scripts on the host. Scanner/verifier builds must later use reviewed, digest-pinned images.
10. The planned Next.js fixture must pin its Node/package-manager/direct dependencies and lock file. Before an
    isolated build, the controller will validate registry URLs and integrity entries. Installation receives no
    host package credentials, disables lifecycle scripts by default, and permits only approved registry egress.

## Dependency update procedure

Dependency changes are explicit review events:

1. Change an exact pin in `pyproject.toml`.
2. Run `make setup` with network access only in the trusted setup phase.
3. Review the `pyproject.toml` and `uv.lock` diff, including source, version, upload time, and new transitive
   packages. Do not approve a direct URL, VCS, path, alternate index, or unexplained package.
4. Run `make check`, `make sbom`, `make malware-check` in the networked setup phase, and `make doctor`.
5. Review relevant upstream release notes, license changes, and security advisories before merging.

Automated dependency/license advisory review and signed, digest-pinned scanner/verifier images remain production
hardening work; they are not claimed as implemented by this ADR.

## Consequences

- Routine local and future CI validation fail closed when dependency provenance or lock integrity violates policy.
- The lock parser is schema-gated. A future uv lock schema change requires an intentional parser/test update.
- Exact direct pins require deliberate updates, which is appropriate for an application/harness rather than a
  reusable dependency library.
- SBOM export and uv malware checking are currently preview capabilities and must be monitored for upstream
  compatibility; native deterministic policy remains authoritative if those services/features are unavailable.
