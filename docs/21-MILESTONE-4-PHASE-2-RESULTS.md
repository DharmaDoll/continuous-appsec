# 21 - Milestone 4 Phase 2 Results

## Scope completed

This phase implements the fixed verdict boundary without claiming a live verifier sandbox.

Implemented:

- fixed HTTP runtime with one reviewed-adapter destination and no executable case fields,
- exact `${fixture.token.<selected-identity>}` resolution from a separate fixture-secret document,
- status plus bounded scalar JSON-path equality oracle,
- `proved`, `not-proved`, `inconclusive`, and transport `error` outcomes,
- response size/SHA-256 observations without raw response or token persistence,
- redacted string oracle observations represented only by length and SHA-256,
- immutable verifier image digest, target tree hash, policy fingerprint, version, and timestamps in each result,
- fixed `/case` input filenames and atomic `/output/result.json` output,
- pure Docker argv construction for an internal network and a least-privilege verifier container,
- strict network/container names, real-directory mounts, digest-only images, and exactly three distinct mounts.

## Fixed runtime input

```text
/case/
├── policy.json
├── adapter.json
├── case.json
├── fixture.json       # ephemeral identity tokens; never copied to output
└── execution.json     # verifier image digest
```

The runtime re-parses policy, adapter, and canonical case before any request. Policy, adapter, runtime image,
fixture, and actor mismatches fail closed. It contacts only the adapter's fixed service host and port; a case can
choose only a validated relative request path.

## Sandbox command boundary

The command builder emits:

- `docker network create --internal`,
- `docker run --pull never --read-only`,
- `--cap-drop ALL` and `no-new-privileges`,
- PID, memory, and CPU limits,
- a `noexec,nosuid,nodev` `/tmp`,
- read-only `/target` and `/case`,
- writable `/output`,
- no other bind mount.

Image references must contain a lowercase SHA-256 digest. Mount injection characters, symlink mount roots, reused
mount directories, and unstructured container/network names are rejected before argv construction.

## Validation exercised

- strict policy/adapter/case re-validation through the fixed entrypoint,
- a forbidden cross-tenant-like response producing `proved`,
- a denied response producing `not-proved`,
- oversized response producing `inconclusive`,
- transport failure producing `error`,
- fixture token use without result leakage,
- mandatory Docker isolation flags and three-mount allowlist,
- mutable image, mount injection, and aliased mount rejection.

The HTTP tests use a deterministic fake connection. Docker was not executed.

## Explicit limitations and next work

- `verifier/Dockerfile` and a reviewed digest-pinned build are not implemented.
- The reviewed adapter `command_id` is not yet resolved to an image-embedded target command.
- Target service, database, health check, fixture seeding, and secret lifecycle are not controller-managed.
- No wall-clock watchdog executes or cleans up containers and networks yet; only cleanup argv is defined.
- Live tests have not proved read-only mounts, blocked egress, absent host credentials/Docker socket, resource
  enforcement, or cleanup.
- VerificationResult persistence into the audit run, artifact hashing, `verify` CLI, Finding promotion, and the
  Next.js/PostgreSQL vulnerable/fixed fixture remain pending.

Therefore this phase does not satisfy Milestone 4 end-to-end acceptance and does not claim a vulnerability PoC was
executed.

## Executed validation

`make check` completed the offline supply-chain gate, Ruff format/lint, strict mypy, and all 98 unit, integration,
and security tests. The test count includes fake HTTP runtime and Docker argv tests, not a live Docker isolation
test.
