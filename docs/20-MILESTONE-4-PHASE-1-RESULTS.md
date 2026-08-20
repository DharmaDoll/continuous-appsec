# 20 - Milestone 4 Phase 1 Results

## Scope completed

This phase establishes the declarative trust boundary before any target/runtime container is executed.

Implemented:

- strict `config/verifier-policy.yaml` parsing with unknown-key rejection,
- mandatory no-egress, read-only, least-privilege policy invariants and hard resource ceilings,
- reviewed Runtime Adapter contract with digest-pinned image, fixed `command_id`, health check, fixture, and identity
  allowlists,
- HTTP-only VerificationCase DSL with bounded methods, local service paths, headers, JSON body, status oracle, and a
  restricted scalar JSON-path equality subset,
- exact Authorization fixture-token template and rejection of other environment/template references,
- policy, adapter, target, and hypothesis fingerprints in the content-derived `VER-` ID,
- immutable run-relative case, normalized policy, and normalized adapter artifacts,
- tamper detection when a stored policy/adapter no longer matches its fingerprint,
- human and JSON `verification-case add/list` CLI operations.

## Commands exercised

```bash
whitebox-audit verification-case add \
  --run-id RUN-... \
  --file case.yaml \
  --adapter reviewed-adapter.yaml \
  --format json

whitebox-audit verification-case list --run-id RUN-... --format json
```

`--policy` may select another strict operator-managed policy. Without it, the harness uses
`config/verifier-policy.yaml`.

## Artifact layout

```text
work/<run-id>/verification/
├── cases.jsonl
├── policies/<policy-sha256>.json
└── adapters/<adapter-sha256>.json
```

The Discovery/operator input cannot set policy or adapter fingerprints directly. The harness derives them from
normalized trusted documents and injects them into the canonical case.

## Validation coverage

- unsafe policy relaxation and unknown policy fields,
- mutable image tag and arbitrary adapter start command,
- unknown fixture and identity references,
- arbitrary shell/host fields and remote URL paths,
- Authorization literals, header injection, and non-Authorization templates,
- body and oracle environment references,
- request/response/timeout/assertion limits,
- unsupported JSON-path expressions,
- target/hypothesis reference and stored policy tampering,
- stable repeat import and CLI add/list behavior.

## Explicit limitations

- No Docker container, runtime service, or HTTP request is executed in this phase.
- The verifier image/entrypoint, internal Docker network, resource flags, timeout cleanup, and fixed verdict writer
  remain Milestone 4 Phase 2 work.
- `VerificationResult` is not persisted and no Finding is promoted by this phase.
- Adapter `command_id` is schema-validated but is not resolved to an image-embedded command until the controller is
  implemented.
- The Next.js/PostgreSQL vulnerable/fixed fixture and real isolation tests are not implemented yet.

## Executed validation

- native supply-chain policy and frozen-lock validation,
- Ruff formatting and linting,
- strict mypy checking,
- 92 unit, integration, and security tests.
