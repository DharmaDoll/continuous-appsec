# 05 - Independent Verifier Sandbox

## Purpose

The verifier is the trust boundary that converts a plausible vulnerability hypothesis into a reproducible result.

The discovery agent must not be able to:

- change the verification oracle,
- modify target source,
- modify verifier code,
- write its own verdict,
- gain unrestricted network,
- access host secrets.

## Core model

```text
Discovery Agent
  |
  | writes declarative VerificationCase
  v
Verifier Controller
  |
  | validates schema + policy
  v
Ephemeral Sandbox
  |
  | executes fixed setup/action/oracle
  v
VerificationResult
```

## Baseline container policy

The baseline for a no-network verification command is:

```bash
docker run --rm \
  --network none \
  --read-only \
  --cap-drop ALL \
  --security-opt no-new-privileges \
  --pids-limit 256 \
  --memory 1g \
  --cpus 1 \
  --tmpfs /tmp:rw,noexec,nosuid,nodev,size=128m \
  -v "$TARGET:/target:ro" \
  -v "$CASE_DIR:/case:ro" \
  -v "$OUTPUT_DIR:/output:rw" \
  org/whitebox-ai-audit-verifier@sha256:<reviewed-64-hex-digest>
```

HTTP fixture verification instead attaches the verifier and target service to a dedicated `docker network create
--internal` network. It must not attach either container to the default bridge or another egress-capable network.

Do not mount:

```text
/var/run/docker.sock
~/.ssh
~/.aws
~/.config/gcloud
host home directory
production config
```

## Network modes

### Default: none

Use `--network none`.

### Local test network

Some HTTP verification requires target + verifier containers to communicate.

Create a dedicated ephemeral Docker internal network with external egress disabled. A normal bridge network is
not sufficient because it may route traffic through the host.

The runtime adapter should start:

```text
target service
test database
optional queue/cache
verifier client
```

inside the same disposable environment.

### External network

Not allowed by default.

Any future support must define:

- explicit allowlist,
- DNS policy,
- HTTP method policy,
- callback sink owned by the test,
- audit logging.

Never allow arbitrary Internet access just because a generated PoC requests it.

## Verification case schema

Conceptual:

```yaml
schema_version: 1
verification_id: VER-... # optional on import; the harness derives and verifies it
hypothesis_id: HYP-...
runtime_profile: demo-webapp

setup:
  fixture: tenant-a-and-b

actor:
  identity: tenant-a-user

action:
  protocol: http
  method: GET
  path: /api/invoices/inv-tenant-b
  headers:
    Authorization: "${fixture.token.tenant-a-user}"

oracle:
  forbidden_status: 200
  json_assertions:
    - path: $.tenant_id
      equals: tenant-b

limits:
  timeout_seconds: 30
  max_response_body_bytes: 262144
```

The discovery agent may fill allowed fields but may not introduce arbitrary host commands. On import, the harness
injects `target_id`, `target_tree_hash`, `policy_fingerprint`, `adapter_fingerprint`, and the digest-pinned runtime
image into the canonical case. The normalized policy and adapter are stored beside the case in the run directory.

## Avoid arbitrary shell PoCs

Bad interface:

```yaml
poc:
  shell: "whatever the agent wants"
```

The v1 interface is deliberately limited to an HTTP request action and an HTTP response oracle. The allowed
response assertions should remain a small, schema-validated subset such as status, selected headers, bounded body,
and JSON-path equality. v1 must reject browser steps, arbitrary SQL, file-system actions, process actions, and
language-specific executable test bodies.

Browser, SQL assertion, file-system assertion, process assertion, and constrained language-specific templates are
post-v1 candidates. Each requires its own threat-model and policy update before it can become an accepted action or
oracle type.

When arbitrary code is unavoidable:

- isolate more strongly,
- remove network,
- remove secrets,
- enforce resource limits,
- use disposable images,
- preserve execution logs,
- require operator approval.

## Verifier verdict

Example:

```json
{
  "verification_id": "VER-...",
  "verifier_run_id": "VRUN-...",
  "target_tree_hash": "...",
  "status": "proved",
  "observations": [
    {
      "type": "http-response",
      "status": 200,
      "body_sha256": "...",
      "evidence_file": "verification/VER-.../response.json"
    }
  ],
  "oracle": {
    "forbidden_status": 200,
    "observed_status": 200,
    "violated": true
  },
  "verifier_image": "org/whitebox-ai-audit-verifier@sha256:<reviewed-64-hex-digest>",
  "policy_fingerprint": "..."
}
```

Only verifier code can create `status = proved`.

The fixed v1 runtime reads only `/case/policy.json`, `adapter.json`, `case.json`, `fixture.json`, and
`execution.json`; it atomically writes `/output/result.json`. It supports one HTTP action followed by the fixed
status/scalar-JSON oracle. Fixture tokens are resolved only for the selected actor and are never copied into the
result. Response bodies are bounded and represented by size and SHA-256 rather than persisted verbatim. Selected
string values used by an oracle are likewise represented only by length and SHA-256 in the result.

## Runtime adapter

Real internal applications differ.

Define a reviewed adapter per application family:

```yaml
schema_version: 1
name: python-fastapi-postgres
image: org/whitebox-runtime-python@sha256:<reviewed-64-hex-digest>
command_id: start-app
service:
  host: app
  port: 8080
health:
  path: /health
  timeout_seconds: 10
fixtures:
  - tenant-a-and-b
identities:
  - anonymous
  - tenant-a-user
  - admin
```

`command_id` refers to a pre-reviewed command embedded in the runtime adapter image; it is not arbitrary text from the target.

## Scanner vs verifier sandboxes

Use separate environments.

Scanner sandbox:

- parses/builds target to derive static facts.

Verifier sandbox:

- tests a specific security invariant.

Do not let a scanner container become a generic privileged build machine.

## Cleanup

Every verification run must:

- have a unique run ID,
- use disposable containers,
- stop/kill on timeout,
- delete transient networks,
- retain only evidence artifacts,
- avoid retaining secret material.

## Verification limitations

Some issues are hard to prove safely:

- race conditions,
- destructive actions,
- cloud IAM escalation,
- external SaaS side effects,
- production-only trust boundaries.

For these, support `high-confidence-static` with explicit limitations rather than manufacturing "proof".

Current implementation boundary (2026-08-17): the fixed HTTP runtime and least-privilege Docker/network argv
builders have unit tests with a fake HTTP connection. A verifier image, target fixture lifecycle, wall-clock
controller, cleanup execution, and live tests proving filesystem/resource/egress isolation are still required.
