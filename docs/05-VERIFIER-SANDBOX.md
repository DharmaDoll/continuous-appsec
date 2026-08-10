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

Example starting command:

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
  whitebox-audit-verifier:local
```

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

Create a dedicated ephemeral Docker network with no external egress where possible.

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
id: VER-...
finding_candidate: HYP-...
runtime_profile: demo-webapp

setup:
  seed_fixture: tenant-a-and-b

actor:
  identity: tenant_a_user

action:
  protocol: http
  method: GET
  path: /api/invoices/inv-tenant-b
  headers:
    Authorization: "${fixture.token.tenant_a_user}"

oracle:
  type: json_assertion
  forbidden_condition:
    response_status: 200
    json:
      path: $.tenant_id
      equals: tenant-b

limits:
  timeout_seconds: 30
```

The discovery agent may fill allowed fields but may not introduce arbitrary host commands.

## Avoid arbitrary shell PoCs

Bad interface:

```yaml
poc:
  shell: "whatever the agent wants"
```

Preferred:

- HTTP request DSL,
- browser action DSL,
- SQL assertion DSL against a test DB,
- file-system assertion,
- process exit/assertion,
- language-specific test template with constrained imports.

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
    "expected_secure_behavior": "403 or not-found",
    "observed_behavior": "200 with tenant-b resource",
    "violated": true
  }
}
```

Only verifier code can create `status = proved`.

## Runtime adapter

Real internal applications differ.

Define a reviewed adapter per application family:

```yaml
name: python-fastapi-postgres
image: org/whitebox-runtime-python:2026-08
start:
  command_id: start-app
health:
  type: http
  url: http://app:8080/health
fixtures:
  - seed-db
identities:
  - anonymous
  - user
  - admin
ports:
  - 8080
network:
  egress: none
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
