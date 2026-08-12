# ADR-0005: Use Next.js and PostgreSQL for the first MVP fixture

- Status: Accepted
- Date: 2026-08-12

## Context

The project will be validated through short MVP feedback cycles. The first runtime fixture must exercise
cross-tenant HTTP authorization in a representative TypeScript application without requiring an external system.

## Decision

Use TypeScript, Next.js App Router, and PostgreSQL for the first disposable fixture and Runtime Adapter. Start
with an HTTP Route Handler for invoice retrieval, deterministic tenant A/B data, and vulnerable/fixed variants.
Browser flows, Server Actions, and generalized adapters are deferred until the HTTP verifier pipeline works.

## Consequences

The audit harness remains Python 3.12+. Node.js and Next.js exist only inside the reviewed fixture/runtime
boundary. The fixture must not introduce target-controlled build commands into host execution.
