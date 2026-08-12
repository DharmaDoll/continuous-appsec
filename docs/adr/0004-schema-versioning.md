# ADR-0004: Start canonical records at schema version 1

- Status: Accepted
- Date: 2026-08-12

## Context

Machine-readable records are canonical and must remain reproducible across application releases.

## Decision

Every persisted canonical record contains integer `schema_version: 1`. Readers reject unknown newer versions.
Breaking changes require an explicit migration and a new schema version. Silent best-effort reinterpretation is
not allowed.

## Consequences

Milestone 0 JSON output already includes the version. A migration framework is deferred to production
hardening, but version checks are not deferred.
