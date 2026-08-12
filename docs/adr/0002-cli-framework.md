# ADR-0002: Use argparse for the CLI

- Status: Accepted
- Date: 2026-08-12

## Context

The initial CLI requires subcommands, stable exit codes, human output, and JSON output. It does not require an
interactive UI.

## Decision

Use the Python standard library `argparse`. Keep command handlers separate so the parser can be replaced later
without changing application services.

Milestone 0 intentionally has no verbose/debug flag. User-facing failures return bounded messages without
tracebacks. A future debug mode must redact secrets and host paths before it is exposed.

## Consequences

The runtime remains dependency-free. CLI UX helpers must be implemented locally when needed.
