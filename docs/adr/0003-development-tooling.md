# ADR-0003: Use Ruff, mypy, and pytest

- Status: Accepted
- Date: 2026-08-12

## Context

Every milestone requires formatting, linting, type checking, and automated tests.

## Decision

Use Ruff for formatting and linting, mypy in strict mode for type checking, and pytest for tests. Pin compatible
version ranges in `pyproject.toml` and resolve exact versions in `uv.lock`.

## Consequences

These are development dependencies only. Production runtime dependencies remain empty at Milestone 0.
