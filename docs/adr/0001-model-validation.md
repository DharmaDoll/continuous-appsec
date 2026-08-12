# ADR-0001: Use dataclasses for the initial internal models

- Status: Accepted
- Date: 2026-08-12

## Context

Milestones 0-2 need small immutable internal objects. Strict parsing of untrusted Hypothesis,
VerificationCase, and configuration documents becomes important in Milestone 3.

## Decision

Use frozen, slotted standard-library dataclasses for Milestones 0-2. Re-evaluate Pydantic at the Milestone 3
input boundary. External records must still reject unknown fields and enforce explicit schema versions.

## Consequences

The initial runtime has no third-party dependency. Validation must be explicit. A later Pydantic decision must
not create two competing canonical model sets.
