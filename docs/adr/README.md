# Architecture Decision Records

- [0001 - Use dataclasses for the initial internal models](0001-model-validation.md)
- [0002 - Use argparse for the CLI](0002-cli-framework.md)
- [0003 - Use Ruff, mypy, and pytest](0003-development-tooling.md)
- [0004 - Start canonical records at schema version 1](0004-schema-versioning.md)
- [0005 - Use Next.js and PostgreSQL for the first MVP fixture](0005-mvp-target-stack.md)
- [0006 - Native supply-chain baseline](0006-native-supply-chain-baseline.md)
- [0007 - Fail-closed target preparation](0007-safe-target-preparation.md)
- [0008 - Semgrep execution and evidence boundary](0008-semgrep-evidence-boundary.md)
- [0009 - Define the Whitebox Audit Engine product boundary](0009-whitebox-audit-engine-boundary.md)

ADRs record decisions that materially affect the implementation or security model.

Status values:

- Proposed
- Accepted
- Superseded
- Rejected

An accepted ADR may be revisited when executable evidence contradicts its assumptions. Security boundaries
defined by `AGENTS.md` cannot be weakened by an ADR without an explicit threat-model update.
