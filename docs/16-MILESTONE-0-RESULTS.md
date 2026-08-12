# 16 - Milestone 0 Results

## Scope

Milestone 0 establishes the executable Python project, development checks, CLI, and non-destructive host
capability diagnostics. It does not prepare targets, execute scanners, persist Evidence, or run a Verifier.

## Implemented

- Python 3.12+ package with a project-local `.venv`
- exact-pinned direct/build dependencies and dependency lock with no runtime dependencies
- native source/hash/cooldown/lock-freshness supply-chain gate in `make check`
- host executable SHA-256 provenance and CycloneDX SBOM generation
- `whitebox-audit --help` and `--version`
- `whitebox-audit doctor` with human and JSON output
- stable exit codes
- required/optional capability aggregation
- bounded subprocess timeouts using argument arrays and `shell=False`
- allowlisted child-process environment
- bounded and redacted diagnostic output
- Ruff formatting/linting, strict mypy, and pytest
- Make targets and a shell doctor wrapper
- ADRs for initial implementation choices

The Codex plugin check uses the stable, automation-oriented `codex plugin list --json` output documented by
OpenAI. It does not add, remove, or upgrade plugins.

## Verification on 2026-08-12

Commands executed:

```text
make setup UV=/home/calvet/.local/bin/uv PYTHON=/usr/bin/python3.13
make format-check UV=/home/calvet/.local/bin/uv
make lint UV=/home/calvet/.local/bin/uv
make typecheck UV=/home/calvet/.local/bin/uv
make test UV=/home/calvet/.local/bin/uv
make supply-chain UV=/home/calvet/.local/bin/uv
make sbom UV=/home/calvet/.local/bin/uv
make malware-check UV=/home/calvet/.local/bin/uv PYTHON=/usr/bin/python3.13
.venv/bin/whitebox-audit doctor
.venv/bin/whitebox-audit doctor --format json
```

Results:

```text
format-check: passed
lint: passed
typecheck: passed
tests: 26 passed
supply-chain: 6 checks passed; 15 locked packages; 165 artifact hash records
SBOM: valid CycloneDX 1.5 document generated
online malware check: 14 locked third-party packages checked successfully
doctor exit: 3 (host not ready)
```

Observed host capabilities:

```text
OK: git, curl, jq, ripgrep, Python 3.13.5, make, uv, Codex 0.147.0
ERROR: Docker daemon socket unavailable in the current sandbox
ERROR: Project CodeGuard plugin not installed
ERROR: Semgrep not installed
WARN: CodeQL not installed (optional)
```

Doctor correctly returned exit code 3 rather than reporting the host as ready.

## Known limitations

- Milestone 0 originally provided only `doctor` and `supply-chain check`; `prepare` was added in Milestone 1.
- Docker daemon success was covered by a fake-tool integration test; this sandbox cannot access the daemon.
- Project CodeGuard and Semgrep success were covered by fake-tool integration tests; they are absent locally.
- CodeQL is not installed and remains optional.
- Linux is the only environment exercised in this milestone.
- uv malware checking and CycloneDX export are preview features; exact pins, source/hash policy, and offline lock
  freshness checks do not depend on those external/preview signals.
- The original controlled-directory no-write test is complemented by Milestone 1 target before/after hashes and
  malicious target fixture tests.
- Configuration files, Target models, scanners, Evidence, Hypotheses, Verifier, and reports are not implemented.
