# 04 - Deterministic Analysis

## Purpose

Deterministic scanners reduce wasted LLM effort and provide reliable evidence primitives.

They are not merely a "first filter" and their findings must not be discarded from later attack-chain reasoning.

## Semgrep

### Role

Default baseline scanner because it is:

- simple to install,
- fast,
- suitable for local use,
- SARIF-capable,
- useful for custom organization rules.

### Bootstrap command

```bash
semgrep scan \
  --config auto \
  --sarif \
  --sarif-output "$RUN_DIR/scanner-runs/semgrep/result.sarif" \
  "$TARGET"
```

Production implementation requirements:

- no `shell=True`,
- timeout,
- version capture,
- stdout/stderr capture,
- exit-code interpretation,
- raw SARIF retention,
- normalized evidence,
- target exclusion policy,
- configurable rulesets.

Example adapter skeleton:

```python
from dataclasses import dataclass
from pathlib import Path
import subprocess

@dataclass(frozen=True)
class CommandResult:
    argv: tuple[str, ...]
    returncode: int
    stdout: str
    stderr: str

def run_semgrep(target: Path, sarif_path: Path, timeout_s: int = 1800) -> CommandResult:
    argv = [
        "semgrep", "scan",
        "--config", "auto",
        "--sarif",
        "--sarif-output", str(sarif_path),
        str(target),
    ]
    p = subprocess.run(
        argv,
        shell=False,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        timeout=timeout_s,
        check=False,
    )
    return CommandResult(tuple(argv), p.returncode, p.stdout, p.stderr)
```

This is a starting point, not final production code.

### Custom rules

Local organization rules should be separate:

```text
rules/semgrep/
├── authz/
├── tenancy/
└── framework/
```

Do not start with hundreds of custom rules.

Add a rule when:

- it represents a stable local security property,
- deterministic matching is appropriate,
- tests can be written,
- it produces actionable signal.

## CodeQL

### Role

Use CodeQL for deeper semantic and data-flow evidence where appropriate.

CodeQL is not "single-file SAST"; its value includes interprocedural and semantic analysis.

### Entitlement

The adapter must refuse/skip by policy when CodeQL use has not been approved for the target repository.

Suggested local config:

```yaml
codeql:
  enabled: auto
  entitlement_acknowledged: false
```

Never infer legal entitlement from the existence of the binary.

### Database creation

Conceptual:

```bash
codeql database create "$DB_DIR" \
  --language=<language> \
  --source-root="$TARGET" \
  --command="<reviewed-build-command>"
```

Do not pass an untrusted build command as a shell string in production.

Build extraction must run in a controlled scanner environment.

### Analysis

Conceptual:

```bash
codeql database analyze "$DB_DIR" \
  <query-suite-or-pack> \
  --format=sarif-latest \
  --output="$RUN_DIR/scanner-runs/codeql/result.sarif"
```

Capture:

- CodeQL CLI version,
- bundle/query pack versions,
- language,
- build command identity,
- DB fingerprint,
- query suite/packs.

## Existing SARIF

Support:

```bash
whitebox-audit ingest-sarif \
  --tool-name existing-ci \
  --input /path/to/result.sarif
```

Never assume all SARIF emitters populate optional fields identically.

The parser must tolerate:

- missing optional fields,
- multiple runs,
- absent snippets,
- URI variants,
- rule metadata in different locations.

## Normalized evidence

Example:

```json
{
  "id": "EVD-...",
  "kind": "static-analysis",
  "tool": {
    "name": "semgrep",
    "version": "..."
  },
  "rule_id": "...",
  "message": "...",
  "severity": "warning",
  "location": {
    "path": "src/foo.py",
    "start_line": 42,
    "end_line": 44
  },
  "fingerprint": "...",
  "raw_ref": "scanner-runs/semgrep/result.sarif#..."
}
```

## Evidence semantics

Scanner evidence can be used in three ways.

### Candidate seed

```text
Semgrep detects unsafe redirect
-> agent checks who controls destination
-> agent discovers OAuth callback chain
-> verifier proves token leakage
```

### Counter-evidence

```text
Hypothesis: unvalidated SQL fragment
CodeQL trace: source is constant enum only
-> hypothesis rejected
```

### Attack-chain node

```text
IDOR
 -> mutable webhook URL
 -> SSRF
 -> internal credential endpoint
```

A scanner finding already known to CI is still relevant to the chain.

## Scanner failure policy

Never silently continue.

Examples:

```text
Semgrep unavailable -> audit may continue but status "degraded"
CodeQL unsupported language -> explicit skip
CodeQL entitlement not acknowledged -> explicit skip
CodeQL DB build failed -> explicit failure with logs
SARIF parse failed -> explicit error
```

Final report must state scanner coverage.

## Scanner sandbox

Even static analysis tools process attacker-controlled syntax.

Where feasible, run scanners in containers or restricted processes.

CodeQL build extraction requires stronger isolation because target build tooling can execute arbitrary code.
