from __future__ import annotations

import json
import shutil
from pathlib import Path

import pytest

from whitebox_audit.errors import ExitCode, WhiteboxAuditError
from whitebox_audit.models import RunStatus, ScannerStatus
from whitebox_audit.prepare import PrepareController
from whitebox_audit.scan import ScanController
from whitebox_audit.scanners.semgrep import (
    SemgrepScanner,
    build_semgrep_argv,
    validate_rulesets,
)

FIXTURES = Path(__file__).parent / "fixtures"


def _harness(tmp_path: Path) -> Path:
    harness = tmp_path / "harness"
    (harness / "work").mkdir(parents=True)
    rules = harness / "rules" / "semgrep"
    rules.mkdir(parents=True)
    shutil.copyfile(
        Path(__file__).parents[1] / "rules" / "semgrep" / "baseline.yaml",
        rules / "baseline.yaml",
    )
    return harness


def _fake_semgrep(bin_dir: Path, *, mode: str, sarif: Path | None = None) -> Path:
    executable = bin_dir / "semgrep"
    bin_dir.mkdir(exist_ok=True)
    sarif_json = "{}" if sarif is None else sarif.read_text(encoding="utf-8")
    benign_json = json.dumps(
        {
            "version": "2.1.0",
            "runs": [{"tool": {"driver": {"name": "Semgrep"}}, "results": []}],
        },
        separators=(",", ":"),
    )
    scan_body = {
        "success": f"SARIF='{sarif_json}'\nprintf '%s' \"$SARIF\" > \"$OUTPUT\"\nexit 1",
        "benign": f"printf '%s' '{benign_json}' > \"$OUTPUT\"\nexit 0",
        "failure": "printf '%s\\n' 'token=supersecret' >&2\nexit 2",
        "timeout": "while :; do :; done",
        "malformed": "printf '%s' '{bad-json' > \"$OUTPUT\"\nexit 0",
        "mutation": (
            f"printf '%s' '{benign_json}' > \"$OUTPUT\"\n"
            "printf '%s\\n' changed >> \"$TARGET/mutated.txt\"\nexit 0"
        ),
    }[mode]
    executable.write_text(
        f"""#!/bin/sh
set -eu
if [ "${{1:-}}" = "--version" ]; then
  printf '%s\n' '1.130.0'
  exit 0
fi
OUTPUT=''
TARGET=''
while [ "$#" -gt 0 ]; do
  if [ "$1" = "--sarif-output" ]; then
    OUTPUT=$2
    shift 2
  elif [ "$1" = "--" ]; then
    TARGET=$2
    break
  else
    shift
  fi
done
{scan_body}
""",
        encoding="utf-8",
    )
    executable.chmod(0o755)
    return executable


def _prepared(harness: Path, target: Path) -> str:
    return PrepareController(harness).prepare(target).run.run_id


def test_semgrep_argv_is_explicit_and_rejects_option_injection(tmp_path: Path) -> None:
    rules = tmp_path / "rules.yaml"
    rules.write_text("rules: []\n", encoding="utf-8")
    argv = build_semgrep_argv(
        "/trusted/semgrep",
        tmp_path / "target",
        tmp_path / "result.sarif",
        (rules,),
        ("node_modules",),
    )

    assert argv[0:3] == ("/trusted/semgrep", "scan", "--error")
    assert argv[-2] == "--"
    assert "--config" in argv
    with pytest.raises(WhiteboxAuditError):
        build_semgrep_argv("semgrep", tmp_path, tmp_path / "out", (rules,), ("--config",))


def test_ruleset_must_be_reviewed_and_structurally_valid(tmp_path: Path) -> None:
    harness = _harness(tmp_path)
    invalid = harness / "rules" / "semgrep" / "invalid.yaml"
    invalid.write_text("not-rules: []\n", encoding="utf-8")
    external = tmp_path / "external.yaml"
    external.write_text("rules: []\n", encoding="utf-8")

    with pytest.raises(WhiteboxAuditError) as malformed:
        validate_rulesets((invalid,), harness)
    assert malformed.value.exit_code is ExitCode.INVALID_INPUT
    with pytest.raises(WhiteboxAuditError) as outside:
        validate_rulesets((external,), harness)
    assert outside.value.exit_code is ExitCode.POLICY_REJECTED


def test_fake_semgrep_success_creates_evidence_and_preserves_target(tmp_path: Path) -> None:
    harness = _harness(tmp_path)
    target = tmp_path / "target"
    shutil.copytree(FIXTURES / "targets" / "semgrep-vulnerable", target)
    original = (target / "src" / "vulnerable.ts").read_bytes()
    executable = _fake_semgrep(
        tmp_path / "bin",
        mode="success",
        sarif=FIXTURES / "sarif" / "semgrep-realistic.sarif",
    )
    scanner = SemgrepScanner(
        harness, executable=str(executable), environ={"PATH": str(executable.parent)}
    )

    result = ScanController(harness, scanner=scanner).scan(run_id=_prepared(harness, target))

    assert result.scanner_run.status is ScannerStatus.SUCCEEDED
    assert len(result.evidence) == 1
    assert (target / "src" / "vulnerable.ts").read_bytes() == original
    run = json.loads((Path(result.run_directory) / "run.json").read_text(encoding="utf-8"))
    assert run["status"] == RunStatus.COMPLETED
    evidence_lines = (
        (Path(result.run_directory) / "evidence" / "evidence.jsonl")
        .read_text(encoding="utf-8")
        .splitlines()
    )
    assert len(evidence_lines) == 1


def test_fake_semgrep_benign_produces_no_seeded_evidence(tmp_path: Path) -> None:
    harness = _harness(tmp_path)
    target = tmp_path / "target"
    shutil.copytree(FIXTURES / "targets" / "semgrep-benign", target)
    executable = _fake_semgrep(tmp_path / "bin", mode="benign")
    scanner = SemgrepScanner(
        harness, executable=str(executable), environ={"PATH": str(executable.parent)}
    )

    result = ScanController(harness, scanner=scanner).scan(run_id=_prepared(harness, target))

    assert result.evidence == ()


def test_fake_semgrep_failure_is_persisted_and_redacted(tmp_path: Path) -> None:
    harness = _harness(tmp_path)
    target = tmp_path / "target"
    target.mkdir()
    executable = _fake_semgrep(tmp_path / "bin", mode="failure")
    scanner = SemgrepScanner(
        harness, executable=str(executable), environ={"PATH": str(executable.parent)}
    )
    run_id = _prepared(harness, target)

    with pytest.raises(WhiteboxAuditError) as raised:
        ScanController(harness, scanner=scanner).scan(run_id=run_id)

    assert raised.value.exit_code is ExitCode.EXECUTION_FAILED
    run_dir = harness / "work" / run_id
    scanner_run = json.loads(
        (run_dir / "scanner-runs" / "semgrep" / "run.json").read_text(encoding="utf-8")
    )
    assert scanner_run["status"] == ScannerStatus.FAILED
    assert json.loads((run_dir / "run.json").read_text(encoding="utf-8"))["status"] == "failed"
    stderr = (run_dir / "scanner-runs" / "semgrep" / "stderr.log").read_text(encoding="utf-8")
    assert "supersecret" not in stderr
    assert "[REDACTED]" in stderr


def test_fake_semgrep_timeout_is_persisted(tmp_path: Path) -> None:
    harness = _harness(tmp_path)
    target = tmp_path / "target"
    target.mkdir()
    executable = _fake_semgrep(tmp_path / "bin", mode="timeout")
    scanner = SemgrepScanner(
        harness,
        executable=str(executable),
        timeout_seconds=0.05,
        environ={"PATH": str(executable.parent)},
    )
    run_id = _prepared(harness, target)

    with pytest.raises(WhiteboxAuditError) as raised:
        ScanController(harness, scanner=scanner).scan(run_id=run_id)

    assert raised.value.exit_code is ExitCode.EXECUTION_FAILED
    scanner_run = json.loads(
        (harness / "work" / run_id / "scanner-runs" / "semgrep" / "run.json").read_text(
            encoding="utf-8"
        )
    )
    assert scanner_run["status"] == ScannerStatus.TIMED_OUT


def test_unavailable_semgrep_is_skipped_and_run_is_degraded(tmp_path: Path) -> None:
    harness = _harness(tmp_path)
    target = tmp_path / "target"
    target.mkdir()
    scanner = SemgrepScanner(harness, executable="missing-semgrep", environ={"PATH": ""})
    run_id = _prepared(harness, target)

    with pytest.raises(WhiteboxAuditError) as raised:
        ScanController(harness, scanner=scanner).scan(run_id=run_id)

    assert raised.value.exit_code is ExitCode.CAPABILITY_MISSING
    run_dir = harness / "work" / run_id
    scanner_run = json.loads(
        (run_dir / "scanner-runs" / "semgrep" / "run.json").read_text(encoding="utf-8")
    )
    assert scanner_run["status"] == ScannerStatus.SKIPPED
    assert json.loads((run_dir / "run.json").read_text(encoding="utf-8"))["status"] == "degraded"


def test_malformed_scanner_sarif_fails_with_data_integrity_error(tmp_path: Path) -> None:
    harness = _harness(tmp_path)
    target = tmp_path / "target"
    target.mkdir()
    executable = _fake_semgrep(tmp_path / "bin", mode="malformed")
    scanner = SemgrepScanner(
        harness, executable=str(executable), environ={"PATH": str(executable.parent)}
    )
    run_id = _prepared(harness, target)

    with pytest.raises(WhiteboxAuditError) as raised:
        ScanController(harness, scanner=scanner).scan(run_id=run_id)

    assert raised.value.exit_code is ExitCode.DATA_INTEGRITY_ERROR
    assert json.loads((harness / "work" / run_id / "run.json").read_text())["status"] == "failed"


def test_scanner_target_mutation_is_detected_and_failed(tmp_path: Path) -> None:
    harness = _harness(tmp_path)
    target = tmp_path / "target"
    target.mkdir()
    executable = _fake_semgrep(tmp_path / "bin", mode="mutation")
    scanner = SemgrepScanner(
        harness, executable=str(executable), environ={"PATH": str(executable.parent)}
    )
    run_id = _prepared(harness, target)

    with pytest.raises(WhiteboxAuditError) as raised:
        ScanController(harness, scanner=scanner).scan(run_id=run_id)

    assert raised.value.exit_code is ExitCode.EXECUTION_FAILED
    scanner_run = json.loads(
        (harness / "work" / run_id / "scanner-runs" / "semgrep" / "run.json").read_text()
    )
    assert scanner_run["status"] == "failed"
    assert scanner_run["reason"] == "target changed during scanner execution"
