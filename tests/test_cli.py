from __future__ import annotations

import io
import json
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

from whitebox_audit import __version__
from whitebox_audit.cli import run
from whitebox_audit.prepare import PrepareController


def test_module_help() -> None:
    completed = subprocess.run(
        [sys.executable, "-m", "whitebox_audit", "--help"],
        check=False,
        capture_output=True,
        text=True,
        timeout=10,
    )

    assert completed.returncode == 0
    assert "doctor" in completed.stdout
    assert "supply-chain" in completed.stdout
    assert "prepare" in completed.stdout
    assert "scan" in completed.stdout
    assert "ingest-sarif" in completed.stdout
    assert completed.stderr == ""


def test_installed_console_script_help() -> None:
    executable = Path(sys.executable).with_name("whitebox-audit")
    completed = subprocess.run(
        [executable, "--help"],
        check=False,
        capture_output=True,
        text=True,
        timeout=10,
    )

    assert completed.returncode == 0
    assert "doctor" in completed.stdout
    assert "supply-chain" in completed.stdout
    assert "prepare" in completed.stdout
    assert "scan" in completed.stdout
    assert "ingest-sarif" in completed.stdout
    assert completed.stderr == ""


def test_module_version() -> None:
    completed = subprocess.run(
        [sys.executable, "-m", "whitebox_audit", "--version"],
        check=False,
        capture_output=True,
        text=True,
        timeout=10,
    )

    assert completed.returncode == 0
    assert completed.stdout.strip() == f"whitebox-audit {__version__}"


def test_invalid_option_returns_two() -> None:
    completed = subprocess.run(
        [sys.executable, "-m", "whitebox_audit", "--not-a-real-option"],
        check=False,
        capture_output=True,
        text=True,
        timeout=10,
    )

    assert completed.returncode == 2
    assert "error:" in completed.stderr


@pytest.mark.parametrize("command", [["doctor", "--format", "xml"], ["unknown"]])
def test_invalid_subcommand_input_returns_two(command: list[str]) -> None:
    completed = subprocess.run(
        [sys.executable, "-m", "whitebox_audit", *command],
        check=False,
        capture_output=True,
        text=True,
        timeout=10,
    )

    assert completed.returncode == 2


def _scan_harness(tmp_path: Path) -> Path:
    harness = tmp_path / "harness"
    (harness / "work").mkdir(parents=True)
    rules = harness / "rules" / "semgrep"
    rules.mkdir(parents=True)
    shutil.copyfile(
        Path(__file__).parents[1] / "rules" / "semgrep" / "baseline.yaml",
        rules / "baseline.yaml",
    )
    return harness


def test_scan_cli_returns_three_and_records_skip_when_semgrep_is_missing(
    tmp_path: Path,
) -> None:
    harness = _scan_harness(tmp_path)
    target = tmp_path / "target"
    target.mkdir()
    run_id = PrepareController(harness).prepare(target).run.run_id
    stdout = io.StringIO()
    stderr = io.StringIO()

    exit_code = run(
        ["scan", "--run-id", run_id],
        stdout=stdout,
        stderr=stderr,
        environ={"PATH": ""},
        harness_root=harness,
    )

    assert exit_code == 3
    assert "Semgrep is unavailable" in stderr.getvalue()
    scanner_run = json.loads(
        (harness / "work" / run_id / "scanner-runs" / "semgrep" / "run.json").read_text()
    )
    assert scanner_run["status"] == "skipped"


def test_ingest_cli_malformed_sarif_returns_six(tmp_path: Path) -> None:
    harness = _scan_harness(tmp_path)
    target = tmp_path / "target"
    target.mkdir()
    run_id = PrepareController(harness).prepare(target).run.run_id
    malformed = tmp_path / "malformed.sarif"
    malformed.write_text("{bad-json", encoding="utf-8")
    stderr = io.StringIO()

    exit_code = run(
        [
            "ingest-sarif",
            "--run-id",
            run_id,
            "--tool-name",
            "external",
            "--input",
            str(malformed),
        ],
        stdout=io.StringIO(),
        stderr=stderr,
        harness_root=harness,
    )

    assert exit_code == 6
    assert "not valid UTF-8 JSON" in stderr.getvalue()
