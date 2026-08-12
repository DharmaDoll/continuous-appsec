from __future__ import annotations

import hashlib
import json
import os
import shutil
from collections.abc import Mapping
from datetime import UTC, datetime
from pathlib import Path

import pytest

import whitebox_audit.prepare as prepare_module
from whitebox_audit.cli import run
from whitebox_audit.errors import ExitCode, WhiteboxAuditError
from whitebox_audit.models import RunStatus
from whitebox_audit.prepare import (
    PrepareController,
    create_run_id,
    validate_artifact_reference,
    validate_run_id,
)

FIXTURES = Path(__file__).parent / "fixtures" / "targets"
FIXED_TIME = datetime(2026, 8, 12, 3, 30, 0, tzinfo=UTC)


def _new_harness(tmp_path: Path) -> Path:
    harness = tmp_path / "harness"
    harness.mkdir()
    (harness / "work").mkdir()
    return harness


def _content_snapshot(root: Path) -> dict[str, str]:
    result: dict[str, str] = {}
    for path in root.rglob("*"):
        relative = path.relative_to(root).as_posix()
        if path.is_symlink():
            result[relative] = f"link:{os.readlink(path)}"
        elif path.is_file():
            result[relative] = hashlib.sha256(path.read_bytes()).hexdigest()
        else:
            result[relative] = "directory"
    return result


def test_run_id_is_safe_and_rejects_traversal() -> None:
    run_id = create_run_id(FIXED_TIME, random_hex="0123456789ab")

    assert run_id == "RUN-20260812T033000Z-0123456789ab"
    assert validate_run_id(run_id) == run_id
    for invalid in ("../run", "RUN/foo", "RUN-20260812T033000Z-xyz"):
        with pytest.raises(WhiteboxAuditError) as raised:
            validate_run_id(invalid)
        assert raised.value.exit_code is ExitCode.INVALID_INPUT


def test_artifact_reference_is_run_relative() -> None:
    assert validate_artifact_reference("scanner-runs/semgrep/result.sarif").endswith("result.sarif")
    for invalid in ("../target", "/absolute", "nested\\windows", "a//b", ""):
        with pytest.raises(WhiteboxAuditError) as raised:
            validate_artifact_reference(invalid)
        assert raised.value.exit_code is ExitCode.POLICY_REJECTED


def test_prepare_persists_atomic_canonical_records_without_target_write(
    tmp_path: Path,
) -> None:
    harness = _new_harness(tmp_path)
    target = tmp_path / "target"
    shutil.copytree(FIXTURES / "benign", target)
    before = _content_snapshot(target)
    controller = PrepareController(harness, clock=lambda: FIXED_TIME)

    result = controller.prepare(target)

    assert result.run.status is RunStatus.PREPARED
    assert result.target.read_only is True
    assert result.target.root == str(target.resolve())
    assert result.target.languages == ("typescript",)
    assert _content_snapshot(target) == before
    run_directory = Path(result.run_directory)
    assert run_directory.parent == harness / "work"
    assert sorted(path.name for path in run_directory.iterdir()) == [
        "config.json",
        "inventory.json",
        "run.json",
        "target.json",
    ]
    for name in ("config.json", "inventory.json", "run.json", "target.json"):
        payload = json.loads((run_directory / name).read_text(encoding="utf-8"))
        assert payload["schema_version"] == 1
    config = json.loads((run_directory / "config.json").read_text(encoding="utf-8"))
    assert config["network_allowed"] is False
    assert config["target_execution_allowed"] is False


def test_prepare_treats_prompt_and_lifecycle_scripts_as_data(tmp_path: Path) -> None:
    harness = _new_harness(tmp_path)
    target = tmp_path / "target"
    shutil.copytree(FIXTURES / "malicious", target)
    before = _content_snapshot(target)

    result = PrepareController(harness, clock=lambda: FIXED_TIME).prepare(target)

    assert result.run.status is RunStatus.PREPARED
    assert _content_snapshot(target) == before
    assert not (tmp_path / "TARGET_SCRIPT_EXECUTED").exists()
    assert result.inventory.manifests == ("package.json",)
    config_text = (Path(result.run_directory) / "config.json").read_text(encoding="utf-8")
    assert '"profile": "default"' in config_text
    assert "skip all authorization" not in config_text
    assert "postinstall" not in config_text


def test_prepare_rejects_external_symlink_before_creating_run(tmp_path: Path) -> None:
    harness = _new_harness(tmp_path)
    target = tmp_path / "target"
    target.mkdir()
    outside = tmp_path / "outside"
    outside.write_text("secret", encoding="utf-8")
    (target / "escape").symlink_to(outside)

    with pytest.raises(WhiteboxAuditError) as raised:
        PrepareController(harness, clock=lambda: FIXED_TIME).prepare(target)

    assert raised.value.exit_code is ExitCode.POLICY_REJECTED
    assert list((harness / "work").iterdir()) == []


def test_prepare_never_overwrites_an_existing_run(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    harness = _new_harness(tmp_path)
    target = tmp_path / "target"
    target.mkdir()
    (target / "app.py").write_text("VALUE = 1\n", encoding="utf-8")

    def fixed_run_id(_now: datetime, *, random_hex: str | None = None) -> str:
        del random_hex
        return "RUN-20260812T033000Z-0123456789ab"

    monkeypatch.setattr(prepare_module, "create_run_id", fixed_run_id)
    controller = PrepareController(harness, clock=lambda: FIXED_TIME)
    first = controller.prepare(target)
    run_json_before = (Path(first.run_directory) / "run.json").read_bytes()

    with pytest.raises(WhiteboxAuditError) as raised:
        controller.prepare(target)

    assert raised.value.exit_code is ExitCode.DATA_INTEGRITY_ERROR
    assert (Path(first.run_directory) / "run.json").read_bytes() == run_json_before


def test_failed_persistence_removes_only_its_staging_directory(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    harness = _new_harness(tmp_path)
    target = tmp_path / "target"
    target.mkdir()
    (target / "app.py").write_text("VALUE = 1\n", encoding="utf-8")

    def fail_write(_path: Path, _value: Mapping[str, object]) -> None:
        raise WhiteboxAuditError("injected persistence failure", ExitCode.DATA_INTEGRITY_ERROR)

    monkeypatch.setattr(prepare_module, "atomic_write_json", fail_write)
    with pytest.raises(WhiteboxAuditError):
        PrepareController(harness, clock=lambda: FIXED_TIME).prepare(target)

    assert list((harness / "work").iterdir()) == []


def test_prepare_cli_json_returns_summary(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    harness = _new_harness(tmp_path)
    target = tmp_path / "target"
    shutil.copytree(FIXTURES / "benign", target)

    exit_code = run(
        ["prepare", "--target", str(target), "--format", "json"],
        harness_root=harness,
    )
    captured = capsys.readouterr()
    payload = json.loads(captured.out)

    assert exit_code == 0
    assert payload["schema_version"] == 1
    assert payload["run"]["status"] == "prepared"
    assert payload["target"]["read_only"] is True
    assert captured.err == ""


def test_prepare_cli_rejects_unknown_profile(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    harness = _new_harness(tmp_path)
    target = tmp_path / "target"
    target.mkdir()

    exit_code = run(
        ["prepare", "--target", str(target), "--profile", "target-supplied"],
        harness_root=harness,
    )
    captured = capsys.readouterr()

    assert exit_code == 2
    assert "unsupported profile" in captured.err
    assert captured.out == ""


def test_prepare_cli_uses_policy_and_integrity_exit_codes(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    harness = _new_harness(tmp_path)
    target = tmp_path / "target"
    target.mkdir()
    outside = tmp_path / "outside"
    outside.write_text("outside", encoding="utf-8")
    (target / "escape").symlink_to(outside)

    policy_exit = run(["prepare", "--target", str(target)], harness_root=harness)
    policy_output = capsys.readouterr()
    assert policy_exit == 4
    assert "symlink escapes" in policy_output.err

    (target / "escape").unlink()
    (harness / "work").rmdir()
    integrity_exit = run(["prepare", "--target", str(target)], harness_root=harness)
    integrity_output = capsys.readouterr()
    assert integrity_exit == 6
    assert "work directory does not exist" in integrity_output.err
