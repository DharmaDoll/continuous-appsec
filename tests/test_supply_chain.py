from __future__ import annotations

import json
from pathlib import Path

import pytest

from whitebox_audit.cli import run
from whitebox_audit.errors import ExitCode, WhiteboxAuditError
from whitebox_audit.supply_chain import SupplyChainStatus, inspect_supply_chain


def _write_project(
    root: Path,
    *,
    requirement: str = "example==1.2.3",
    source: str = 'registry = "https://pypi.org/simple"',
    artifact_hash: str = "sha256:" + ("a" * 64),
) -> None:
    artifact_url = "https://files.pythonhosted.org/packages/example.tar.gz"
    sdist_line = f'sdist = {{ url = "{artifact_url}", hash = "{artifact_hash}" }}'
    (root / "pyproject.toml").write_text(
        f"""[build-system]
requires = ["hatchling==1.27.0"]
build-backend = "hatchling.build"

[project]
name = "whitebox-ai-audit"
version = "0.1.0"
dependencies = []

[dependency-groups]
dev = ["{requirement}"]

""",
        encoding="utf-8",
    )
    (root / "uv.toml").write_text('exclude-newer = "72 hours"\n', encoding="utf-8")
    (root / "uv.lock").write_text(
        f"""version = 1
revision = 3
requires-python = ">=3.12"
[options]
exclude-newer = "0001-01-01T00:00:00Z"
exclude-newer-span = "PT72H"

[[package]]
name = "example"
version = "1.2.3"
source = {{ {source} }}
{sdist_line}

[[package]]
name = "whitebox-ai-audit"
version = "0.1.0"
source = {{ editable = "." }}
""",
        encoding="utf-8",
    )


def test_valid_locked_project_passes_native_policy(tmp_path: Path) -> None:
    _write_project(tmp_path)

    report = inspect_supply_chain(tmp_path, check_freshness=False)

    assert report.ok
    assert report.package_count == 2
    assert report.lock_sha256 is not None
    assert all(check.status is SupplyChainStatus.PASS for check in report.checks)


def test_direct_url_dependency_is_rejected(tmp_path: Path) -> None:
    _write_project(tmp_path, requirement="example @ https://attacker.invalid/pkg.whl")

    report = inspect_supply_chain(tmp_path, check_freshness=False)

    check = next(item for item in report.checks if item.check_id == "SC-DECLARED-DEPS")
    assert check.status is SupplyChainStatus.FAIL
    assert "direct references are forbidden" in check.detail


def test_unpinned_dependency_is_rejected(tmp_path: Path) -> None:
    _write_project(tmp_path, requirement="example>=1.2")

    report = inspect_supply_chain(tmp_path, check_freshness=False)

    check = next(item for item in report.checks if item.check_id == "SC-DECLARED-DEPS")
    assert check.status is SupplyChainStatus.FAIL
    assert "exact == pins" in check.detail


def test_git_lock_source_is_rejected(tmp_path: Path) -> None:
    _write_project(tmp_path, source='git = "https://attacker.invalid/repo"')

    report = inspect_supply_chain(tmp_path, check_freshness=False)

    check = next(item for item in report.checks if item.check_id == "SC-LOCK-SOURCES")
    assert check.status is SupplyChainStatus.FAIL
    assert "unapproved source" in check.detail


def test_missing_artifact_hash_is_rejected(tmp_path: Path) -> None:
    _write_project(tmp_path, artifact_hash="md5:bad")

    report = inspect_supply_chain(tmp_path, check_freshness=False)

    check = next(item for item in report.checks if item.check_id == "SC-ARTIFACT-INTEGRITY")
    assert check.status is SupplyChainStatus.FAIL
    assert "SHA-256" in check.detail


def test_lock_symlink_outside_project_is_rejected(tmp_path: Path) -> None:
    project = tmp_path / "project"
    project.mkdir()
    _write_project(project)
    outside_lock = tmp_path / "outside.lock"
    (project / "uv.lock").replace(outside_lock)
    (project / "uv.lock").symlink_to(outside_lock)

    with pytest.raises(WhiteboxAuditError) as raised:
        inspect_supply_chain(project, check_freshness=False)

    assert raised.value.exit_code is ExitCode.POLICY_REJECTED


def test_supply_chain_cli_json_reports_policy_failure(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    _write_project(tmp_path, requirement="example>=1.2")

    exit_code = run(
        [
            "supply-chain",
            "check",
            "--project-root",
            str(tmp_path),
            "--uv",
            "missing-uv",
            "--format",
            "json",
        ]
    )
    captured = capsys.readouterr()
    payload = json.loads(captured.out)

    assert exit_code == 4
    assert payload["ok"] is False
    assert payload["exit_code"] == 4
