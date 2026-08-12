from __future__ import annotations

import json
import os
from pathlib import Path

import pytest

from whitebox_audit.cli import run
from whitebox_audit.doctor import (
    Doctor,
    Health,
    Requirement,
    ToolCapability,
    minimal_env,
    parse_version,
    redact_output,
)


def _write_executable(directory: Path, name: str, body: str) -> None:
    path = directory / name
    path.write_text(f"#!/bin/sh\nset -eu\n{body}\n", encoding="utf-8")
    path.chmod(0o755)


def _fake_toolchain(tmp_path: Path, *, include_codeql: bool = False) -> dict[str, str]:
    bin_dir = tmp_path / "bin"
    home_dir = tmp_path / "home"
    bin_dir.mkdir()
    home_dir.mkdir()

    versions = {
        "git": "git version 2.47.2",
        "curl": "curl 8.14.1",
        "jq": "jq-1.7",
        "rg": "ripgrep 15.2.0",
        "make": "GNU Make 4.4.1",
        "uv": "uv 0.11.21",
        "semgrep": "1.130.0",
    }
    for name, version in versions.items():
        _write_executable(bin_dir, name, f"printf '%s\\n' '{version}'")
    _write_executable(
        bin_dir,
        "git",
        "printf '%s %s\\n' 'git version 2.47.2' \"${TOP_SECRET_TOKEN-unset}\"",
    )

    _write_executable(bin_dir, "docker", "printf '%s\\n' '26.1.4'")
    plugin_json = (
        '{"installed":[{"name":"codeguard-security",'
        '"marketplaceName":"project-codeguard","version":"1.0.0",'
        '"installed":true,"enabled":true}],"available":[]}'
    )
    _write_executable(
        bin_dir,
        "codex",
        f"""if [ "${{1:-}}" = "plugin" ]; then
    printf '%s\\n' '{plugin_json}'
else
    printf '%s\\n' 'codex-cli 0.147.0'
fi""",
    )
    if include_codeql:
        _write_executable(
            bin_dir, "codeql", "printf '%s\\n' 'CodeQL command-line toolchain 2.20.0'"
        )

    return {
        "PATH": str(bin_dir),
        "HOME": str(home_dir),
        "LANG": "C.UTF-8",
        "TOP_SECRET_TOKEN": "must-not-be-inherited",
    }


@pytest.mark.parametrize(
    ("raw", "expected"),
    [
        ("codex-cli 0.147.0", (0, 147, 0)),
        ("Python 3.13.5", (3, 13, 5)),
        ("tool 2.7", (2, 7, 0)),
        ("no version", None),
    ],
)
def test_parse_version(raw: str, expected: tuple[int, int, int] | None) -> None:
    assert parse_version(raw) == expected


def test_minimal_env_uses_allowlist() -> None:
    result = minimal_env(
        {
            "PATH": "/safe/bin",
            "HOME": "/safe/home",
            "LANG": "C.UTF-8",
            "AWS_SECRET_ACCESS_KEY": "secret",
            "GITHUB_TOKEN": "secret",
        }
    )

    assert result == {"PATH": "/safe/bin", "HOME": "/safe/home", "LANG": "C.UTF-8"}


def test_redact_output_bounds_and_redacts() -> None:
    value = "Authorization: Bearer abc token=def password=ghi " + ("x" * 400)
    result = redact_output(value)

    assert "abc" not in result
    assert "def" not in result
    assert "ghi" not in result
    assert "[REDACTED]" in result
    assert len(result) == 300


def test_required_error_makes_report_not_ready() -> None:
    report = Doctor(environ={"PATH": os.devnull}).run()

    assert not report.ok
    assert any(
        capability.requirement is Requirement.REQUIRED and capability.health is Health.ERROR
        for capability in report.capabilities
    )


def test_fake_toolchain_succeeds_with_optional_codeql_missing(tmp_path: Path) -> None:
    report = Doctor(environ=_fake_toolchain(tmp_path)).run()

    assert report.ok
    assert "must-not-be-inherited" not in repr(report)
    codeql = next(item for item in report.capabilities if item.name == "codeql")
    assert codeql.health is Health.WARNING
    assert not codeql.available
    git = next(item for item in report.capabilities if item.name == "git")
    assert git.executable == str((tmp_path / "bin" / "git").resolve())
    assert git.executable_sha256 is not None
    assert len(git.executable_sha256) == 64


def test_codeql_without_entitlement_is_warning(tmp_path: Path) -> None:
    report = Doctor(environ=_fake_toolchain(tmp_path, include_codeql=True)).run()

    assert report.ok
    codeql = next(item for item in report.capabilities if item.name == "codeql")
    assert codeql.health is Health.WARNING
    assert codeql.available
    assert codeql.detail == "entitlement acknowledgement is not configured"


def test_doctor_json_output(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    exit_code = run(
        ["doctor", "--format", "json"],
        environ=_fake_toolchain(tmp_path),
    )
    captured = capsys.readouterr()
    payload = json.loads(captured.out)

    assert exit_code == 0
    assert payload["schema_version"] == 1
    assert payload["ok"] is True
    assert captured.err == ""


def test_capability_serialization_uses_string_enums() -> None:
    capability = ToolCapability(
        name="example",
        requirement=Requirement.OPTIONAL,
        health=Health.WARNING,
        available=False,
    )

    assert capability.to_dict()["requirement"] == "optional"
    assert capability.to_dict()["health"] == "warning"


def test_doctor_does_not_modify_checked_directories(tmp_path: Path) -> None:
    environment = _fake_toolchain(tmp_path)
    before = {
        path.relative_to(tmp_path): (
            path.stat().st_mode,
            path.stat().st_size,
            path.stat().st_mtime_ns,
        )
        for path in tmp_path.rglob("*")
    }

    Doctor(environ=environment).run()

    after = {
        path.relative_to(tmp_path): (
            path.stat().st_mode,
            path.stat().st_size,
            path.stat().st_mtime_ns,
        )
        for path in tmp_path.rglob("*")
    }
    assert after == before


def test_version_check_timeout_is_visible(tmp_path: Path) -> None:
    environment = _fake_toolchain(tmp_path)
    _write_executable(tmp_path / "bin", "semgrep", "while :; do :; done")

    report = Doctor(environ=environment, timeout_seconds=0.05).run()

    semgrep = next(item for item in report.capabilities if item.name == "semgrep")
    assert semgrep.health is Health.ERROR
    assert semgrep.detail == "version check timed out after 0.05s"
