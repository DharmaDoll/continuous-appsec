from __future__ import annotations

import os
import shutil
import subprocess
from pathlib import Path

import pytest

import whitebox_audit.target as target_module
from whitebox_audit.errors import ExitCode, WhiteboxAuditError
from whitebox_audit.target import (
    InventoryLimits,
    collect_git_metadata,
    inspect_target,
    resolve_under,
    validate_same_filesystem,
    validate_target_root,
)

FIXTURES = Path(__file__).parent / "fixtures" / "targets"


def _snapshot(root: Path) -> dict[str, tuple[int, int, int]]:
    return {
        path.relative_to(root).as_posix(): (
            path.lstat().st_mode,
            path.lstat().st_size,
            path.lstat().st_mtime_ns,
        )
        for path in root.rglob("*")
    }


def _run_git(root: Path, *args: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        ["git", "-C", str(root), *args],
        check=True,
        shell=False,
        capture_output=True,
        text=True,
        timeout=10,
        env={"PATH": os.environ.get("PATH", os.defpath), "HOME": str(root.parent)},
    )


def test_validate_target_rejects_harness_relationships(tmp_path: Path) -> None:
    harness = tmp_path / "harness"
    harness.mkdir()
    child = harness / "child"
    child.mkdir()
    parent = tmp_path

    for target in (harness, child, parent):
        with pytest.raises(WhiteboxAuditError) as raised:
            validate_target_root(target, harness)
        assert raised.value.exit_code is ExitCode.POLICY_REJECTED


def test_resolve_under_rejects_absolute_and_parent_escape(tmp_path: Path) -> None:
    root = tmp_path / "root"
    root.mkdir()
    inside = root / "inside.txt"
    inside.write_text("safe", encoding="utf-8")
    outside = tmp_path / "outside.txt"
    outside.write_text("outside", encoding="utf-8")

    assert resolve_under(root, Path("inside.txt")) == inside
    for candidate in (outside, Path("../outside.txt")):
        with pytest.raises(WhiteboxAuditError) as raised:
            resolve_under(root, candidate)
        assert raised.value.exit_code is ExitCode.POLICY_REJECTED


def test_inventory_is_stable_across_root_mtime_and_file_order(tmp_path: Path) -> None:
    first = tmp_path / "first"
    second = tmp_path / "second"
    first.mkdir()
    second.mkdir()
    (first / "b.ts").write_text("export const b = 2;\n", encoding="utf-8")
    (first / "a.py").write_text("A = 1\n", encoding="utf-8")
    (second / "a.py").write_text("A = 1\n", encoding="utf-8")
    (second / "b.ts").write_text("export const b = 2;\n", encoding="utf-8")
    os.utime(first / "a.py", (1, 1))
    os.utime(second / "a.py", (2, 2))

    first_result = inspect_target(first)
    second_result = inspect_target(second)

    assert first_result.tree_hash == second_result.tree_hash
    assert first_result.inventory.languages == ("python", "typescript")


def test_content_or_executable_change_changes_fingerprint(tmp_path: Path) -> None:
    target = tmp_path / "target"
    target.mkdir()
    source = target / "app.py"
    source.write_text("VALUE = 1\n", encoding="utf-8")
    initial = inspect_target(target).tree_hash

    source.write_text("VALUE = 2\n", encoding="utf-8")
    content_changed = inspect_target(target).tree_hash
    source.chmod(0o755)
    mode_changed = inspect_target(target).tree_hash

    assert initial != content_changed
    assert content_changed != mode_changed


def test_inventory_detects_manifest_route_and_excludes_vendor(tmp_path: Path) -> None:
    target = tmp_path / "target"
    shutil.copytree(FIXTURES / "benign", target)
    vendor = target / "node_modules" / "dependency"
    vendor.mkdir(parents=True)
    (vendor / "ignored.ts").write_text("throw new Error();\n", encoding="utf-8")

    result = inspect_target(target)

    assert result.inventory.languages == ("typescript",)
    assert result.inventory.manifests == ("package.json",)
    assert result.inventory.route_candidates == ("app/api/invoices/route.ts",)
    assert result.inventory.excluded_directories == ("node_modules",)
    assert result.inventory.file_count == 2


def test_inventory_supports_multiple_language_and_manifest_families(tmp_path: Path) -> None:
    target = tmp_path / "target"
    target.mkdir()
    files = {
        "app.py": "",
        "app.ts": "",
        "App.java": "",
        "main.go": "",
        "app.rb": "",
        "index.php": "",
        "App.cs": "",
        "requirements-dev.txt": "",
        "pom.xml": "",
        "build.gradle.kts": "",
        "go.mod": "",
        "Gemfile": "",
        "composer.json": "",
        "App.csproj": "",
    }
    for name, content in files.items():
        (target / name).write_text(content, encoding="utf-8")

    inventory = inspect_target(target).inventory

    assert inventory.languages == (
        "csharp",
        "go",
        "java",
        "kotlin",
        "php",
        "python",
        "ruby",
        "typescript",
    )
    assert inventory.manifests == tuple(
        sorted(
            {
                "App.csproj",
                "Gemfile",
                "build.gradle.kts",
                "composer.json",
                "go.mod",
                "pom.xml",
                "requirements-dev.txt",
            }
        )
    )


def test_external_and_broken_symlinks_are_rejected(tmp_path: Path) -> None:
    target = tmp_path / "target"
    target.mkdir()
    outside = tmp_path / "outside.txt"
    outside.write_text("outside", encoding="utf-8")
    (target / "escape").symlink_to(outside)

    with pytest.raises(WhiteboxAuditError) as external:
        inspect_target(target)
    assert external.value.exit_code is ExitCode.POLICY_REJECTED

    (target / "escape").unlink()
    (target / "broken").symlink_to(target / "missing")
    with pytest.raises(WhiteboxAuditError) as broken:
        inspect_target(target)
    assert broken.value.exit_code is ExitCode.POLICY_REJECTED


def test_internal_symlink_is_recorded_but_not_followed(tmp_path: Path) -> None:
    target = tmp_path / "target"
    target.mkdir()
    source = target / "source.ts"
    source.write_text("export const safe = true;\n", encoding="utf-8")
    (target / "alias.ts").symlink_to(source.name)

    result = inspect_target(target)

    assert result.inventory.symlinks == ("alias.ts",)
    assert result.inventory.file_count == 1


def test_absolute_internal_symlink_fingerprint_is_root_independent(tmp_path: Path) -> None:
    first = tmp_path / "first"
    second = tmp_path / "second"
    first.mkdir()
    second.mkdir()
    for root in (first, second):
        source = root / "source.ts"
        source.write_text("export const safe = true;\n", encoding="utf-8")
        (root / "alias.ts").symlink_to(source)

    assert inspect_target(first).tree_hash == inspect_target(second).tree_hash


def test_inventory_limits_fail_closed(tmp_path: Path) -> None:
    target = tmp_path / "target"
    target.mkdir()
    (target / "one.txt").write_text("1", encoding="utf-8")
    (target / "two.txt").write_text("2", encoding="utf-8")

    with pytest.raises(WhiteboxAuditError) as raised:
        inspect_target(target, limits=InventoryLimits(max_files=1))
    assert raised.value.exit_code is ExitCode.POLICY_REJECTED

    (target / "large.bin").write_bytes(b"large")
    with pytest.raises(WhiteboxAuditError) as oversized:
        inspect_target(target, limits=InventoryLimits(max_file_bytes=1))
    assert oversized.value.exit_code is ExitCode.POLICY_REJECTED


def test_inventory_timeout_fails_closed(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    target = tmp_path / "target"
    target.mkdir()
    (target / "one.txt").write_text("1", encoding="utf-8")
    moments = iter((0.0, 0.0, 2.0))
    monkeypatch.setattr(target_module, "monotonic_time", lambda: next(moments))

    with pytest.raises(WhiteboxAuditError) as raised:
        inspect_target(target, limits=InventoryLimits(timeout_seconds=1.0))

    assert raised.value.exit_code is ExitCode.POLICY_REJECTED


def test_mount_boundary_is_rejected() -> None:
    with pytest.raises(WhiteboxAuditError) as raised:
        validate_same_filesystem(10, 11, "mounted")
    assert raised.value.exit_code is ExitCode.POLICY_REJECTED


def test_git_metadata_records_commit_tree_and_dirty_state(tmp_path: Path) -> None:
    target = tmp_path / "target"
    target.mkdir()
    _run_git(target, "init", "-q")
    _run_git(target, "config", "user.name", "Fixture")
    _run_git(target, "config", "user.email", "fixture@example.invalid")
    source = target / "app.py"
    source.write_text("VALUE = 1\n", encoding="utf-8")
    _run_git(target, "add", "app.py")
    _run_git(target, "commit", "-qm", "fixture")

    clean = collect_git_metadata(
        target, environ={"PATH": os.environ["PATH"], "HOME": str(tmp_path)}
    )
    source.write_text("VALUE = 2\n", encoding="utf-8")
    dirty = collect_git_metadata(
        target, environ={"PATH": os.environ["PATH"], "HOME": str(tmp_path)}
    )

    assert clean.commit is not None
    assert clean.tree_hash is not None
    assert clean.dirty is False
    assert dirty.commit == clean.commit
    assert dirty.dirty is True


def test_external_git_worktree_pointer_is_rejected_without_following(tmp_path: Path) -> None:
    target = tmp_path / "target"
    target.mkdir()
    (target / ".git").write_text("gitdir: /sensitive/external/path\n", encoding="utf-8")

    with pytest.raises(WhiteboxAuditError) as raised:
        collect_git_metadata(target)

    assert raised.value.exit_code is ExitCode.POLICY_REJECTED


def test_git_config_external_include_is_rejected(tmp_path: Path) -> None:
    target = tmp_path / "target"
    target.mkdir()
    _run_git(target, "init", "-q")
    config = target / ".git" / "config"
    config.write_text(
        config.read_text(encoding="utf-8") + '\n[include]\npath = "/sensitive/config"\n',
        encoding="utf-8",
    )

    with pytest.raises(WhiteboxAuditError) as raised:
        collect_git_metadata(target)

    assert raised.value.exit_code is ExitCode.POLICY_REJECTED
