"""Prepare validated targets and atomically persist canonical run metadata."""

from __future__ import annotations

import json
import os
import re
import secrets
import shutil
from collections.abc import Callable, Mapping
from contextlib import suppress
from dataclasses import asdict, dataclass
from datetime import UTC, datetime
from pathlib import Path, PurePosixPath
from typing import Final

from whitebox_audit.errors import ExitCode, WhiteboxAuditError
from whitebox_audit.models import (
    SCHEMA_VERSION,
    AuditRun,
    PrepareResult,
    RunStatus,
    Target,
)
from whitebox_audit.target import (
    InventoryLimits,
    collect_git_metadata,
    inspect_target,
    validate_target_root,
)

RUN_ID_PATTERN: Final[re.Pattern[str]] = re.compile(r"RUN-[0-9]{8}T[0-9]{6}Z-[0-9a-f]{12}\Z")
TARGET_ID_PATTERN: Final[re.Pattern[str]] = re.compile(r"TGT-[0-9a-f]{20}\Z")
SUPPORTED_PROFILES: Final[frozenset[str]] = frozenset({"default"})


@dataclass(frozen=True, slots=True)
class EffectivePrepareConfig:
    schema_version: int
    profile: str
    inventory_max_files: int
    inventory_max_total_bytes: int
    inventory_max_file_bytes: int
    inventory_timeout_seconds: float
    git_timeout_seconds: float
    target_read_only: bool = True
    network_allowed: bool = False
    target_execution_allowed: bool = False

    def to_dict(self) -> dict[str, object]:
        return asdict(self)


def utc_now() -> datetime:
    return datetime.now(UTC)


def format_timestamp(value: datetime) -> str:
    return value.astimezone(UTC).isoformat(timespec="seconds").replace("+00:00", "Z")


def create_run_id(now: datetime, *, random_hex: str | None = None) -> str:
    suffix = secrets.token_hex(6) if random_hex is None else random_hex.lower()
    if re.fullmatch(r"[0-9a-f]{12}", suffix) is None:
        raise WhiteboxAuditError("invalid run identifier entropy", ExitCode.DATA_INTEGRITY_ERROR)
    stamp = now.astimezone(UTC).strftime("%Y%m%dT%H%M%SZ")
    run_id = f"RUN-{stamp}-{suffix}"
    if RUN_ID_PATTERN.fullmatch(run_id) is None:
        raise WhiteboxAuditError(
            "generated run identifier is invalid", ExitCode.DATA_INTEGRITY_ERROR
        )
    return run_id


def validate_run_id(run_id: str) -> str:
    if RUN_ID_PATTERN.fullmatch(run_id) is None:
        raise WhiteboxAuditError("invalid run ID", ExitCode.INVALID_INPUT)
    return run_id


def validate_artifact_reference(reference: str) -> str:
    """Require a normalized run-relative artifact path."""

    path = PurePosixPath(reference)
    if (
        not reference
        or "\\" in reference
        or path.is_absolute()
        or any(part in {"", ".", ".."} for part in path.parts)
        or path.as_posix() != reference
    ):
        raise WhiteboxAuditError("invalid artifact reference", ExitCode.POLICY_REJECTED)
    return reference


def _project_name(pyproject: Path) -> str | None:
    try:
        import tomllib

        payload = tomllib.loads(pyproject.read_text(encoding="utf-8"))
        project = payload.get("project")
        if isinstance(project, dict):
            name = project.get("name")
            return name if isinstance(name, str) else None
    except (OSError, UnicodeError, tomllib.TOMLDecodeError):
        return None
    return None


def discover_harness_root(start: Path) -> Path:
    """Find the trusted harness root without consulting target-local instructions."""

    try:
        current = start.resolve(strict=True)
    except OSError as error:
        raise WhiteboxAuditError(
            "current directory is unavailable", ExitCode.INVALID_INPUT
        ) from error
    if current.is_file():
        current = current.parent
    for candidate in (current, *current.parents):
        if _project_name(candidate / "pyproject.toml") == "whitebox-ai-audit":
            return candidate
    raise WhiteboxAuditError(
        "run prepare from the whitebox-ai-audit harness repository",
        ExitCode.POLICY_REJECTED,
    )


def _validate_work_root(harness_root: Path, work_root: Path) -> Path:
    harness = harness_root.resolve(strict=True)
    try:
        resolved = work_root.resolve(strict=True)
    except OSError as error:
        raise WhiteboxAuditError(
            "work directory does not exist", ExitCode.DATA_INTEGRITY_ERROR
        ) from error
    if not resolved.is_dir() or not resolved.is_relative_to(harness):
        raise WhiteboxAuditError(
            "work directory must be inside the audit harness", ExitCode.POLICY_REJECTED
        )
    return resolved


def atomic_write_json(path: Path, value: Mapping[str, object]) -> None:
    temporary = path.with_name(f".{path.name}.tmp-{secrets.token_hex(6)}")
    data = json.dumps(value, indent=2, sort_keys=True, ensure_ascii=False) + "\n"
    descriptor: int | None = None
    try:
        descriptor = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(descriptor, "w", encoding="utf-8") as stream:
            descriptor = None
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
    except OSError as error:
        raise WhiteboxAuditError(
            f"could not persist {path.name} atomically", ExitCode.DATA_INTEGRITY_ERROR
        ) from error
    finally:
        if descriptor is not None:
            os.close(descriptor)
        with suppress(OSError):
            temporary.unlink(missing_ok=True)


def _persist_result(
    work_root: Path,
    result: PrepareResult,
    config: EffectivePrepareConfig,
) -> Path:
    run_id = validate_run_id(result.run.run_id)
    final_directory = work_root / run_id
    staging = work_root / f".{run_id}.staging-{secrets.token_hex(6)}"
    if final_directory.exists():
        raise WhiteboxAuditError("run directory already exists", ExitCode.DATA_INTEGRITY_ERROR)
    try:
        staging.mkdir(mode=0o700)
        atomic_write_json(staging / "target.json", result.target.to_dict())
        atomic_write_json(staging / "inventory.json", result.inventory.to_dict())
        atomic_write_json(staging / "config.json", config.to_dict())
        atomic_write_json(staging / "run.json", result.run.to_dict())
        os.replace(staging, final_directory)
    except WhiteboxAuditError:
        shutil.rmtree(staging, ignore_errors=True)
        raise
    except OSError as error:
        shutil.rmtree(staging, ignore_errors=True)
        raise WhiteboxAuditError(
            "could not finalize run metadata", ExitCode.DATA_INTEGRITY_ERROR
        ) from error
    return final_directory


class PrepareController:
    """Orchestrate Phase 0 without executing or writing to the target."""

    def __init__(
        self,
        harness_root: Path,
        *,
        work_root: Path | None = None,
        environ: Mapping[str, str] | None = None,
        clock: Callable[[], datetime] = utc_now,
        inventory_limits: InventoryLimits | None = None,
        git_timeout_seconds: float = 10.0,
    ) -> None:
        self._harness_root = harness_root.resolve(strict=True)
        requested_work_root = self._harness_root / "work" if work_root is None else work_root
        self._work_root = _validate_work_root(self._harness_root, requested_work_root)
        self._environ = environ
        self._clock = clock
        self._limits = InventoryLimits() if inventory_limits is None else inventory_limits
        self._git_timeout_seconds = git_timeout_seconds

    def prepare(self, target_path: Path, *, profile: str = "default") -> PrepareResult:
        if profile not in SUPPORTED_PROFILES:
            raise WhiteboxAuditError(f"unsupported profile: {profile}", ExitCode.INVALID_INPUT)
        target_root = validate_target_root(target_path, self._harness_root)
        before = inspect_target(target_root, limits=self._limits)
        git = collect_git_metadata(
            target_root,
            environ=self._environ,
            timeout_seconds=self._git_timeout_seconds,
        )
        after = inspect_target(target_root, limits=self._limits)
        if before.tree_hash != after.tree_hash:
            raise WhiteboxAuditError(
                "target changed while it was being prepared", ExitCode.DATA_INTEGRITY_ERROR
            )

        prepared_at = self._clock()
        timestamp = format_timestamp(prepared_at)
        target_id = f"TGT-{before.tree_hash[:20]}"
        if TARGET_ID_PATTERN.fullmatch(target_id) is None:
            raise WhiteboxAuditError("target ID generation failed", ExitCode.DATA_INTEGRITY_ERROR)
        run_id = create_run_id(prepared_at)
        target = Target(
            schema_version=SCHEMA_VERSION,
            target_id=target_id,
            root=str(target_root),
            git_commit=git.commit,
            git_tree_hash=git.tree_hash,
            git_dirty=git.dirty,
            tree_hash=before.tree_hash,
            languages=before.inventory.languages,
            manifests=before.inventory.manifests,
            prepared_at=timestamp,
        )
        artifacts = ("target.json", "inventory.json", "config.json", "run.json")
        for artifact in artifacts:
            validate_artifact_reference(artifact)
        run = AuditRun(
            schema_version=SCHEMA_VERSION,
            run_id=run_id,
            target_id=target_id,
            status=RunStatus.PREPARED,
            profile=profile,
            created_at=timestamp,
            artifacts=artifacts,
        )
        config = EffectivePrepareConfig(
            schema_version=SCHEMA_VERSION,
            profile=profile,
            inventory_max_files=self._limits.max_files,
            inventory_max_total_bytes=self._limits.max_total_bytes,
            inventory_max_file_bytes=self._limits.max_file_bytes,
            inventory_timeout_seconds=self._limits.timeout_seconds,
            git_timeout_seconds=self._git_timeout_seconds,
        )
        provisional = PrepareResult(
            run=run,
            target=target,
            inventory=before.inventory,
            run_directory=str(self._work_root / run_id),
        )
        final_directory = _persist_result(self._work_root, provisional, config)
        return PrepareResult(
            run=run,
            target=target,
            inventory=before.inventory,
            run_directory=str(final_directory),
        )
