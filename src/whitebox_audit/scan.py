"""Scanner orchestration for prepared audit runs."""

from __future__ import annotations

import json
import os
import secrets
import shutil
from collections.abc import Mapping
from contextlib import suppress
from dataclasses import dataclass, replace
from datetime import UTC, datetime
from pathlib import Path

from whitebox_audit.errors import ExitCode, WhiteboxAuditError
from whitebox_audit.evidence_store import write_evidence_jsonl
from whitebox_audit.models import (
    SCHEMA_VERSION,
    AuditRun,
    Evidence,
    RunStatus,
    ScannerResourcePolicy,
    ScannerRun,
    ScannerStatus,
    Target,
)
from whitebox_audit.prepare import (
    PrepareController,
    atomic_write_json,
    format_timestamp,
    validate_run_id,
)
from whitebox_audit.sarif import load_sarif, normalize_sarif
from whitebox_audit.scanners.base import Scanner
from whitebox_audit.scanners.semgrep import SemgrepScanner
from whitebox_audit.target import inspect_target


@dataclass(frozen=True, slots=True)
class ScanResult:
    audit_run_id: str
    scanner_run: ScannerRun
    evidence: tuple[Evidence, ...]
    run_directory: str

    def to_dict(self) -> dict[str, object]:
        return {
            "schema_version": SCHEMA_VERSION,
            "audit_run_id": self.audit_run_id,
            "scanner_run": self.scanner_run.to_dict(),
            "evidence": [item.to_dict() for item in self.evidence],
            "run_directory": self.run_directory,
        }


def _load_json(path: Path) -> dict[str, object]:
    try:
        if path.is_symlink() or not path.is_file():
            raise WhiteboxAuditError("run artifact violates file policy", ExitCode.POLICY_REJECTED)
        value = json.loads(path.read_text(encoding="utf-8"))
    except WhiteboxAuditError:
        raise
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        raise WhiteboxAuditError(
            "run artifact is invalid JSON", ExitCode.DATA_INTEGRITY_ERROR
        ) from error
    if not isinstance(value, dict) or value.get("schema_version") != SCHEMA_VERSION:
        raise WhiteboxAuditError(
            "run artifact schema is unsupported", ExitCode.DATA_INTEGRITY_ERROR
        )
    return {str(key): item for key, item in value.items()}


def load_target(run_directory: Path) -> Target:
    value = _load_json(run_directory / "target.json")
    required = {
        "schema_version",
        "target_id",
        "root",
        "git_commit",
        "git_tree_hash",
        "git_dirty",
        "tree_hash",
        "languages",
        "manifests",
        "prepared_at",
        "read_only",
    }
    if set(value) != required or value.get("read_only") is not True:
        raise WhiteboxAuditError("target record fields are invalid", ExitCode.DATA_INTEGRITY_ERROR)
    try:
        languages_value = value["languages"]
        manifests_value = value["manifests"]
        if not isinstance(languages_value, list) or not isinstance(manifests_value, list):
            raise TypeError
        return Target(
            schema_version=SCHEMA_VERSION,
            target_id=str(value["target_id"]),
            root=str(value["root"]),
            git_commit=value["git_commit"] if isinstance(value["git_commit"], str) else None,
            git_tree_hash=value["git_tree_hash"]
            if isinstance(value["git_tree_hash"], str)
            else None,
            git_dirty=value["git_dirty"] if isinstance(value["git_dirty"], bool) else None,
            tree_hash=str(value["tree_hash"]),
            languages=tuple(str(item) for item in languages_value),
            manifests=tuple(str(item) for item in manifests_value),
            prepared_at=str(value["prepared_at"]),
            read_only=True,
        )
    except (KeyError, TypeError) as error:
        raise WhiteboxAuditError(
            "target record types are invalid", ExitCode.DATA_INTEGRITY_ERROR
        ) from error


def load_audit_run(run_directory: Path) -> AuditRun:
    value = _load_json(run_directory / "run.json")
    required = {
        "schema_version",
        "run_id",
        "target_id",
        "status",
        "profile",
        "created_at",
        "artifacts",
    }
    if set(value) != required:
        raise WhiteboxAuditError("run record fields are invalid", ExitCode.DATA_INTEGRITY_ERROR)
    try:
        artifacts_value = value["artifacts"]
        if not isinstance(artifacts_value, list):
            raise TypeError
        return AuditRun(
            schema_version=SCHEMA_VERSION,
            run_id=validate_run_id(str(value["run_id"])),
            target_id=str(value["target_id"]),
            status=RunStatus(str(value["status"])),
            profile=str(value["profile"]),
            created_at=str(value["created_at"]),
            artifacts=tuple(str(item) for item in artifacts_value),
        )
    except (KeyError, TypeError, ValueError) as error:
        raise WhiteboxAuditError("run record is invalid", ExitCode.DATA_INTEGRITY_ERROR) from error


def _run_directory(harness_root: Path, run_id: str) -> Path:
    identifier = validate_run_id(run_id)
    work = (harness_root / "work").resolve(strict=True)
    candidate = work / identifier
    try:
        resolved = candidate.resolve(strict=True)
    except OSError as error:
        raise WhiteboxAuditError("prepared run does not exist", ExitCode.INVALID_INPUT) from error
    if not resolved.is_dir() or not resolved.is_relative_to(work) or candidate.is_symlink():
        raise WhiteboxAuditError("prepared run path is unsafe", ExitCode.POLICY_REJECTED)
    return resolved


def _update_run(run_directory: Path, run: AuditRun, status: RunStatus) -> None:
    candidates = (
        "scanner-runs/semgrep/run.json",
        "scanner-runs/semgrep/result.sarif",
        "scanner-runs/semgrep/stdout.log",
        "scanner-runs/semgrep/stderr.log",
        "scanner-runs/semgrep/normalization.json",
        "evidence/evidence.jsonl",
    )
    new_artifacts = tuple(
        reference for reference in candidates if (run_directory / reference).is_file()
    )
    artifacts = tuple(dict.fromkeys((*run.artifacts, *new_artifacts)))
    atomic_write_json(
        run_directory / "run.json", replace(run, status=status, artifacts=artifacts).to_dict()
    )


def _add_run_artifacts(run_directory: Path, run: AuditRun, references: tuple[str, ...]) -> None:
    artifacts = tuple(dict.fromkeys((*run.artifacts, *references)))
    atomic_write_json(run_directory / "run.json", replace(run, artifacts=artifacts).to_dict())


def _atomic_copy(source: Path, destination: Path) -> None:
    temporary = destination.with_name(f".{destination.name}.tmp-{secrets.token_hex(6)}")
    descriptor: int | None = None
    try:
        descriptor = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with source.open("rb") as input_stream, os.fdopen(descriptor, "wb") as output_stream:
            descriptor = None
            shutil.copyfileobj(input_stream, output_stream)
            output_stream.flush()
            os.fsync(output_stream.fileno())
        os.replace(temporary, destination)
    except OSError as error:
        raise WhiteboxAuditError(
            "could not persist SARIF atomically", ExitCode.DATA_INTEGRITY_ERROR
        ) from error
    finally:
        if descriptor is not None:
            os.close(descriptor)
        with suppress(OSError):
            temporary.unlink(missing_ok=True)


class ScanController:
    def __init__(
        self,
        harness_root: Path,
        *,
        scanner: Scanner | None = None,
        environ: Mapping[str, str] | None = None,
    ) -> None:
        self._harness_root = harness_root.resolve(strict=True)
        self._scanner = (
            SemgrepScanner(self._harness_root, environ=environ) if scanner is None else scanner
        )

    def scan(self, *, target_path: Path | None = None, run_id: str | None = None) -> ScanResult:
        if (target_path is None) == (run_id is None):
            raise WhiteboxAuditError(
                "specify exactly one of target or run ID", ExitCode.INVALID_INPUT
            )
        if target_path is not None:
            prepared = PrepareController(self._harness_root).prepare(target_path)
            run_directory = Path(prepared.run_directory)
            run = prepared.run
            target = prepared.target
        else:
            assert run_id is not None
            run_directory = _run_directory(self._harness_root, run_id)
            run = load_audit_run(run_directory)
            target = load_target(run_directory)
            if run.status is not RunStatus.PREPARED:
                raise WhiteboxAuditError("run is not in prepared state", ExitCode.POLICY_REJECTED)
            if inspect_target(Path(target.root)).tree_hash != target.tree_hash:
                raise WhiteboxAuditError(
                    "prepared target has changed", ExitCode.DATA_INTEGRITY_ERROR
                )

        try:
            scanner_run = self._scanner.run(target, run.run_id, run_directory)
            if scanner_run.status is not ScannerStatus.SUCCEEDED:
                _update_run(run_directory, run, RunStatus.FAILED)
                raise WhiteboxAuditError(
                    scanner_run.reason or "scanner execution failed", ExitCode.EXECUTION_FAILED
                )
            evidence = self._scanner.normalize(scanner_run, target, run_directory)
            scanner_run = replace(scanner_run, findings_count=len(evidence))
            atomic_write_json(
                run_directory / "scanner-runs" / "semgrep" / "run.json",
                scanner_run.to_dict(),
            )
        except WhiteboxAuditError as error:
            if error.exit_code is ExitCode.CAPABILITY_MISSING:
                _update_run(run_directory, run, RunStatus.DEGRADED)
            elif error.exit_code is ExitCode.DATA_INTEGRITY_ERROR:
                _update_run(run_directory, run, RunStatus.FAILED)
            raise
        _update_run(run_directory, run, RunStatus.COMPLETED)
        return ScanResult(run.run_id, scanner_run, evidence, str(run_directory))


def ingest_sarif(
    harness_root: Path, *, run_id: str, tool_name: str, input_path: Path
) -> tuple[Evidence, ...]:
    if (
        not tool_name
        or len(tool_name) > 100
        or any(
            char not in "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789._-"
            for char in tool_name
        )
    ):
        raise WhiteboxAuditError("invalid tool name", ExitCode.INVALID_INPUT)
    run_directory = _run_directory(harness_root, run_id)
    run = load_audit_run(run_directory)
    target = load_target(run_directory)
    try:
        source = input_path.resolve(strict=True)
    except OSError as error:
        raise WhiteboxAuditError("SARIF input does not exist", ExitCode.INVALID_INPUT) from error
    if input_path.is_symlink() or not source.is_file():
        raise WhiteboxAuditError("SARIF input path is unsafe", ExitCode.POLICY_REJECTED)
    load_sarif(source)
    ingest_dir = run_directory / "scanner-runs" / f"ingest-{tool_name}"
    try:
        ingest_dir.mkdir(parents=True, exist_ok=False)
    except FileExistsError as error:
        raise WhiteboxAuditError(
            "SARIF producer was already ingested for this run", ExitCode.POLICY_REJECTED
        ) from error
    except OSError as error:
        raise WhiteboxAuditError(
            "could not create SARIF ingest directory", ExitCode.DATA_INTEGRITY_ERROR
        ) from error
    raw = ingest_dir / "result.sarif"
    _atomic_copy(source, raw)
    scanner_run_id = f"SCAN-{secrets.token_hex(10)}"
    timestamp = format_timestamp(datetime.now(UTC))
    result = normalize_sarif(
        load_sarif(raw),
        target_id=target.target_id,
        target_tree_hash=target.tree_hash,
        scanner_run_id=scanner_run_id,
        raw_ref=f"scanner-runs/ingest-{tool_name}/result.sarif",
        target_root=Path(target.root),
        fallback_tool_name=tool_name,
    )
    write_evidence_jsonl(
        run_directory / "evidence" / "evidence.jsonl",
        result.evidence,
        target_tree_hash=target.tree_hash,
    )
    scanner_run = ScannerRun(
        schema_version=SCHEMA_VERSION,
        scanner_run_id=scanner_run_id,
        audit_run_id=run.run_id,
        target_id=target.target_id,
        target_tree_hash=target.tree_hash,
        scanner_name=tool_name,
        scanner_version=None,
        scanner_executable=None,
        scanner_executable_sha256=None,
        status=ScannerStatus.SUCCEEDED,
        argv=(),
        started_at=timestamp,
        finished_at=timestamp,
        returncode=None,
        reason="operator-supplied SARIF; scanner was not executed by the harness",
        findings_count=len(result.evidence),
        stdout_ref=None,
        stderr_ref=None,
        raw_result_ref=f"scanner-runs/ingest-{tool_name}/result.sarif",
        evidence_ref="evidence/evidence.jsonl",
        resource_policy=ScannerResourcePolicy(
            timeout_seconds=0,
            network_allowed=False,
            network_enforcement="not-applicable-no-execution",
            target_read_only=True,
            target_write_enforcement="not-applicable-no-execution",
            max_output_bytes=0,
        ),
    )
    atomic_write_json(ingest_dir / "run.json", scanner_run.to_dict())
    atomic_write_json(
        ingest_dir / "normalization.json",
        {
            "schema_version": SCHEMA_VERSION,
            "result_count": result.result_count,
            "evidence_count": len(result.evidence),
            "duplicate_count": result.duplicate_count,
            "warnings": list(result.warnings),
        },
    )
    _add_run_artifacts(
        run_directory,
        run,
        (
            f"scanner-runs/ingest-{tool_name}/run.json",
            f"scanner-runs/ingest-{tool_name}/result.sarif",
            f"scanner-runs/ingest-{tool_name}/normalization.json",
            "evidence/evidence.jsonl",
        ),
    )
    return result.evidence
