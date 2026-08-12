"""Semgrep CE adapter with explicit execution and evidence boundaries."""

from __future__ import annotations

import os
import re
import secrets
import shutil
import subprocess
from collections.abc import Mapping, Sequence
from contextlib import suppress
from datetime import UTC, datetime
from pathlib import Path
from typing import Final

from whitebox_audit.doctor import (
    Health,
    Requirement,
    ToolCapability,
    executable_identity,
    minimal_env,
    redact_output,
)
from whitebox_audit.errors import ExitCode, WhiteboxAuditError
from whitebox_audit.evidence_store import write_evidence_jsonl
from whitebox_audit.models import (
    SCHEMA_VERSION,
    Evidence,
    ScannerResourcePolicy,
    ScannerRun,
    ScannerStatus,
    Target,
)
from whitebox_audit.prepare import atomic_write_json, format_timestamp
from whitebox_audit.sarif import load_sarif, normalize_sarif
from whitebox_audit.target import inspect_target

MAX_LOG_BYTES: Final[int] = 1024 * 1024
DEFAULT_TIMEOUT_SECONDS: Final[float] = 1800.0
FINDINGS_EXIT_CODE: Final[int] = 1


def validate_rulesets(rulesets: Sequence[Path], harness_root: Path) -> tuple[Path, ...]:
    if not rulesets:
        raise WhiteboxAuditError("at least one Semgrep ruleset is required", ExitCode.INVALID_INPUT)
    root = harness_root.resolve(strict=True)
    validated: list[Path] = []
    for ruleset in rulesets:
        try:
            resolved = ruleset.resolve(strict=True)
        except OSError as error:
            raise WhiteboxAuditError(
                "Semgrep ruleset does not exist", ExitCode.INVALID_INPUT
            ) from error
        if not resolved.is_file() or not resolved.is_relative_to(root):
            raise WhiteboxAuditError(
                "Semgrep rulesets must be reviewed files inside the harness",
                ExitCode.POLICY_REJECTED,
            )
        try:
            content = resolved.read_text(encoding="utf-8")
        except (OSError, UnicodeError) as error:
            raise WhiteboxAuditError(
                "Semgrep ruleset is not readable UTF-8", ExitCode.INVALID_INPUT
            ) from error
        if (
            resolved.suffix not in {".yaml", ".yml"}
            or re.search(r"(?m)^\s*rules\s*:", content[:4096]) is None
        ):
            raise WhiteboxAuditError(
                "Semgrep ruleset has an unsupported structure", ExitCode.INVALID_INPUT
            )
        validated.append(resolved)
    return tuple(validated)


def build_semgrep_argv(
    executable: str,
    target_root: Path,
    sarif_output: Path,
    rulesets: Sequence[Path],
    excludes: Sequence[str],
) -> tuple[str, ...]:
    argv = [
        executable,
        "scan",
        "--error",
        "--metrics",
        "off",
        "--disable-version-check",
        "--sarif",
        "--sarif-output",
        str(sarif_output),
    ]
    for ruleset in rulesets:
        argv.extend(("--config", str(ruleset)))
    for excluded in excludes:
        if not excluded or excluded.startswith("-") or "\x00" in excluded:
            raise WhiteboxAuditError("invalid Semgrep exclusion", ExitCode.INVALID_INPUT)
        argv.extend(("--exclude", excluded))
    argv.extend(("--", str(target_root)))
    return tuple(argv)


def _bounded_redacted_log(value: str) -> str:
    encoded = value.encode("utf-8", errors="replace")[:MAX_LOG_BYTES]
    return redact_output(encoded.decode("utf-8", errors="replace"), limit=MAX_LOG_BYTES)


def _write_text(path: Path, value: str) -> None:
    temporary = path.with_name(f".{path.name}.tmp-{secrets.token_hex(6)}")
    descriptor: int | None = None
    try:
        descriptor = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(descriptor, "w", encoding="utf-8") as stream:
            descriptor = None
            stream.write(value)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
    except OSError as error:
        raise WhiteboxAuditError(
            "could not persist scanner log", ExitCode.DATA_INTEGRITY_ERROR
        ) from error
    finally:
        if descriptor is not None:
            os.close(descriptor)
        with suppress(OSError):
            temporary.unlink(missing_ok=True)


def _resource_policy(timeout_seconds: float) -> ScannerResourcePolicy:
    return ScannerResourcePolicy(
        timeout_seconds=timeout_seconds,
        network_allowed=False,
        network_enforcement="semgrep-offline-flags-only",
        target_read_only=True,
        target_write_enforcement="post-run-tree-fingerprint",
        max_output_bytes=MAX_LOG_BYTES,
    )


class SemgrepScanner:
    def __init__(
        self,
        harness_root: Path,
        *,
        executable: str = "semgrep",
        rulesets: Sequence[Path] | None = None,
        excludes: Sequence[str] = ("node_modules", ".venv", "vendor", "dist", "build", ".next"),
        timeout_seconds: float = DEFAULT_TIMEOUT_SECONDS,
        environ: Mapping[str, str] | None = None,
    ) -> None:
        self._harness_root = harness_root.resolve(strict=True)
        self._executable_name = executable
        default_ruleset = self._harness_root / "rules" / "semgrep" / "baseline.yaml"
        self._rulesets = validate_rulesets(
            (default_ruleset,) if rulesets is None else rulesets, self._harness_root
        )
        self._excludes = tuple(excludes)
        self._timeout_seconds = timeout_seconds
        self._source_env = os.environ if environ is None else environ

    def _executable(self) -> str | None:
        return shutil.which(self._executable_name, path=self._source_env.get("PATH", os.defpath))

    def doctor(self) -> ToolCapability:
        executable = self._executable()
        if executable is None:
            return ToolCapability(
                "semgrep", Requirement.REQUIRED, Health.ERROR, False, detail="executable not found"
            )
        path, digest = executable_identity(executable)
        try:
            completed = subprocess.run(
                [executable, "--version"],
                check=False,
                shell=False,
                capture_output=True,
                text=True,
                timeout=10,
                env=minimal_env(self._source_env),
            )
        except (OSError, subprocess.TimeoutExpired) as error:
            return ToolCapability(
                "semgrep",
                Requirement.REQUIRED,
                Health.ERROR,
                True,
                detail=redact_output(str(error)),
                executable=path,
                executable_sha256=digest,
            )
        lines = (completed.stdout or completed.stderr).splitlines()
        version = lines[0].strip() if lines else "version unavailable"
        health = Health.OK if completed.returncode == 0 else Health.ERROR
        return ToolCapability(
            "semgrep",
            Requirement.REQUIRED,
            health,
            True,
            version=redact_output(version),
            executable=path,
            executable_sha256=digest,
        )

    def run(self, target: Target, audit_run_id: str, run_directory: Path) -> ScannerRun:
        scanner_dir = run_directory / "scanner-runs" / "semgrep"
        scanner_dir.mkdir(parents=True, exist_ok=False)
        started = datetime.now(UTC)
        scanner_run_id = f"SCAN-{secrets.token_hex(10)}"
        capability = self.doctor()
        if capability.health is not Health.OK or capability.executable is None:
            finished = datetime.now(UTC)
            skipped = ScannerRun(
                schema_version=SCHEMA_VERSION,
                scanner_run_id=scanner_run_id,
                audit_run_id=audit_run_id,
                target_id=target.target_id,
                target_tree_hash=target.tree_hash,
                scanner_name="semgrep",
                scanner_version=capability.version,
                scanner_executable=capability.executable,
                scanner_executable_sha256=capability.executable_sha256,
                status=ScannerStatus.SKIPPED,
                argv=(),
                started_at=format_timestamp(started),
                finished_at=format_timestamp(finished),
                returncode=None,
                reason=capability.detail or "Semgrep is unavailable",
                findings_count=0,
                stdout_ref=None,
                stderr_ref=None,
                raw_result_ref="scanner-runs/semgrep/result.sarif",
                evidence_ref="evidence/evidence.jsonl",
                resource_policy=_resource_policy(self._timeout_seconds),
            )
            atomic_write_json(scanner_dir / "run.json", skipped.to_dict())
            raise WhiteboxAuditError("Semgrep is unavailable", ExitCode.CAPABILITY_MISSING)
        sarif_path = scanner_dir / "result.sarif"
        stdout_path = scanner_dir / "stdout.log"
        stderr_path = scanner_dir / "stderr.log"
        argv = build_semgrep_argv(
            capability.executable, Path(target.root), sarif_path, self._rulesets, self._excludes
        )
        returncode: int | None = None
        reason: str | None = None
        stdout = ""
        stderr = ""
        status = ScannerStatus.FAILED
        env = minimal_env(self._source_env)
        env.pop("HOME", None)
        env.update({"SEMGREP_SEND_METRICS": "off", "SEMGREP_ENABLE_VERSION_CHECK": "0"})
        try:
            completed = subprocess.run(
                list(argv),
                check=False,
                shell=False,
                capture_output=True,
                text=True,
                timeout=self._timeout_seconds,
                env=env,
            )
            returncode = completed.returncode
            stdout = _bounded_redacted_log(completed.stdout)
            stderr = _bounded_redacted_log(completed.stderr)
            if returncode in {0, FINDINGS_EXIT_CODE} and sarif_path.is_file():
                sarif_path.chmod(0o600)
                status = ScannerStatus.SUCCEEDED
            else:
                reason = f"Semgrep execution failed with exit code {returncode}"
        except subprocess.TimeoutExpired as error:
            status = ScannerStatus.TIMED_OUT
            reason = f"Semgrep timed out after {self._timeout_seconds:g}s"
            stdout = _bounded_redacted_log(str(error.stdout or ""))
            stderr = _bounded_redacted_log(str(error.stderr or ""))
        except OSError as error:
            reason = f"Semgrep could not start: {redact_output(str(error))}"
        finished = datetime.now(UTC)
        _write_text(stdout_path, stdout)
        _write_text(stderr_path, stderr)
        try:
            after = inspect_target(Path(target.root))
        except WhiteboxAuditError as error:
            status = ScannerStatus.FAILED
            reason = f"target could not be safely revalidated: {error}"
        else:
            if after.tree_hash != target.tree_hash:
                status = ScannerStatus.FAILED
                reason = "target changed during scanner execution"
        record = ScannerRun(
            schema_version=SCHEMA_VERSION,
            scanner_run_id=scanner_run_id,
            audit_run_id=audit_run_id,
            target_id=target.target_id,
            target_tree_hash=target.tree_hash,
            scanner_name="semgrep",
            scanner_version=capability.version,
            scanner_executable=capability.executable,
            scanner_executable_sha256=capability.executable_sha256,
            status=status,
            argv=argv,
            started_at=format_timestamp(started),
            finished_at=format_timestamp(finished),
            returncode=returncode,
            reason=reason,
            findings_count=0,
            stdout_ref="scanner-runs/semgrep/stdout.log",
            stderr_ref="scanner-runs/semgrep/stderr.log",
            raw_result_ref="scanner-runs/semgrep/result.sarif",
            evidence_ref="evidence/evidence.jsonl",
            resource_policy=_resource_policy(self._timeout_seconds),
        )
        atomic_write_json(scanner_dir / "run.json", record.to_dict())
        return record

    def normalize(
        self, scanner_run: ScannerRun, target: Target, run_directory: Path
    ) -> tuple[Evidence, ...]:
        if scanner_run.status is not ScannerStatus.SUCCEEDED:
            return ()
        sarif_path = run_directory / scanner_run.raw_result_ref
        result = normalize_sarif(
            load_sarif(sarif_path),
            target_id=target.target_id,
            target_tree_hash=target.tree_hash,
            scanner_run_id=scanner_run.scanner_run_id,
            raw_ref=scanner_run.raw_result_ref,
            target_root=Path(target.root),
            fallback_tool_name="semgrep",
        )
        write_evidence_jsonl(
            run_directory / "evidence" / "evidence.jsonl",
            result.evidence,
            target_tree_hash=target.tree_hash,
        )
        atomic_write_json(
            run_directory / "scanner-runs" / "semgrep" / "normalization.json",
            {
                "schema_version": 1,
                "result_count": result.result_count,
                "evidence_count": len(result.evidence),
                "duplicate_count": result.duplicate_count,
                "warnings": list(result.warnings),
            },
        )
        return result.evidence
