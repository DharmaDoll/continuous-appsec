"""Canonical immutable records for prepared audit targets and runs."""

from __future__ import annotations

from dataclasses import asdict, dataclass
from enum import StrEnum
from typing import Final

SCHEMA_VERSION: Final[int] = 1


class RunStatus(StrEnum):
    CREATED = "created"
    PREPARED = "prepared"
    RUNNING = "running"
    COMPLETED = "completed"
    DEGRADED = "degraded"
    FAILED = "failed"
    CANCELLED = "cancelled"


class ScannerStatus(StrEnum):
    SUCCEEDED = "succeeded"
    SKIPPED = "skipped"
    FAILED = "failed"
    TIMED_OUT = "timed-out"


@dataclass(frozen=True, slots=True)
class Inventory:
    schema_version: int
    languages: tuple[str, ...]
    manifests: tuple[str, ...]
    route_candidates: tuple[str, ...]
    symlinks: tuple[str, ...]
    excluded_directories: tuple[str, ...]
    file_count: int
    total_bytes: int

    def to_dict(self) -> dict[str, object]:
        return asdict(self)


@dataclass(frozen=True, slots=True)
class Target:
    schema_version: int
    target_id: str
    root: str
    git_commit: str | None
    git_tree_hash: str | None
    git_dirty: bool | None
    tree_hash: str
    languages: tuple[str, ...]
    manifests: tuple[str, ...]
    prepared_at: str
    read_only: bool = True

    def to_dict(self) -> dict[str, object]:
        return asdict(self)


@dataclass(frozen=True, slots=True)
class AuditRun:
    schema_version: int
    run_id: str
    target_id: str
    status: RunStatus
    profile: str
    created_at: str
    artifacts: tuple[str, ...]

    def to_dict(self) -> dict[str, object]:
        return asdict(self)


@dataclass(frozen=True, slots=True)
class PrepareResult:
    run: AuditRun
    target: Target
    inventory: Inventory
    run_directory: str

    def to_dict(self) -> dict[str, object]:
        return {
            "schema_version": SCHEMA_VERSION,
            "run": self.run.to_dict(),
            "target": self.target.to_dict(),
            "inventory": self.inventory.to_dict(),
            "run_directory": self.run_directory,
        }


@dataclass(frozen=True, slots=True)
class ScannerResourcePolicy:
    timeout_seconds: float
    network_allowed: bool
    network_enforcement: str
    target_read_only: bool
    target_write_enforcement: str
    max_output_bytes: int

    def to_dict(self) -> dict[str, object]:
        return asdict(self)


@dataclass(frozen=True, slots=True)
class ScannerRun:
    schema_version: int
    scanner_run_id: str
    audit_run_id: str
    target_id: str
    target_tree_hash: str
    scanner_name: str
    scanner_version: str | None
    scanner_executable: str | None
    scanner_executable_sha256: str | None
    status: ScannerStatus
    argv: tuple[str, ...]
    started_at: str
    finished_at: str
    returncode: int | None
    reason: str | None
    findings_count: int
    stdout_ref: str | None
    stderr_ref: str | None
    raw_result_ref: str
    evidence_ref: str
    resource_policy: ScannerResourcePolicy

    def to_dict(self) -> dict[str, object]:
        return asdict(self)


@dataclass(frozen=True, slots=True)
class EvidenceLocation:
    path: str | None
    path_safe: bool
    start_line: int | None
    end_line: int | None
    snippet_hash: str | None

    def to_dict(self) -> dict[str, object]:
        return asdict(self)


@dataclass(frozen=True, slots=True)
class Evidence:
    schema_version: int
    evidence_id: str
    kind: str
    tool_name: str
    tool_version: str | None
    rule_id: str
    claim: str
    severity: str
    location: EvidenceLocation
    fingerprint: str
    content_hash: str
    confidence: str
    target_id: str
    target_tree_hash: str
    provenance_run_id: str
    raw_ref: str

    def to_dict(self) -> dict[str, object]:
        return asdict(self)


@dataclass(frozen=True, slots=True)
class SarifNormalizationResult:
    evidence: tuple[Evidence, ...]
    warnings: tuple[str, ...]
    result_count: int
    duplicate_count: int
