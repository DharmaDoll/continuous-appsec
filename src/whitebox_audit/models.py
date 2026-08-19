"""Canonical immutable records for audit targets, evidence, and findings."""

from __future__ import annotations

import hashlib
import json
import re
from collections.abc import Mapping
from dataclasses import asdict, dataclass, replace
from enum import StrEnum
from pathlib import PurePosixPath
from typing import Final, Self

SCHEMA_VERSION: Final[int] = 1
_HASH_PATTERN: Final[re.Pattern[str]] = re.compile(r"[0-9a-f]{64}\Z")
_RECORD_ID_PATTERN: Final[re.Pattern[str]] = re.compile(r"(?:INV|HYP|EVD|VER|FND)-[0-9a-f]{20}\Z")
_TARGET_ID_PATTERN: Final[re.Pattern[str]] = re.compile(r"TGT-[0-9a-f]{20}\Z")
_IMAGE_DIGEST_PATTERN: Final[re.Pattern[str]] = re.compile(
    r"[A-Za-z0-9][A-Za-z0-9._/:+-]{0,500}@sha256:[0-9a-f]{64}\Z"
)


def stable_record_id(prefix: str, content: Mapping[str, object]) -> str:
    """Derive a stable identifier from normalized, host-independent content."""

    if prefix not in {"INV", "HYP", "EVD", "VER", "FND"}:
        raise ValueError("unsupported record ID prefix")
    encoded = json.dumps(
        content,
        allow_nan=False,
        ensure_ascii=False,
        separators=(",", ":"),
        sort_keys=True,
    ).encode()
    return f"{prefix}-{hashlib.sha256(encoded).hexdigest()[:20]}"


def validate_record_id(identifier: str, prefix: str | None = None) -> str:
    if _RECORD_ID_PATTERN.fullmatch(identifier) is None:
        raise ValueError("invalid canonical record ID")
    if prefix is not None and not identifier.startswith(f"{prefix}-"):
        raise ValueError(f"record ID must use {prefix}- prefix")
    return identifier


def _validate_schema_version(value: int) -> None:
    if value != SCHEMA_VERSION:
        raise ValueError("unsupported schema version")


def _validate_hash(value: str, label: str) -> None:
    if _HASH_PATTERN.fullmatch(value) is None:
        raise ValueError(f"{label} must be a lowercase SHA-256 value")


def _validate_nonempty(value: str, label: str, *, maximum: int = 10_000) -> None:
    if not value.strip() or len(value) > maximum or "\x00" in value:
        raise ValueError(f"{label} is empty or exceeds its limit")


def _json_object(value: Mapping[str, object]) -> dict[str, object]:
    """Return a detached JSON-compatible object or reject unsupported values."""

    encoded = json.dumps(value, allow_nan=False, ensure_ascii=False, sort_keys=True)
    decoded = json.loads(encoded)
    if not isinstance(decoded, dict):
        raise ValueError("expected a JSON object")
    return {str(key): item for key, item in decoded.items()}


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


class EvidenceKind(StrEnum):
    SOURCE = "source"
    STATIC_ANALYSIS = "static-analysis"
    RUNTIME = "runtime"
    CONFIG = "config"
    TEST = "test"


class EvidenceConfidence(StrEnum):
    OBSERVED_RUNTIME = "observed-runtime"
    DETERMINISTIC_STATIC = "deterministic-static"
    DIRECT_SOURCE_TRACE = "direct-source-trace"
    INFERRED = "inferred"
    OPERATOR_ASSERTED = "operator-asserted"


class InvariantDerivation(StrEnum):
    DECLARED = "declared"
    INFERRED = "inferred"


class InvariantOrigin(StrEnum):
    OPERATOR = "operator"
    PRODUCT_REQUIREMENT = "product-requirement"
    ORGANIZATION_POLICY = "organization-policy"
    FRAMEWORK_CONTRACT = "framework-contract"
    SOURCE_ANALYSIS = "source-analysis"


class Confidence(StrEnum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"


class FindingStatus(StrEnum):
    HYPOTHESIS = "hypothesis"
    NEEDS_VERIFICATION = "needs-verification"
    VERIFIED = "verified"
    HIGH_CONFIDENCE_STATIC = "high-confidence-static"
    REJECTED = "rejected"
    ACCEPTED_RISK = "accepted-risk"
    DUPLICATE = "duplicate"


class VerificationStatus(StrEnum):
    PROVED = "proved"
    NOT_PROVED = "not-proved"
    INCONCLUSIVE = "inconclusive"
    POLICY_REJECTED = "policy-rejected"
    ERROR = "error"


class RecordOrigin(StrEnum):
    OPERATOR = "operator"
    DISCOVERY_AGENT = "discovery-agent"
    VERIFIER = "verifier"
    REPORTER = "reporter"


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
    symbol: str | None = None

    def to_dict(self) -> dict[str, object]:
        return asdict(self)

    def __post_init__(self) -> None:
        if self.path_safe:
            if self.path is None:
                raise ValueError("safe location requires a relative path")
            path = PurePosixPath(self.path)
            if path.is_absolute() or ".." in path.parts or path.as_posix() != self.path:
                raise ValueError("location path must be normalized and relative")
        if self.start_line is not None and self.start_line < 1:
            raise ValueError("start line must be positive")
        if self.end_line is not None and (
            self.start_line is None or self.end_line < self.start_line
        ):
            raise ValueError("end line must not precede start line")
        if self.snippet_hash is not None:
            _validate_hash(self.snippet_hash, "snippet hash")


@dataclass(frozen=True, slots=True)
class EvidenceProvenance:
    source_type: str
    run_id: str | None
    raw_uri: str
    tool_name: str | None = None
    tool_version: str | None = None
    rule_id: str | None = None
    target_tree_hash: str | None = None
    content_sha256: str | None = None

    def __post_init__(self) -> None:
        _validate_nonempty(self.source_type, "provenance source type", maximum=100)
        _validate_nonempty(self.raw_uri, "provenance raw URI", maximum=2_000)
        if self.target_tree_hash is not None:
            _validate_hash(self.target_tree_hash, "provenance target tree hash")
        if self.content_sha256 is not None:
            _validate_hash(self.content_sha256, "provenance content hash")

    def to_dict(self) -> dict[str, object]:
        return asdict(self)


@dataclass(frozen=True, slots=True)
class Redaction:
    field: str
    kind: str

    def __post_init__(self) -> None:
        _validate_nonempty(self.field, "redaction field", maximum=200)
        _validate_nonempty(self.kind, "redaction kind", maximum=100)

    def to_dict(self) -> dict[str, object]:
        return asdict(self)


@dataclass(frozen=True, slots=True)
class Evidence:
    schema_version: int
    evidence_id: str
    kind: EvidenceKind
    claim: str
    location: EvidenceLocation | None
    artifact_ref: str
    fingerprint: str
    content_hash: str
    confidence: EvidenceConfidence
    target_id: str
    target_tree_hash: str
    provenance: EvidenceProvenance
    redactions: tuple[Redaction, ...] = ()
    severity: str | None = None

    def to_dict(self) -> dict[str, object]:
        return {
            "schema_version": self.schema_version,
            "evidence_id": self.evidence_id,
            "kind": self.kind,
            "claim": self.claim,
            "location": self.location.to_dict() if self.location is not None else None,
            "artifact_ref": self.artifact_ref,
            "fingerprint": self.fingerprint,
            "content_hash": self.content_hash,
            "confidence": self.confidence,
            "target_id": self.target_id,
            "target_tree_hash": self.target_tree_hash,
            "provenance": self.provenance.to_dict(),
            "redactions": [item.to_dict() for item in self.redactions],
            "severity": self.severity,
        }

    def __post_init__(self) -> None:
        _validate_schema_version(self.schema_version)
        validate_record_id(self.evidence_id, "EVD")
        _validate_nonempty(self.claim, "evidence claim", maximum=4_000)
        _validate_nonempty(self.artifact_ref, "artifact reference", maximum=2_000)
        _validate_hash(self.fingerprint, "evidence fingerprint")
        _validate_hash(self.content_hash, "evidence content hash")
        _validate_hash(self.target_tree_hash, "target tree hash")

    @property
    def raw_ref(self) -> str:
        return self.artifact_ref

    @property
    def tool_name(self) -> str:
        return self.provenance.tool_name or self.provenance.source_type

    @property
    def tool_version(self) -> str | None:
        return self.provenance.tool_version

    @property
    def rule_id(self) -> str:
        return self.provenance.rule_id or ""

    @property
    def provenance_run_id(self) -> str:
        return self.provenance.run_id or ""


@dataclass(frozen=True, slots=True)
class InvariantSource:
    derivation: InvariantDerivation
    origin: InvariantOrigin

    def __post_init__(self) -> None:
        if (
            self.derivation is InvariantDerivation.DECLARED
            and self.origin is InvariantOrigin.SOURCE_ANALYSIS
        ):
            raise ValueError("source analysis cannot declare a product requirement")
        if (
            self.derivation is InvariantDerivation.INFERRED
            and self.origin is not InvariantOrigin.SOURCE_ANALYSIS
        ):
            raise ValueError("inferred invariants must identify source analysis as their origin")

    def to_dict(self) -> dict[str, object]:
        return {"derivation": self.derivation, "origin": self.origin}


@dataclass(frozen=True, slots=True)
class SecurityInvariant:
    schema_version: int
    invariant_id: str
    target_id: str
    target_tree_hash: str
    title: str
    scope: tuple[str, ...]
    statement: str
    source: InvariantSource
    source_evidence: tuple[str, ...]
    confidence: Confidence
    counterexample: Mapping[str, object]

    def __post_init__(self) -> None:
        _validate_schema_version(self.schema_version)
        validate_record_id(self.invariant_id, "INV")
        if _TARGET_ID_PATTERN.fullmatch(self.target_id) is None:
            raise ValueError("invalid target ID")
        _validate_hash(self.target_tree_hash, "target tree hash")
        _validate_nonempty(self.title, "invariant title", maximum=300)
        _validate_nonempty(self.statement, "invariant statement")
        if not self.scope or any(not item.strip() or len(item) > 200 for item in self.scope):
            raise ValueError("invariant scope must contain bounded non-empty values")
        if not self.source_evidence:
            raise ValueError("invariant source evidence is required")
        for identifier in self.source_evidence:
            validate_record_id(identifier, "EVD")
        if not self.counterexample:
            raise ValueError("invariant counterexample is required")
        _json_object(self.counterexample)
        expected = stable_record_id("INV", self.stable_content())
        if self.invariant_id != expected:
            raise ValueError("invariant ID does not match normalized content")

    def stable_content(self) -> dict[str, object]:
        return {
            "target_tree_hash": self.target_tree_hash,
            "title": self.title,
            "scope": list(self.scope),
            "statement": self.statement,
            "source": self.source.to_dict(),
            "source_evidence": list(self.source_evidence),
            "confidence": self.confidence,
            "counterexample": _json_object(self.counterexample),
        }

    def to_dict(self) -> dict[str, object]:
        return {
            "schema_version": self.schema_version,
            "invariant_id": self.invariant_id,
            "target_id": self.target_id,
            "target_tree_hash": self.target_tree_hash,
            **self.stable_content(),
        }

    @classmethod
    def create(
        cls,
        *,
        target_id: str,
        target_tree_hash: str,
        title: str,
        scope: tuple[str, ...],
        statement: str,
        source: InvariantSource,
        source_evidence: tuple[str, ...],
        confidence: Confidence,
        counterexample: Mapping[str, object],
    ) -> Self:
        content = {
            "target_tree_hash": target_tree_hash,
            "title": title,
            "scope": list(scope),
            "statement": statement,
            "source": source.to_dict(),
            "source_evidence": list(source_evidence),
            "confidence": confidence,
            "counterexample": _json_object(counterexample),
        }
        return cls(
            SCHEMA_VERSION,
            stable_record_id("INV", content),
            target_id,
            target_tree_hash,
            title,
            scope,
            statement,
            source,
            source_evidence,
            confidence,
            _json_object(counterexample),
        )


@dataclass(frozen=True, slots=True)
class Hypothesis:
    schema_version: int
    hypothesis_id: str
    target_id: str
    target_tree_hash: str
    invariant_id: str
    title: str
    attacker_preconditions: tuple[str, ...]
    entry_point: EvidenceLocation
    suspected_path: tuple[EvidenceLocation, ...]
    files_symbols_to_inspect: tuple[EvidenceLocation, ...]
    supporting_evidence: tuple[str, ...]
    counter_evidence: tuple[str, ...]
    falsification_conditions: tuple[str, ...]
    verification_plan: Mapping[str, object]
    status: FindingStatus = FindingStatus.HYPOTHESIS

    def __post_init__(self) -> None:
        _validate_schema_version(self.schema_version)
        validate_record_id(self.hypothesis_id, "HYP")
        validate_record_id(self.invariant_id, "INV")
        if _TARGET_ID_PATTERN.fullmatch(self.target_id) is None:
            raise ValueError("invalid target ID")
        _validate_hash(self.target_tree_hash, "target tree hash")
        _validate_nonempty(self.title, "hypothesis title", maximum=300)
        if not self.attacker_preconditions or not self.suspected_path:
            raise ValueError("attacker preconditions and suspected path are required")
        if not self.files_symbols_to_inspect:
            raise ValueError("files and symbols to inspect are required")
        if not self.supporting_evidence:
            raise ValueError("supporting evidence is required")
        if not self.falsification_conditions or not self.verification_plan:
            raise ValueError("falsification conditions and verification plan are required")
        for identifier in (*self.supporting_evidence, *self.counter_evidence):
            validate_record_id(identifier, "EVD")
        if self.status not in {
            FindingStatus.HYPOTHESIS,
            FindingStatus.NEEDS_VERIFICATION,
            FindingStatus.REJECTED,
        }:
            raise ValueError("hypothesis has an invalid status")
        _json_object(self.verification_plan)
        if self.hypothesis_id != stable_record_id("HYP", self.stable_content()):
            raise ValueError("hypothesis ID does not match normalized content")

    def stable_content(self) -> dict[str, object]:
        return {
            "target_tree_hash": self.target_tree_hash,
            "invariant_id": self.invariant_id,
            "title": self.title,
            "attacker_preconditions": list(self.attacker_preconditions),
            "entry_point": self.entry_point.to_dict(),
            "suspected_path": [item.to_dict() for item in self.suspected_path],
            "files_symbols_to_inspect": [item.to_dict() for item in self.files_symbols_to_inspect],
            "supporting_evidence": list(self.supporting_evidence),
            "counter_evidence": list(self.counter_evidence),
            "falsification_conditions": list(self.falsification_conditions),
            "verification_plan": _json_object(self.verification_plan),
        }

    def to_dict(self) -> dict[str, object]:
        return {
            "schema_version": self.schema_version,
            "hypothesis_id": self.hypothesis_id,
            "target_id": self.target_id,
            **self.stable_content(),
            "status": self.status,
        }

    @classmethod
    def create(
        cls,
        *,
        target_id: str,
        target_tree_hash: str,
        invariant_id: str,
        title: str,
        attacker_preconditions: tuple[str, ...],
        entry_point: EvidenceLocation,
        suspected_path: tuple[EvidenceLocation, ...],
        files_symbols_to_inspect: tuple[EvidenceLocation, ...],
        supporting_evidence: tuple[str, ...],
        counter_evidence: tuple[str, ...],
        falsification_conditions: tuple[str, ...],
        verification_plan: Mapping[str, object],
        status: FindingStatus = FindingStatus.HYPOTHESIS,
    ) -> Self:
        content = {
            "target_tree_hash": target_tree_hash,
            "invariant_id": invariant_id,
            "title": title,
            "attacker_preconditions": list(attacker_preconditions),
            "entry_point": entry_point.to_dict(),
            "suspected_path": [item.to_dict() for item in suspected_path],
            "files_symbols_to_inspect": [item.to_dict() for item in files_symbols_to_inspect],
            "supporting_evidence": list(supporting_evidence),
            "counter_evidence": list(counter_evidence),
            "falsification_conditions": list(falsification_conditions),
            "verification_plan": _json_object(verification_plan),
        }
        return cls(
            SCHEMA_VERSION,
            stable_record_id("HYP", content),
            target_id,
            target_tree_hash,
            invariant_id,
            title,
            attacker_preconditions,
            entry_point,
            suspected_path,
            files_symbols_to_inspect,
            supporting_evidence,
            counter_evidence,
            falsification_conditions,
            _json_object(verification_plan),
            status,
        )


@dataclass(frozen=True, slots=True)
class VerificationCase:
    schema_version: int
    verification_id: str
    target_id: str
    target_tree_hash: str
    hypothesis_id: str
    policy_fingerprint: str
    adapter_fingerprint: str
    runtime_profile: str
    runtime_image: str
    setup: Mapping[str, object]
    actor: Mapping[str, object]
    action: Mapping[str, object]
    oracle: Mapping[str, object]
    limits: Mapping[str, object]

    def __post_init__(self) -> None:
        _validate_schema_version(self.schema_version)
        validate_record_id(self.verification_id, "VER")
        validate_record_id(self.hypothesis_id, "HYP")
        if _TARGET_ID_PATTERN.fullmatch(self.target_id) is None:
            raise ValueError("invalid target ID")
        _validate_hash(self.target_tree_hash, "target tree hash")
        _validate_hash(self.policy_fingerprint, "verifier policy fingerprint")
        _validate_hash(self.adapter_fingerprint, "runtime adapter fingerprint")
        _validate_nonempty(self.runtime_profile, "runtime profile", maximum=200)
        if _IMAGE_DIGEST_PATTERN.fullmatch(self.runtime_image) is None:
            raise ValueError("runtime image must use an immutable sha256 digest")
        for value in (self.setup, self.actor, self.action, self.oracle, self.limits):
            if not value:
                raise ValueError("verification case objects must not be empty")
            _json_object(value)
        if self.verification_id != stable_record_id("VER", self.stable_content()):
            raise ValueError("verification ID does not match normalized content")

    def stable_content(self) -> dict[str, object]:
        return {
            "target_tree_hash": self.target_tree_hash,
            "hypothesis_id": self.hypothesis_id,
            "policy_fingerprint": self.policy_fingerprint,
            "adapter_fingerprint": self.adapter_fingerprint,
            "runtime_profile": self.runtime_profile,
            "runtime_image": self.runtime_image,
            "setup": _json_object(self.setup),
            "actor": _json_object(self.actor),
            "action": _json_object(self.action),
            "oracle": _json_object(self.oracle),
            "limits": _json_object(self.limits),
        }

    def to_dict(self) -> dict[str, object]:
        return {
            "schema_version": self.schema_version,
            "verification_id": self.verification_id,
            "target_id": self.target_id,
            **self.stable_content(),
        }

    @classmethod
    def create(
        cls,
        *,
        target_id: str,
        target_tree_hash: str,
        hypothesis_id: str,
        policy_fingerprint: str,
        adapter_fingerprint: str,
        runtime_profile: str,
        runtime_image: str,
        setup: Mapping[str, object],
        actor: Mapping[str, object],
        action: Mapping[str, object],
        oracle: Mapping[str, object],
        limits: Mapping[str, object],
    ) -> Self:
        content = {
            "target_tree_hash": target_tree_hash,
            "hypothesis_id": hypothesis_id,
            "policy_fingerprint": policy_fingerprint,
            "adapter_fingerprint": adapter_fingerprint,
            "runtime_profile": runtime_profile,
            "runtime_image": runtime_image,
            "setup": _json_object(setup),
            "actor": _json_object(actor),
            "action": _json_object(action),
            "oracle": _json_object(oracle),
            "limits": _json_object(limits),
        }
        return cls(
            SCHEMA_VERSION,
            stable_record_id("VER", content),
            target_id,
            target_tree_hash,
            hypothesis_id,
            policy_fingerprint,
            adapter_fingerprint,
            runtime_profile,
            runtime_image,
            _json_object(setup),
            _json_object(actor),
            _json_object(action),
            _json_object(oracle),
            _json_object(limits),
        )


@dataclass(frozen=True, slots=True)
class VerificationResult:
    schema_version: int
    verification_id: str
    verifier_run_id: str
    target_tree_hash: str
    status: VerificationStatus
    observations: tuple[Mapping[str, object], ...]
    oracle: Mapping[str, object]
    started_at: str
    finished_at: str
    verifier_version: str
    verifier_image: str
    policy_fingerprint: str

    def __post_init__(self) -> None:
        _validate_schema_version(self.schema_version)
        validate_record_id(self.verification_id, "VER")
        _validate_hash(self.target_tree_hash, "target tree hash")
        _validate_hash(self.policy_fingerprint, "policy fingerprint")
        _validate_nonempty(self.verifier_run_id, "verifier run ID", maximum=200)
        _validate_nonempty(self.verifier_version, "verifier version", maximum=200)
        if _IMAGE_DIGEST_PATTERN.fullmatch(self.verifier_image) is None:
            raise ValueError("verifier image must use an immutable sha256 digest")
        for observation in self.observations:
            _json_object(observation)
        if not self.oracle:
            raise ValueError("verification oracle comparison is required")
        _json_object(self.oracle)

    def to_dict(self) -> dict[str, object]:
        return {
            "schema_version": self.schema_version,
            "verification_id": self.verification_id,
            "verifier_run_id": self.verifier_run_id,
            "target_tree_hash": self.target_tree_hash,
            "status": self.status,
            "observations": [_json_object(item) for item in self.observations],
            "oracle": _json_object(self.oracle),
            "started_at": self.started_at,
            "finished_at": self.finished_at,
            "verifier_version": self.verifier_version,
            "verifier_image": self.verifier_image,
            "policy_fingerprint": self.policy_fingerprint,
        }


@dataclass(frozen=True, slots=True)
class Finding:
    schema_version: int
    finding_id: str
    target_tree_hash: str
    hypothesis_id: str
    invariant_id: str
    status: FindingStatus
    title: str
    severity: Mapping[str, object]
    cwe: tuple[str, ...]
    evidence: tuple[str, ...]
    verification_result_id: str | None
    attacker_preconditions: tuple[str, ...]
    impact: Mapping[str, object]
    falsification_summary: Mapping[str, object]
    remediation: Mapping[str, object]
    regression: Mapping[str, object]
    record_origin: RecordOrigin

    def __post_init__(self) -> None:
        _validate_schema_version(self.schema_version)
        validate_record_id(self.finding_id, "FND")
        validate_record_id(self.hypothesis_id, "HYP")
        validate_record_id(self.invariant_id, "INV")
        _validate_hash(self.target_tree_hash, "target tree hash")
        _validate_nonempty(self.title, "finding title", maximum=300)
        for identifier in self.evidence:
            validate_record_id(identifier, "EVD")
        if self.status is FindingStatus.VERIFIED:
            if self.record_origin is not RecordOrigin.VERIFIER:
                raise ValueError("only verifier-origin construction may create verified findings")
            if self.verification_result_id is None:
                raise ValueError("verified finding requires a verification result")
        if self.verification_result_id is not None:
            validate_record_id(self.verification_result_id, "VER")
        for value in (
            self.severity,
            self.impact,
            self.falsification_summary,
            self.remediation,
            self.regression,
        ):
            _json_object(value)
        expected = stable_record_id(
            "FND",
            {
                "target_tree_hash": self.target_tree_hash,
                "hypothesis_id": self.hypothesis_id,
                "invariant_id": self.invariant_id,
                "title": self.title,
            },
        )
        if self.finding_id != expected:
            raise ValueError("finding ID does not match normalized content")

    def to_dict(self) -> dict[str, object]:
        return {
            "schema_version": self.schema_version,
            "finding_id": self.finding_id,
            "target_tree_hash": self.target_tree_hash,
            "hypothesis_id": self.hypothesis_id,
            "invariant_id": self.invariant_id,
            "status": self.status,
            "title": self.title,
            "severity": _json_object(self.severity),
            "cwe": list(self.cwe),
            "evidence": list(self.evidence),
            "verification_result_id": self.verification_result_id,
            "attacker_preconditions": list(self.attacker_preconditions),
            "impact": _json_object(self.impact),
            "falsification_summary": _json_object(self.falsification_summary),
            "remediation": _json_object(self.remediation),
            "regression": _json_object(self.regression),
            "record_origin": self.record_origin,
        }


_ALLOWED_FINDING_TRANSITIONS: Final[dict[FindingStatus, frozenset[FindingStatus]]] = {
    FindingStatus.HYPOTHESIS: frozenset({FindingStatus.REJECTED, FindingStatus.NEEDS_VERIFICATION}),
    FindingStatus.NEEDS_VERIFICATION: frozenset(
        {
            FindingStatus.VERIFIED,
            FindingStatus.HIGH_CONFIDENCE_STATIC,
            FindingStatus.REJECTED,
        }
    ),
    FindingStatus.VERIFIED: frozenset({FindingStatus.ACCEPTED_RISK, FindingStatus.DUPLICATE}),
    FindingStatus.HIGH_CONFIDENCE_STATIC: frozenset(
        {FindingStatus.ACCEPTED_RISK, FindingStatus.DUPLICATE}
    ),
    FindingStatus.REJECTED: frozenset(),
    FindingStatus.ACCEPTED_RISK: frozenset(),
    FindingStatus.DUPLICATE: frozenset(),
}


def transition_finding(
    finding: Finding,
    new_status: FindingStatus,
    *,
    verification_result: VerificationResult | None = None,
    complete_static_trace: bool = False,
) -> Finding:
    """Apply the canonical finding state machine with verifier/static gates."""

    if new_status not in _ALLOWED_FINDING_TRANSITIONS[finding.status]:
        raise ValueError("invalid finding state transition")
    if new_status is FindingStatus.VERIFIED:
        if (
            verification_result is None
            or verification_result.status is not VerificationStatus.PROVED
            or verification_result.target_tree_hash != finding.target_tree_hash
        ):
            raise ValueError("verified transition requires a matching proved verifier result")
        return replace(
            finding,
            status=new_status,
            verification_result_id=verification_result.verification_id,
            record_origin=RecordOrigin.VERIFIER,
        )
    if new_status is FindingStatus.HIGH_CONFIDENCE_STATIC and not complete_static_trace:
        raise ValueError("high-confidence-static requires a complete trace and falsification")
    return replace(finding, status=new_status)


@dataclass(frozen=True, slots=True)
class SarifNormalizationResult:
    evidence: tuple[Evidence, ...]
    warnings: tuple[str, ...]
    result_count: int
    duplicate_count: int
