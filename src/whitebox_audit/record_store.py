"""Strict manual-record parsing and immutable run-relative persistence."""

from __future__ import annotations

import hashlib
import json
import math
import os
import secrets
from collections.abc import Callable, Mapping, Sequence
from contextlib import suppress
from pathlib import Path
from typing import Final, cast

import yaml  # type: ignore[import-untyped]

from whitebox_audit.errors import ExitCode, WhiteboxAuditError
from whitebox_audit.evidence_store import write_evidence_jsonl
from whitebox_audit.models import (
    SCHEMA_VERSION,
    Confidence,
    Evidence,
    EvidenceConfidence,
    EvidenceKind,
    EvidenceLocation,
    EvidenceProvenance,
    FindingStatus,
    Hypothesis,
    InvariantDerivation,
    InvariantOrigin,
    InvariantSource,
    Redaction,
    SecurityInvariant,
)
from whitebox_audit.scan import (
    add_run_artifacts,
    load_audit_run,
    load_target,
    resolve_run_directory,
)

MAX_INPUT_BYTES: Final[int] = 1024 * 1024
MAX_JSONL_BYTES: Final[int] = 32 * 1024 * 1024
MAX_DOCUMENT_NODES: Final[int] = 10_000
MAX_DOCUMENT_DEPTH: Final[int] = 24


class _StrictSafeLoader(yaml.SafeLoader):  # type: ignore[misc]
    pass


def _construct_unique_mapping(
    loader: _StrictSafeLoader, node: yaml.nodes.MappingNode, deep: bool = False
) -> dict[object, object]:
    loader.flatten_mapping(node)
    pairs = loader.construct_pairs(node, deep=deep)
    result: dict[object, object] = {}
    for key, value in pairs:
        if key in result:
            raise yaml.constructor.ConstructorError(
                "while constructing a mapping",
                getattr(node, "start_mark", None),
                f"duplicate key: {key!r}",
                getattr(node, "start_mark", None),
            )
        result[key] = value
    return result


_StrictSafeLoader.add_constructor(
    yaml.resolver.BaseResolver.DEFAULT_MAPPING_TAG,
    _construct_unique_mapping,
)


def _reject_duplicate_json(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f"duplicate key: {key}")
        result[key] = value
    return result


def _reject_json_constant(value: str) -> object:
    raise ValueError(f"invalid JSON constant: {value}")


def _validate_document_shape(value: object, *, depth: int = 0, seen: set[int] | None = None) -> int:
    if depth > MAX_DOCUMENT_DEPTH:
        raise ValueError("input document exceeds maximum nesting depth")
    if value is None or isinstance(value, str | int | bool):
        return 1
    if isinstance(value, float):
        if not math.isfinite(value):
            raise ValueError("input document contains a non-finite number")
        return 1
    visited = set() if seen is None else seen
    identity = id(value)
    if identity in visited:
        raise ValueError("input document contains a recursive alias")
    visited.add(identity)
    try:
        if isinstance(value, list):
            count = 1 + sum(
                _validate_document_shape(item, depth=depth + 1, seen=visited) for item in value
            )
        elif isinstance(value, dict):
            if any(not isinstance(key, str) for key in value):
                raise ValueError("all input object keys must be strings")
            count = 1 + sum(
                _validate_document_shape(item, depth=depth + 1, seen=visited)
                for item in value.values()
            )
        else:
            raise ValueError("input document contains an unsupported scalar type")
    finally:
        visited.remove(identity)
    if count > MAX_DOCUMENT_NODES:
        raise ValueError("input document exceeds maximum node count")
    return count


def load_record_document(path: Path) -> tuple[dict[str, object], bytes, str]:
    """Load bounded JSON/YAML without object construction or duplicate keys."""

    try:
        metadata = path.stat(follow_symlinks=False)
        resolved = path.resolve(strict=True)
    except OSError as error:
        raise WhiteboxAuditError("record input does not exist", ExitCode.INVALID_INPUT) from error
    if path.is_symlink() or not resolved.is_file() or metadata.st_size > MAX_INPUT_BYTES:
        raise WhiteboxAuditError("record input violates file policy", ExitCode.POLICY_REJECTED)
    suffix = resolved.suffix.lower()
    if suffix not in {".json", ".yaml", ".yml"}:
        raise WhiteboxAuditError("record input must be JSON or YAML", ExitCode.INVALID_INPUT)
    try:
        raw = resolved.read_bytes()
        text = raw.decode("utf-8")
        if suffix == ".json":
            value = json.loads(
                text,
                object_pairs_hook=_reject_duplicate_json,
                parse_constant=_reject_json_constant,
            )
        else:
            value = yaml.load(text, Loader=_StrictSafeLoader)
        _validate_document_shape(value)
    except WhiteboxAuditError:
        raise
    except (OSError, UnicodeError, json.JSONDecodeError, yaml.YAMLError, ValueError) as error:
        raise WhiteboxAuditError(
            "record input is not valid strict JSON/YAML", ExitCode.INVALID_INPUT
        ) from error
    if not isinstance(value, dict):
        raise WhiteboxAuditError("record input must be an object", ExitCode.INVALID_INPUT)
    return {str(key): item for key, item in value.items()}, raw, suffix


def _object(value: object, label: str) -> dict[str, object]:
    if not isinstance(value, dict) or any(not isinstance(key, str) for key in value):
        raise ValueError(f"{label} must be an object")
    return {str(key): item for key, item in value.items()}


def _strict_keys(
    value: Mapping[str, object],
    *,
    required: frozenset[str],
    optional: frozenset[str] = frozenset(),
) -> None:
    keys = set(value)
    if not required.issubset(keys) or not keys.issubset(required | optional):
        missing = sorted(required - keys)
        unknown = sorted(keys - required - optional)
        detail = f"missing={missing}, unknown={unknown}"
        raise ValueError(f"record fields are invalid ({detail})")


def _string(value: object, label: str) -> str:
    if not isinstance(value, str):
        raise ValueError(f"{label} must be a string")
    return value


def _strings(value: object, label: str, *, allow_empty: bool = False) -> tuple[str, ...]:
    if not isinstance(value, list) or any(not isinstance(item, str) for item in value):
        raise ValueError(f"{label} must be a string array")
    result = tuple(cast(str, item) for item in value)
    if not allow_empty and not result:
        raise ValueError(f"{label} must not be empty")
    return result


def _schema(value: object) -> int:
    if value != SCHEMA_VERSION:
        raise ValueError("unsupported schema version")
    return SCHEMA_VERSION


def _location_input(value: object, label: str) -> EvidenceLocation:
    item = _object(value, label)
    _strict_keys(
        item,
        required=frozenset({"path"}),
        optional=frozenset({"symbol", "start_line", "end_line", "content_hash"}),
    )
    path = _string(item["path"], f"{label}.path")
    symbol = item.get("symbol")
    start_line = item.get("start_line")
    end_line = item.get("end_line")
    content_hash = item.get("content_hash")
    if symbol is not None and not isinstance(symbol, str):
        raise ValueError(f"{label}.symbol must be a string or null")
    if start_line is not None and not isinstance(start_line, int):
        raise ValueError(f"{label}.start_line must be an integer or null")
    if end_line is not None and not isinstance(end_line, int):
        raise ValueError(f"{label}.end_line must be an integer or null")
    if content_hash is not None and not isinstance(content_hash, str):
        raise ValueError(f"{label}.content_hash must be a string or null")
    return EvidenceLocation(path, True, start_line, end_line, content_hash, symbol)


def _location_record(value: object, label: str) -> EvidenceLocation | None:
    if value is None:
        return None
    item = _object(value, label)
    _strict_keys(
        item,
        required=frozenset(
            {"path", "path_safe", "start_line", "end_line", "snippet_hash", "symbol"}
        ),
    )
    path = item["path"]
    if path is not None and not isinstance(path, str):
        raise ValueError(f"{label}.path must be a string or null")
    if not isinstance(item["path_safe"], bool):
        raise ValueError(f"{label}.path_safe must be boolean")
    start_line = item["start_line"]
    end_line = item["end_line"]
    snippet_hash = item["snippet_hash"]
    symbol = item["symbol"]
    if start_line is not None and not isinstance(start_line, int):
        raise ValueError(f"{label}.start_line is invalid")
    if end_line is not None and not isinstance(end_line, int):
        raise ValueError(f"{label}.end_line is invalid")
    if snippet_hash is not None and not isinstance(snippet_hash, str):
        raise ValueError(f"{label}.snippet_hash is invalid")
    if symbol is not None and not isinstance(symbol, str):
        raise ValueError(f"{label}.symbol is invalid")
    return EvidenceLocation(
        path,
        item["path_safe"],
        start_line,
        end_line,
        snippet_hash,
        symbol,
    )


def _evidence_from_record(value: Mapping[str, object]) -> Evidence:
    legacy_fields = frozenset(
        {
            "schema_version",
            "evidence_id",
            "kind",
            "tool_name",
            "tool_version",
            "rule_id",
            "claim",
            "severity",
            "location",
            "fingerprint",
            "content_hash",
            "confidence",
            "target_id",
            "target_tree_hash",
            "provenance_run_id",
            "raw_ref",
        }
    )
    if set(value) == legacy_fields:
        location_value = _object(value["location"], "location")
        _strict_keys(
            location_value,
            required=frozenset({"path", "path_safe", "start_line", "end_line", "snippet_hash"}),
        )
        location_value["symbol"] = None
        tool_version = value["tool_version"]
        if tool_version is not None and not isinstance(tool_version, str):
            raise ValueError("legacy tool_version must be a string or null")
        return Evidence(
            schema_version=_schema(value["schema_version"]),
            evidence_id=_string(value["evidence_id"], "evidence_id"),
            kind=EvidenceKind(_string(value["kind"], "kind")),
            claim=_string(value["claim"], "claim"),
            location=_location_record(location_value, "location"),
            artifact_ref=_string(value["raw_ref"], "raw_ref"),
            fingerprint=_string(value["fingerprint"], "fingerprint"),
            content_hash=_string(value["content_hash"], "content_hash"),
            confidence=EvidenceConfidence(_string(value["confidence"], "confidence")),
            target_id=_string(value["target_id"], "target_id"),
            target_tree_hash=_string(value["target_tree_hash"], "target_tree_hash"),
            provenance=EvidenceProvenance(
                source_type="static-analysis",
                run_id=_string(value["provenance_run_id"], "provenance_run_id"),
                raw_uri=_string(value["raw_ref"], "raw_ref"),
                tool_name=_string(value["tool_name"], "tool_name"),
                tool_version=tool_version,
                rule_id=_string(value["rule_id"], "rule_id"),
                target_tree_hash=_string(value["target_tree_hash"], "target_tree_hash"),
            ),
            severity=_string(value["severity"], "severity"),
        )
    _strict_keys(
        value,
        required=frozenset(
            {
                "schema_version",
                "evidence_id",
                "kind",
                "claim",
                "location",
                "artifact_ref",
                "fingerprint",
                "content_hash",
                "confidence",
                "target_id",
                "target_tree_hash",
                "provenance",
                "redactions",
                "severity",
            }
        ),
    )
    provenance = _object(value["provenance"], "provenance")
    _strict_keys(
        provenance,
        required=frozenset(
            {
                "source_type",
                "run_id",
                "raw_uri",
                "tool_name",
                "tool_version",
                "rule_id",
                "target_tree_hash",
                "content_sha256",
            }
        ),
    )
    redactions_value = value["redactions"]
    if not isinstance(redactions_value, list):
        raise ValueError("redactions must be an array")
    redactions: list[Redaction] = []
    for raw_redaction in redactions_value:
        redaction = _object(raw_redaction, "redaction")
        _strict_keys(redaction, required=frozenset({"field", "kind"}))
        redactions.append(
            Redaction(
                _string(redaction["field"], "redaction.field"),
                _string(redaction["kind"], "redaction.kind"),
            )
        )

    def optional_string(key: str) -> str | None:
        item = provenance[key]
        if item is not None and not isinstance(item, str):
            raise ValueError(f"provenance.{key} must be a string or null")
        return item

    severity = value["severity"]
    if severity is not None and not isinstance(severity, str):
        raise ValueError("severity must be a string or null")
    return Evidence(
        schema_version=_schema(value["schema_version"]),
        evidence_id=_string(value["evidence_id"], "evidence_id"),
        kind=EvidenceKind(_string(value["kind"], "kind")),
        claim=_string(value["claim"], "claim"),
        location=_location_record(value["location"], "location"),
        artifact_ref=_string(value["artifact_ref"], "artifact_ref"),
        fingerprint=_string(value["fingerprint"], "fingerprint"),
        content_hash=_string(value["content_hash"], "content_hash"),
        confidence=EvidenceConfidence(_string(value["confidence"], "confidence")),
        target_id=_string(value["target_id"], "target_id"),
        target_tree_hash=_string(value["target_tree_hash"], "target_tree_hash"),
        provenance=EvidenceProvenance(
            source_type=_string(provenance["source_type"], "provenance.source_type"),
            run_id=optional_string("run_id"),
            raw_uri=_string(provenance["raw_uri"], "provenance.raw_uri"),
            tool_name=optional_string("tool_name"),
            tool_version=optional_string("tool_version"),
            rule_id=optional_string("rule_id"),
            target_tree_hash=optional_string("target_tree_hash"),
            content_sha256=optional_string("content_sha256"),
        ),
        redactions=tuple(redactions),
        severity=severity,
    )


def _read_jsonl[T](
    path: Path,
    parser: Callable[[Mapping[str, object]], T],
) -> tuple[T, ...]:
    if not path.exists():
        return ()
    try:
        metadata = path.stat(follow_symlinks=False)
        if path.is_symlink() or not path.is_file() or metadata.st_size > MAX_JSONL_BYTES:
            raise WhiteboxAuditError("record JSONL violates file policy", ExitCode.POLICY_REJECTED)
        records: list[T] = []
        for line_number, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
            try:
                value = json.loads(
                    line,
                    object_pairs_hook=_reject_duplicate_json,
                    parse_constant=_reject_json_constant,
                )
                if not isinstance(value, dict):
                    raise ValueError("record must be an object")
                records.append(parser({str(key): item for key, item in value.items()}))
            except (json.JSONDecodeError, TypeError, ValueError) as error:
                raise WhiteboxAuditError(
                    f"{path.name} contains an invalid record at line {line_number}",
                    ExitCode.DATA_INTEGRITY_ERROR,
                ) from error
        return tuple(records)
    except WhiteboxAuditError:
        raise
    except (OSError, UnicodeError) as error:
        raise WhiteboxAuditError(
            f"could not read {path.name}", ExitCode.DATA_INTEGRITY_ERROR
        ) from error


def _fsync_directory(path: Path) -> None:
    descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def _atomic_write_records(path: Path, records: Sequence[Mapping[str, object]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(f".{path.name}.tmp-{secrets.token_hex(6)}")
    descriptor: int | None = None
    try:
        descriptor = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(descriptor, "w", encoding="utf-8") as stream:
            descriptor = None
            for record in records:
                stream.write(
                    json.dumps(
                        record,
                        allow_nan=False,
                        ensure_ascii=False,
                        sort_keys=True,
                    )
                    + "\n"
                )
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
        _fsync_directory(path.parent)
    except OSError as error:
        raise WhiteboxAuditError(
            f"could not persist {path.name} atomically", ExitCode.DATA_INTEGRITY_ERROR
        ) from error
    finally:
        if descriptor is not None:
            os.close(descriptor)
        with suppress(OSError):
            temporary.unlink(missing_ok=True)


def _persist_immutable[T](
    path: Path,
    records: Sequence[T],
    item: T,
    *,
    identifier: Callable[[T], str],
    serialize: Callable[[T], Mapping[str, object]],
) -> None:
    existing = {identifier(record): record for record in records}
    item_id = identifier(item)
    if item_id in existing:
        if dict(serialize(existing[item_id])) == dict(serialize(item)):
            return
        raise WhiteboxAuditError(
            "stable ID collision or record revision rejected", ExitCode.DATA_INTEGRITY_ERROR
        )
    _atomic_write_records(path, [serialize(record) for record in (*records, item)])


def _require_unique_identifiers(identifiers: Sequence[str], label: str) -> None:
    if len(set(identifiers)) != len(identifiers):
        raise WhiteboxAuditError(
            f"{label} contains duplicate stable IDs", ExitCode.DATA_INTEGRITY_ERROR
        )


def _parse_invariant(value: Mapping[str, object]) -> SecurityInvariant:
    _strict_keys(
        value,
        required=frozenset(
            {
                "schema_version",
                "invariant_id",
                "target_id",
                "target_tree_hash",
                "title",
                "scope",
                "statement",
                "source",
                "source_evidence",
                "confidence",
                "counterexample",
            }
        ),
    )
    source = _object(value["source"], "source")
    _strict_keys(source, required=frozenset({"derivation", "origin"}))
    return SecurityInvariant(
        schema_version=_schema(value["schema_version"]),
        invariant_id=_string(value["invariant_id"], "invariant_id"),
        target_id=_string(value["target_id"], "target_id"),
        target_tree_hash=_string(value["target_tree_hash"], "target_tree_hash"),
        title=_string(value["title"], "title"),
        scope=_strings(value["scope"], "scope"),
        statement=_string(value["statement"], "statement"),
        source=InvariantSource(
            InvariantDerivation(_string(source["derivation"], "source.derivation")),
            InvariantOrigin(_string(source["origin"], "source.origin")),
        ),
        source_evidence=_strings(value["source_evidence"], "source_evidence"),
        confidence=Confidence(_string(value["confidence"], "confidence")),
        counterexample=_object(value["counterexample"], "counterexample"),
    )


def _parse_hypothesis(value: Mapping[str, object]) -> Hypothesis:
    _strict_keys(
        value,
        required=frozenset(
            {
                "schema_version",
                "hypothesis_id",
                "target_id",
                "target_tree_hash",
                "invariant_id",
                "title",
                "attacker_preconditions",
                "entry_point",
                "suspected_path",
                "files_symbols_to_inspect",
                "supporting_evidence",
                "counter_evidence",
                "falsification_conditions",
                "verification_plan",
                "status",
            }
        ),
    )
    suspected_path_value = value["suspected_path"]
    inspect_value = value["files_symbols_to_inspect"]
    if not isinstance(suspected_path_value, list) or not isinstance(inspect_value, list):
        raise ValueError("hypothesis path fields must be arrays")
    return Hypothesis(
        schema_version=_schema(value["schema_version"]),
        hypothesis_id=_string(value["hypothesis_id"], "hypothesis_id"),
        target_id=_string(value["target_id"], "target_id"),
        target_tree_hash=_string(value["target_tree_hash"], "target_tree_hash"),
        invariant_id=_string(value["invariant_id"], "invariant_id"),
        title=_string(value["title"], "title"),
        attacker_preconditions=_strings(value["attacker_preconditions"], "attacker_preconditions"),
        entry_point=cast(EvidenceLocation, _location_record(value["entry_point"], "entry_point")),
        suspected_path=tuple(
            cast(EvidenceLocation, _location_record(item, "suspected_path"))
            for item in suspected_path_value
        ),
        files_symbols_to_inspect=tuple(
            cast(EvidenceLocation, _location_record(item, "files_symbols_to_inspect"))
            for item in inspect_value
        ),
        supporting_evidence=_strings(value["supporting_evidence"], "supporting_evidence"),
        counter_evidence=_strings(value["counter_evidence"], "counter_evidence", allow_empty=True),
        falsification_conditions=_strings(
            value["falsification_conditions"], "falsification_conditions"
        ),
        verification_plan=_object(value["verification_plan"], "verification_plan"),
        status=FindingStatus(_string(value["status"], "status")),
    )


class RunRecordStore:
    """Run-confined immutable repository for evidence, invariants, and hypotheses."""

    def __init__(self, harness_root: Path, run_id: str) -> None:
        self.run_directory = resolve_run_directory(harness_root, run_id)
        self.run_id = run_id
        self.target = load_target(self.run_directory)
        self.evidence_path = self.run_directory / "evidence" / "evidence.jsonl"
        self.invariant_path = self.run_directory / "invariants" / "invariants.jsonl"
        self.hypothesis_path = self.run_directory / "hypotheses" / "hypotheses.jsonl"

    def list_evidence(self, *, kind: EvidenceKind | None = None) -> tuple[Evidence, ...]:
        records = _read_jsonl(self.evidence_path, _evidence_from_record)
        for record in records:
            if (
                record.target_id != self.target.target_id
                or record.target_tree_hash != self.target.tree_hash
            ):
                raise WhiteboxAuditError(
                    "evidence target fingerprint does not match the run",
                    ExitCode.DATA_INTEGRITY_ERROR,
                )
        _require_unique_identifiers([record.evidence_id for record in records], "evidence JSONL")
        return tuple(record for record in records if kind is None or record.kind is kind)

    def get_evidence(self, evidence_id: str) -> Evidence:
        matches = [item for item in self.list_evidence() if item.evidence_id == evidence_id]
        if len(matches) != 1:
            raise WhiteboxAuditError("evidence ID was not found uniquely", ExitCode.INVALID_INPUT)
        return matches[0]

    def list_invariants(self) -> tuple[SecurityInvariant, ...]:
        records = _read_jsonl(self.invariant_path, _parse_invariant)
        for record in records:
            if (
                record.target_id != self.target.target_id
                or record.target_tree_hash != self.target.tree_hash
            ):
                raise WhiteboxAuditError(
                    "invariant target fingerprint does not match the run",
                    ExitCode.DATA_INTEGRITY_ERROR,
                )
        _require_unique_identifiers([record.invariant_id for record in records], "invariant JSONL")
        available_evidence = {item.evidence_id for item in self.list_evidence()}
        for record in records:
            if not set(record.source_evidence).issubset(available_evidence):
                raise WhiteboxAuditError(
                    "invariant references missing source evidence",
                    ExitCode.DATA_INTEGRITY_ERROR,
                )
        return records

    def get_invariant(self, invariant_id: str) -> SecurityInvariant:
        matches = [item for item in self.list_invariants() if item.invariant_id == invariant_id]
        if len(matches) != 1:
            raise WhiteboxAuditError("invariant ID was not found uniquely", ExitCode.INVALID_INPUT)
        return matches[0]

    def list_hypotheses(self) -> tuple[Hypothesis, ...]:
        records = _read_jsonl(self.hypothesis_path, _parse_hypothesis)
        for record in records:
            if (
                record.target_id != self.target.target_id
                or record.target_tree_hash != self.target.tree_hash
            ):
                raise WhiteboxAuditError(
                    "hypothesis target fingerprint does not match the run",
                    ExitCode.DATA_INTEGRITY_ERROR,
                )
        _require_unique_identifiers(
            [record.hypothesis_id for record in records], "hypothesis JSONL"
        )
        available_invariants = {item.invariant_id for item in self.list_invariants()}
        available_evidence = {item.evidence_id for item in self.list_evidence()}
        for record in records:
            if record.invariant_id not in available_invariants:
                raise WhiteboxAuditError(
                    "hypothesis references a missing invariant", ExitCode.DATA_INTEGRITY_ERROR
                )
            if not set((*record.supporting_evidence, *record.counter_evidence)).issubset(
                available_evidence
            ):
                raise WhiteboxAuditError(
                    "hypothesis references missing evidence", ExitCode.DATA_INTEGRITY_ERROR
                )
        return records

    def get_hypothesis(self, hypothesis_id: str) -> Hypothesis:
        matches = [item for item in self.list_hypotheses() if item.hypothesis_id == hypothesis_id]
        if len(matches) != 1:
            raise WhiteboxAuditError("hypothesis ID was not found uniquely", ExitCode.INVALID_INPUT)
        return matches[0]

    def add_invariant_document(
        self, document: Mapping[str, object], *, raw: bytes, suffix: str
    ) -> SecurityInvariant:
        _strict_keys(
            document,
            required=frozenset({"schema_version", "invariant", "source_evidence"}),
        )
        _schema(document["schema_version"])
        invariant_value = _object(document["invariant"], "invariant")
        _strict_keys(
            invariant_value,
            required=frozenset(
                {"title", "scope", "statement", "source", "confidence", "counterexample"}
            ),
            optional=frozenset({"invariant_id"}),
        )
        source = _object(invariant_value["source"], "invariant.source")
        _strict_keys(source, required=frozenset({"derivation", "origin"}))
        evidence_values = document["source_evidence"]
        if not isinstance(evidence_values, list) or not evidence_values:
            raise ValueError("source_evidence must be a non-empty array")

        document_hash = hashlib.sha256(raw).hexdigest()
        artifact_ref = f"evidence/operator-inputs/{document_hash}{suffix}"
        evidence: list[Evidence] = []
        for index, raw_item in enumerate(evidence_values):
            item = _object(raw_item, f"source_evidence[{index}]")
            _strict_keys(
                item,
                required=frozenset({"kind", "claim"}),
                optional=frozenset({"location", "redactions"}),
            )
            location = (
                _location_input(item["location"], f"source_evidence[{index}].location")
                if item.get("location") is not None
                else None
            )
            kind = EvidenceKind(_string(item["kind"], f"source_evidence[{index}].kind"))
            if kind not in {EvidenceKind.SOURCE, EvidenceKind.CONFIG, EvidenceKind.TEST}:
                raise ValueError("operator invariant evidence must be source, config, or test")
            claim = _string(item["claim"], f"source_evidence[{index}].claim")
            redactions_value = item.get("redactions", [])
            if not isinstance(redactions_value, list):
                raise ValueError("redactions must be an array")
            redactions: list[Redaction] = []
            for raw_redaction in redactions_value:
                redaction = _object(raw_redaction, "redaction")
                _strict_keys(redaction, required=frozenset({"field", "kind"}))
                redactions.append(
                    Redaction(
                        _string(redaction["field"], "redaction.field"),
                        _string(redaction["kind"], "redaction.kind"),
                    )
                )
            normalized = {
                "target_tree_hash": self.target.tree_hash,
                "kind": kind,
                "claim": claim,
                "location": location.to_dict() if location is not None else None,
                "document_hash": document_hash,
                "index": index,
            }
            fingerprint = hashlib.sha256(
                json.dumps(normalized, ensure_ascii=False, sort_keys=True).encode()
            ).hexdigest()
            evidence.append(
                Evidence(
                    schema_version=SCHEMA_VERSION,
                    evidence_id=f"EVD-{fingerprint[:20]}",
                    kind=kind,
                    claim=claim,
                    location=location,
                    artifact_ref=artifact_ref,
                    fingerprint=fingerprint,
                    content_hash=document_hash,
                    confidence=EvidenceConfidence.OPERATOR_ASSERTED,
                    target_id=self.target.target_id,
                    target_tree_hash=self.target.tree_hash,
                    provenance=EvidenceProvenance(
                        source_type="operator-input",
                        run_id=self.run_id,
                        raw_uri=artifact_ref,
                        target_tree_hash=self.target.tree_hash,
                        content_sha256=document_hash,
                    ),
                    redactions=tuple(redactions),
                )
            )

        invariant = SecurityInvariant.create(
            target_id=self.target.target_id,
            target_tree_hash=self.target.tree_hash,
            title=_string(invariant_value["title"], "invariant.title"),
            scope=_strings(invariant_value["scope"], "invariant.scope"),
            statement=_string(invariant_value["statement"], "invariant.statement"),
            source=InvariantSource(
                InvariantDerivation(_string(source["derivation"], "invariant.source.derivation")),
                InvariantOrigin(_string(source["origin"], "invariant.source.origin")),
            ),
            source_evidence=tuple(item.evidence_id for item in evidence),
            confidence=Confidence(_string(invariant_value["confidence"], "invariant.confidence")),
            counterexample=_object(invariant_value["counterexample"], "counterexample"),
        )
        supplied_id = invariant_value.get("invariant_id")
        if supplied_id is not None and supplied_id != invariant.invariant_id:
            raise ValueError("supplied invariant ID does not match normalized content")

        existing_evidence = {item.evidence_id for item in self.list_evidence()}
        if any(item.evidence_id in existing_evidence for item in evidence):
            existing_records = {item.evidence_id: item for item in self.list_evidence()}
            for evidence_item in evidence:
                current = existing_records.get(evidence_item.evidence_id)
                if current is not None and current.to_dict() != evidence_item.to_dict():
                    raise WhiteboxAuditError(
                        "evidence stable ID collision rejected", ExitCode.DATA_INTEGRITY_ERROR
                    )

        input_path = self.run_directory / artifact_ref
        input_path.parent.mkdir(parents=True, exist_ok=True)
        if input_path.exists():
            if input_path.is_symlink() or input_path.read_bytes() != raw:
                raise WhiteboxAuditError(
                    "operator input artifact collision rejected", ExitCode.DATA_INTEGRITY_ERROR
                )
        else:
            _atomic_write_bytes(input_path, raw)
        write_evidence_jsonl(
            self.evidence_path,
            evidence,
            target_tree_hash=self.target.tree_hash,
        )
        existing_invariants = self.list_invariants()
        _persist_immutable(
            self.invariant_path,
            existing_invariants,
            invariant,
            identifier=lambda item: item.invariant_id,
            serialize=lambda item: item.to_dict(),
        )
        add_run_artifacts(
            self.run_directory,
            load_audit_run(self.run_directory),
            (artifact_ref, "evidence/evidence.jsonl", "invariants/invariants.jsonl"),
        )
        return invariant

    def add_hypothesis_document(self, document: Mapping[str, object]) -> Hypothesis:
        _strict_keys(
            document,
            required=frozenset(
                {
                    "schema_version",
                    "invariant_id",
                    "title",
                    "attacker_preconditions",
                    "entry_point",
                    "suspected_path",
                    "files_symbols_to_inspect",
                    "supporting_evidence",
                    "counter_evidence",
                    "falsification_conditions",
                    "verification_plan",
                }
            ),
            optional=frozenset({"hypothesis_id", "status", "target_id", "target_tree_hash"}),
        )
        _schema(document["schema_version"])
        if document.get("target_id", self.target.target_id) != self.target.target_id:
            raise ValueError("hypothesis target ID does not match the run")
        if document.get("target_tree_hash", self.target.tree_hash) != self.target.tree_hash:
            raise ValueError("hypothesis target fingerprint does not match the run")
        status = FindingStatus(_string(document.get("status", "hypothesis"), "status"))
        if status is not FindingStatus.HYPOTHESIS:
            raise ValueError("manual hypothesis import must begin in hypothesis state")
        invariant_id = _string(document["invariant_id"], "invariant_id")
        self.get_invariant(invariant_id)
        supporting = _strings(document["supporting_evidence"], "supporting_evidence")
        counter = _strings(document["counter_evidence"], "counter_evidence", allow_empty=True)
        if set(supporting) & set(counter):
            raise ValueError("evidence cannot be both supporting and counter-evidence")
        available = {item.evidence_id for item in self.list_evidence()}
        missing = sorted(set((*supporting, *counter)) - available)
        if missing:
            raise ValueError(f"hypothesis references missing evidence: {missing}")
        path_value = document["suspected_path"]
        inspect_value = document["files_symbols_to_inspect"]
        if not isinstance(path_value, list) or not isinstance(inspect_value, list):
            raise ValueError("hypothesis path fields must be arrays")
        hypothesis = Hypothesis.create(
            target_id=self.target.target_id,
            target_tree_hash=self.target.tree_hash,
            invariant_id=invariant_id,
            title=_string(document["title"], "title"),
            attacker_preconditions=_strings(
                document["attacker_preconditions"], "attacker_preconditions"
            ),
            entry_point=_location_input(document["entry_point"], "entry_point"),
            suspected_path=tuple(_location_input(item, "suspected_path") for item in path_value),
            files_symbols_to_inspect=tuple(
                _location_input(item, "files_symbols_to_inspect") for item in inspect_value
            ),
            supporting_evidence=supporting,
            counter_evidence=counter,
            falsification_conditions=_strings(
                document["falsification_conditions"], "falsification_conditions"
            ),
            verification_plan=_object(document["verification_plan"], "verification_plan"),
            status=status,
        )
        supplied_id = document.get("hypothesis_id")
        if supplied_id is not None and supplied_id != hypothesis.hypothesis_id:
            raise ValueError("supplied hypothesis ID does not match normalized content")
        existing = self.list_hypotheses()
        _persist_immutable(
            self.hypothesis_path,
            existing,
            hypothesis,
            identifier=lambda item: item.hypothesis_id,
            serialize=lambda item: item.to_dict(),
        )
        add_run_artifacts(
            self.run_directory,
            load_audit_run(self.run_directory),
            ("hypotheses/hypotheses.jsonl",),
        )
        return hypothesis


def _atomic_write_bytes(path: Path, data: bytes) -> None:
    temporary = path.with_name(f".{path.name}.tmp-{secrets.token_hex(6)}")
    descriptor: int | None = None
    try:
        descriptor = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(descriptor, "wb") as stream:
            descriptor = None
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
        _fsync_directory(path.parent)
    except OSError as error:
        raise WhiteboxAuditError(
            "could not persist operator input atomically", ExitCode.DATA_INTEGRITY_ERROR
        ) from error
    finally:
        if descriptor is not None:
            os.close(descriptor)
        with suppress(OSError):
            temporary.unlink(missing_ok=True)
