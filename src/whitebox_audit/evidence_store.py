"""Atomic, deduplicating JSONL persistence for normalized evidence."""

from __future__ import annotations

import json
import os
import secrets
from collections.abc import Sequence
from contextlib import suppress
from pathlib import Path

from whitebox_audit.errors import ExitCode, WhiteboxAuditError
from whitebox_audit.models import SCHEMA_VERSION, Evidence


def _reject_json_constant(value: str) -> object:
    raise ValueError(f"invalid JSON constant: {value}")


def _load_existing(path: Path, target_tree_hash: str) -> dict[str, dict[str, object]]:
    if not path.exists():
        return {}
    if path.is_symlink() or not path.is_file():
        raise WhiteboxAuditError("evidence JSONL violates file policy", ExitCode.POLICY_REJECTED)
    records: dict[str, dict[str, object]] = {}
    try:
        for line_number, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
            try:
                value = json.loads(line, parse_constant=_reject_json_constant)
                if (
                    not isinstance(value, dict)
                    or value.get("schema_version") != SCHEMA_VERSION
                    or not isinstance(value.get("fingerprint"), str)
                    or value.get("target_tree_hash") != target_tree_hash
                ):
                    raise ValueError
                record = {str(key): item for key, item in value.items()}
                records[str(value["fingerprint"])] = record
            except (json.JSONDecodeError, ValueError) as error:
                raise WhiteboxAuditError(
                    f"existing evidence JSONL is corrupt at line {line_number}",
                    ExitCode.DATA_INTEGRITY_ERROR,
                ) from error
    except WhiteboxAuditError:
        raise
    except (OSError, UnicodeError) as error:
        raise WhiteboxAuditError(
            "existing evidence JSONL is corrupt", ExitCode.DATA_INTEGRITY_ERROR
        ) from error
    return records


def write_evidence_jsonl(
    path: Path, evidence: Sequence[Evidence], *, target_tree_hash: str
) -> None:
    """Merge evidence by stable fingerprint and replace the JSONL atomically."""

    records = _load_existing(path, target_tree_hash)
    for item in evidence:
        if item.target_tree_hash != target_tree_hash:
            raise WhiteboxAuditError(
                "evidence target fingerprint does not match the run",
                ExitCode.DATA_INTEGRITY_ERROR,
            )
        records[item.fingerprint] = item.to_dict()

    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(f".{path.name}.tmp-{secrets.token_hex(6)}")
    descriptor: int | None = None
    try:
        descriptor = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(descriptor, "w", encoding="utf-8") as stream:
            descriptor = None
            for record in records.values():
                stream.write(
                    json.dumps(
                        record,
                        allow_nan=False,
                        sort_keys=True,
                        ensure_ascii=False,
                    )
                    + "\n"
                )
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
        directory_descriptor = os.open(path.parent, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
        try:
            os.fsync(directory_descriptor)
        finally:
            os.close(directory_descriptor)
    except OSError as error:
        raise WhiteboxAuditError(
            "could not persist evidence atomically", ExitCode.DATA_INTEGRITY_ERROR
        ) from error
    finally:
        if descriptor is not None:
            os.close(descriptor)
        with suppress(OSError):
            temporary.unlink(missing_ok=True)
