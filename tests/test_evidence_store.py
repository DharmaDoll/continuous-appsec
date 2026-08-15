from __future__ import annotations

import json
from dataclasses import replace
from pathlib import Path

import pytest

from whitebox_audit.errors import ExitCode, WhiteboxAuditError
from whitebox_audit.evidence_store import write_evidence_jsonl
from whitebox_audit.models import (
    SCHEMA_VERSION,
    Evidence,
    EvidenceConfidence,
    EvidenceKind,
    EvidenceLocation,
    EvidenceProvenance,
)


def _evidence(fingerprint: str = "f" * 64, tree_hash: str = "a" * 64) -> Evidence:
    return Evidence(
        schema_version=SCHEMA_VERSION,
        evidence_id=f"EVD-{fingerprint[:20]}",
        kind=EvidenceKind.STATIC_ANALYSIS,
        claim="test claim",
        location=EvidenceLocation("src/app.ts", True, 1, 1, None),
        artifact_ref="scanner-runs/test/result.sarif#runs/0/results/0",
        fingerprint=fingerprint,
        content_hash="c" * 64,
        confidence=EvidenceConfidence.DETERMINISTIC_STATIC,
        target_id="TGT-0123456789abcdefabcd",
        target_tree_hash=tree_hash,
        provenance=EvidenceProvenance(
            source_type="static-analysis",
            run_id="SCAN-0123456789abcdefabcd",
            raw_uri="scanner-runs/test/result.sarif#runs/0/results/0",
            tool_name="test",
            tool_version="1",
            rule_id="test.rule",
        ),
        severity="warning",
    )


def test_evidence_store_merges_and_deduplicates_atomically(tmp_path: Path) -> None:
    path = tmp_path / "evidence" / "evidence.jsonl"
    first = _evidence()
    second = _evidence("b" * 64)

    write_evidence_jsonl(path, (first,), target_tree_hash="a" * 64)
    write_evidence_jsonl(path, (first, second), target_tree_hash="a" * 64)

    records = [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines()]
    assert [record["fingerprint"] for record in records] == ["f" * 64, "b" * 64]
    assert path.stat().st_mode & 0o777 == 0o600


def test_evidence_store_rejects_corruption_and_target_mismatch(tmp_path: Path) -> None:
    path = tmp_path / "evidence.jsonl"
    path.write_text("not-json\n", encoding="utf-8")

    with pytest.raises(WhiteboxAuditError) as corrupt:
        write_evidence_jsonl(path, (), target_tree_hash="a" * 64)
    assert corrupt.value.exit_code is ExitCode.DATA_INTEGRITY_ERROR

    path.unlink()
    with pytest.raises(WhiteboxAuditError) as mismatch:
        write_evidence_jsonl(
            path,
            (replace(_evidence(), target_tree_hash="b" * 64),),
            target_tree_hash="a" * 64,
        )
    assert mismatch.value.exit_code is ExitCode.DATA_INTEGRITY_ERROR
