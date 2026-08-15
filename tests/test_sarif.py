from __future__ import annotations

import json
from pathlib import Path

import pytest

from whitebox_audit.errors import ExitCode, WhiteboxAuditError
from whitebox_audit.models import SarifNormalizationResult
from whitebox_audit.prepare import PrepareController
from whitebox_audit.sarif import load_sarif, normalize_sarif
from whitebox_audit.scan import ingest_sarif

SARIF_FIXTURES = Path(__file__).parent / "fixtures" / "sarif"


def _normalize(name: str, target: Path) -> SarifNormalizationResult:
    return normalize_sarif(
        load_sarif(SARIF_FIXTURES / name),
        target_id="TGT-0123456789abcdefabcd",
        target_tree_hash="a" * 64,
        scanner_run_id="SCAN-0123456789abcdefabcd",
        raw_ref="scanner-runs/test/result.sarif",
        target_root=target,
        fallback_tool_name="fallback",
    )


def test_realistic_sarif_normalizes_stable_evidence(tmp_path: Path) -> None:
    target = tmp_path / "target"
    (target / "src").mkdir(parents=True)
    (target / "src" / "vulnerable.ts").write_text("eval(input)\n", encoding="utf-8")

    first = _normalize("semgrep-realistic.sarif", target)
    second = _normalize("semgrep-realistic.sarif", target)

    assert first == second
    assert len(first.evidence) == 1
    evidence = first.evidence[0]
    assert evidence.location is not None
    assert evidence.evidence_id.startswith("EVD-")
    assert evidence.confidence == "deterministic-static"
    assert evidence.location.path == "src/vulnerable.ts"
    assert evidence.location.path_safe is True
    assert evidence.location.start_line == 2
    assert evidence.raw_ref.endswith("#runs/0/results/0")


def test_optional_fields_and_partial_parse_are_preserved(tmp_path: Path) -> None:
    result = _normalize("optional-fields.sarif", tmp_path)

    assert result.result_count == 2
    assert len(result.evidence) == 2
    assert len(result.warnings) == 1
    assert result.evidence[0].location is not None
    assert result.evidence[0].location.path is None


def test_multiple_runs_deduplicate_and_quarantine_external_uri(tmp_path: Path) -> None:
    target = tmp_path / "target"
    (target / "src").mkdir(parents=True)
    result = _normalize("multiple-runs.sarif", target)

    assert result.result_count == 3
    assert len(result.evidence) == 2
    assert result.duplicate_count == 1
    external = next(item for item in result.evidence if item.rule_id == "rule.external")
    assert external.location is not None
    assert external.location.path is not None
    assert external.location.path.startswith("external-uri:")
    assert external.location.path_safe is False


def test_malformed_and_missing_runs_fail_visibly(tmp_path: Path) -> None:
    with pytest.raises(WhiteboxAuditError) as malformed:
        load_sarif(SARIF_FIXTURES / "malformed.sarif")
    assert malformed.value.exit_code is ExitCode.DATA_INTEGRITY_ERROR

    missing = tmp_path / "missing-runs.sarif"
    missing.write_text('{"version":"2.1.0"}', encoding="utf-8")
    with pytest.raises(WhiteboxAuditError) as required:
        load_sarif(missing)
    assert required.value.exit_code is ExitCode.DATA_INTEGRITY_ERROR


def test_ingest_sarif_persists_provenance_and_merges_evidence(tmp_path: Path) -> None:
    harness = tmp_path / "harness"
    (harness / "work").mkdir(parents=True)
    target = tmp_path / "target"
    (target / "src").mkdir(parents=True)
    (target / "src" / "vulnerable.ts").write_text("eval(input)\n", encoding="utf-8")
    run_id = PrepareController(harness).prepare(target).run.run_id

    first = ingest_sarif(
        harness,
        run_id=run_id,
        tool_name="external-tool",
        input_path=SARIF_FIXTURES / "semgrep-realistic.sarif",
    )

    run_dir = harness / "work" / run_id
    scanner_dir = run_dir / "scanner-runs" / "ingest-external-tool"
    scanner_run = json.loads((scanner_dir / "run.json").read_text(encoding="utf-8"))
    evidence = (run_dir / "evidence" / "evidence.jsonl").read_text(encoding="utf-8")
    assert len(first) == 1
    assert scanner_run["status"] == "succeeded"
    assert scanner_run["reason"].startswith("operator-supplied")
    assert len(evidence.splitlines()) == 1
    assert (scanner_dir / "result.sarif").read_bytes() == (
        SARIF_FIXTURES / "semgrep-realistic.sarif"
    ).read_bytes()


def test_ingest_rejects_missing_or_symlinked_sarif(tmp_path: Path) -> None:
    harness = tmp_path / "harness"
    (harness / "work").mkdir(parents=True)
    target = tmp_path / "target"
    target.mkdir()
    run_id = PrepareController(harness).prepare(target).run.run_id

    with pytest.raises(WhiteboxAuditError) as missing:
        ingest_sarif(
            harness,
            run_id=run_id,
            tool_name="test",
            input_path=tmp_path / "missing.sarif",
        )
    assert missing.value.exit_code is ExitCode.INVALID_INPUT

    link = tmp_path / "link.sarif"
    link.symlink_to(SARIF_FIXTURES / "semgrep-realistic.sarif")
    with pytest.raises(WhiteboxAuditError) as unsafe:
        ingest_sarif(harness, run_id=run_id, tool_name="test", input_path=link)
    assert unsafe.value.exit_code is ExitCode.POLICY_REJECTED
