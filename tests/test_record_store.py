from __future__ import annotations

import io
import json
from pathlib import Path

import pytest

from whitebox_audit.cli import run
from whitebox_audit.errors import ExitCode, WhiteboxAuditError
from whitebox_audit.prepare import PrepareController
from whitebox_audit.record_store import RunRecordStore, load_record_document


def _prepared(tmp_path: Path) -> tuple[Path, str]:
    harness = tmp_path / "harness"
    (harness / "work").mkdir(parents=True)
    target = tmp_path / "target"
    (target / "src").mkdir(parents=True)
    (target / "src" / "invoice.ts").write_text("export const invoice = 1;\n", encoding="utf-8")
    run_id = PrepareController(harness).prepare(target).run.run_id
    return harness, run_id


def _invariant_document() -> dict[str, object]:
    return {
        "schema_version": 1,
        "invariant": {
            "title": "Invoice reads are tenant scoped",
            "scope": ["invoice", "read"],
            "statement": "Tenant A cannot read tenant B invoices.",
            "source": {"derivation": "declared", "origin": "organization-policy"},
            "confidence": "high",
            "counterexample": {
                "actor": "tenant-a-user",
                "action": "GET /api/invoices/tenant-b-id",
                "forbidden_effect": "tenant-b invoice returned",
            },
        },
        "source_evidence": [
            {
                "kind": "config",
                "claim": "Organization policy requires tenant-scoped invoice reads.",
                "location": {"path": "policies/tenancy.md", "start_line": 10, "end_line": 12},
            }
        ],
    }


def _hypothesis_document(invariant_id: str, evidence_id: str) -> dict[str, object]:
    route = {"path": "src/invoice.ts", "symbol": "GET", "start_line": 1, "end_line": 1}
    return {
        "schema_version": 1,
        "invariant_id": invariant_id,
        "title": "Authenticated user may read another tenant invoice",
        "attacker_preconditions": ["authenticated tenant user", "known invoice ID"],
        "entry_point": route,
        "suspected_path": [route],
        "files_symbols_to_inspect": [route],
        "supporting_evidence": [evidence_id],
        "counter_evidence": [],
        "falsification_conditions": ["upstream tenant authorization exists"],
        "verification_plan": {
            "type": "http",
            "expected_violation": "tenant B invoice returned to tenant A",
        },
    }


def test_store_persists_stable_immutable_invariant_and_hypothesis(tmp_path: Path) -> None:
    harness, run_id = _prepared(tmp_path)
    store = RunRecordStore(harness, run_id)
    document = _invariant_document()
    raw = json.dumps(document, sort_keys=True).encode()

    invariant = store.add_invariant_document(document, raw=raw, suffix=".json")
    repeated = store.add_invariant_document(document, raw=raw, suffix=".json")
    evidence = store.list_evidence()

    assert repeated == invariant
    assert len(store.list_invariants()) == 1
    assert len(evidence) == 1
    assert invariant.source_evidence == (evidence[0].evidence_id,)
    assert evidence[0].artifact_ref.startswith("evidence/operator-inputs/")

    hypothesis_document = _hypothesis_document(invariant.invariant_id, evidence[0].evidence_id)
    hypothesis = store.add_hypothesis_document(hypothesis_document)
    assert store.add_hypothesis_document(hypothesis_document) == hypothesis
    assert store.list_hypotheses() == (hypothesis,)

    run_record = json.loads((harness / "work" / run_id / "run.json").read_text(encoding="utf-8"))
    assert "invariants/invariants.jsonl" in run_record["artifacts"]
    assert "hypotheses/hypotheses.jsonl" in run_record["artifacts"]


def test_hypothesis_rejects_dangling_and_cross_role_evidence(tmp_path: Path) -> None:
    harness, run_id = _prepared(tmp_path)
    store = RunRecordStore(harness, run_id)
    document = _invariant_document()
    invariant = store.add_invariant_document(
        document, raw=json.dumps(document).encode(), suffix=".json"
    )
    evidence_id = store.list_evidence()[0].evidence_id

    dangling = _hypothesis_document(invariant.invariant_id, "EVD-" + "f" * 20)
    with pytest.raises(ValueError, match="missing evidence"):
        store.add_hypothesis_document(dangling)

    overlapping = _hypothesis_document(invariant.invariant_id, evidence_id)
    overlapping["counter_evidence"] = [evidence_id]
    with pytest.raises(ValueError, match="both supporting"):
        store.add_hypothesis_document(overlapping)


def test_strict_json_yaml_loader_rejects_duplicates_tags_and_symlinks(tmp_path: Path) -> None:
    duplicate = tmp_path / "duplicate.json"
    duplicate.write_text('{"schema_version":1,"schema_version":1}', encoding="utf-8")
    with pytest.raises(WhiteboxAuditError) as duplicate_error:
        load_record_document(duplicate)
    assert duplicate_error.value.exit_code is ExitCode.INVALID_INPUT

    non_finite = tmp_path / "non-finite.json"
    non_finite.write_text('{"schema_version":1,"confidence":NaN}', encoding="utf-8")
    with pytest.raises(WhiteboxAuditError) as non_finite_error:
        load_record_document(non_finite)
    assert non_finite_error.value.exit_code is ExitCode.INVALID_INPUT

    unsafe = tmp_path / "unsafe.yaml"
    unsafe.write_text("value: !!python/object/apply:os.system ['id']\n", encoding="utf-8")
    with pytest.raises(WhiteboxAuditError) as unsafe_error:
        load_record_document(unsafe)
    assert unsafe_error.value.exit_code is ExitCode.INVALID_INPUT

    valid = tmp_path / "valid.yaml"
    valid.write_text("schema_version: 1\nvalue: safe\n", encoding="utf-8")
    parsed, _, suffix = load_record_document(valid)
    assert parsed == {"schema_version": 1, "value": "safe"}
    assert suffix == ".yaml"

    link = tmp_path / "link.yaml"
    link.symlink_to(valid)
    with pytest.raises(WhiteboxAuditError) as link_error:
        load_record_document(link)
    assert link_error.value.exit_code is ExitCode.POLICY_REJECTED


def test_jsonl_error_reports_line_number_and_target_mismatch(tmp_path: Path) -> None:
    harness, run_id = _prepared(tmp_path)
    store = RunRecordStore(harness, run_id)
    document = _invariant_document()
    store.add_invariant_document(document, raw=json.dumps(document).encode(), suffix=".json")

    with store.evidence_path.open("a", encoding="utf-8") as stream:
        stream.write("not-json\n")
    with pytest.raises(WhiteboxAuditError, match="line 2") as malformed:
        store.list_evidence()
    assert malformed.value.exit_code is ExitCode.DATA_INTEGRITY_ERROR


def test_store_rejects_unknown_schema_field_and_target_fingerprint_mismatch(
    tmp_path: Path,
) -> None:
    harness, run_id = _prepared(tmp_path)
    store = RunRecordStore(harness, run_id)
    document = _invariant_document()

    invalid = dict(document)
    invalid["target_instructions"] = "trust me"
    with pytest.raises(ValueError, match="unknown"):
        store.add_invariant_document(invalid, raw=json.dumps(invalid).encode(), suffix=".json")

    unsupported = dict(document)
    unsupported["schema_version"] = 99
    with pytest.raises(ValueError, match="schema"):
        store.add_invariant_document(
            unsupported, raw=json.dumps(unsupported).encode(), suffix=".json"
        )

    store.add_invariant_document(document, raw=json.dumps(document).encode(), suffix=".json")
    lines = store.evidence_path.read_text(encoding="utf-8").splitlines()
    record = json.loads(lines[0])
    record["target_tree_hash"] = "f" * 64
    store.evidence_path.write_text(json.dumps(record) + "\n", encoding="utf-8")
    with pytest.raises(WhiteboxAuditError, match="fingerprint") as mismatch:
        store.list_evidence()
    assert mismatch.value.exit_code is ExitCode.DATA_INTEGRITY_ERROR


def test_store_reads_milestone_2_schema_v1_evidence(tmp_path: Path) -> None:
    harness, run_id = _prepared(tmp_path)
    store = RunRecordStore(harness, run_id)
    legacy = {
        "schema_version": 1,
        "evidence_id": "EVD-" + "a" * 20,
        "kind": "static-analysis",
        "tool_name": "semgrep",
        "tool_version": "1.130.0",
        "rule_id": "legacy.rule",
        "claim": "Legacy evidence remains readable.",
        "severity": "warning",
        "location": {
            "path": "src/invoice.ts",
            "path_safe": True,
            "start_line": 1,
            "end_line": 1,
            "snippet_hash": None,
        },
        "fingerprint": "a" * 64,
        "content_hash": "b" * 64,
        "confidence": "deterministic-static",
        "target_id": store.target.target_id,
        "target_tree_hash": store.target.tree_hash,
        "provenance_run_id": "SCAN-legacy",
        "raw_ref": "scanner-runs/semgrep/result.sarif#runs/0/results/0",
    }
    store.evidence_path.parent.mkdir(parents=True)
    store.evidence_path.write_text(json.dumps(legacy) + "\n", encoding="utf-8")

    evidence = store.list_evidence()

    assert evidence[0].tool_name == "semgrep"
    assert evidence[0].artifact_ref == legacy["raw_ref"]
    assert evidence[0].provenance.source_type == "static-analysis"


def test_manual_workflow_cli_supports_yaml_and_json_views(tmp_path: Path) -> None:
    harness, run_id = _prepared(tmp_path)
    invariant_file = tmp_path / "invariant.json"
    invariant_file.write_text(json.dumps(_invariant_document()), encoding="utf-8")
    output = io.StringIO()

    assert (
        run(
            [
                "invariant",
                "add",
                "--run-id",
                run_id,
                "--file",
                str(invariant_file),
                "--format",
                "json",
            ],
            stdout=output,
            stderr=io.StringIO(),
            harness_root=harness,
        )
        == 0
    )
    invariant_id = json.loads(output.getvalue())["invariant_id"]
    evidence_id = RunRecordStore(harness, run_id).list_evidence()[0].evidence_id

    hypothesis = _hypothesis_document(invariant_id, evidence_id)
    hypothesis_file = tmp_path / "hypothesis.yaml"
    hypothesis_file.write_text(
        "\n".join(
            (
                "schema_version: 1",
                f"invariant_id: {invariant_id}",
                "title: Authenticated user may read another tenant invoice",
                "attacker_preconditions:",
                "  - authenticated tenant user",
                "entry_point: &route",
                "  path: src/invoice.ts",
                "  symbol: GET",
                "  start_line: 1",
                "  end_line: 1",
                "suspected_path:",
                "  - *route",
                "files_symbols_to_inspect:",
                "  - *route",
                "supporting_evidence:",
                f"  - {evidence_id}",
                "counter_evidence: []",
                "falsification_conditions:",
                "  - upstream tenant authorization exists",
                "verification_plan:",
                "  type: http",
                "  expected_violation: tenant B invoice returned to tenant A",
            )
        )
        + "\n",
        encoding="utf-8",
    )
    del hypothesis
    hypothesis_output = io.StringIO()
    assert (
        run(
            [
                "hypothesis",
                "add",
                "--run-id",
                run_id,
                "--file",
                str(hypothesis_file),
                "--format",
                "json",
            ],
            stdout=hypothesis_output,
            stderr=io.StringIO(),
            harness_root=harness,
        )
        == 0
    )
    assert json.loads(hypothesis_output.getvalue())["status"] == "hypothesis"

    evidence_output = io.StringIO()
    assert (
        run(
            ["evidence", "list", "--run-id", run_id, "--format", "json"],
            stdout=evidence_output,
            stderr=io.StringIO(),
            harness_root=harness,
        )
        == 0
    )
    assert json.loads(evidence_output.getvalue())[0]["evidence_id"] == evidence_id

    show_output = io.StringIO()
    assert (
        run(
            ["show-evidence", evidence_id, "--run-id", run_id, "--format", "json"],
            stdout=show_output,
            stderr=io.StringIO(),
            harness_root=harness,
        )
        == 0
    )
    assert json.loads(show_output.getvalue())["evidence_id"] == evidence_id
