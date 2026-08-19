from __future__ import annotations

import io
import json
import shutil
from pathlib import Path

import pytest

from whitebox_audit.cli import run
from whitebox_audit.errors import ExitCode, WhiteboxAuditError
from whitebox_audit.prepare import PrepareController
from whitebox_audit.record_store import RunRecordStore
from whitebox_audit.verifier import parse_runtime_adapter, parse_verifier_policy

from .test_record_store import _hypothesis_document, _invariant_document
from .test_verifier import adapter_document, case_document, policy_document


def _store_with_hypothesis(tmp_path: Path) -> tuple[Path, str, RunRecordStore, str]:
    harness = tmp_path / "harness"
    (harness / "work").mkdir(parents=True)
    (harness / "config").mkdir()
    shutil.copyfile(
        Path(__file__).parents[1] / "config" / "verifier-policy.yaml",
        harness / "config" / "verifier-policy.yaml",
    )
    target = tmp_path / "target"
    (target / "src").mkdir(parents=True)
    (target / "src" / "invoice.ts").write_text("export const invoice = 1;\n", encoding="utf-8")
    run_id = PrepareController(harness).prepare(target).run.run_id
    store = RunRecordStore(harness, run_id)
    invariant_document = _invariant_document()
    invariant = store.add_invariant_document(
        invariant_document,
        raw=json.dumps(invariant_document).encode(),
        suffix=".json",
    )
    evidence_id = store.list_evidence()[0].evidence_id
    hypothesis = store.add_hypothesis_document(
        _hypothesis_document(invariant.invariant_id, evidence_id)
    )
    return harness, run_id, store, hypothesis.hypothesis_id


def test_verification_case_store_pins_policy_adapter_and_references(tmp_path: Path) -> None:
    harness, run_id, store, hypothesis_id = _store_with_hypothesis(tmp_path)
    policy = parse_verifier_policy(policy_document())
    adapter = parse_runtime_adapter(adapter_document(), policy)
    document = case_document()
    document["hypothesis_id"] = hypothesis_id

    case = store.add_verification_case_document(document, policy=policy, adapter=adapter)
    repeated = store.add_verification_case_document(document, policy=policy, adapter=adapter)

    assert repeated == case
    assert store.list_verification_cases() == (case,)
    assert store.get_verification_case(case.verification_id) == case
    assert (
        harness / "work" / run_id / "verification" / "policies" / f"{policy.fingerprint}.json"
    ).is_file()
    assert (
        harness / "work" / run_id / "verification" / "adapters" / f"{adapter.fingerprint}.json"
    ).is_file()
    run_record = json.loads((harness / "work" / run_id / "run.json").read_text())
    assert "verification/cases.jsonl" in run_record["artifacts"]


def test_verification_case_store_detects_policy_artifact_tampering(tmp_path: Path) -> None:
    harness, run_id, store, hypothesis_id = _store_with_hypothesis(tmp_path)
    policy = parse_verifier_policy(policy_document())
    adapter = parse_runtime_adapter(adapter_document(), policy)
    document = case_document()
    document["hypothesis_id"] = hypothesis_id
    store.add_verification_case_document(document, policy=policy, adapter=adapter)
    policy_path = (
        harness / "work" / run_id / "verification" / "policies" / f"{policy.fingerprint}.json"
    )
    tampered = json.loads(policy_path.read_text())
    tampered["network"]["external_egress"] = True
    policy_path.write_text(json.dumps(tampered), encoding="utf-8")

    with pytest.raises(WhiteboxAuditError) as error:
        store.list_verification_cases()
    assert error.value.exit_code is ExitCode.DATA_INTEGRITY_ERROR


def test_verification_case_store_rejects_missing_hypothesis(tmp_path: Path) -> None:
    _harness, _run_id, store, _hypothesis_id = _store_with_hypothesis(tmp_path)
    policy = parse_verifier_policy(policy_document())
    adapter = parse_runtime_adapter(adapter_document(), policy)
    document = case_document()
    document["hypothesis_id"] = "HYP-" + "f" * 20

    with pytest.raises(WhiteboxAuditError, match="hypothesis") as error:
        store.add_verification_case_document(document, policy=policy, adapter=adapter)
    assert error.value.exit_code is ExitCode.INVALID_INPUT


def test_verification_case_cli_adds_and_lists_json(tmp_path: Path) -> None:
    harness, run_id, _store, hypothesis_id = _store_with_hypothesis(tmp_path)
    adapter_path = tmp_path / "adapter.json"
    case_path = tmp_path / "case.json"
    adapter_path.write_text(json.dumps(adapter_document()), encoding="utf-8")
    case = case_document()
    case["hypothesis_id"] = hypothesis_id
    case_path.write_text(json.dumps(case), encoding="utf-8")
    output = io.StringIO()

    exit_code = run(
        [
            "verification-case",
            "add",
            "--run-id",
            run_id,
            "--file",
            str(case_path),
            "--adapter",
            str(adapter_path),
            "--format",
            "json",
        ],
        stdout=output,
        stderr=io.StringIO(),
        harness_root=harness,
    )

    assert exit_code == 0
    verification_id = json.loads(output.getvalue())["verification_id"]
    list_output = io.StringIO()
    assert (
        run(
            ["verification-case", "list", "--run-id", run_id, "--format", "json"],
            stdout=list_output,
            stderr=io.StringIO(),
            harness_root=harness,
        )
        == 0
    )
    assert json.loads(list_output.getvalue())[0]["verification_id"] == verification_id
