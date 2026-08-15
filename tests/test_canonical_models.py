from __future__ import annotations

import json
from dataclasses import replace

import pytest

from whitebox_audit.models import (
    SCHEMA_VERSION,
    Confidence,
    EvidenceLocation,
    Finding,
    FindingStatus,
    InvariantDerivation,
    InvariantOrigin,
    InvariantSource,
    RecordOrigin,
    SecurityInvariant,
    VerificationCase,
    VerificationResult,
    VerificationStatus,
    stable_record_id,
    transition_finding,
    validate_record_id,
)

TARGET_ID = "TGT-" + "1" * 20
TREE_HASH = "a" * 64
INVARIANT_ID = "INV-" + "2" * 20
HYPOTHESIS_ID = "HYP-" + "3" * 20
VERIFICATION_ID = "VER-" + "4" * 20
EVIDENCE_ID = "EVD-" + "5" * 20


def _invariant() -> SecurityInvariant:
    return SecurityInvariant.create(
        target_id=TARGET_ID,
        target_tree_hash=TREE_HASH,
        title="Invoice reads are tenant scoped",
        scope=("invoice", "read"),
        statement="Tenant A cannot read tenant B invoices.",
        source=InvariantSource(InvariantDerivation.DECLARED, InvariantOrigin.ORGANIZATION_POLICY),
        source_evidence=(EVIDENCE_ID,),
        confidence=Confidence.HIGH,
        counterexample={"actor": "tenant-a", "forbidden_effect": "tenant-b invoice"},
    )


def _finding() -> Finding:
    content = {
        "target_tree_hash": TREE_HASH,
        "hypothesis_id": HYPOTHESIS_ID,
        "invariant_id": INVARIANT_ID,
        "title": "Cross-tenant invoice read",
    }
    return Finding(
        schema_version=SCHEMA_VERSION,
        finding_id=stable_record_id("FND", content),
        target_tree_hash=TREE_HASH,
        hypothesis_id=HYPOTHESIS_ID,
        invariant_id=INVARIANT_ID,
        status=FindingStatus.NEEDS_VERIFICATION,
        title="Cross-tenant invoice read",
        severity={"level": "high", "reason": "cross-tenant confidentiality"},
        cwe=("CWE-639",),
        evidence=(EVIDENCE_ID,),
        verification_result_id=None,
        attacker_preconditions=("authenticated tenant user",),
        impact={"confidentiality": "high"},
        falsification_summary={"checked": ["middleware", "repository scope"]},
        remediation={"summary": "scope by trusted tenant"},
        regression={"case": VERIFICATION_ID},
        record_origin=RecordOrigin.REPORTER,
    )


def _verification(status: VerificationStatus) -> VerificationResult:
    return VerificationResult(
        schema_version=SCHEMA_VERSION,
        verification_id=VERIFICATION_ID,
        verifier_run_id="VRUN-test",
        target_tree_hash=TREE_HASH,
        status=status,
        observations=({"type": "http-response", "status": 200},),
        oracle={"violated": status is VerificationStatus.PROVED},
        started_at="2026-08-15T00:00:00Z",
        finished_at="2026-08-15T00:00:01Z",
        verifier_version="test",
        policy_fingerprint="b" * 64,
    )


def test_invariant_id_is_stable_and_provenance_is_semantic() -> None:
    first = _invariant()
    second = _invariant()

    assert first == second
    assert first.invariant_id.startswith("INV-")
    assert first.to_dict()["source"] == {
        "derivation": "declared",
        "origin": "organization-policy",
    }

    with pytest.raises(ValueError, match="inferred invariants"):
        InvariantSource(InvariantDerivation.INFERRED, InvariantOrigin.OPERATOR)


def test_ids_and_locations_reject_wrong_prefix_and_absolute_host_paths() -> None:
    with pytest.raises(ValueError, match="HYP"):
        validate_record_id(EVIDENCE_ID, "HYP")
    with pytest.raises(ValueError, match="relative"):
        EvidenceLocation("/home/operator/secret.py", True, 1, 1, None)
    with pytest.raises(ValueError, match="normalized content"):
        replace(_invariant(), invariant_id="INV-" + "f" * 20)


def test_finding_state_machine_requires_independent_proved_result() -> None:
    finding = _finding()

    with pytest.raises(ValueError, match="proved verifier result"):
        transition_finding(
            finding,
            FindingStatus.VERIFIED,
            verification_result=_verification(VerificationStatus.NOT_PROVED),
        )

    verified = transition_finding(
        finding,
        FindingStatus.VERIFIED,
        verification_result=_verification(VerificationStatus.PROVED),
    )
    assert verified.status is FindingStatus.VERIFIED
    assert verified.record_origin is RecordOrigin.VERIFIER
    assert verified.verification_result_id == VERIFICATION_ID

    with pytest.raises(ValueError, match="only verifier-origin"):
        replace(
            finding,
            status=FindingStatus.VERIFIED,
            verification_result_id=VERIFICATION_ID,
            record_origin=RecordOrigin.DISCOVERY_AGENT,
        )


def test_high_confidence_static_requires_explicit_complete_trace_gate() -> None:
    finding = _finding()
    with pytest.raises(ValueError, match="complete trace"):
        transition_finding(finding, FindingStatus.HIGH_CONFIDENCE_STATIC)

    transitioned = transition_finding(
        finding,
        FindingStatus.HIGH_CONFIDENCE_STATIC,
        complete_static_trace=True,
    )
    assert transitioned.status is FindingStatus.HIGH_CONFIDENCE_STATIC


def test_future_verification_and_finding_models_have_json_round_trip() -> None:
    case_content = {
        "target_tree_hash": TREE_HASH,
        "hypothesis_id": HYPOTHESIS_ID,
        "runtime_profile": "nextjs-postgres",
        "setup": {"fixture": "tenant-a-and-b"},
        "actor": {"identity": "tenant-a-user"},
        "action": {"protocol": "http", "method": "GET", "path": "/api/invoices/b"},
        "oracle": {"forbidden_status": 200},
        "limits": {"timeout_seconds": 30},
    }
    case = VerificationCase(
        schema_version=SCHEMA_VERSION,
        verification_id=stable_record_id("VER", case_content),
        target_id=TARGET_ID,
        target_tree_hash=TREE_HASH,
        hypothesis_id=HYPOTHESIS_ID,
        runtime_profile="nextjs-postgres",
        setup={"fixture": "tenant-a-and-b"},
        actor={"identity": "tenant-a-user"},
        action={"protocol": "http", "method": "GET", "path": "/api/invoices/b"},
        oracle={"forbidden_status": 200},
        limits={"timeout_seconds": 30},
    )
    result = _verification(VerificationStatus.PROVED)
    finding = transition_finding(_finding(), FindingStatus.VERIFIED, verification_result=result)

    for record in (_invariant(), case, result, finding):
        payload = record.to_dict()
        assert json.loads(json.dumps(payload, sort_keys=True)) == payload
