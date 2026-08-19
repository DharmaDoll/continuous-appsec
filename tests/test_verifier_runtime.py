from __future__ import annotations

import json
from collections.abc import Mapping
from datetime import UTC, datetime
from pathlib import Path

from whitebox_audit.models import VerificationCase, VerificationStatus
from whitebox_audit.verifier import (
    RuntimeAdapter,
    create_http_verification_case,
    parse_runtime_adapter,
    parse_verifier_policy,
)
from whitebox_audit.verifier_runtime import (
    FixtureSecrets,
    execute_http_verification_case,
    run_fixed_verifier,
)

from .test_verifier import TARGET_ID, TREE_HASH, adapter_document, case_document, policy_document

VERIFIER_IMAGE = "example/verifier@sha256:" + "c" * 64


class FakeResponse:
    def __init__(self, status: int, body: bytes) -> None:
        self.status = status
        self.body = body

    def read(self, amount: int | None = None) -> bytes:
        return self.body if amount is None else self.body[:amount]


class FakeConnection:
    def __init__(self, response: FakeResponse) -> None:
        self.response = response
        self.request_headers: Mapping[str, str] | None = None
        self.closed = False

    def request(
        self,
        method: str,
        url: str,
        body: bytes | None = None,
        headers: Mapping[str, str] | None = None,
    ) -> None:
        del method, url, body
        self.request_headers = headers

    def getresponse(self) -> FakeResponse:
        return self.response

    def close(self) -> None:
        self.closed = True


class FakeConnectionFactory:
    def __init__(self, connection: FakeConnection) -> None:
        self.connection = connection

    def __call__(self, _host: str, _port: int, _timeout: float) -> FakeConnection:
        return self.connection


def _case() -> tuple[VerificationCase, RuntimeAdapter]:
    policy = parse_verifier_policy(policy_document())
    adapter = parse_runtime_adapter(adapter_document(), policy)
    case = create_http_verification_case(
        case_document(),
        target_id=TARGET_ID,
        target_tree_hash=TREE_HASH,
        policy=policy,
        adapter=adapter,
    )
    return case, adapter


def test_fixed_runtime_proves_or_does_not_prove_only_from_observations() -> None:
    case, adapter = _case()
    connection = FakeConnection(FakeResponse(200, b'{"tenant_id":"tenant-b"}'))
    times = iter(
        (
            datetime(2026, 8, 17, 0, 0, 0, tzinfo=UTC),
            datetime(2026, 8, 17, 0, 0, 1, tzinfo=UTC),
        )
    )
    secrets = FixtureSecrets("tenant-a-and-b", {"tenant-a-user": "ephemeral-secret"})

    result = execute_http_verification_case(
        case,
        adapter,
        secrets,
        verifier_image=VERIFIER_IMAGE,
        connection_factory=lambda _host, _port, _timeout: connection,
        now=lambda: next(times),
    )

    assert result.status is VerificationStatus.PROVED
    assert result.oracle["violated"] is True
    assert connection.request_headers is not None
    assert connection.request_headers["authorization"] == "ephemeral-secret"
    assert "ephemeral-secret" not in json.dumps(result.to_dict())
    assert connection.closed is True

    safe_connection = FakeConnection(FakeResponse(403, b'{"tenant_id":"sensitive-tenant-secret"}'))
    safe_result = execute_http_verification_case(
        case,
        adapter,
        secrets,
        verifier_image=VERIFIER_IMAGE,
        connection_factory=lambda _host, _port, _timeout: safe_connection,
    )
    assert safe_result.status is VerificationStatus.NOT_PROVED
    assert safe_result.oracle["violated"] is False
    assert "sensitive-tenant-secret" not in json.dumps(safe_result.to_dict())
    assertions = safe_result.oracle["assertions"]
    assert isinstance(assertions, list)
    assert isinstance(assertions[0], dict)
    actual = assertions[0]["actual"]
    assert isinstance(actual, dict)
    assert actual["redacted"] is True
    assert actual["length"] == len("sensitive-tenant-secret")


def test_fixed_runtime_bounds_responses_and_classifies_transport_errors() -> None:
    case, adapter = _case()
    secrets = FixtureSecrets("tenant-a-and-b", {"tenant-a-user": "ephemeral-secret"})
    oversized = FakeConnection(FakeResponse(200, b"x" * 65_537))

    limited = execute_http_verification_case(
        case,
        adapter,
        secrets,
        verifier_image=VERIFIER_IMAGE,
        connection_factory=lambda _host, _port, _timeout: oversized,
    )
    assert limited.status is VerificationStatus.INCONCLUSIVE
    assert limited.oracle["reason"] == "response-body-limit"

    def fail_connection(_host: str, _port: int, _timeout: float) -> FakeConnection:
        raise OSError("connection refused")

    failed = execute_http_verification_case(
        case,
        adapter,
        secrets,
        verifier_image=VERIFIER_IMAGE,
        connection_factory=fail_connection,
    )
    assert failed.status is VerificationStatus.ERROR
    assert failed.observations == ({"type": "execution-error", "category": "http-transport"},)


def test_fixed_runtime_treats_nonstandard_or_pathological_json_as_not_proved() -> None:
    case, adapter = _case()
    secrets = FixtureSecrets("tenant-a-and-b", {"tenant-a-user": "ephemeral-secret"})

    oversized_integer = b'{"tenant_id":' + b"9" * 5_000 + b"}"
    for body in (b'{"tenant_id":NaN}', oversized_integer):
        connection = FakeConnection(FakeResponse(200, body))
        result = execute_http_verification_case(
            case,
            adapter,
            secrets,
            verifier_image=VERIFIER_IMAGE,
            connection_factory=FakeConnectionFactory(connection),
        )

        assert result.status is VerificationStatus.NOT_PROVED
        assert result.oracle["json_valid"] is False


def test_fixed_entrypoint_reads_only_fixed_inputs_and_writes_result(tmp_path: Path) -> None:
    case, adapter = _case()
    policy = parse_verifier_policy(policy_document())
    input_directory = tmp_path / "case"
    output_directory = tmp_path / "output"
    input_directory.mkdir()
    output_directory.mkdir()
    documents = {
        "policy.json": policy.to_dict(),
        "adapter.json": adapter.to_dict(),
        "case.json": case.to_dict(),
        "fixture.json": {
            "schema_version": 1,
            "fixture": "tenant-a-and-b",
            "tokens": {"tenant-a-user": "ephemeral-secret"},
        },
        "execution.json": {"schema_version": 1, "verifier_image": VERIFIER_IMAGE},
    }
    for name, document in documents.items():
        (input_directory / name).write_text(json.dumps(document), encoding="utf-8")
    connection = FakeConnection(FakeResponse(200, b'{"tenant_id":"tenant-b"}'))

    result = run_fixed_verifier(
        input_directory,
        output_directory,
        connection_factory=lambda _host, _port, _timeout: connection,
    )

    persisted = json.loads((output_directory / "result.json").read_text())
    assert result.status is VerificationStatus.PROVED
    assert persisted["status"] == "proved"
    assert persisted["verifier_image"] == VERIFIER_IMAGE
    assert persisted["policy_fingerprint"] == policy.fingerprint
    assert "ephemeral-secret" not in json.dumps(persisted)
