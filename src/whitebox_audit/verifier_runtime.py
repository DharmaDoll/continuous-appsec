"""Fixed HTTP verifier runtime that alone may emit a VerificationResult."""

from __future__ import annotations

import hashlib
import http.client
import json
import re
import secrets
from collections.abc import Callable, Mapping
from contextlib import suppress
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Protocol, cast

from whitebox_audit import __version__
from whitebox_audit.models import (
    SCHEMA_VERSION,
    VerificationCase,
    VerificationResult,
    VerificationStatus,
)
from whitebox_audit.prepare import atomic_write_json, format_timestamp
from whitebox_audit.record_store import load_record_document
from whitebox_audit.verifier import (
    RuntimeAdapter,
    parse_runtime_adapter,
    parse_stored_verification_case,
    parse_verifier_policy,
    validate_digest_image,
)

_PATH_TOKEN = re.compile(r"\.([A-Za-z_][A-Za-z0-9_-]{0,63})|\[([0-9]{1,4})\]")
_IDENTIFIER = re.compile(r"[a-z][a-z0-9-]{0,63}\Z")
_MISSING = object()


class _Response(Protocol):
    status: int

    def read(self, amount: int | None = None) -> bytes: ...


class _Connection(Protocol):
    def request(
        self,
        method: str,
        url: str,
        body: bytes | None = None,
        headers: Mapping[str, str] | None = None,
    ) -> None: ...

    def getresponse(self) -> _Response: ...

    def close(self) -> None: ...


ConnectionFactory = Callable[[str, int, float], _Connection]


@dataclass(frozen=True, slots=True)
class FixtureSecrets:
    fixture: str
    tokens: Mapping[str, str]

    def __post_init__(self) -> None:
        if not self.fixture or len(self.fixture) > 64:
            raise ValueError("fixture secret document has an invalid fixture ID")
        if not self.tokens:
            raise ValueError("fixture secret document requires identity tokens")
        for identity, token in self.tokens.items():
            if (
                _IDENTIFIER.fullmatch(identity) is None
                or not token
                or len(token) > 8_192
                or "\x00" in token
                or "\r" in token
                or "\n" in token
            ):
                raise ValueError("fixture secret document contains an invalid token")


def parse_fixture_secrets(document: Mapping[str, object]) -> FixtureSecrets:
    if set(document) != {"schema_version", "fixture", "tokens"}:
        raise ValueError("fixture secret document fields are invalid")
    if document["schema_version"] != SCHEMA_VERSION:
        raise ValueError("unsupported fixture secret schema version")
    fixture = document["fixture"]
    tokens = document["tokens"]
    if not isinstance(fixture, str) or not isinstance(tokens, dict):
        raise ValueError("fixture secret document has invalid field types")
    if any(not isinstance(key, str) or not isinstance(value, str) for key, value in tokens.items()):
        raise ValueError("fixture tokens must map identity strings to token strings")
    return FixtureSecrets(
        fixture=fixture,
        tokens={cast(str, key): cast(str, value) for key, value in tokens.items()},
    )


def _default_connection(host: str, port: int, timeout: float) -> _Connection:
    return cast(_Connection, http.client.HTTPConnection(host, port, timeout=timeout))


def _object(value: object, label: str) -> dict[str, object]:
    if not isinstance(value, dict) or any(not isinstance(key, str) for key in value):
        raise ValueError(f"canonical {label} is invalid")
    return {cast(str, key): item for key, item in value.items()}


def _json_path_get(value: object, path: str) -> object:
    current = value
    for match in _PATH_TOKEN.finditer(path[1:]):
        key, raw_index = match.groups()
        if key is not None:
            if not isinstance(current, dict) or key not in current:
                return _MISSING
            current = current[key]
        else:
            if not isinstance(current, list):
                return _MISSING
            index = int(cast(str, raw_index))
            if index >= len(current):
                return _MISSING
            current = current[index]
    return current


def _json_equal(left: object, right: object) -> bool:
    return json.dumps(left, allow_nan=False, sort_keys=True) == json.dumps(
        right, allow_nan=False, sort_keys=True
    )


def _reject_json_constant(value: str) -> object:
    raise ValueError(f"non-standard JSON constant: {value}")


def _bounded_observed(value: object) -> object:
    if value is _MISSING:
        return {"missing": True}
    if isinstance(value, str):
        return {
            "redacted": True,
            "length": len(value),
            "sha256": hashlib.sha256(value.encode()).hexdigest(),
        }
    if isinstance(value, dict | list):
        encoded = json.dumps(value, allow_nan=False, ensure_ascii=False, sort_keys=True).encode()
        return {
            "redacted": True,
            "length": len(encoded),
            "sha256": hashlib.sha256(encoded).hexdigest(),
        }
    return value


def _evaluate_oracle(case: VerificationCase, status: int, body: bytes) -> dict[str, object]:
    oracle = _object(case.oracle, "oracle")
    forbidden_status = oracle["forbidden_status"]
    checks: list[bool] = []
    if forbidden_status is not None:
        checks.append(status == forbidden_status)
    raw_assertions = oracle["json_assertions"]
    if not isinstance(raw_assertions, list):
        raise ValueError("canonical oracle assertions are invalid")
    parsed_json: object = _MISSING
    json_error = False
    if raw_assertions:
        try:
            parsed_json = json.loads(body.decode("utf-8"), parse_constant=_reject_json_constant)
        except (UnicodeError, json.JSONDecodeError, RecursionError, ValueError):
            json_error = True
    observations: list[object] = []
    for raw_assertion in raw_assertions:
        assertion = _object(raw_assertion, "oracle assertion")
        path = assertion["path"]
        if not isinstance(path, str):
            raise ValueError("canonical oracle assertion path is invalid")
        actual = _MISSING if json_error else _json_path_get(parsed_json, path)
        matched = actual is not _MISSING and _json_equal(actual, assertion["equals"])
        checks.append(matched)
        observations.append(
            {
                "path": path,
                "expected": assertion["equals"],
                "actual": _bounded_observed(actual),
                "matched": matched,
            }
        )
    return {
        "forbidden_status": forbidden_status,
        "observed_status": status,
        "json_valid": not json_error,
        "assertions": observations,
        "violated": bool(checks) and all(checks),
    }


def execute_http_verification_case(
    case: VerificationCase,
    adapter: RuntimeAdapter,
    fixture_secrets: FixtureSecrets,
    *,
    verifier_image: str,
    connection_factory: ConnectionFactory = _default_connection,
    now: Callable[[], datetime] = lambda: datetime.now(UTC),
) -> VerificationResult:
    """Execute one canonical case without accepting executable input from the case."""

    if case.runtime_profile != adapter.name or case.adapter_fingerprint != adapter.fingerprint:
        raise ValueError("verification case does not match the runtime adapter")
    image = validate_digest_image(verifier_image, "verifier image")
    setup = _object(case.setup, "setup")
    actor = _object(case.actor, "actor")
    action = _object(case.action, "action")
    limits = _object(case.limits, "limits")
    fixture = setup["fixture"]
    identity = actor["identity"]
    if fixture != fixture_secrets.fixture or not isinstance(identity, str):
        raise ValueError("verification case does not match fixture secrets")
    token = fixture_secrets.tokens.get(identity)
    if token is None:
        raise ValueError("selected fixture identity has no token")
    raw_headers = _object(action["headers"], "action headers")
    headers: dict[str, str] = {}
    template = f"${{fixture.token.{identity}}}"
    for name, raw_value in raw_headers.items():
        if not isinstance(raw_value, str):
            raise ValueError("canonical action header is invalid")
        if name == "authorization":
            if raw_value != template:
                raise ValueError("canonical Authorization template is invalid")
            headers[name] = token
        else:
            if "${" in raw_value:
                raise ValueError("canonical action header contains an invalid template")
            headers[name] = raw_value
    raw_body = action["body"]
    body = (
        None
        if raw_body is None
        else json.dumps(
            raw_body,
            allow_nan=False,
            ensure_ascii=False,
            separators=(",", ":"),
            sort_keys=True,
        ).encode()
    )
    timeout = limits["timeout_seconds"]
    response_limit = limits["max_response_body_bytes"]
    if not isinstance(timeout, int) or not isinstance(response_limit, int):
        raise ValueError("canonical case limits are invalid")
    started_at = now()
    verifier_run_id = f"VRUN-{secrets.token_hex(10)}"
    connection: _Connection | None = None
    try:
        connection = connection_factory(adapter.service_host, adapter.service_port, float(timeout))
        connection.request(
            cast(str, action["method"]),
            cast(str, action["path"]),
            body=body,
            headers=headers,
        )
        response = connection.getresponse()
        response_body = response.read(response_limit + 1)
        if len(response_body) > response_limit:
            status = VerificationStatus.INCONCLUSIVE
            observation: dict[str, object] = {
                "type": "http-response",
                "status": response.status,
                "body_truncated": True,
                "body_limit": response_limit,
            }
            oracle = {"violated": False, "reason": "response-body-limit"}
        else:
            oracle = _evaluate_oracle(case, response.status, response_body)
            status = (
                VerificationStatus.PROVED
                if oracle["violated"] is True
                else VerificationStatus.NOT_PROVED
            )
            observation = {
                "type": "http-response",
                "status": response.status,
                "body_bytes": len(response_body),
                "body_sha256": hashlib.sha256(response_body).hexdigest(),
                "body_truncated": False,
            }
    except (OSError, http.client.HTTPException):
        status = VerificationStatus.ERROR
        observation = {"type": "execution-error", "category": "http-transport"}
        oracle = {"violated": False, "reason": "http-transport-error"}
    finally:
        if connection is not None:
            with suppress(OSError, http.client.HTTPException):
                connection.close()
    finished_at = now()
    return VerificationResult(
        schema_version=SCHEMA_VERSION,
        verification_id=case.verification_id,
        verifier_run_id=verifier_run_id,
        target_tree_hash=case.target_tree_hash,
        status=status,
        observations=(observation,),
        oracle=oracle,
        started_at=format_timestamp(started_at),
        finished_at=format_timestamp(finished_at),
        verifier_version=__version__,
        verifier_image=image,
        policy_fingerprint=case.policy_fingerprint,
    )


def run_fixed_verifier(
    input_directory: Path,
    output_directory: Path,
    *,
    connection_factory: ConnectionFactory = _default_connection,
) -> VerificationResult:
    """Load fixed filenames and atomically emit the only verifier result artifact."""

    if input_directory.is_symlink() or output_directory.is_symlink():
        raise ValueError("verifier input/output directories cannot be symlinks")
    if not input_directory.is_dir() or not output_directory.is_dir():
        raise ValueError("verifier input/output directories must exist")
    policy_document, _policy_raw, _policy_suffix = load_record_document(
        input_directory / "policy.json"
    )
    adapter_document, _adapter_raw, _adapter_suffix = load_record_document(
        input_directory / "adapter.json"
    )
    case_document, _case_raw, _case_suffix = load_record_document(input_directory / "case.json")
    fixture_document, _fixture_raw, _fixture_suffix = load_record_document(
        input_directory / "fixture.json"
    )
    execution_document, _execution_raw, _execution_suffix = load_record_document(
        input_directory / "execution.json"
    )
    if set(execution_document) != {"schema_version", "verifier_image"}:
        raise ValueError("verifier execution document fields are invalid")
    if execution_document["schema_version"] != SCHEMA_VERSION or not isinstance(
        execution_document["verifier_image"], str
    ):
        raise ValueError("verifier execution document is invalid")
    policy = parse_verifier_policy(policy_document)
    adapter = parse_runtime_adapter(adapter_document, policy)
    case = parse_stored_verification_case(case_document, policy=policy, adapter=adapter)
    fixture_secrets = parse_fixture_secrets(fixture_document)
    result = execute_http_verification_case(
        case,
        adapter,
        fixture_secrets,
        verifier_image=execution_document["verifier_image"],
        connection_factory=connection_factory,
    )
    atomic_write_json(output_directory / "result.json", result.to_dict())
    return result


def entrypoint() -> None:
    run_fixed_verifier(Path("/case"), Path("/output"))


if __name__ == "__main__":
    entrypoint()
