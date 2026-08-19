from __future__ import annotations

from copy import deepcopy
from pathlib import Path
from typing import cast

import pytest

from whitebox_audit.record_store import load_record_document
from whitebox_audit.verifier import (
    create_http_verification_case,
    parse_runtime_adapter,
    parse_stored_verification_case,
    parse_verifier_policy,
)

TARGET_ID = "TGT-" + "1" * 20
TREE_HASH = "a" * 64
HYPOTHESIS_ID = "HYP-" + "2" * 20


def policy_document() -> dict[str, object]:
    return {
        "schema_version": 1,
        "network": {"default": "none", "internal_allowed": True, "external_egress": False},
        "filesystem": {
            "root_read_only": True,
            "target_read_only": True,
            "case_read_only": True,
            "output_only_writable": True,
            "docker_socket": False,
            "host_home": False,
        },
        "capabilities": {"drop_all": True, "no_new_privileges": True},
        "limits": {
            "timeout_seconds": 30,
            "memory_bytes": 1_073_741_824,
            "cpu_count": 1.0,
            "pids": 256,
            "request_body_bytes": 65_536,
            "response_body_bytes": 262_144,
            "json_assertions": 8,
        },
        "http": {
            "methods": ["GET", "POST", "PATCH"],
            "headers": ["accept", "authorization", "content-type"],
        },
        "image": {"require_digest": True},
    }


def adapter_document() -> dict[str, object]:
    return {
        "schema_version": 1,
        "name": "nextjs-postgres",
        "image": "example/fixture@sha256:" + "b" * 64,
        "command_id": "start-app",
        "service": {"host": "app", "port": 3000},
        "health": {"path": "/health", "timeout_seconds": 10},
        "fixtures": ["tenant-a-and-b"],
        "identities": ["tenant-a-user", "tenant-b-user"],
    }


def case_document() -> dict[str, object]:
    return {
        "schema_version": 1,
        "hypothesis_id": HYPOTHESIS_ID,
        "runtime_profile": "nextjs-postgres",
        "setup": {"fixture": "tenant-a-and-b"},
        "actor": {"identity": "tenant-a-user"},
        "action": {
            "protocol": "http",
            "method": "get",
            "path": "/api/invoices/tenant-b?view=full",
            "headers": {
                "Accept": "application/json",
                "Authorization": "${fixture.token.tenant-a-user}",
            },
        },
        "oracle": {
            "forbidden_status": 200,
            "json_assertions": [{"path": "$.tenant_id", "equals": "tenant-b"}],
        },
        "limits": {"timeout_seconds": 10, "max_response_body_bytes": 65_536},
    }


def _nested(document: dict[str, object], key: str) -> dict[str, object]:
    return cast(dict[str, object], document[key])


def test_policy_adapter_and_http_case_are_canonical_and_stable() -> None:
    policy = parse_verifier_policy(policy_document())
    adapter = parse_runtime_adapter(adapter_document(), policy)
    first = create_http_verification_case(
        case_document(),
        target_id=TARGET_ID,
        target_tree_hash=TREE_HASH,
        policy=policy,
        adapter=adapter,
    )
    second = create_http_verification_case(
        case_document(),
        target_id=TARGET_ID,
        target_tree_hash=TREE_HASH,
        policy=policy,
        adapter=adapter,
    )

    assert first == second
    assert first.policy_fingerprint == policy.fingerprint
    assert first.adapter_fingerprint == adapter.fingerprint
    assert first.action["method"] == "GET"
    assert first.action["headers"] == {
        "accept": "application/json",
        "authorization": "${fixture.token.tenant-a-user}",
    }
    assert parse_stored_verification_case(first.to_dict(), policy=policy, adapter=adapter) == first


def test_repository_default_policy_matches_the_strict_schema() -> None:
    policy_path = Path(__file__).parents[1] / "config" / "verifier-policy.yaml"
    document, _raw, _suffix = load_record_document(policy_path)

    policy = parse_verifier_policy(document)

    assert policy.network_default == "none"
    assert policy.external_egress_allowed is False
    assert len(policy.fingerprint) == 64


def test_policy_rejects_unknown_fields_and_isolation_relaxation() -> None:
    unknown = policy_document()
    unknown["discovery_override"] = True
    with pytest.raises(ValueError, match="unknown"):
        parse_verifier_policy(unknown)

    external = policy_document()
    _nested(external, "network")["external_egress"] = True
    with pytest.raises(ValueError, match="external network"):
        parse_verifier_policy(external)

    docker_socket = policy_document()
    _nested(docker_socket, "filesystem")["docker_socket"] = True
    with pytest.raises(ValueError, match="host authority"):
        parse_verifier_policy(docker_socket)

    excessive = policy_document()
    _nested(excessive, "limits")["timeout_seconds"] = 3_600
    with pytest.raises(ValueError, match="timeout"):
        parse_verifier_policy(excessive)


def test_http_case_rejects_shell_remote_paths_templates_and_policy_bypass() -> None:
    policy = parse_verifier_policy(policy_document())
    adapter = parse_runtime_adapter(adapter_document(), policy)

    shell = deepcopy(case_document())
    _nested(shell, "action")["shell"] = "id"
    with pytest.raises(ValueError, match="unknown"):
        create_http_verification_case(
            shell,
            target_id=TARGET_ID,
            target_tree_hash=TREE_HASH,
            policy=policy,
            adapter=adapter,
        )

    host_path = deepcopy(case_document())
    _nested(host_path, "action")["host_path"] = "/etc/passwd"
    with pytest.raises(ValueError, match="unknown"):
        create_http_verification_case(
            host_path,
            target_id=TARGET_ID,
            target_tree_hash=TREE_HASH,
            policy=policy,
            adapter=adapter,
        )

    remote = deepcopy(case_document())
    _nested(remote, "action")["path"] = "https://attacker.invalid/collect"
    with pytest.raises(ValueError, match="local"):
        create_http_verification_case(
            remote,
            target_id=TARGET_ID,
            target_tree_hash=TREE_HASH,
            policy=policy,
            adapter=adapter,
        )

    literal_token = deepcopy(case_document())
    headers = _nested(_nested(literal_token, "action"), "headers")
    headers["Authorization"] = "Bearer production-secret"
    with pytest.raises(ValueError, match="fixture identity"):
        create_http_verification_case(
            literal_token,
            target_id=TARGET_ID,
            target_tree_hash=TREE_HASH,
            policy=policy,
            adapter=adapter,
        )

    excessive = deepcopy(case_document())
    _nested(excessive, "limits")["timeout_seconds"] = 31
    with pytest.raises(ValueError, match="timeout"):
        create_http_verification_case(
            excessive,
            target_id=TARGET_ID,
            target_tree_hash=TREE_HASH,
            policy=policy,
            adapter=adapter,
        )

    unsafe_json_path = deepcopy(case_document())
    assertions = cast(
        list[dict[str, object]], _nested(unsafe_json_path, "oracle")["json_assertions"]
    )
    assertions[0]["path"] = "$..token"
    with pytest.raises(ValueError, match="JSON path subset"):
        create_http_verification_case(
            unsafe_json_path,
            target_id=TARGET_ID,
            target_tree_hash=TREE_HASH,
            policy=policy,
            adapter=adapter,
        )

    environment_body = deepcopy(case_document())
    _nested(environment_body, "action")["method"] = "POST"
    _nested(environment_body, "action")["body"] = {"token": "${env.AWS_SECRET_ACCESS_KEY}"}
    with pytest.raises(ValueError, match="environment/template"):
        create_http_verification_case(
            environment_body,
            target_id=TARGET_ID,
            target_tree_hash=TREE_HASH,
            policy=policy,
            adapter=adapter,
        )

    no_internal_document = policy_document()
    _nested(no_internal_document, "network")["internal_allowed"] = False
    no_internal_policy = parse_verifier_policy(no_internal_document)
    no_internal_adapter = parse_runtime_adapter(adapter_document(), no_internal_policy)
    with pytest.raises(ValueError, match="internal network"):
        create_http_verification_case(
            case_document(),
            target_id=TARGET_ID,
            target_tree_hash=TREE_HASH,
            policy=no_internal_policy,
            adapter=no_internal_adapter,
        )


def test_runtime_adapter_rejects_mutable_images_and_target_commands() -> None:
    policy = parse_verifier_policy(policy_document())
    mutable = adapter_document()
    mutable["image"] = "example/fixture:latest"
    with pytest.raises(ValueError, match="immutable"):
        parse_runtime_adapter(mutable, policy)

    target_command = adapter_document()
    target_command["start_command"] = ["npm", "run", "dev"]
    with pytest.raises(ValueError, match="unknown"):
        parse_runtime_adapter(target_command, policy)


def test_http_case_enforces_adapter_allowlists_and_all_payload_limits() -> None:
    policy = parse_verifier_policy(policy_document())
    adapter = parse_runtime_adapter(adapter_document(), policy)

    unknown_fixture = deepcopy(case_document())
    _nested(unknown_fixture, "setup")["fixture"] = "production-data"
    with pytest.raises(ValueError, match="fixture"):
        create_http_verification_case(
            unknown_fixture,
            target_id=TARGET_ID,
            target_tree_hash=TREE_HASH,
            policy=policy,
            adapter=adapter,
        )

    header_injection = deepcopy(case_document())
    headers = _nested(_nested(header_injection, "action"), "headers")
    headers["Accept"] = "application/json\r\nHost: attacker.invalid"
    with pytest.raises(ValueError, match="line breaks"):
        create_http_verification_case(
            header_injection,
            target_id=TARGET_ID,
            target_tree_hash=TREE_HASH,
            policy=policy,
            adapter=adapter,
        )

    oversized_body = deepcopy(case_document())
    _nested(oversized_body, "action")["method"] = "POST"
    _nested(oversized_body, "action")["body"] = {"value": "x" * 65_536}
    with pytest.raises(ValueError, match="request body"):
        create_http_verification_case(
            oversized_body,
            target_id=TARGET_ID,
            target_tree_hash=TREE_HASH,
            policy=policy,
            adapter=adapter,
        )

    oversized_response = deepcopy(case_document())
    _nested(oversized_response, "limits")["max_response_body_bytes"] = 262_145
    with pytest.raises(ValueError, match="response_body"):
        create_http_verification_case(
            oversized_response,
            target_id=TARGET_ID,
            target_tree_hash=TREE_HASH,
            policy=policy,
            adapter=adapter,
        )

    excessive_assertions = deepcopy(case_document())
    _nested(excessive_assertions, "oracle")["json_assertions"] = [
        {"path": "$.tenant_id", "equals": "tenant-b"}
    ] * 9
    with pytest.raises(ValueError, match="json_assertions"):
        create_http_verification_case(
            excessive_assertions,
            target_id=TARGET_ID,
            target_tree_hash=TREE_HASH,
            policy=policy,
            adapter=adapter,
        )
