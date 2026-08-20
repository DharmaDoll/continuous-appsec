from __future__ import annotations

from pathlib import Path

import pytest

from whitebox_audit.verifier import parse_verifier_policy
from whitebox_audit.verifier_sandbox import (
    build_internal_network_create_argv,
    build_network_remove_argv,
    build_verifier_remove_argv,
    build_verifier_run_argv,
)

from .test_verifier import policy_document

RUN_ID = "RUN-20260817T000000Z-abcdef123456"
NETWORK = "wba-net-abcdef123456"
CONTAINER = "wba-verifier-abcdef123456"
VERIFIER_IMAGE = "example/verifier@sha256:" + "c" * 64


def _directories(tmp_path: Path) -> tuple[Path, Path, Path]:
    target = tmp_path / "target"
    case = tmp_path / "case"
    output = tmp_path / "output"
    target.mkdir()
    case.mkdir()
    output.mkdir()
    return target, case, output


def test_sandbox_argv_has_internal_network_and_mandatory_isolation(tmp_path: Path) -> None:
    policy = parse_verifier_policy(policy_document())
    target, case, output = _directories(tmp_path)

    network_argv = build_internal_network_create_argv(
        "/usr/bin/docker", network_name=NETWORK, audit_run_id=RUN_ID
    )
    run_argv = build_verifier_run_argv(
        "/usr/bin/docker",
        verifier_image=VERIFIER_IMAGE,
        container_name=CONTAINER,
        network_name=NETWORK,
        target_directory=target,
        input_directory=case,
        output_directory=output,
        policy=policy,
    )

    assert network_argv[:4] == ("/usr/bin/docker", "network", "create", "--internal")
    assert "--read-only" in run_argv
    assert run_argv[run_argv.index("--cap-drop") + 1] == "ALL"
    assert run_argv[run_argv.index("--security-opt") + 1] == "no-new-privileges"
    assert run_argv[run_argv.index("--pull") + 1] == "never"
    assert run_argv[run_argv.index("--network") + 1] == NETWORK
    assert any(value.endswith("dst=/target,readonly") for value in run_argv)
    assert any(value.endswith("dst=/case,readonly") for value in run_argv)
    assert any(value.endswith("dst=/output") for value in run_argv)
    assert "--privileged" not in run_argv
    assert all("docker.sock" not in value for value in run_argv)
    assert sum(value.startswith("type=bind,") for value in run_argv) == 3
    assert run_argv[-1] == VERIFIER_IMAGE
    assert build_network_remove_argv("docker", network_name=NETWORK) == (
        "docker",
        "network",
        "rm",
        NETWORK,
    )
    assert build_verifier_remove_argv("docker", container_name=CONTAINER) == (
        "docker",
        "rm",
        "--force",
        CONTAINER,
    )


def test_sandbox_argv_rejects_mutable_images_mount_injection_and_aliasing(
    tmp_path: Path,
) -> None:
    policy = parse_verifier_policy(policy_document())
    target, case, output = _directories(tmp_path)
    with pytest.raises(ValueError, match="immutable"):
        build_verifier_run_argv(
            "docker",
            verifier_image="example/verifier:latest",
            container_name=CONTAINER,
            network_name=NETWORK,
            target_directory=target,
            input_directory=case,
            output_directory=output,
            policy=policy,
        )

    unsafe = tmp_path / "unsafe,mount"
    unsafe.mkdir()
    with pytest.raises(ValueError, match="represented safely"):
        build_verifier_run_argv(
            "docker",
            verifier_image=VERIFIER_IMAGE,
            container_name=CONTAINER,
            network_name=NETWORK,
            target_directory=unsafe,
            input_directory=case,
            output_directory=output,
            policy=policy,
        )

    with pytest.raises(ValueError, match="distinct"):
        build_verifier_run_argv(
            "docker",
            verifier_image=VERIFIER_IMAGE,
            container_name=CONTAINER,
            network_name=NETWORK,
            target_directory=target,
            input_directory=case,
            output_directory=case,
            policy=policy,
        )
