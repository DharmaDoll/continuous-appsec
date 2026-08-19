"""Pure Docker command construction for the least-privilege verifier sandbox."""

from __future__ import annotations

import re
import stat
from pathlib import Path
from typing import Final

from whitebox_audit.prepare import validate_run_id
from whitebox_audit.verifier import VerifierPolicy, validate_digest_image

_NETWORK_NAME: Final[re.Pattern[str]] = re.compile(r"wba-net-[0-9a-f]{12,64}\Z")
_CONTAINER_NAME: Final[re.Pattern[str]] = re.compile(r"wba-verifier-[0-9a-f]{12,64}\Z")
_TMPFS_BYTES: Final[int] = 128 * 1024 * 1024


def _executable(value: str) -> str:
    if not value or "\x00" in value or "\r" in value or "\n" in value:
        raise ValueError("Docker executable is invalid")
    return value


def _network_name(value: str) -> str:
    if _NETWORK_NAME.fullmatch(value) is None:
        raise ValueError("invalid verifier network name")
    return value


def _mount_directory(path: Path, label: str) -> Path:
    try:
        metadata = path.stat(follow_symlinks=False)
        resolved = path.resolve(strict=True)
    except OSError as error:
        raise ValueError(f"{label} mount directory does not exist") from error
    rendered = str(resolved)
    if path.is_symlink() or not stat.S_ISDIR(metadata.st_mode) or not resolved.is_dir():
        raise ValueError(f"{label} mount must be a real directory")
    if "," in rendered or "\x00" in rendered or "\r" in rendered or "\n" in rendered:
        raise ValueError(f"{label} mount path cannot be represented safely")
    return resolved


def build_internal_network_create_argv(
    docker_executable: str,
    *,
    network_name: str,
    audit_run_id: str,
) -> tuple[str, ...]:
    return (
        _executable(docker_executable),
        "network",
        "create",
        "--internal",
        "--label",
        "whitebox-audit.component=verifier",
        "--label",
        f"whitebox-audit.run={validate_run_id(audit_run_id)}",
        _network_name(network_name),
    )


def build_network_remove_argv(docker_executable: str, *, network_name: str) -> tuple[str, ...]:
    return (_executable(docker_executable), "network", "rm", _network_name(network_name))


def build_verifier_remove_argv(docker_executable: str, *, container_name: str) -> tuple[str, ...]:
    if _CONTAINER_NAME.fullmatch(container_name) is None:
        raise ValueError("invalid verifier container name")
    return (_executable(docker_executable), "rm", "--force", container_name)


def build_verifier_run_argv(
    docker_executable: str,
    *,
    verifier_image: str,
    container_name: str,
    network_name: str,
    target_directory: Path,
    input_directory: Path,
    output_directory: Path,
    policy: VerifierPolicy,
) -> tuple[str, ...]:
    if _CONTAINER_NAME.fullmatch(container_name) is None:
        raise ValueError("invalid verifier container name")
    if not policy.internal_network_allowed or policy.external_egress_allowed:
        raise ValueError("verifier policy does not permit an isolated internal network")
    target = _mount_directory(target_directory, "target")
    case_input = _mount_directory(input_directory, "case")
    output = _mount_directory(output_directory, "output")
    if len({target, case_input, output}) != 3:
        raise ValueError("verifier mount directories must be distinct")
    image = validate_digest_image(verifier_image, "verifier image")
    return (
        _executable(docker_executable),
        "run",
        "--rm",
        "--pull",
        "never",
        "--name",
        container_name,
        "--label",
        "whitebox-audit.component=verifier",
        "--network",
        _network_name(network_name),
        "--read-only",
        "--cap-drop",
        "ALL",
        "--security-opt",
        "no-new-privileges",
        "--pids-limit",
        str(policy.max_pids),
        "--memory",
        str(policy.max_memory_bytes),
        "--cpus",
        format(policy.max_cpu_count, "g"),
        "--tmpfs",
        f"/tmp:rw,noexec,nosuid,nodev,size={_TMPFS_BYTES}",
        "--mount",
        f"type=bind,src={target},dst=/target,readonly",
        "--mount",
        f"type=bind,src={case_input},dst=/case,readonly",
        "--mount",
        f"type=bind,src={output},dst=/output",
        image,
    )
