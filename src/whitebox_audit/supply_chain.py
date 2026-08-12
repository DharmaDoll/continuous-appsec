"""Native supply-chain policy checks for the audit harness itself."""

from __future__ import annotations

import hashlib
import os
import re
import shutil
import subprocess
import tomllib
from collections.abc import Mapping, Sequence
from dataclasses import asdict, dataclass
from enum import StrEnum
from pathlib import Path
from typing import Final
from urllib.parse import urlparse

from whitebox_audit.doctor import minimal_env, redact_output
from whitebox_audit.errors import ExitCode, WhiteboxAuditError

LOCK_SCHEMA_VERSION: Final[int] = 1
PROJECT_NAME: Final[str] = "whitebox-ai-audit"
APPROVED_REGISTRY: Final[str] = "https://pypi.org/simple"
APPROVED_ARTIFACT_HOST: Final[str] = "files.pythonhosted.org"
REQUIRED_EXCLUDE_NEWER: Final[str] = "72 hours"
DEFAULT_TIMEOUT_SECONDS: Final[float] = 30.0

_SHA256_PATTERN: Final[re.Pattern[str]] = re.compile(r"sha256:[0-9a-f]{64}\Z")
_EXACT_REQUIREMENT_PATTERN: Final[re.Pattern[str]] = re.compile(
    r"^[A-Za-z0-9_.-]+(?:\[[A-Za-z0-9_,.-]+\])?==[^\s;*]+(?:\s*;\s*.+)?\Z"
)
_DIRECT_REFERENCE_MARKERS: Final[tuple[str, ...]] = (
    " @ ",
    "git+",
    "http://",
    "https://",
    "file:",
)


class SupplyChainStatus(StrEnum):
    PASS = "pass"
    FAIL = "fail"


@dataclass(frozen=True, slots=True)
class SupplyChainCheck:
    check_id: str
    status: SupplyChainStatus
    detail: str

    def to_dict(self) -> dict[str, object]:
        return asdict(self)


@dataclass(frozen=True, slots=True)
class SupplyChainReport:
    project_root: str
    lock_sha256: str | None
    package_count: int
    checks: tuple[SupplyChainCheck, ...]

    @property
    def ok(self) -> bool:
        return all(check.status is SupplyChainStatus.PASS for check in self.checks)

    @property
    def exit_code(self) -> ExitCode:
        return ExitCode.OK if self.ok else ExitCode.POLICY_REJECTED

    def to_dict(self) -> dict[str, object]:
        return {
            "schema_version": 1,
            "ok": self.ok,
            "exit_code": int(self.exit_code),
            "project_root": self.project_root,
            "lock_sha256": self.lock_sha256,
            "package_count": self.package_count,
            "checks": [check.to_dict() for check in self.checks],
        }


def _pass(check_id: str, detail: str) -> SupplyChainCheck:
    return SupplyChainCheck(check_id, SupplyChainStatus.PASS, detail)


def _fail(check_id: str, detail: str) -> SupplyChainCheck:
    return SupplyChainCheck(check_id, SupplyChainStatus.FAIL, detail)


def _load_toml(path: Path) -> dict[str, object]:
    try:
        document = tomllib.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, tomllib.TOMLDecodeError) as error:
        raise WhiteboxAuditError(
            f"cannot parse {path.name}: {redact_output(str(error))}",
            ExitCode.DATA_INTEGRITY_ERROR,
        ) from error
    return document


def _table(value: object) -> dict[str, object]:
    if not isinstance(value, dict):
        return {}
    return {str(key): item for key, item in value.items()}


def _string_list(value: object) -> list[str]:
    if not isinstance(value, list):
        return []
    return [item for item in value if isinstance(item, str)]


def _declared_requirements(pyproject: Mapping[str, object]) -> list[str]:
    project = _table(pyproject.get("project"))
    build_system = _table(pyproject.get("build-system"))
    requirements = _string_list(project.get("dependencies"))
    requirements.extend(_string_list(build_system.get("requires")))

    optional = _table(project.get("optional-dependencies"))
    for group in optional.values():
        requirements.extend(_string_list(group))

    dependency_groups = _table(pyproject.get("dependency-groups"))
    for group in dependency_groups.values():
        requirements.extend(_string_list(group))
    return requirements


def _check_declared_dependencies(
    pyproject: Mapping[str, object], uv_config: Mapping[str, object]
) -> SupplyChainCheck:
    requirements = _declared_requirements(pyproject)
    unsafe = [
        requirement
        for requirement in requirements
        if any(marker in requirement.lower() for marker in _DIRECT_REFERENCE_MARKERS)
    ]
    unpinned = [
        requirement
        for requirement in requirements
        if not _EXACT_REQUIREMENT_PATTERN.fullmatch(requirement)
    ]

    forbidden_uv_keys = {
        "sources",
        "index",
        "default-index",
        "index-url",
        "extra-index-url",
        "find-links",
        "no-index",
    }
    configured_sources = sorted(key for key in forbidden_uv_keys if uv_config.get(key))

    failures: list[str] = []
    if unsafe:
        failures.append(f"direct references are forbidden: {', '.join(sorted(unsafe))}")
    if unpinned:
        failures.append(f"requirements must use exact == pins: {', '.join(sorted(unpinned))}")
    if configured_sources:
        failures.append(f"alternate uv sources are forbidden: {', '.join(configured_sources)}")
    if failures:
        return _fail("SC-DECLARED-DEPS", "; ".join(failures))
    return _pass(
        "SC-DECLARED-DEPS",
        f"{len(requirements)} direct/build requirements are exact pins with no direct references",
    )


def _check_uv_policy(uv_config: Mapping[str, object]) -> SupplyChainCheck:
    exclude_newer = uv_config.get("exclude-newer")
    if exclude_newer != REQUIRED_EXCLUDE_NEWER:
        return _fail(
            "SC-DEPENDENCY-COOLDOWN",
            f"tool.uv.exclude-newer must be {REQUIRED_EXCLUDE_NEWER!r}",
        )
    return _pass(
        "SC-DEPENDENCY-COOLDOWN",
        f"new releases are held back for {REQUIRED_EXCLUDE_NEWER}",
    )


def _packages(lock: Mapping[str, object]) -> list[dict[str, object]]:
    value = lock.get("package")
    if not isinstance(value, list):
        return []
    return [_table(item) for item in value if isinstance(item, dict)]


def _check_lock_metadata(
    lock: Mapping[str, object], packages: Sequence[dict[str, object]]
) -> SupplyChainCheck:
    failures: list[str] = []
    if lock.get("version") != LOCK_SCHEMA_VERSION:
        failures.append(f"lock schema version must be {LOCK_SCHEMA_VERSION}")
    if not isinstance(lock.get("revision"), int):
        failures.append("lock revision is missing")
    options = _table(lock.get("options"))
    if options.get("exclude-newer-span") != "PT72H":
        failures.append("resolved 72-hour dependency cooldown is missing")
    if not packages:
        failures.append("lock contains no packages")
    if failures:
        return _fail("SC-LOCK-METADATA", "; ".join(failures))
    return _pass("SC-LOCK-METADATA", f"lock schema and {len(packages)} packages are valid")


def _check_lock_sources(packages: Sequence[dict[str, object]]) -> SupplyChainCheck:
    failures: list[str] = []
    for package in packages:
        name = package.get("name")
        label = name if isinstance(name, str) else "<unnamed>"
        source = _table(package.get("source"))
        if source.get("registry") == APPROVED_REGISTRY and len(source) == 1:
            version = package.get("version")
            if not isinstance(version, str) or not version:
                failures.append(f"{label}: registry package has no exact version")
            continue
        if label == PROJECT_NAME and source == {"editable": "."}:
            continue
        failures.append(f"{label}: unapproved source {source!r}")
    if failures:
        return _fail("SC-LOCK-SOURCES", "; ".join(failures))
    return _pass(
        "SC-LOCK-SOURCES",
        f"all third-party packages resolve only from {APPROVED_REGISTRY}",
    )


def _artifact_error(package: str, artifact: Mapping[str, object]) -> str | None:
    url = artifact.get("url")
    digest = artifact.get("hash")
    if not isinstance(url, str):
        return f"{package}: artifact URL is missing"
    parsed = urlparse(url)
    if parsed.scheme != "https" or parsed.hostname != APPROVED_ARTIFACT_HOST:
        return f"{package}: artifact host is not approved"
    if not isinstance(digest, str) or _SHA256_PATTERN.fullmatch(digest) is None:
        return f"{package}: artifact SHA-256 is missing or invalid"
    return None


def _check_artifact_integrity(packages: Sequence[dict[str, object]]) -> SupplyChainCheck:
    failures: list[str] = []
    artifact_count = 0
    registry_package_count = 0
    for package in packages:
        source = _table(package.get("source"))
        if source.get("registry") != APPROVED_REGISTRY:
            continue
        registry_package_count += 1
        name = package.get("name")
        label = name if isinstance(name, str) else "<unnamed>"
        artifacts: list[dict[str, object]] = []
        sdist = package.get("sdist")
        if isinstance(sdist, dict):
            artifacts.append(_table(sdist))
        wheels = package.get("wheels")
        if isinstance(wheels, list):
            artifacts.extend(_table(wheel) for wheel in wheels if isinstance(wheel, dict))
        if not artifacts:
            failures.append(f"{label}: no hashed artifacts in lock")
            continue
        artifact_count += len(artifacts)
        for artifact in artifacts:
            error = _artifact_error(label, artifact)
            if error is not None:
                failures.append(error)
    if failures:
        return _fail("SC-ARTIFACT-INTEGRITY", "; ".join(failures))
    return _pass(
        "SC-ARTIFACT-INTEGRITY",
        f"lock records approved HTTPS hosting and SHA-256 for {artifact_count} artifacts "
        f"across {registry_package_count} packages",
    )


def _resolve_project_file(root: Path, name: str) -> Path:
    candidate = root / name
    try:
        resolved = candidate.resolve(strict=True)
    except OSError as error:
        raise WhiteboxAuditError(
            f"required project file is unavailable: {name}", ExitCode.DATA_INTEGRITY_ERROR
        ) from error
    if not resolved.is_relative_to(root) or not resolved.is_file():
        raise WhiteboxAuditError(
            f"project file must be a regular file inside the project root: {name}",
            ExitCode.POLICY_REJECTED,
        )
    return resolved


def _lock_freshness_check(
    root: Path,
    *,
    uv_executable: str,
    environ: Mapping[str, str] | None,
    timeout_seconds: float,
) -> SupplyChainCheck:
    source_env = os.environ if environ is None else environ
    path = source_env.get("PATH", os.defpath)
    executable = shutil.which(uv_executable, path=path)
    if executable is None:
        return _fail("SC-LOCK-FRESHNESS", f"uv executable not found: {uv_executable}")
    env = minimal_env(source_env)
    try:
        completed = subprocess.run(
            [
                executable,
                "lock",
                "--check",
                "--offline",
                "--no-cache",
                "--config-file",
                str(root / "uv.toml"),
                "--project",
                str(root),
            ],
            check=False,
            shell=False,
            capture_output=True,
            text=True,
            timeout=timeout_seconds,
            env=env,
        )
    except (OSError, subprocess.TimeoutExpired) as error:
        return _fail("SC-LOCK-FRESHNESS", redact_output(str(error)))
    if completed.returncode != 0:
        detail = completed.stderr or completed.stdout or f"exit code {completed.returncode}"
        return _fail("SC-LOCK-FRESHNESS", redact_output(detail))
    return _pass("SC-LOCK-FRESHNESS", "uv confirmed pyproject.toml and uv.lock are in sync offline")


def inspect_supply_chain(
    project_root: Path,
    *,
    check_freshness: bool = True,
    uv_executable: str = "uv",
    environ: Mapping[str, str] | None = None,
    timeout_seconds: float = DEFAULT_TIMEOUT_SECONDS,
) -> SupplyChainReport:
    """Validate the harness dependency declarations and locked artifacts."""

    try:
        root = project_root.resolve(strict=True)
    except OSError as error:
        raise WhiteboxAuditError("project root does not exist", ExitCode.INVALID_INPUT) from error
    if not root.is_dir():
        raise WhiteboxAuditError("project root must be a directory", ExitCode.INVALID_INPUT)

    pyproject_path = _resolve_project_file(root, "pyproject.toml")
    uv_config_path = _resolve_project_file(root, "uv.toml")
    lock_path = _resolve_project_file(root, "uv.lock")
    pyproject = _load_toml(pyproject_path)
    uv_config = _load_toml(uv_config_path)
    lock = _load_toml(lock_path)
    packages = _packages(lock)
    checks = [
        _check_declared_dependencies(pyproject, uv_config),
        _check_uv_policy(uv_config),
        _check_lock_metadata(lock, packages),
        _check_lock_sources(packages),
        _check_artifact_integrity(packages),
    ]
    if check_freshness:
        checks.append(
            _lock_freshness_check(
                root,
                uv_executable=uv_executable,
                environ=environ,
                timeout_seconds=timeout_seconds,
            )
        )
    lock_sha256 = hashlib.sha256(lock_path.read_bytes()).hexdigest()
    return SupplyChainReport(
        project_root=str(root),
        lock_sha256=lock_sha256,
        package_count=len(packages),
        checks=tuple(checks),
    )
