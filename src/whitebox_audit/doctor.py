"""Non-destructive audit host capability checks."""

from __future__ import annotations

import hashlib
import json
import os
import re
import shutil
import subprocess
import sys
from collections.abc import Mapping, Sequence
from dataclasses import asdict, dataclass
from enum import StrEnum
from pathlib import Path
from typing import Final

from whitebox_audit.errors import ExitCode

SAFE_ENV_KEYS: Final[frozenset[str]] = frozenset(
    {
        "HOME",
        "LANG",
        "LC_ALL",
        "PATH",
        "TMPDIR",
        "WHITEBOX_CODEQL_ENTITLEMENT_ACKNOWLEDGED",
    }
)
DEFAULT_TIMEOUT_SECONDS: Final[float] = 10.0
MAX_OUTPUT_CHARS: Final[int] = 300
MINIMUM_CODEX_VERSION: Final[tuple[int, int, int]] = (0, 142, 0)

_SECRET_PATTERNS: Final[tuple[re.Pattern[str], ...]] = (
    re.compile(r"(?i)(authorization\s*:\s*bearer\s+)[^\s]+"),
    re.compile(r"(?i)((?:token|password|secret|api[_-]?key)\s*[=:]\s*)[^\s]+"),
)
_VERSION_PATTERN: Final[re.Pattern[str]] = re.compile(r"(?<!\d)(\d+)\.(\d+)(?:\.(\d+))?")


class Requirement(StrEnum):
    REQUIRED = "required"
    OPTIONAL = "optional"


class Health(StrEnum):
    OK = "ok"
    WARNING = "warning"
    ERROR = "error"


@dataclass(frozen=True, slots=True)
class CommandResult:
    argv: tuple[str, ...]
    returncode: int
    stdout: str
    stderr: str


@dataclass(frozen=True, slots=True)
class ToolCapability:
    name: str
    requirement: Requirement
    health: Health
    available: bool
    version: str | None = None
    detail: str | None = None
    executable: str | None = None
    executable_sha256: str | None = None

    def to_dict(self) -> dict[str, object]:
        return asdict(self)


@dataclass(frozen=True, slots=True)
class DoctorReport:
    capabilities: tuple[ToolCapability, ...]

    @property
    def ok(self) -> bool:
        return all(capability.health is not Health.ERROR for capability in self.capabilities)

    @property
    def exit_code(self) -> ExitCode:
        return ExitCode.OK if self.ok else ExitCode.CAPABILITY_MISSING

    def to_dict(self) -> dict[str, object]:
        return {
            "schema_version": 1,
            "ok": self.ok,
            "exit_code": int(self.exit_code),
            "capabilities": [capability.to_dict() for capability in self.capabilities],
        }


def minimal_env(source: Mapping[str, str] | None = None) -> dict[str, str]:
    """Return only environment variables explicitly required by diagnostic tools."""

    values = os.environ if source is None else source
    return {key: values[key] for key in SAFE_ENV_KEYS if key in values}


def redact_output(value: str, *, limit: int = MAX_OUTPUT_CHARS) -> str:
    """Redact common secret forms and bound diagnostic output."""

    redacted = value.replace("\x00", "").strip()
    for pattern in _SECRET_PATTERNS:
        redacted = pattern.sub(r"\1[REDACTED]", redacted)
    redacted = " ".join(redacted.split())
    if len(redacted) > limit:
        return f"{redacted[: limit - 3]}..."
    return redacted


def parse_version(value: str) -> tuple[int, int, int] | None:
    """Extract the first semantic-looking numeric version from tool output."""

    match = _VERSION_PATTERN.search(value)
    if match is None:
        return None
    major, minor, patch = match.groups()
    return int(major), int(minor), int(patch or 0)


def find_executable(names: Sequence[str], *, path: str | None = None) -> str | None:
    """Find the first executable in ``names`` without executing it."""

    for name in names:
        executable = shutil.which(name, path=path)
        if executable is not None:
            return executable
    return None


def executable_identity(executable: str) -> tuple[str, str | None]:
    """Resolve and hash a trusted host executable for provenance."""

    try:
        path = Path(executable).resolve(strict=True)
        if not path.is_file():
            return str(path), None
        digest = hashlib.sha256()
        with path.open("rb") as stream:
            for block in iter(lambda: stream.read(1024 * 1024), b""):
                digest.update(block)
        return str(path), digest.hexdigest()
    except OSError:
        return executable, None


def run_command(
    argv: Sequence[str],
    *,
    env: Mapping[str, str],
    timeout_seconds: float = DEFAULT_TIMEOUT_SECONDS,
) -> CommandResult:
    """Run a trusted diagnostic command with a bounded environment and timeout."""

    completed = subprocess.run(
        list(argv),
        check=False,
        shell=False,
        capture_output=True,
        text=True,
        timeout=timeout_seconds,
        env=dict(env),
    )
    return CommandResult(
        argv=tuple(argv),
        returncode=completed.returncode,
        stdout=completed.stdout,
        stderr=completed.stderr,
    )


def _failure_detail(result: CommandResult) -> str:
    output = result.stderr or result.stdout or f"exit code {result.returncode}"
    return redact_output(output)


def _version_line(result: CommandResult) -> str:
    output = result.stdout or result.stderr
    first_line = next((line.strip() for line in output.splitlines() if line.strip()), "")
    return redact_output(first_line) or "version unavailable"


class Doctor:
    """Collect tool capabilities without modifying host state."""

    def __init__(
        self,
        *,
        environ: Mapping[str, str] | None = None,
        timeout_seconds: float = DEFAULT_TIMEOUT_SECONDS,
    ) -> None:
        self._source_env = dict(os.environ if environ is None else environ)
        self._env = minimal_env(self._source_env)
        self._timeout_seconds = timeout_seconds
        self._path = self._env.get("PATH", os.defpath)

    def run(self) -> DoctorReport:
        checks = (
            self._check_simple("git", ("git",), ("--version",)),
            self._check_simple("curl", ("curl",), ("--version",)),
            self._check_simple("jq", ("jq",), ("--version",)),
            self._check_simple("ripgrep", ("rg",), ("--version",)),
            self._check_python(),
            self._check_simple("make", ("make",), ("--version",)),
            self._check_environment_manager(),
            self._check_docker(),
            self._check_codex(),
            self._check_codeguard(),
            self._check_simple("semgrep", ("semgrep",), ("--version",)),
            self._check_codeql(),
        )
        return DoctorReport(checks)

    def _execute(self, executable: str, args: Sequence[str]) -> CommandResult:
        return run_command(
            (executable, *args), env=self._env, timeout_seconds=self._timeout_seconds
        )

    def _check_simple(
        self,
        name: str,
        executable_names: Sequence[str],
        version_args: Sequence[str],
        *,
        requirement: Requirement = Requirement.REQUIRED,
    ) -> ToolCapability:
        executable = find_executable(executable_names, path=self._path)
        if executable is None:
            health = Health.ERROR if requirement is Requirement.REQUIRED else Health.WARNING
            return ToolCapability(
                name=name,
                requirement=requirement,
                health=health,
                available=False,
                detail="executable not found",
            )
        executable_path, executable_sha256 = executable_identity(executable)
        try:
            result = self._execute(executable, version_args)
        except subprocess.TimeoutExpired:
            health = Health.ERROR if requirement is Requirement.REQUIRED else Health.WARNING
            return ToolCapability(
                name=name,
                requirement=requirement,
                health=health,
                available=True,
                detail=f"version check timed out after {self._timeout_seconds:g}s",
                executable=executable_path,
                executable_sha256=executable_sha256,
            )
        except OSError as error:
            health = Health.ERROR if requirement is Requirement.REQUIRED else Health.WARNING
            return ToolCapability(
                name=name,
                requirement=requirement,
                health=health,
                available=True,
                detail=redact_output(str(error)),
                executable=executable_path,
                executable_sha256=executable_sha256,
            )
        if result.returncode != 0:
            health = Health.ERROR if requirement is Requirement.REQUIRED else Health.WARNING
            return ToolCapability(
                name=name,
                requirement=requirement,
                health=health,
                available=True,
                detail=_failure_detail(result),
                executable=executable_path,
                executable_sha256=executable_sha256,
            )
        return ToolCapability(
            name=name,
            requirement=requirement,
            health=Health.OK,
            available=True,
            version=_version_line(result),
            executable=executable_path,
            executable_sha256=executable_sha256,
        )

    def _check_python(self) -> ToolCapability:
        version = sys.version_info[:3]
        version_text = ".".join(str(part) for part in version)
        executable, executable_sha256 = executable_identity(sys.executable)
        if version < (3, 12, 0):
            return ToolCapability(
                name="python",
                requirement=Requirement.REQUIRED,
                health=Health.ERROR,
                available=True,
                version=version_text,
                detail="Python 3.12 or newer is required",
                executable=executable,
                executable_sha256=executable_sha256,
            )
        return ToolCapability(
            name="python",
            requirement=Requirement.REQUIRED,
            health=Health.OK,
            available=True,
            version=version_text,
            executable=executable,
            executable_sha256=executable_sha256,
        )

    def _check_environment_manager(self) -> ToolCapability:
        executable = find_executable(("uv", "pipx"), path=self._path)
        if executable is None:
            return ToolCapability(
                name="uv-or-pipx",
                requirement=Requirement.REQUIRED,
                health=Health.ERROR,
                available=False,
                detail="neither uv nor pipx was found",
            )
        return self._check_simple("uv-or-pipx", (Path(executable).name,), ("--version",))

    def _check_docker(self) -> ToolCapability:
        capability = self._check_simple("docker", ("docker",), ("--version",))
        if capability.health is not Health.OK:
            return capability
        executable = find_executable(("docker",), path=self._path)
        assert executable is not None
        try:
            result = self._execute(executable, ("version", "--format", "{{.Server.Version}}"))
        except subprocess.TimeoutExpired:
            return ToolCapability(
                name="docker",
                requirement=Requirement.REQUIRED,
                health=Health.ERROR,
                available=True,
                version=capability.version,
                detail=f"daemon check timed out after {self._timeout_seconds:g}s",
                executable=capability.executable,
                executable_sha256=capability.executable_sha256,
            )
        if result.returncode != 0:
            return ToolCapability(
                name="docker",
                requirement=Requirement.REQUIRED,
                health=Health.ERROR,
                available=True,
                version=capability.version,
                detail=f"daemon unavailable: {_failure_detail(result)}",
                executable=capability.executable,
                executable_sha256=capability.executable_sha256,
            )
        server_version = redact_output(result.stdout)
        return ToolCapability(
            name="docker",
            requirement=Requirement.REQUIRED,
            health=Health.OK,
            available=True,
            version=f"client={capability.version}; server={server_version}",
            executable=capability.executable,
            executable_sha256=capability.executable_sha256,
        )

    def _check_codex(self) -> ToolCapability:
        capability = self._check_simple("codex", ("codex",), ("--version",))
        if capability.health is not Health.OK or capability.version is None:
            return capability
        parsed = parse_version(capability.version)
        if parsed is None:
            return ToolCapability(
                name="codex",
                requirement=Requirement.REQUIRED,
                health=Health.ERROR,
                available=True,
                version=capability.version,
                detail="could not parse Codex version",
                executable=capability.executable,
                executable_sha256=capability.executable_sha256,
            )
        if parsed < MINIMUM_CODEX_VERSION:
            required = ".".join(str(part) for part in MINIMUM_CODEX_VERSION)
            return ToolCapability(
                name="codex",
                requirement=Requirement.REQUIRED,
                health=Health.ERROR,
                available=True,
                version=capability.version,
                detail=f"Codex {required} or newer is required",
                executable=capability.executable,
                executable_sha256=capability.executable_sha256,
            )
        return capability

    def _check_codeguard(self) -> ToolCapability:
        executable = find_executable(("codex",), path=self._path)
        if executable is None:
            return ToolCapability(
                name="codeguard-plugin",
                requirement=Requirement.REQUIRED,
                health=Health.ERROR,
                available=False,
                detail="Codex is unavailable, so the plugin cannot be checked",
            )
        executable_path, executable_sha256 = executable_identity(executable)
        try:
            result = self._execute(
                executable,
                ("plugin", "list", "--marketplace", "project-codeguard", "--json"),
            )
        except subprocess.TimeoutExpired:
            return ToolCapability(
                name="codeguard-plugin",
                requirement=Requirement.REQUIRED,
                health=Health.ERROR,
                available=False,
                detail=f"plugin check timed out after {self._timeout_seconds:g}s",
                executable=executable_path,
                executable_sha256=executable_sha256,
            )
        if result.returncode != 0:
            return ToolCapability(
                name="codeguard-plugin",
                requirement=Requirement.REQUIRED,
                health=Health.ERROR,
                available=False,
                detail=_failure_detail(result),
                executable=executable_path,
                executable_sha256=executable_sha256,
            )
        try:
            payload = json.loads(result.stdout)
            installed_plugins = payload["installed"]
        except (json.JSONDecodeError, KeyError, TypeError):
            return ToolCapability(
                name="codeguard-plugin",
                requirement=Requirement.REQUIRED,
                health=Health.ERROR,
                available=False,
                detail="Codex returned invalid plugin JSON",
                executable=executable_path,
                executable_sha256=executable_sha256,
            )
        plugin = next(
            (
                item
                for item in installed_plugins
                if isinstance(item, dict)
                and item.get("name") == "codeguard-security"
                and item.get("marketplaceName") == "project-codeguard"
            ),
            None,
        )
        if plugin is None:
            return ToolCapability(
                name="codeguard-plugin",
                requirement=Requirement.REQUIRED,
                health=Health.ERROR,
                available=False,
                detail="plugin not installed",
                executable=executable_path,
                executable_sha256=executable_sha256,
            )
        if plugin.get("enabled") is not True:
            return ToolCapability(
                name="codeguard-plugin",
                requirement=Requirement.REQUIRED,
                health=Health.ERROR,
                available=True,
                version=redact_output(str(plugin.get("version", "version unavailable"))),
                detail="plugin is installed but disabled",
                executable=executable_path,
                executable_sha256=executable_sha256,
            )
        return ToolCapability(
            name="codeguard-plugin",
            requirement=Requirement.REQUIRED,
            health=Health.OK,
            available=True,
            version=redact_output(str(plugin.get("version", "version unavailable"))),
            executable=executable_path,
            executable_sha256=executable_sha256,
        )

    def _check_codeql(self) -> ToolCapability:
        capability = self._check_simple(
            "codeql", ("codeql",), ("version",), requirement=Requirement.OPTIONAL
        )
        if capability.health is not Health.OK:
            return capability
        acknowledged = self._source_env.get(
            "WHITEBOX_CODEQL_ENTITLEMENT_ACKNOWLEDGED", "false"
        ).lower() in {"1", "true", "yes"}
        if not acknowledged:
            return ToolCapability(
                name="codeql",
                requirement=Requirement.OPTIONAL,
                health=Health.WARNING,
                available=True,
                version=capability.version,
                detail="entitlement acknowledgement is not configured",
                executable=capability.executable,
                executable_sha256=capability.executable_sha256,
            )
        return capability
