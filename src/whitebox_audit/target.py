"""Safe, non-executing target validation, inventory, and fingerprinting."""

from __future__ import annotations

import hashlib
import os
import re
import stat
import subprocess
import time
from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Final

from whitebox_audit.doctor import minimal_env, redact_output
from whitebox_audit.errors import ExitCode, WhiteboxAuditError
from whitebox_audit.models import SCHEMA_VERSION, Inventory

DEFAULT_MAX_FILES: Final[int] = 100_000
DEFAULT_MAX_TOTAL_BYTES: Final[int] = 2 * 1024 * 1024 * 1024
DEFAULT_MAX_FILE_BYTES: Final[int] = 128 * 1024 * 1024
DEFAULT_TIMEOUT_SECONDS: Final[float] = 30.0
MAX_ROUTE_CANDIDATES: Final[int] = 2_000
MAX_GIT_METADATA_ENTRIES: Final[int] = 200_000
MAX_GIT_CONFIG_BYTES: Final[int] = 1024 * 1024

EXCLUDED_DIRECTORY_NAMES: Final[frozenset[str]] = frozenset(
    {
        ".git",
        ".hg",
        ".svn",
        ".venv",
        "__pycache__",
        ".mypy_cache",
        ".pytest_cache",
        ".ruff_cache",
        ".next",
        "node_modules",
        "vendor",
        "dist",
        "build",
        "coverage",
        "work",
        "reports",
    }
)

LANGUAGE_EXTENSIONS: Final[dict[str, str]] = {
    ".py": "python",
    ".pyi": "python",
    ".js": "javascript",
    ".jsx": "javascript",
    ".mjs": "javascript",
    ".cjs": "javascript",
    ".ts": "typescript",
    ".tsx": "typescript",
    ".mts": "typescript",
    ".cts": "typescript",
    ".java": "java",
    ".go": "go",
    ".rb": "ruby",
    ".php": "php",
    ".cs": "csharp",
    ".rs": "rust",
    ".kt": "kotlin",
    ".kts": "kotlin",
}

MANIFEST_NAMES: Final[frozenset[str]] = frozenset(
    {
        "pyproject.toml",
        "setup.py",
        "setup.cfg",
        "Pipfile",
        "Pipfile.lock",
        "poetry.lock",
        "uv.lock",
        "package.json",
        "package-lock.json",
        "pnpm-lock.yaml",
        "yarn.lock",
        "bun.lock",
        "bun.lockb",
        "pom.xml",
        "build.gradle",
        "build.gradle.kts",
        "go.mod",
        "go.sum",
        "Gemfile",
        "Gemfile.lock",
        "composer.json",
        "composer.lock",
        "Cargo.toml",
        "Cargo.lock",
    }
)

_REQUIREMENTS_PATTERN: Final[re.Pattern[str]] = re.compile(r"requirements(?:-[^/]+)?\.txt\Z")
_PROJECT_MANIFEST_PATTERN: Final[re.Pattern[str]] = re.compile(
    r".+\.(?:csproj|fsproj|vbproj|sln)\Z"
)
_ROUTE_NAMES: Final[frozenset[str]] = frozenset(
    {
        "route.ts",
        "route.tsx",
        "route.js",
        "route.jsx",
        "routes.py",
        "urls.py",
        "router.py",
        "controllers.py",
    }
)


@dataclass(frozen=True, slots=True)
class InventoryLimits:
    max_files: int = DEFAULT_MAX_FILES
    max_total_bytes: int = DEFAULT_MAX_TOTAL_BYTES
    max_file_bytes: int = DEFAULT_MAX_FILE_BYTES
    timeout_seconds: float = DEFAULT_TIMEOUT_SECONDS

    def validate(self) -> None:
        if (
            self.max_files <= 0
            or self.max_total_bytes <= 0
            or self.max_file_bytes <= 0
            or self.timeout_seconds <= 0
        ):
            raise WhiteboxAuditError("inventory limits must be positive", ExitCode.INVALID_INPUT)


@dataclass(frozen=True, slots=True)
class TargetInspection:
    tree_hash: str
    inventory: Inventory


@dataclass(frozen=True, slots=True)
class GitMetadata:
    commit: str | None
    tree_hash: str | None
    dirty: bool | None


def _is_relative_to(candidate: Path, root: Path) -> bool:
    return candidate == root or candidate.is_relative_to(root)


def validate_target_root(target: Path, harness_root: Path) -> Path:
    """Resolve a target and reject unsafe relationships with the harness."""

    try:
        root = target.resolve(strict=True)
    except OSError as error:
        raise WhiteboxAuditError("target does not exist", ExitCode.INVALID_INPUT) from error
    try:
        harness = harness_root.resolve(strict=True)
    except OSError as error:
        raise WhiteboxAuditError(
            "audit harness root does not exist", ExitCode.DATA_INTEGRITY_ERROR
        ) from error
    if not root.is_dir():
        raise WhiteboxAuditError("target must be a directory", ExitCode.INVALID_INPUT)
    if not harness.is_dir():
        raise WhiteboxAuditError(
            "audit harness root must be a directory", ExitCode.DATA_INTEGRITY_ERROR
        )
    if _is_relative_to(root, harness) or _is_relative_to(harness, root):
        raise WhiteboxAuditError(
            "target and audit harness must not be identical or contain one another",
            ExitCode.POLICY_REJECTED,
        )
    try:
        with os.scandir(root) as entries:
            next(entries, None)
    except OSError as error:
        raise WhiteboxAuditError("target is not readable", ExitCode.POLICY_REJECTED) from error
    return root


def resolve_under(root: Path, candidate: Path) -> Path:
    """Resolve an existing relative path while confining it beneath root."""

    if candidate.is_absolute():
        raise WhiteboxAuditError("absolute artifact path is forbidden", ExitCode.POLICY_REJECTED)
    if ".." in candidate.parts:
        raise WhiteboxAuditError("parent path segments are forbidden", ExitCode.POLICY_REJECTED)
    try:
        canonical_root = root.resolve(strict=True)
        resolved = (canonical_root / candidate).resolve(strict=True)
    except OSError as error:
        raise WhiteboxAuditError("path does not exist", ExitCode.INVALID_INPUT) from error
    if not resolved.is_relative_to(canonical_root):
        raise WhiteboxAuditError("path escapes its allowed root", ExitCode.POLICY_REJECTED)
    return resolved


def _check_deadline(deadline: float) -> None:
    if monotonic_time() > deadline:
        raise WhiteboxAuditError("target inventory timed out", ExitCode.POLICY_REJECTED)


def monotonic_time() -> float:
    return time.monotonic()


def validate_same_filesystem(root_device: int, candidate_device: int, relative: str) -> None:
    if candidate_device != root_device:
        raise WhiteboxAuditError(
            f"nested filesystem mount is forbidden: {relative}", ExitCode.POLICY_REJECTED
        )


def _hash_file(
    directory_fd: int,
    name: str,
    label: str,
    expected: os.stat_result,
    *,
    max_file_bytes: int,
) -> str:
    if expected.st_size > max_file_bytes:
        raise WhiteboxAuditError(
            f"target file exceeds the {max_file_bytes}-byte safety limit: {label}",
            ExitCode.POLICY_REJECTED,
        )
    flags = os.O_RDONLY
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        descriptor = os.open(name, flags, dir_fd=directory_fd)
    except OSError as error:
        raise WhiteboxAuditError(
            f"target file could not be opened safely: {label}", ExitCode.POLICY_REJECTED
        ) from error
    digest = hashlib.sha256()
    try:
        actual = os.fstat(descriptor)
        if not stat.S_ISREG(actual.st_mode) or (actual.st_dev, actual.st_ino) != (
            expected.st_dev,
            expected.st_ino,
        ):
            raise WhiteboxAuditError(
                f"target file changed during inventory: {label}", ExitCode.DATA_INTEGRITY_ERROR
            )
        while block := os.read(descriptor, 1024 * 1024):
            digest.update(block)
        final = os.fstat(descriptor)
        if (actual.st_size, actual.st_mtime_ns) != (final.st_size, final.st_mtime_ns):
            raise WhiteboxAuditError(
                f"target file changed during inventory: {label}", ExitCode.DATA_INTEGRITY_ERROR
            )
    finally:
        os.close(descriptor)
    return digest.hexdigest()


def _is_manifest(name: str) -> bool:
    return (
        name in MANIFEST_NAMES
        or _REQUIREMENTS_PATTERN.fullmatch(name) is not None
        or _PROJECT_MANIFEST_PATTERN.fullmatch(name) is not None
    )


def _is_route_candidate(path: Path) -> bool:
    name = path.name
    lower = name.lower()
    return (
        name in _ROUTE_NAMES
        or "controller" in lower
        or lower.startswith("routes.")
        or ("app" in path.parts and name.startswith("route."))
    )


def _canonical_record(kind: str, relative: str, *values: object) -> bytes:
    fields = (kind, relative, *(str(value) for value in values))
    return ("\0".join(fields) + "\n").encode()


def inspect_target(root: Path, *, limits: InventoryLimits | None = None) -> TargetInspection:
    """Build a bounded inventory and content fingerprint without following symlinks."""

    active_limits = InventoryLimits() if limits is None else limits
    active_limits.validate()
    deadline = monotonic_time() + active_limits.timeout_seconds
    directory_flags = os.O_RDONLY
    if hasattr(os, "O_DIRECTORY"):
        directory_flags |= os.O_DIRECTORY
    if hasattr(os, "O_NOFOLLOW"):
        directory_flags |= os.O_NOFOLLOW
    try:
        root_fd = os.open(root, directory_flags)
    except OSError as error:
        raise WhiteboxAuditError(
            "target root could not be opened safely", ExitCode.POLICY_REJECTED
        ) from error
    root_stat = os.fstat(root_fd)
    tree_digest = hashlib.sha256()
    languages: set[str] = set()
    manifests: list[str] = []
    routes: list[str] = []
    symlinks: list[str] = []
    excluded: set[str] = set()
    file_count = 0
    total_bytes = 0
    pending: list[tuple[int, Path]] = [(root_fd, Path())]

    try:
        while pending:
            _check_deadline(deadline)
            directory_fd, relative_directory = pending.pop()
            try:
                directory_stat = os.fstat(directory_fd)
                if not stat.S_ISDIR(directory_stat.st_mode):
                    raise WhiteboxAuditError(
                        "target directory changed type during inventory",
                        ExitCode.DATA_INTEGRITY_ERROR,
                    )
                validate_same_filesystem(
                    root_stat.st_dev, directory_stat.st_dev, relative_directory.as_posix() or "."
                )
                iterator = os.scandir(directory_fd)
                try:
                    entries = sorted(iterator, key=lambda entry: entry.name)
                    for entry in entries:
                        _check_deadline(deadline)
                        relative_path = relative_directory / entry.name
                        relative = relative_path.as_posix()
                        try:
                            item_stat = entry.stat(follow_symlinks=False)
                        except OSError as error:
                            raise WhiteboxAuditError(
                                f"target path changed during inventory: {relative}",
                                ExitCode.DATA_INTEGRITY_ERROR,
                            ) from error
                        if entry.is_symlink():
                            try:
                                link_text = os.readlink(entry.name, dir_fd=directory_fd)
                                resolved = (root / relative_directory / link_text).resolve(
                                    strict=True
                                )
                                final_stat = os.stat(
                                    entry.name, dir_fd=directory_fd, follow_symlinks=False
                                )
                            except OSError as error:
                                raise WhiteboxAuditError(
                                    f"broken or unreadable symlink is forbidden: {relative}",
                                    ExitCode.POLICY_REJECTED,
                                ) from error
                            if (item_stat.st_dev, item_stat.st_ino) != (
                                final_stat.st_dev,
                                final_stat.st_ino,
                            ):
                                raise WhiteboxAuditError(
                                    f"symlink changed during inventory: {relative}",
                                    ExitCode.DATA_INTEGRITY_ERROR,
                                )
                            if not resolved.is_relative_to(root):
                                raise WhiteboxAuditError(
                                    f"symlink escapes target root: {relative}",
                                    ExitCode.POLICY_REJECTED,
                                )
                            symlinks.append(relative)
                            canonical_target = resolved.relative_to(root).as_posix()
                            tree_digest.update(
                                _canonical_record("symlink", relative, canonical_target)
                            )
                            continue
                        if entry.is_dir(follow_symlinks=False):
                            if entry.name in EXCLUDED_DIRECTORY_NAMES:
                                excluded.add(relative)
                                continue
                            validate_same_filesystem(root_stat.st_dev, item_stat.st_dev, relative)
                            try:
                                child_fd = os.open(entry.name, directory_flags, dir_fd=directory_fd)
                            except OSError as error:
                                raise WhiteboxAuditError(
                                    f"target directory could not be opened safely: {relative}",
                                    ExitCode.DATA_INTEGRITY_ERROR,
                                ) from error
                            child_stat = os.fstat(child_fd)
                            if (item_stat.st_dev, item_stat.st_ino) != (
                                child_stat.st_dev,
                                child_stat.st_ino,
                            ):
                                os.close(child_fd)
                                raise WhiteboxAuditError(
                                    f"target directory changed during inventory: {relative}",
                                    ExitCode.DATA_INTEGRITY_ERROR,
                                )
                            tree_digest.update(_canonical_record("directory", relative))
                            pending.append((child_fd, relative_path))
                            continue
                        if not entry.is_file(follow_symlinks=False):
                            raise WhiteboxAuditError(
                                f"unsupported special file in target: {relative}",
                                ExitCode.POLICY_REJECTED,
                            )
                        file_count += 1
                        total_bytes += item_stat.st_size
                        if file_count > active_limits.max_files:
                            raise WhiteboxAuditError(
                                "target file-count limit exceeded", ExitCode.POLICY_REJECTED
                            )
                        if total_bytes > active_limits.max_total_bytes:
                            raise WhiteboxAuditError(
                                "target byte limit exceeded", ExitCode.POLICY_REJECTED
                            )
                        content_hash = _hash_file(
                            directory_fd,
                            entry.name,
                            relative,
                            item_stat,
                            max_file_bytes=active_limits.max_file_bytes,
                        )
                        executable_bits = stat.S_IMODE(item_stat.st_mode) & 0o111
                        tree_digest.update(
                            _canonical_record(
                                "file",
                                relative,
                                item_stat.st_size,
                                executable_bits,
                                content_hash,
                            )
                        )
                        language = LANGUAGE_EXTENSIONS.get(relative_path.suffix.lower())
                        if language is not None:
                            languages.add(language)
                        if _is_manifest(relative_path.name):
                            manifests.append(relative)
                        if len(routes) < MAX_ROUTE_CANDIDATES and _is_route_candidate(
                            relative_path
                        ):
                            routes.append(relative)
                finally:
                    iterator.close()
            finally:
                os.close(directory_fd)
    finally:
        for descriptor, _ in pending:
            os.close(descriptor)

    inventory = Inventory(
        schema_version=SCHEMA_VERSION,
        languages=tuple(sorted(languages)),
        manifests=tuple(sorted(manifests)),
        route_candidates=tuple(sorted(routes)),
        symlinks=tuple(sorted(symlinks)),
        excluded_directories=tuple(sorted(excluded)),
        file_count=file_count,
        total_bytes=total_bytes,
    )
    return TargetInspection(tree_hash=tree_digest.hexdigest(), inventory=inventory)


def _git_env(environ: Mapping[str, str] | None) -> dict[str, str]:
    env = minimal_env(environ)
    env.update(
        {
            "GIT_CONFIG_NOSYSTEM": "1",
            "GIT_CONFIG_GLOBAL": os.devnull,
            "GIT_OPTIONAL_LOCKS": "0",
            "GIT_TERMINAL_PROMPT": "0",
            "GIT_DISCOVERY_ACROSS_FILESYSTEM": "0",
        }
    )
    return env


def _read_bounded_file(directory_fd: int, name: str, *, limit: int) -> bytes:
    flags = os.O_RDONLY
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    descriptor = os.open(name, flags, dir_fd=directory_fd)
    try:
        metadata = os.fstat(descriptor)
        if not stat.S_ISREG(metadata.st_mode) or metadata.st_size > limit:
            raise WhiteboxAuditError(
                "Git metadata file exceeds its safety policy", ExitCode.POLICY_REJECTED
            )
        value = os.read(descriptor, limit + 1)
        if len(value) > limit:
            raise WhiteboxAuditError(
                "Git metadata file exceeds its safety policy", ExitCode.POLICY_REJECTED
            )
        return value
    finally:
        os.close(descriptor)


def _validate_git_metadata_directory(git_directory: Path, *, timeout_seconds: float) -> None:
    """Reject Git metadata that could redirect Git outside the target."""

    flags = os.O_RDONLY
    if hasattr(os, "O_DIRECTORY"):
        flags |= os.O_DIRECTORY
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    deadline = monotonic_time() + timeout_seconds
    try:
        root_fd = os.open(git_directory, flags)
    except OSError as error:
        raise WhiteboxAuditError(
            "Git metadata directory could not be opened safely", ExitCode.POLICY_REJECTED
        ) from error
    root_stat = os.fstat(root_fd)
    pending: list[tuple[int, Path]] = [(root_fd, Path())]
    entry_count = 0
    try:
        while pending:
            _check_deadline(deadline)
            directory_fd, relative_directory = pending.pop()
            try:
                with os.scandir(directory_fd) as iterator:
                    entries = sorted(iterator, key=lambda entry: entry.name)
                for entry in entries:
                    entry_count += 1
                    if entry_count > MAX_GIT_METADATA_ENTRIES:
                        raise WhiteboxAuditError(
                            "Git metadata entry limit exceeded", ExitCode.POLICY_REJECTED
                        )
                    _check_deadline(deadline)
                    relative = relative_directory / entry.name
                    metadata = entry.stat(follow_symlinks=False)
                    if entry.is_symlink():
                        raise WhiteboxAuditError(
                            f"symlink in Git metadata is forbidden: {relative.as_posix()}",
                            ExitCode.POLICY_REJECTED,
                        )
                    if metadata.st_dev != root_stat.st_dev:
                        raise WhiteboxAuditError(
                            "Git metadata crosses a filesystem boundary",
                            ExitCode.POLICY_REJECTED,
                        )
                    if entry.is_dir(follow_symlinks=False):
                        try:
                            child_fd = os.open(entry.name, flags, dir_fd=directory_fd)
                        except OSError as error:
                            raise WhiteboxAuditError(
                                "Git metadata directory changed during validation",
                                ExitCode.DATA_INTEGRITY_ERROR,
                            ) from error
                        child_stat = os.fstat(child_fd)
                        if (metadata.st_dev, metadata.st_ino) != (
                            child_stat.st_dev,
                            child_stat.st_ino,
                        ):
                            os.close(child_fd)
                            raise WhiteboxAuditError(
                                "Git metadata directory changed during validation",
                                ExitCode.DATA_INTEGRITY_ERROR,
                            )
                        pending.append((child_fd, relative))
                        continue
                    if not entry.is_file(follow_symlinks=False):
                        raise WhiteboxAuditError(
                            f"special file in Git metadata is forbidden: {relative.as_posix()}",
                            ExitCode.POLICY_REJECTED,
                        )
                    relative_text = relative.as_posix()
                    if relative_text in {"commondir", "objects/info/alternates"}:
                        raise WhiteboxAuditError(
                            f"external Git metadata reference is forbidden: {relative_text}",
                            ExitCode.POLICY_REJECTED,
                        )
                    if relative_text == "config":
                        config = _read_bounded_file(
                            directory_fd, entry.name, limit=MAX_GIT_CONFIG_BYTES
                        ).decode("utf-8", errors="replace")
                        if re.search(r"(?im)^\s*\[\s*include(?:if)?\b", config) or re.search(
                            r"(?im)^\s*worktree\s*=", config
                        ):
                            raise WhiteboxAuditError(
                                "Git config contains an external include or worktree override",
                                ExitCode.POLICY_REJECTED,
                            )
            finally:
                os.close(directory_fd)
    finally:
        for descriptor, _ in pending:
            os.close(descriptor)


def _git_command(
    executable: str,
    root: Path,
    args: Sequence[str],
    *,
    environ: Mapping[str, str] | None,
    timeout_seconds: float,
) -> subprocess.CompletedProcess[str]:
    argv = [
        executable,
        "--no-optional-locks",
        "-c",
        "core.hooksPath=/dev/null",
        "-c",
        "core.fsmonitor=false",
        "-c",
        "credential.helper=",
        "-c",
        f"core.worktree={root}",
        "-c",
        "diff.external=",
        "-C",
        str(root),
        *args,
    ]
    try:
        return subprocess.run(
            argv,
            check=False,
            shell=False,
            capture_output=True,
            text=True,
            timeout=timeout_seconds,
            env=_git_env(environ),
        )
    except (OSError, subprocess.TimeoutExpired) as error:
        raise WhiteboxAuditError(
            f"Git metadata collection failed: {redact_output(str(error))}",
            ExitCode.DATA_INTEGRITY_ERROR,
        ) from error


def collect_git_metadata(
    root: Path,
    *,
    git_executable: str = "git",
    environ: Mapping[str, str] | None = None,
    timeout_seconds: float = 10.0,
) -> GitMetadata:
    """Collect bounded Git identifiers without invoking target code."""

    git_marker = root / ".git"
    try:
        git_marker_stat = git_marker.lstat()
    except FileNotFoundError:
        return GitMetadata(None, None, None)
    except OSError as error:
        raise WhiteboxAuditError(
            "Git metadata could not be inspected safely", ExitCode.DATA_INTEGRITY_ERROR
        ) from error
    if not stat.S_ISDIR(git_marker_stat.st_mode):
        raise WhiteboxAuditError(
            "external or non-directory Git metadata is forbidden in the default profile",
            ExitCode.POLICY_REJECTED,
        )
    _validate_git_metadata_directory(git_marker, timeout_seconds=timeout_seconds)

    commit_result = _git_command(
        git_executable,
        root,
        ("rev-parse", "--verify", "HEAD^{commit}"),
        environ=environ,
        timeout_seconds=timeout_seconds,
    )
    tree_result = _git_command(
        git_executable,
        root,
        ("rev-parse", "--verify", "HEAD^{tree}"),
        environ=environ,
        timeout_seconds=timeout_seconds,
    )
    if commit_result.returncode != 0 or tree_result.returncode != 0:
        return GitMetadata(None, None, True)
    values = [commit_result.stdout.strip(), tree_result.stdout.strip()]
    if len(values) != 2 or any(
        re.fullmatch(r"[0-9a-fA-F]{40,64}", value) is None for value in values
    ):
        raise WhiteboxAuditError(
            "Git returned invalid object identifiers", ExitCode.DATA_INTEGRITY_ERROR
        )

    status_result = _git_command(
        git_executable,
        root,
        ("status", "--porcelain=v1", "-z", "--untracked-files=normal", "--ignore-submodules=all"),
        environ=environ,
        timeout_seconds=timeout_seconds,
    )
    if status_result.returncode != 0:
        detail = status_result.stderr or status_result.stdout or "status failed"
        raise WhiteboxAuditError(
            f"Git dirty-state collection failed: {redact_output(detail)}",
            ExitCode.DATA_INTEGRITY_ERROR,
        )
    return GitMetadata(values[0].lower(), values[1].lower(), bool(status_result.stdout))


def iter_inventory_paths(inventory: Inventory) -> Iterable[str]:
    """Expose bounded paths intended for later focused navigation."""

    yield from inventory.manifests
    yield from inventory.route_candidates
