"""Application errors and stable CLI exit codes."""

from __future__ import annotations

from enum import IntEnum


class ExitCode(IntEnum):
    """Stable process exit codes defined by the application specification."""

    OK = 0
    GENERAL_ERROR = 1
    INVALID_INPUT = 2
    CAPABILITY_MISSING = 3
    POLICY_REJECTED = 4
    EXECUTION_FAILED = 5
    DATA_INTEGRITY_ERROR = 6


class WhiteboxAuditError(Exception):
    """A user-facing error that does not expose an internal traceback."""

    def __init__(self, message: str, exit_code: ExitCode = ExitCode.GENERAL_ERROR) -> None:
        super().__init__(message)
        self.message = message
        self.exit_code = exit_code

    def __str__(self) -> str:
        return self.message
