"""Common deterministic scanner interface."""

from __future__ import annotations

from pathlib import Path
from typing import Protocol

from whitebox_audit.doctor import ToolCapability
from whitebox_audit.models import Evidence, ScannerRun, Target


class Scanner(Protocol):
    def doctor(self) -> ToolCapability: ...

    def run(self, target: Target, audit_run_id: str, run_directory: Path) -> ScannerRun: ...

    def normalize(
        self, scanner_run: ScannerRun, target: Target, run_directory: Path
    ) -> tuple[Evidence, ...]: ...
