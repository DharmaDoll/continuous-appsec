"""Command-line interface for Whitebox AI Audit."""

from __future__ import annotations

import argparse
import json
import sys
from collections.abc import Mapping, Sequence
from pathlib import Path
from typing import TextIO

from whitebox_audit import __version__
from whitebox_audit.doctor import Doctor, DoctorReport, Health, ToolCapability, redact_output
from whitebox_audit.errors import ExitCode, WhiteboxAuditError
from whitebox_audit.models import PrepareResult
from whitebox_audit.prepare import PrepareController, discover_harness_root
from whitebox_audit.scan import ScanController, ScanResult, ingest_sarif
from whitebox_audit.supply_chain import (
    SupplyChainReport,
    SupplyChainStatus,
    inspect_supply_chain,
)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="whitebox-audit",
        description="Evidence-driven white-box AppSec audit harness",
    )
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    subparsers = parser.add_subparsers(dest="command", required=True)

    doctor = subparsers.add_parser("doctor", help="check required host capabilities")
    doctor.add_argument(
        "--format",
        choices=("human", "json"),
        default="human",
        help="output format (default: human)",
    )

    supply_chain = subparsers.add_parser(
        "supply-chain", help="enforce audit harness dependency integrity policy"
    )
    supply_chain_subparsers = supply_chain.add_subparsers(
        dest="supply_chain_command", required=True
    )
    supply_chain_check = supply_chain_subparsers.add_parser(
        "check", help="validate pinned dependencies, lock sources, and artifact hashes"
    )
    supply_chain_check.add_argument(
        "--project-root",
        type=str,
        default=".",
        help="audit harness project root (default: current directory)",
    )
    supply_chain_check.add_argument(
        "--uv",
        default="uv",
        help="trusted uv executable used for the offline freshness check",
    )
    supply_chain_check.add_argument(
        "--format",
        choices=("human", "json"),
        default="human",
        help="output format (default: human)",
    )

    prepare = subparsers.add_parser(
        "prepare", help="validate and register an untrusted target without executing it"
    )
    prepare.add_argument("--target", required=True, help="path to the untrusted target repository")
    prepare.add_argument(
        "--profile", default="default", help="reviewed prepare profile (default: default)"
    )
    prepare.add_argument(
        "--format",
        choices=("human", "json"),
        default="human",
        help="output format (default: human)",
    )

    scan = subparsers.add_parser("scan", help="run a deterministic scanner against a target")
    scan_source = scan.add_mutually_exclusive_group(required=True)
    scan_source.add_argument("--target", help="untrusted target path; creates a new prepared run")
    scan_source.add_argument("--run-id", help="existing prepared run ID")
    scan.add_argument("--scanner", choices=("semgrep",), default="semgrep")
    scan.add_argument("--format", choices=("human", "json"), default="human")

    ingest = subparsers.add_parser("ingest-sarif", help="ingest operator-supplied SARIF")
    ingest.add_argument("--run-id", required=True, help="prepared audit run ID")
    ingest.add_argument("--tool-name", required=True, help="SARIF producer name")
    ingest.add_argument("--input", required=True, help="SARIF input file")
    ingest.add_argument("--format", choices=("human", "json"), default="human")
    return parser


def _status_label(capability: ToolCapability) -> str:
    if capability.health is Health.OK:
        return "OK"
    if capability.health is Health.WARNING:
        return "WARN"
    return "ERROR"


def render_doctor_human(report: DoctorReport) -> str:
    lines: list[str] = []
    for capability in report.capabilities:
        version = f" {capability.version}" if capability.version else ""
        detail = f" — {capability.detail}" if capability.detail else ""
        lines.append(f"[{_status_label(capability)}] {capability.name}{version}{detail}")
    lines.append("Doctor result: ready" if report.ok else "Doctor result: not ready")
    return "\n".join(lines)


def render_supply_chain_human(report: SupplyChainReport) -> str:
    lines = [
        f"[{'OK' if check.status is SupplyChainStatus.PASS else 'ERROR'}] "
        f"{check.check_id} — {check.detail}"
        for check in report.checks
    ]
    if report.lock_sha256 is not None:
        lines.append(f"Lock SHA-256: {report.lock_sha256}")
    lines.append("Supply-chain result: compliant" if report.ok else "Supply-chain result: rejected")
    return "\n".join(lines)


def render_prepare_human(result: PrepareResult) -> str:
    languages = ", ".join(result.target.languages) or "none detected"
    manifests = str(len(result.target.manifests))
    git_commit = result.target.git_commit or "not a Git repository / no commit"
    return "\n".join(
        (
            f"Prepared run: {result.run.run_id}",
            f"Target: {result.target.target_id}",
            f"Fingerprint: {result.target.tree_hash}",
            f"Git commit: {git_commit}",
            f"Languages: {languages}",
            f"Manifests: {manifests}",
            f"Run directory: {result.run_directory}",
        )
    )


def render_scan_human(result: ScanResult) -> str:
    return "\n".join(
        (
            f"Scan run: {result.scanner_run.scanner_run_id}",
            f"Audit run: {result.audit_run_id}",
            (
                f"Scanner: {result.scanner_run.scanner_name} "
                f"{result.scanner_run.scanner_version or ''}"
            ).rstrip(),
            f"Status: {result.scanner_run.status}",
            f"Evidence: {len(result.evidence)}",
            f"Run directory: {result.run_directory}",
        )
    )


def run(
    argv: Sequence[str] | None = None,
    *,
    stdout: TextIO | None = None,
    stderr: TextIO | None = None,
    environ: Mapping[str, str] | None = None,
    harness_root: Path | None = None,
) -> int:
    out = sys.stdout if stdout is None else stdout
    err = sys.stderr if stderr is None else stderr
    parser = build_parser()
    args = parser.parse_args(argv)

    try:
        if args.command == "doctor":
            doctor_report = Doctor(environ=environ).run()
            if args.format == "json":
                json.dump(doctor_report.to_dict(), out, indent=2, sort_keys=True)
                out.write("\n")
            else:
                out.write(render_doctor_human(doctor_report))
                out.write("\n")
            return int(doctor_report.exit_code)
        if args.command == "supply-chain" and args.supply_chain_command == "check":
            supply_chain_report = inspect_supply_chain(
                Path(args.project_root),
                uv_executable=args.uv,
                environ=environ,
            )
            if args.format == "json":
                json.dump(supply_chain_report.to_dict(), out, indent=2, sort_keys=True)
                out.write("\n")
            else:
                out.write(render_supply_chain_human(supply_chain_report))
                out.write("\n")
            return int(supply_chain_report.exit_code)
        if args.command == "prepare":
            root = discover_harness_root(Path.cwd()) if harness_root is None else harness_root
            prepare_result = PrepareController(root, environ=environ).prepare(
                Path(args.target), profile=args.profile
            )
            if args.format == "json":
                json.dump(prepare_result.to_dict(), out, indent=2, sort_keys=True)
                out.write("\n")
            else:
                out.write(render_prepare_human(prepare_result))
                out.write("\n")
            return int(ExitCode.OK)
        if args.command == "scan":
            root = discover_harness_root(Path.cwd()) if harness_root is None else harness_root
            scan_result = ScanController(root, environ=environ).scan(
                target_path=Path(args.target) if args.target else None,
                run_id=args.run_id,
            )
            if args.format == "json":
                json.dump(scan_result.to_dict(), out, indent=2, sort_keys=True)
                out.write("\n")
            else:
                out.write(render_scan_human(scan_result) + "\n")
            return int(ExitCode.OK)
        if args.command == "ingest-sarif":
            root = discover_harness_root(Path.cwd()) if harness_root is None else harness_root
            evidence = ingest_sarif(
                root,
                run_id=args.run_id,
                tool_name=args.tool_name,
                input_path=Path(args.input),
            )
            if args.format == "json":
                json.dump([item.to_dict() for item in evidence], out, indent=2, sort_keys=True)
                out.write("\n")
            else:
                out.write(f"Ingested evidence: {len(evidence)}\n")
            return int(ExitCode.OK)
        raise WhiteboxAuditError("unknown command", ExitCode.INVALID_INPUT)
    except WhiteboxAuditError as error:
        err.write(f"error: {redact_output(str(error))}\n")
        return int(error.exit_code)
    except Exception:
        err.write("error: internal failure; no operation was completed\n")
        return int(ExitCode.GENERAL_ERROR)


def entrypoint() -> None:
    raise SystemExit(run())
