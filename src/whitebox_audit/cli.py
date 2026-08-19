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
from whitebox_audit.models import (
    Evidence,
    EvidenceKind,
    Hypothesis,
    PrepareResult,
    SecurityInvariant,
    VerificationCase,
)
from whitebox_audit.prepare import PrepareController, discover_harness_root
from whitebox_audit.record_store import RunRecordStore, load_record_document
from whitebox_audit.scan import ScanController, ScanResult, ingest_sarif
from whitebox_audit.supply_chain import (
    SupplyChainReport,
    SupplyChainStatus,
    inspect_supply_chain,
)
from whitebox_audit.verifier import parse_runtime_adapter, parse_verifier_policy


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

    evidence = subparsers.add_parser("evidence", help="inspect canonical evidence records")
    evidence_subparsers = evidence.add_subparsers(dest="evidence_command", required=True)
    evidence_list = evidence_subparsers.add_parser("list", help="list evidence for a run")
    evidence_list.add_argument("--run-id", required=True)
    evidence_list.add_argument("--kind", choices=tuple(item.value for item in EvidenceKind))
    evidence_list.add_argument("--format", choices=("human", "json"), default="human")

    show_evidence = subparsers.add_parser("show-evidence", help="show one evidence record")
    show_evidence.add_argument("evidence_id")
    show_evidence.add_argument("--run-id", required=True)
    show_evidence.add_argument("--format", choices=("human", "json"), default="human")

    invariant = subparsers.add_parser("invariant", help="manage security invariants")
    invariant_subparsers = invariant.add_subparsers(dest="invariant_command", required=True)
    invariant_add = invariant_subparsers.add_parser(
        "add", help="import a declared/inferred invariant and its source evidence"
    )
    invariant_add.add_argument("--run-id", required=True)
    invariant_add.add_argument("--file", required=True)
    invariant_add.add_argument("--format", choices=("human", "json"), default="human")
    invariant_list = invariant_subparsers.add_parser("list", help="list invariants for a run")
    invariant_list.add_argument("--run-id", required=True)
    invariant_list.add_argument("--format", choices=("human", "json"), default="human")

    hypothesis = subparsers.add_parser("hypothesis", help="manage vulnerability hypotheses")
    hypothesis_subparsers = hypothesis.add_subparsers(dest="hypothesis_command", required=True)
    hypothesis_add = hypothesis_subparsers.add_parser(
        "add", help="validate and persist a manual hypothesis"
    )
    hypothesis_add.add_argument("--run-id", required=True)
    hypothesis_add.add_argument("--file", required=True)
    hypothesis_add.add_argument("--format", choices=("human", "json"), default="human")
    hypothesis_list = hypothesis_subparsers.add_parser("list", help="list hypotheses for a run")
    hypothesis_list.add_argument("--run-id", required=True)
    hypothesis_list.add_argument("--format", choices=("human", "json"), default="human")

    verification_case = subparsers.add_parser(
        "verification-case", help="manage declarative verifier cases"
    )
    verification_case_subparsers = verification_case.add_subparsers(
        dest="verification_case_command", required=True
    )
    verification_case_add = verification_case_subparsers.add_parser(
        "add", help="validate and persist an HTTP verification case"
    )
    verification_case_add.add_argument("--run-id", required=True)
    verification_case_add.add_argument("--file", required=True)
    verification_case_add.add_argument(
        "--policy", help="verifier policy JSON/YAML (default: config/verifier-policy.yaml)"
    )
    verification_case_add.add_argument("--adapter", required=True)
    verification_case_add.add_argument("--format", choices=("human", "json"), default="human")
    verification_case_list = verification_case_subparsers.add_parser(
        "list", help="list verification cases for a run"
    )
    verification_case_list.add_argument("--run-id", required=True)
    verification_case_list.add_argument("--format", choices=("human", "json"), default="human")
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


def render_evidence_human(records: Sequence[Evidence]) -> str:
    if not records:
        return "No evidence records."
    return "\n".join(f"{item.evidence_id} [{item.kind}] {item.claim}" for item in records)


def render_invariants_human(records: Sequence[SecurityInvariant]) -> str:
    if not records:
        return "No invariant records."
    return "\n".join(
        f"{item.invariant_id} [{item.source.derivation}] {item.title}" for item in records
    )


def render_hypotheses_human(records: Sequence[Hypothesis]) -> str:
    if not records:
        return "No hypothesis records."
    return "\n".join(f"{item.hypothesis_id} [{item.status}] {item.title}" for item in records)


def render_verification_cases_human(records: Sequence[VerificationCase]) -> str:
    if not records:
        return "No verification case records."
    return "\n".join(
        f"{item.verification_id} [http] {item.hypothesis_id} via {item.runtime_profile}"
        for item in records
    )


def _record_error(error: TypeError | ValueError) -> WhiteboxAuditError:
    return WhiteboxAuditError(f"invalid canonical record: {error}", ExitCode.INVALID_INPUT)


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
        if args.command == "evidence" and args.evidence_command == "list":
            root = discover_harness_root(Path.cwd()) if harness_root is None else harness_root
            store = RunRecordStore(root, args.run_id)
            kind = EvidenceKind(args.kind) if args.kind is not None else None
            evidence_records = store.list_evidence(kind=kind)
            if args.format == "json":
                json.dump(
                    [item.to_dict() for item in evidence_records], out, indent=2, sort_keys=True
                )
                out.write("\n")
            else:
                out.write(render_evidence_human(evidence_records) + "\n")
            return int(ExitCode.OK)
        if args.command == "show-evidence":
            root = discover_harness_root(Path.cwd()) if harness_root is None else harness_root
            record = RunRecordStore(root, args.run_id).get_evidence(args.evidence_id)
            if args.format == "json":
                json.dump(record.to_dict(), out, indent=2, sort_keys=True)
                out.write("\n")
            else:
                out.write(render_evidence_human((record,)) + "\n")
            return int(ExitCode.OK)
        if args.command == "invariant":
            root = discover_harness_root(Path.cwd()) if harness_root is None else harness_root
            store = RunRecordStore(root, args.run_id)
            if args.invariant_command == "add":
                document, raw, suffix = load_record_document(Path(args.file))
                try:
                    invariant_record = store.add_invariant_document(
                        document, raw=raw, suffix=suffix
                    )
                except (TypeError, ValueError) as error:
                    raise _record_error(error) from error
                invariant_records: tuple[SecurityInvariant, ...] = (invariant_record,)
            else:
                invariant_records = store.list_invariants()
            if args.format == "json":
                payload: object = (
                    invariant_records[0].to_dict()
                    if args.invariant_command == "add"
                    else [item.to_dict() for item in invariant_records]
                )
                json.dump(payload, out, indent=2, sort_keys=True)
                out.write("\n")
            else:
                out.write(render_invariants_human(invariant_records) + "\n")
            return int(ExitCode.OK)
        if args.command == "hypothesis":
            root = discover_harness_root(Path.cwd()) if harness_root is None else harness_root
            store = RunRecordStore(root, args.run_id)
            if args.hypothesis_command == "add":
                document, _raw, _suffix = load_record_document(Path(args.file))
                try:
                    hypothesis_record = store.add_hypothesis_document(document)
                except (TypeError, ValueError) as error:
                    raise _record_error(error) from error
                hypothesis_records: tuple[Hypothesis, ...] = (hypothesis_record,)
            else:
                hypothesis_records = store.list_hypotheses()
            if args.format == "json":
                payload = (
                    hypothesis_records[0].to_dict()
                    if args.hypothesis_command == "add"
                    else [item.to_dict() for item in hypothesis_records]
                )
                json.dump(payload, out, indent=2, sort_keys=True)
                out.write("\n")
            else:
                out.write(render_hypotheses_human(hypothesis_records) + "\n")
            return int(ExitCode.OK)
        if args.command == "verification-case":
            root = discover_harness_root(Path.cwd()) if harness_root is None else harness_root
            store = RunRecordStore(root, args.run_id)
            if args.verification_case_command == "add":
                policy_path = (
                    Path(args.policy)
                    if args.policy is not None
                    else root / "config" / "verifier-policy.yaml"
                )
                case_document, _case_raw, _case_suffix = load_record_document(Path(args.file))
                policy_document, _policy_raw, _policy_suffix = load_record_document(policy_path)
                adapter_document, _adapter_raw, _adapter_suffix = load_record_document(
                    Path(args.adapter)
                )
                try:
                    policy = parse_verifier_policy(policy_document)
                    adapter = parse_runtime_adapter(adapter_document, policy)
                    verification_case_record = store.add_verification_case_document(
                        case_document,
                        policy=policy,
                        adapter=adapter,
                    )
                except (TypeError, ValueError) as error:
                    raise _record_error(error) from error
                verification_case_records: tuple[VerificationCase, ...] = (
                    verification_case_record,
                )
            else:
                verification_case_records = store.list_verification_cases()
            if args.format == "json":
                payload = (
                    verification_case_records[0].to_dict()
                    if args.verification_case_command == "add"
                    else [item.to_dict() for item in verification_case_records]
                )
                json.dump(payload, out, indent=2, sort_keys=True)
                out.write("\n")
            else:
                out.write(render_verification_cases_human(verification_case_records) + "\n")
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
