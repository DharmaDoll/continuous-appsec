"""Defensive SARIF loading and scanner-evidence normalization."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path, PurePosixPath
from typing import Final
from urllib.parse import unquote, urljoin, urlparse

from whitebox_audit.doctor import redact_output
from whitebox_audit.errors import ExitCode, WhiteboxAuditError
from whitebox_audit.models import (
    SCHEMA_VERSION,
    Evidence,
    EvidenceConfidence,
    EvidenceKind,
    EvidenceLocation,
    EvidenceProvenance,
    SarifNormalizationResult,
)

MAX_SARIF_BYTES: Final[int] = 100 * 1024 * 1024
MAX_CLAIM_CHARS: Final[int] = 4_000
_SAFE_LEVELS: Final[frozenset[str]] = frozenset({"none", "note", "warning", "error"})


def load_sarif(path: Path) -> dict[str, object]:
    try:
        metadata = path.stat(follow_symlinks=False)
        if path.is_symlink() or not path.is_file() or metadata.st_size > MAX_SARIF_BYTES:
            raise WhiteboxAuditError("SARIF input violates file policy", ExitCode.POLICY_REJECTED)
        payload = json.loads(path.read_text(encoding="utf-8"))
    except WhiteboxAuditError:
        raise
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        raise WhiteboxAuditError(
            "SARIF is not valid UTF-8 JSON", ExitCode.DATA_INTEGRITY_ERROR
        ) from error
    if not isinstance(payload, dict) or not isinstance(payload.get("runs"), list):
        raise WhiteboxAuditError("SARIF must contain a runs array", ExitCode.DATA_INTEGRITY_ERROR)
    return {str(key): value for key, value in payload.items()}


def _table(value: object) -> dict[str, object]:
    return {str(key): item for key, item in value.items()} if isinstance(value, dict) else {}


def _list(value: object) -> list[object]:
    return value if isinstance(value, list) else []


def _text(value: object, default: str = "") -> str:
    return value if isinstance(value, str) else default


def _message(value: object) -> str:
    message = _table(value)
    text = _text(message.get("text")) or _text(message.get("markdown"))
    normalized = " ".join(text.replace("\x00", "").split())
    return redact_output(normalized, limit=MAX_CLAIM_CHARS) or "scanner result"


def _safe_path(uri: str, base_uri: str | None, target_root: Path | None) -> tuple[str, bool]:
    combined = urljoin(base_uri, uri) if base_uri else uri
    parsed = urlparse(combined)
    decoded = unquote(parsed.path if parsed.scheme == "file" else combined)
    candidate = Path(decoded)
    if target_root is not None:
        try:
            resolved = (
                candidate.resolve(strict=False)
                if candidate.is_absolute()
                else (target_root / candidate).resolve(strict=False)
            )
            if resolved.is_relative_to(target_root):
                return resolved.relative_to(target_root).as_posix(), True
        except OSError:
            pass
    if (
        not candidate.is_absolute()
        and ".." not in PurePosixPath(decoded).parts
        and not parsed.scheme
    ):
        normalized = PurePosixPath(decoded).as_posix().removeprefix("./")
        if normalized:
            return normalized, target_root is not None
    digest = hashlib.sha256(combined.encode()).hexdigest()[:20]
    return f"external-uri:{digest}", False


def _rule_map(tool: dict[str, object], driver: dict[str, object]) -> dict[str, dict[str, object]]:
    rules: dict[str, dict[str, object]] = {}
    sources = [_list(driver.get("rules"))]
    for extension in _list(tool.get("extensions")):
        sources.append(_list(_table(extension).get("rules")))
    for source in sources:
        for item in source:
            rule = _table(item)
            rule_id = _text(rule.get("id"))
            if rule_id:
                rules[rule_id] = rule
    return rules


def _severity(result: dict[str, object], rule: dict[str, object]) -> str:
    level = _text(result.get("level"))
    if not level:
        level = _text(_table(rule.get("defaultConfiguration")).get("level"))
    if not level:
        level = _text(_table(rule.get("properties")).get("severity"), "warning").lower()
    return level if level in _SAFE_LEVELS else "warning"


def normalize_sarif(
    payload: dict[str, object],
    *,
    target_id: str,
    target_tree_hash: str,
    scanner_run_id: str,
    raw_ref: str,
    target_root: Path | None,
    fallback_tool_name: str,
) -> SarifNormalizationResult:
    evidence_by_fingerprint: dict[str, Evidence] = {}
    warnings: list[str] = []
    result_count = 0
    for run_index, run_value in enumerate(_list(payload.get("runs"))):
        run = _table(run_value)
        if not run:
            warnings.append(f"runs[{run_index}] is not an object")
            continue
        tool = _table(run.get("tool"))
        driver = _table(tool.get("driver"))
        tool_name = _text(driver.get("name"), fallback_tool_name)
        tool_version = _text(driver.get("semanticVersion")) or _text(driver.get("version")) or None
        rules = _rule_map(tool, driver)
        bases = _table(run.get("originalUriBaseIds"))
        results = _list(run.get("results"))
        if not results:
            continue
        for result_index, result_value in enumerate(results):
            result = _table(result_value)
            if not result:
                warnings.append(f"runs[{run_index}].results[{result_index}] is not an object")
                continue
            result_count += 1
            rule_id = (
                _text(result.get("ruleId"))
                or _text(_table(result.get("rule")).get("id"))
                or "unknown-rule"
            )
            rule = rules.get(rule_id, {})
            claim = _message(result.get("message"))
            locations = _list(result.get("locations"))
            path: str | None = None
            path_safe = False
            start_line: int | None = None
            end_line: int | None = None
            snippet_hash: str | None = None
            if locations:
                physical = _table(_table(locations[0]).get("physicalLocation"))
                artifact = _table(physical.get("artifactLocation"))
                uri = _text(artifact.get("uri"))
                base_id = _text(artifact.get("uriBaseId"))
                base_uri = _text(_table(bases.get(base_id)).get("uri")) if base_id else None
                if uri:
                    path, path_safe = _safe_path(uri, base_uri, target_root)
                region = _table(physical.get("region"))
                start_value = region.get("startLine")
                end_value = region.get("endLine")
                start_line = start_value if isinstance(start_value, int) else None
                end_line = end_value if isinstance(end_value, int) else start_line
                snippet = _message(region.get("snippet")) if region.get("snippet") else ""
                snippet_hash = hashlib.sha256(snippet.encode()).hexdigest() if snippet else None
            stable = json.dumps(
                [target_tree_hash, tool_name, rule_id, path, start_line, end_line, claim],
                separators=(",", ":"),
                ensure_ascii=False,
            )
            fingerprint = hashlib.sha256(stable.encode()).hexdigest()
            evidence_id = f"EVD-{fingerprint[:20]}"
            result_raw_ref = f"{raw_ref}#runs/{run_index}/results/{result_index}"
            evidence_by_fingerprint.setdefault(
                fingerprint,
                Evidence(
                    schema_version=SCHEMA_VERSION,
                    evidence_id=evidence_id,
                    kind=EvidenceKind.STATIC_ANALYSIS,
                    claim=claim,
                    location=EvidenceLocation(path, path_safe, start_line, end_line, snippet_hash),
                    artifact_ref=result_raw_ref,
                    fingerprint=fingerprint,
                    content_hash=hashlib.sha256(
                        json.dumps(result, sort_keys=True).encode()
                    ).hexdigest(),
                    confidence=EvidenceConfidence.DETERMINISTIC_STATIC,
                    target_id=target_id,
                    target_tree_hash=target_tree_hash,
                    provenance=EvidenceProvenance(
                        source_type="static-analysis",
                        run_id=scanner_run_id,
                        raw_uri=result_raw_ref,
                        tool_name=tool_name,
                        tool_version=tool_version,
                        rule_id=rule_id,
                        target_tree_hash=target_tree_hash,
                    ),
                    severity=_severity(result, rule),
                ),
            )
    return SarifNormalizationResult(
        evidence=tuple(evidence_by_fingerprint.values()),
        warnings=tuple(warnings),
        result_count=result_count,
        duplicate_count=result_count - len(evidence_by_fingerprint),
    )
