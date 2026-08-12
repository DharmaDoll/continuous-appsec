# 15 - Requirements Traceability

This table links the first implementation milestone to executable checks. It will grow with each milestone.

| Requirement | Implementation | Test or check |
|---|---|---|
| FR-DOC-001 | `whitebox_audit.cli`, `Makefile` | `test_module_help`, `make doctor` |
| FR-DOC-002 | `whitebox_audit.doctor.Doctor` | fake toolchain tests, real doctor run |
| FR-DOC-003 | optional CodeQL capability | `test_fake_toolchain_succeeds_with_optional_codeql_missing` |
| FR-DOC-004 | human and JSON renderers | `test_doctor_json_output`, real doctor run |
| FR-DOC-005 | `DoctorReport.exit_code` | `test_required_error_makes_report_not_ready` |
| FR-DOC-006 | read-only diagnostic commands | no-write test and command review |
| SEC-005 | `minimal_env` | `test_minimal_env_uses_allowlist` |
| SEC-008 | `run_command(..., shell=False)` | code review and fake executable integration tests |
| SEC-015 | `redact_output` | `test_redact_output_bounds_and_redacts` |
| SEC-SC-001 | exact direct/build pins and 72-hour cooldown | `SC-DECLARED-DEPS`, `SC-DEPENDENCY-COOLDOWN` |
| SEC-SC-002 | approved registry/artifact sources and SHA-256 lock records | supply-chain source/hash tests |
| SEC-SC-003 | offline lock freshness and schema gate | `make supply-chain` |
| SEC-SC-004 | project-file confinement | `test_lock_symlink_outside_project_is_rejected` |
| SEC-SC-005 | executable provenance | fake toolchain executable SHA-256 assertion |
| SEC-SC-006 | CycloneDX harness inventory | `make sbom` and JSON structure check |
| FR-TGT-001/002/003 | `PrepareController`, `validate_target_root` | target relationship and CLI tests |
| FR-TGT-004/005 | content fingerprint and hardened Git metadata | deterministic/Git tests |
| FR-TGT-006/007 | directory-FD traversal, no-follow opens, before/after hash | symlink and no-write tests |
| FR-TGT-008 | staged canonical run persistence | persistence, overwrite, failure-cleanup tests |
| SEC-002/003 | target text remains data; no target execution | malicious fixture prepare test |
| SEC-006/007 | symlink/mount/path confinement | path, symlink, device boundary tests |
| FR-SCN-001/002 | `Scanner` protocol and Semgrep adapter | argv/ruleset and fake scanner integration tests |
| FR-SCN-003 | raw SARIF and `ScannerRun` persistence | success/failure/timeout/skipped tests |
| FR-SCN-004 | defensive SARIF parser | realistic, optional-field, multiple-run, external-URI fixtures |
| FR-SCN-005 | visible scanner/SARIF failures | exit 5/6 and final run-state tests |
| FR-SCN-006 | operator SARIF ingestion | ingest path/provenance/symlink tests |
| FR-SCN-009 | stable Evidence fingerprint and atomic deduplication | Evidence store merge/corruption/target-mismatch tests |
| SEC-005/008/015 | minimal env, argument arrays, redaction | fake scanner argv/log tests |
| SEC-003 | no target lifecycle execution | scanner adapter command review and fixture tests |
| SEC-007 | target mutation detection | malicious fake scanner mutation test |
