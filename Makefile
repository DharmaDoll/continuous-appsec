UV ?= uv
PYTHON ?= python3
UV_CACHE_DIR ?= /tmp/whitebox-audit-uv-cache
UV_RUN = $(UV) run --config-file uv.toml --frozen --no-sync
export UV_CACHE_DIR
export TARGET

.PHONY: help setup malware-check format format-check lint typecheck test doctor prepare scan supply-chain sbom check

help:
	@echo "Whitebox AI Audit development commands"
	@echo "  make setup         Create/update the Python environment"
	@echo "  make malware-check Run uv's online OSV malware check during trusted setup"
	@echo "  make format        Format Python sources"
	@echo "  make format-check  Check Python formatting"
	@echo "  make lint          Run Ruff lint checks"
	@echo "  make typecheck     Run mypy"
	@echo "  make test          Run pytest"
	@echo "  make doctor        Check audit host capabilities"
	@echo "  make prepare       Validate/register TARGET without executing it"
	@echo "  make scan          Prepare and Semgrep-scan TARGET"
	@echo "  make supply-chain  Enforce dependency and lock integrity policy"
	@echo "  make sbom          Generate a CycloneDX SBOM under reports/"
	@echo "  make check         Run all non-mutating development checks"

setup:
	$(UV) sync --config-file uv.toml --all-groups --locked --python $(PYTHON)

malware-check:
	UV_MALWARE_CHECK=1 $(UV) sync --config-file uv.toml --preview-features malware-check --all-groups --locked --python $(PYTHON)

format:
	$(UV_RUN) ruff format src tests
	$(UV_RUN) ruff check --fix src tests

format-check:
	$(UV_RUN) ruff format --check src tests

lint:
	$(UV_RUN) ruff check src tests

typecheck:
	$(UV_RUN) mypy src tests

test:
	$(UV_RUN) pytest

doctor:
	$(UV_RUN) whitebox-audit doctor

prepare:
	@test -n "$$TARGET" || (echo "TARGET is required" >&2; exit 2)
	$(UV_RUN) whitebox-audit prepare --target "$$TARGET"

scan:
	@test -n "$$TARGET" || (echo "TARGET is required" >&2; exit 2)
	$(UV_RUN) whitebox-audit scan --target "$$TARGET" --scanner semgrep

supply-chain:
	$(UV_RUN) whitebox-audit supply-chain check --project-root . --uv $(UV)

sbom:
	$(UV) export --config-file uv.toml --no-cache --preview-features sbom-export --format cyclonedx1.5 --all-groups --frozen --no-emit-project --output-file reports/whitebox-ai-audit.cdx.json

check: supply-chain format-check lint typecheck test
