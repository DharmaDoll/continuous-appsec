#!/bin/sh
set -eu

PROJECT_ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)

if command -v uv >/dev/null 2>&1; then
    exec uv run --config-file "$PROJECT_ROOT/uv.toml" --frozen --no-sync --project "$PROJECT_ROOT" whitebox-audit doctor "$@"
fi

PYTHONPATH="$PROJECT_ROOT/src${PYTHONPATH:+:$PYTHONPATH}"
export PYTHONPATH
exec python3 -m whitebox_audit doctor "$@"
