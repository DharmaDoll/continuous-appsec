# 01 - Environment Setup

This document defines the supported local environment and the bootstrap procedure.

The goal is that a new operator can clone the audit harness, install dependencies, run `make doctor`, and know exactly what is ready.

## 1. Recommended host

Preferred:

- Linux x86_64, or
- macOS with Docker Desktop / equivalent container runtime.

Windows:

- Prefer WSL2 for the audit harness when practical.
- Native Codex is supported, but verifier/scanner scripts should have explicit Windows support before claiming parity.

Do not use Alpine Linux as the primary CodeQL runtime because the CodeQL CLI is not compatible with non-glibc Linux distributions such as Alpine.

## 2. Host prerequisites

Required:

```text
git
curl
jq
ripgrep (rg)
python >= 3.12
uv or pipx
docker
make
codex
```

Recommended:

```text
gh
zstd
shellcheck
```

Sanity check:

```bash
git --version
curl --version
jq --version
rg --version
python3 --version
docker version
make --version
```

## 3. Install Codex CLI

Official current macOS/Linux installer:

```bash
curl -fsSL https://chatgpt.com/codex/install.sh | sh
```

Then:

```bash
codex --version
codex
```

Sign in using the supported authentication flow.

### Audit-safe Codex profile

Do not use full-access mode for this project.

Recommended interactive invocation while implementing the harness:

```bash
codex \
  --sandbox workspace-write \
  --ask-for-approval on-request
```

For a read-only audit/review session:

```bash
codex \
  --sandbox read-only \
  --ask-for-approval on-request
```

Network is disabled by default in `workspace-write` unless explicitly enabled in Codex configuration.

### Optional local profile

Create a profile outside the repository so target content cannot modify it.

Example `~/.codex/whitebox-audit.config.toml`:

```toml
approval_policy = "on-request"
sandbox_mode = "workspace-write"
allow_login_shell = false

[shell_environment_policy]
inherit = "core"

[shell_environment_policy.filters]
"AWS_*" = "exclude"
"AZURE_*" = "exclude"
"GOOGLE_*" = "exclude"
"GITHUB_TOKEN" = "exclude"
"GH_TOKEN" = "exclude"
"NPM_TOKEN" = "exclude"
"PYPI_*" = "exclude"
```

Launch:

```bash
codex --profile whitebox-audit
```

Do not put real credentials in repository-local Codex config.

## 4. Install Project CodeGuard

### Recommended route for this project: Codex plugin

Project CodeGuard currently provides a Codex plugin.

Prerequisite:

```text
Codex CLI >= 0.142.0
```

Check:

```bash
codex --version
```

Install:

```bash
codex plugin marketplace add cosai-oasis/project-codeguard
codex plugin add codeguard-security@project-codeguard
```

Verify:

```bash
codex plugin list --marketplace project-codeguard
```

Start a new Codex session after installation.

Update:

```bash
codex plugin marketplace upgrade project-codeguard
codex plugin list --marketplace project-codeguard
```

### Why plugin instead of copying CodeGuard into this repository?

Default choice:

- CodeGuard provides baseline security knowledge.
- This repository owns the **audit protocol** and organization/domain-specific invariants.
- A managed plugin avoids maintaining a stale vendored copy.
- Record the installed version in audit metadata for reproducibility.

For environments requiring strict review/pinning, project-scoped Agent Skills/rules may be vendored at a reviewed release instead. Do not silently pull `main` during an audit.

## 5. Install Semgrep

Preferred official methods include `pipx` and `uv`.

Using `uv`:

```bash
uv tool install semgrep
semgrep --version
```

or:

```bash
pipx install semgrep
semgrep --version
```

Homebrew is supported on a best-effort basis and may lag, so do not use it as the reproducibility baseline.

Basic local smoke test in a benign fixture:

```bash
semgrep scan --config auto ./tests/fixtures/benign
```

SARIF output:

```bash
semgrep scan \
  --config auto \
  --sarif \
  --sarif-output work/semgrep.sarif \
  /path/to/target
```

Production implementation must wrap this command and must not rely on operators typing it manually.

## 6. Install CodeQL CLI

CodeQL is **optional but strongly recommended** when:

- the target language is supported,
- the organization is entitled to use CodeQL on that repository,
- build extraction can be performed safely.

### Licensing / entitlement gate

Do not make CodeQL a hard dependency.

GitHub documents CodeQL CLI use for:

- public repositories on GitHub.com, and
- organization-owned repositories with GitHub Code Security enabled under the applicable plan/terms.

Before scanning private/internal code, the operator must confirm entitlement.

The implementation should support:

```yaml
codeql:
  enabled: auto
```

Where `auto` means:

- use when executable is installed,
- target appears supported,
- operator has explicitly acknowledged entitlement in local config,
- otherwise skip with a visible reason.

### Download the CodeQL bundle

GitHub recommends the **CodeQL bundle**, not a standalone CLI plus separately checked-out query libraries.

Official bundle releases:

```text
https://github.com/github/codeql-action/releases
```

Download the appropriate `codeql-bundle-<platform>.tar.zst` or gzip equivalent.

Example installation layout:

```bash
mkdir -p "$HOME/tools/codeql"
# extract bundle so that executable becomes:
# $HOME/tools/codeql/codeql/codeql

export PATH="$HOME/tools/codeql/codeql:$PATH"
```

Verify:

```bash
codeql version
codeql resolve packs
```

The output should resolve query/library packs from inside the extracted bundle.

### Critical safety note: CodeQL builds can execute target code

For compiled languages, `codeql database create --command ...` can invoke the target build system.

A malicious or merely complex target build may execute:

- package install scripts,
- Gradle/Maven plugins,
- npm lifecycle scripts,
- generators,
- arbitrary shell commands.

Therefore:

**Never run untrusted CodeQL build extraction directly on the operator host by default.**

Implement CodeQL extraction inside a dedicated scanner container/VM with:

- source mounted read-only where possible,
- separate writable build workspace,
- no host credentials,
- controlled network,
- resource limits,
- explicit build command.

## 7. Docker

Verify:

```bash
docker run --rm hello-world
```

The verifier must later support at least:

```text
--network none
--read-only
--cap-drop ALL
--security-opt no-new-privileges
--pids-limit
--memory
--cpus
tmpfs
read-only target mount
separate output mount
```

Do not add `/var/run/docker.sock` to the verifier container.

## 8. Python project environment

Recommended:

```bash
uv venv
source .venv/bin/activate
```

When `pyproject.toml` exists:

```bash
uv sync
```

The implementation should pin direct dependencies and commit the lock file if the chosen workflow supports it.

## 9. Suggested initial Python dependencies

Keep this intentionally small:

```text
pydantic or dataclasses-based validation
PyYAML
rich          # optional CLI UX
typer         # optional CLI; argparse is acceptable
```

Prefer the standard library if it keeps the system simple.

Do not add an agent framework until a concrete need exists.

## 10. `make doctor` acceptance criteria

Codex should implement `scripts/doctor.sh` or equivalent.

It must report:

```text
[OK] git
[OK] python
[OK] docker daemon
[OK] codex
[OK] CodeGuard plugin
[OK] semgrep
[OPTIONAL] codeql
[WARN] codeql entitlement acknowledgement not configured
[OK] ripgrep
[OK] jq
```

It must print versions and never modify the host.

Exit behavior:

- required dependency missing -> nonzero,
- optional CodeQL missing -> warning only,
- Docker unavailable -> nonzero because verifier is required.

## 11. No-secret environment

Before using a real target, run the audit from a shell/session that does not expose unnecessary credentials.

The eventual harness should invoke child tools with an explicit minimal environment, for example:

```python
SAFE_ENV_KEYS = {
    "PATH",
    "HOME",
    "LANG",
    "LC_ALL",
    "TMPDIR",
}

def minimal_env(source: dict[str, str]) -> dict[str, str]:
    return {k: v for k, v in source.items() if k in SAFE_ENV_KEYS}
```

Do not blindly pass `os.environ` into untrusted build or PoC processes.

## 12. First setup validation

After Codex implements Milestone 0:

```bash
make doctor
make test
```

Then use only purpose-built fixture repositories before auditing real code.

## Upstream references

Checked on 2026-08-10:

- https://developers.openai.com/codex/cli
- https://developers.openai.com/codex/agent-approvals-security
- https://developers.openai.com/codex/config-file/config-advanced
- https://project-codeguard.org/codex-skill-plugin/
- https://project-codeguard.org/install-paths/
- https://docs.semgrep.dev/getting-started/quickstart
- https://docs.semgrep.dev/cli-reference
- https://docs.github.com/en/code-security/how-tos/find-and-fix-code-vulnerabilities/scan-from-the-command-line/set-up-codeql-cli
