# 13 - Upstream References

Verified on 2026-08-10.

This file exists so future Codex work can re-check tool behavior instead of relying on stale assumptions.

## OpenAI Codex

- CLI
  - https://developers.openai.com/codex/cli
- AGENTS.md
  - https://developers.openai.com/codex/agent-configuration/agents-md
- Skills
  - https://developers.openai.com/codex/build-skills
- Sandbox / approvals / network
  - https://developers.openai.com/codex/agent-approvals-security
- Configuration
  - https://developers.openai.com/codex/config-file/config-basic
  - https://developers.openai.com/codex/config-file/config-advanced
- Codex Security
  - https://developers.openai.com/codex/security

## Project CodeGuard

- Home
  - https://project-codeguard.org/
- Codex plugin
  - https://project-codeguard.org/codex-skill-plugin/
- Install paths
  - https://project-codeguard.org/install-paths/
- Skills
  - https://project-codeguard.org/skills/
- Source repository
  - https://github.com/cosai-oasis/project-codeguard

## CodeQL

- CLI setup
  - https://docs.github.com/en/code-security/how-tos/find-and-fix-code-vulnerabilities/scan-from-the-command-line/set-up-codeql-cli
- CLI overview
  - https://docs.github.com/en/code-security/concepts/code-scanning/codeql/codeql-cli
- SARIF
  - https://docs.github.com/en/code-security/reference/code-scanning/codeql/codeql-cli/sarif-output
- Query/libraries source
  - https://github.com/github/codeql
- Bundle releases
  - https://github.com/github/codeql-action/releases

## Semgrep

- Quickstart
  - https://docs.semgrep.dev/getting-started/quickstart
- Local scanning
  - https://docs.semgrep.dev/getting-started/cli
- CLI reference
  - https://docs.semgrep.dev/cli-reference
- CE customization / SARIF
  - https://docs.semgrep.dev/customize-semgrep-ce

## Maintenance rule

Whenever setup/tool behavior changes:

1. re-check the official upstream reference,
2. update setup docs,
3. update `doctor`,
4. add/adjust tests,
5. record breaking changes in the project changelog.

Do not rely on blog posts when primary vendor documentation exists.
