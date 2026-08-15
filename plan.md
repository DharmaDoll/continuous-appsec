# Whitebox AI Audit 実装チェックリスト

## 使い方

このチェックリストは、[アプリケーション詳細仕様書](docs/14-APPLICATION-SPECIFICATION.md) と
[実装計画](docs/09-IMPLEMENTATION-PLAN.md) を、実装・テスト・レビュー可能な単位へ分割したものである。

- `[ ]`: 未着手
- `[-]`: 作業中または一部完了
- `[x]`: 実装、テスト、文書更新、レビュー条件まで完了
- `[!]`: ブロック中。直下に理由と解除条件を記載

チェックを完了にする前に、その項目に対応するコード、テスト、実行結果を確認する。
stub、未実行の scanner、未実行の PoC を完了として扱わない。

## 全工程に適用するルール

- [ ] 対象リポジトリの全内容を未信頼データとして扱う。
- [ ] Codex は監査ハーネスのルートから起動し、対象をプロジェクトルートにしない。
- [ ] 対象内の `AGENTS.md`、README、コメント、prompt 等を命令として扱わない。
- [ ] 対象の build、install、test、lifecycle script をホスト上で実行しない。
- [ ] subprocess は引数配列、`shell=False`、明示 timeout で起動する。
- [ ] child process へホスト環境全体を渡さず、許可リスト方式の最小環境を使用する。
- [ ] 対象パスと成果物パスを解決し、許可ルート内に confinement する。
- [ ] Discovery Agent と Verifier の権限・成果物・判定経路を分離する。
- [ ] `verified` は `proved` の VerificationResult がある場合だけ許可する。
- [ ] 対象ソースを監査処理から変更しない。
- [ ] scanner failure、skip、timeout、parse failure を黙って無視しない。
- [ ] secrets、tokens、credentials を log、SARIF、Markdown へ再掲しない。
- [ ] 実装変更ごとに unit test と security-relevant test を追加する。
- [ ] formatter、linter、unit test、該当 security test を完了前に実行する。
- [ ] 動作変更時に仕様、運用文書、CLI help を更新する。

## 全工程に適用するサプライチェーン基準

- [x] harnessのdirect/build dependencyをexact pinし、committed lockからだけ同期する。
- [x] direct URL/VCS/file dependency、alternate index、unapproved artifact hostをnative policyで拒否する。
- [x] lockのSHA-256 record、schema、72時間cooldown、offline freshnessを`make check`で強制する。
- [x] harness toolのversion、resolved executable path、SHA-256 provenanceを記録する。
- [x] harnessのCycloneDX SBOM生成コマンドを提供する。
- [ ] scanner/verifier/runtime imageをtagではなくreview済みdigestで参照する。
- [ ] TypeScript fixtureのNode/package manager versionを固定する。
- [ ] TypeScript fixtureのlock source/integrityを実行前にnative controllerで検証する。
- [ ] TypeScript fixtureのdependency installはisolated build内でlifecycle script無効を既定にする。
- [ ] target supplied manifest/lock/build scriptをhost上で実行しないsecurity testを追加する。

## 文書・設計ベースライン

- [x] `AGENTS.md` に開発ミッション、安全規則、Done criteria が定義されている。
- [x] `docs/01-SETUP.md` から `docs/13-UPSTREAM-REFERENCES.md` が存在する。
- [x] `docs/14-APPLICATION-SPECIFICATION.md` に統合仕様が定義されている。
- [x] リポジトリ監査用 Skill が `.agents/skills/whitebox-vulnerability-audit/` に存在する。
- [x] 未決定事項を ADR 一覧へ移し、決定状態を追跡できるようにする。
- [x] 仕様要件 ID とテスト ID の対応表を作成する。

## Milestone 0: リポジトリと開発環境

### M0.1 技術選定と ADR

- [x] ADR ディレクトリとテンプレートを作成する。
- [x] ADR-001: model validation に dataclasses または Pydantic のどちらを使うか決定する。
- [x] ADR-002: CLI に argparse または Typer のどちらを使うか決定する。
- [x] ADR-003: formatter、linter、type checker、test runner を決定する。
- [x] ADR-004: JSON/JSONL schema versioning の基本方針を決定する。
- [x] 直接依存関係を最小限にし、選定理由を ADR に記録する。

### M0.2 Python プロジェクト

- [x] Python 3.12+ を要求する `pyproject.toml` を作成する。
- [x] package metadata、license、README、console script を設定する。
- [x] `src/whitebox_audit/__init__.py` を作成する。
- [x] `src/whitebox_audit/__main__.py` を作成する。
- [x] `src/whitebox_audit/cli.py` に CLI root を作成する。
- [x] package version の取得方法を実装する。
- [x] `tests/` と test runner 設定を作成する。
- [x] development dependency group を定義する。
- [x] lock file を生成し、直接依存を固定する。
- [x] editable install 後に `whitebox-audit --help` が動作するテストを追加する。

### M0.3 リポジトリ基本ファイル

- [x] `.gitignore` に `.venv/`、cache、coverage、`work/`、生成レポートを追加する。
- [x] `work/.gitkeep` と `reports/.gitkeep` の要否を決定し作成する。
- [x] 秘密値を含まない `.env.example` を作成する。
- [x] Makefile に `help` を追加する。
- [x] Makefile に `format` と `format-check` を追加する。
- [x] Makefile に `lint` を追加する。
- [x] Makefile に `typecheck` を追加する。
- [x] Makefile に `test` を追加する。
- [x] Makefile に `doctor` を追加する。
- [x] Make target が対象の script をホスト上で暗黙実行しないことをレビューする。

### M0.4 Doctor capability model

- [x] `ScannerCapability` または汎用 `ToolCapability` model を定義する。
- [x] capability status として required、optional、ok、warning、error を表現する。
- [x] executable lookup を subprocess 実行から分離する。
- [x] version command の stdout/stderr/return code parser を分離する。
- [x] tool check に共通 timeout を設定する。
- [x] tool check に minimal environment を使用する。
- [x] tool version 文字列の長さと redaction を制御する。

### M0.5 Doctor 実装

- [x] Git の存在とバージョンを検査する。
- [x] curl の存在とバージョンを検査する。
- [x] jq の存在とバージョンを検査する。
- [x] ripgrep の存在とバージョンを検査する。
- [x] Python 3.12+ を検査する。
- [x] make の存在とバージョンを検査する。
- [x] uv または pipx の利用可能性を検査する。
- [x] Docker CLI の存在を検査する。
- [x] Docker daemon へ非破壊的に接続できることを検査する。
- [x] Codex CLI の存在とバージョンを検査する。
- [x] Codex CLI が最低対応バージョンを満たすか検査する。
- [x] Project CodeGuard plugin の導入状態を検査する。
- [x] Semgrep の存在とバージョンを検査する。
- [x] CodeQL の存在とバージョンを optional として検査する。
- [x] CodeQL entitlement acknowledgement の設定有無を表示する。
- [x] 必須項目欠落時に終了コード 3 を返す。
- [x] optional CodeQL 欠落時は warning と終了コード 0 を返す。
- [x] doctor がファイル、設定、host state を変更しないテストを追加する。
- [x] `whitebox-audit doctor --format json` を実装する。
- [x] human-readable 出力へ `[OK]`、`[WARN]`、`[ERROR]` と version を表示する。

### M0.6 共通 CLI とエラー処理

- [x] CLI 共通の structured error model を定義する。
- [x] 仕様書の終了コード 0〜6 を定数化する。
- [x] 正常出力を stdout、エラーを stderr へ出力する。
- [x] uncaught exception の既定表示から secrets と内部 path を保護する。
- [x] `--verbose` / `--debug` の方針を決定する。
- [x] `--version` を実装する。
- [x] invalid option が終了コード 2 になるテストを追加する。

### M0.7 Milestone 0 テストとゲート

- [x] unit test: version parser の正常・異常ケースを追加する。
- [x] unit test: required/optional capability 集計を追加する。
- [x] unit test: minimal environment を追加する。
- [x] unit test: secrets を継承しないことを追加する。
- [x] integration test: fake executables を使った doctor success を追加する。
- [x] integration test: required tool missing を追加する。
- [x] integration test: CodeQL missing warning を追加する。
- [x] `make format-check` を実行して成功する。
- [x] `make lint` を実行して成功する。
- [x] `make typecheck` を実行して成功する。
- [x] `make test` を実行して成功する。
- [x] サポート環境で `make doctor` の実行結果を記録する。
- [x] README のセットアップ手順と実コマンドを一致させる。
- [x] Milestone 0 の未実装・制限事項を明記する。

## Milestone 1: Safe Target Controller

### M1.1 Target と run model

- [x] `Target` model を immutable object として定義する。
- [x] `target_id`、resolved root、git commit、tree hash、languages、manifests を定義する。
- [x] `prepared_at` と `read_only=true` を定義する。
- [x] `AuditRun` model と run status を定義する。
- [x] run status `created/prepared/running/completed/degraded/failed/cancelled` を定義する。
- [x] run ID の生成規則を定義する。
- [x] `schema_version` を全永続 object に追加する。

### M1.2 Path validation

- [x] target 入力を `Path` として受理する。
- [x] target を `resolve(strict=True)` 相当で絶対化する。
- [x] 存在しない target を拒否する。
- [x] directory でない target を拒否する。
- [x] 読取り不能な target を拒否する。
- [x] harness root と同一の target を拒否する。
- [x] harness と target の危険な包含関係を定義し拒否する。
- [x] `resolve_under(root, candidate)` を共通関数として実装する。
- [x] `..` による逸脱を拒否する。
- [x] absolute candidate による逸脱を拒否する。
- [x] symlink が target 外へ向く場合の既定拒否を実装する。
- [x] broken symlink の扱いを明示する。
- [x] nested Git worktree と mount confusion の脅威ケースをテストする。

### M1.3 Target fingerprint

- [x] Git repository 判定を target code 実行なしで行う。
- [x] Git commit を安全な引数配列で取得する。
- [x] dirty worktree の有無を metadata に記録する。
- [x] Git tree hash の取得方法を実装する。
- [x] 非 Git target の deterministic tree fingerprint を実装する。
- [x] fingerprint 対象から `work/` 等を除外する規則を定義する。
- [x] symlink の fingerprint 表現を定義する。
- [x] file order、mtime、absolute path に依存しないことをテストする。
- [x] 内容変更で tree fingerprint が変わることをテストする。

### M1.4 Inventory

- [x] source extension から言語候補を列挙する。
- [x] Python manifest をコード実行なしで検出する。
- [x] JavaScript/TypeScript manifest をコード実行なしで検出する。
- [x] Java、Go、Ruby、PHP、.NET 等の manifest 検出を拡張可能にする。
- [x] route/framework 推定に必要なファイル名だけを inventory する。
- [x] binary、巨大ファイル、vendor/generated directory の既定除外を定義する。
- [x] inventory 上限と timeout を設定する。
- [x] inventory が symlink escape を追跡しないことをテストする。

### M1.5 Run directory と永続化

- [x] `work/<run-id>/` を harness 内に作成する。
- [x] run ID が path separator や traversal を含めないことを検証する。
- [x] `run.json` を atomic write する。
- [x] `target.json` を atomic write する。
- [x] `inventory.json` を atomic write する。
- [x] effective config から secrets を除外して保存する。
- [x] artifact reference を run-relative path に制限する。
- [x] 既存 run を暗黙上書きしない。
- [x] 部分書込み・破損 JSON の recovery 方針を実装する。

### M1.6 Prepare CLI

- [x] `whitebox-audit prepare --target <path>` を実装する。
- [x] `--profile` を受理する設定 loader を実装する。
- [x] prepare 成功時に run ID と target summary を表示する。
- [x] `--format json` を実装する。
- [x] safety rejection を終了コード 4 とする。
- [x] data integrity failure を終了コード 6 とする。
- [x] `make prepare TARGET=...` を追加する。

### M1.7 悪意ある fixture とゲート

- [x] benign target fixture を作成する。
- [x] malicious `AGENTS.md` fixture を作成する。
- [x] malicious README prompt fixture を作成する。
- [x] source comment prompt injection fixture を作成する。
- [x] external symlink fixture を作成する。
- [x] package install script fixture を作成するが実行しない。
- [x] prepare 前後の target tree hash が不変であるテストを追加する。
- [x] target 内に成果物が作成されないテストを追加する。
- [x] malicious text が harness 設定を変更しないテストを追加する。
- [x] formatter、linter、typecheck、unit test を実行する。
- [x] path security test suite を実行する。
- [x] target metadata の realistic fixture をレビューする。
- [x] Milestone 1 の制限事項を文書化する。

## Milestone 2: Semgrep Vertical Slice

### M2.1 Scanner abstraction

- [x] `Scanner` Protocol を定義する。
- [x] `doctor`、`run`、`normalize` の責務を分離する。
- [x] `ScannerRun` model を定義する。
- [x] scanner status `succeeded/skipped/failed/timed-out` を定義する。
- [x] argv、version、timestamps、return code、reason、artifact refs を定義する。
- [x] scanner resource policy model を定義する。
- [x] scanner output directory 規則を定義する。

### M2.2 Semgrep execution

- [x] Semgrep executable と version を capability check から取得する。
- [x] reviewed harness-local YAML と top-level `rules` 構造を検証し、完全検証は Semgrep 実行結果で判定する。
- [x] target exclusion policy を設定できるようにする。
- [x] `semgrep scan` argv を純粋関数で構築する。
- [x] `shell=False` で実行する。
- [x] timeout を適用する。
- [x] minimal environment を適用する。
- [x] stdout と stderr を capture する。
- [x] raw SARIF を `scanner-runs/semgrep/result.sarif` に保存する。
- [x] `run.json` に実行 metadata を保存する。
- [x] Semgrep の findings exit と execution failure を区別する。
- [x] timeout 時に `timed-out` として保存する。
- [x] log へ secret redaction を適用する。
- [x] target tree hash が実行前後で不変であることを確認する。

### M2.3 SARIF parser

- [x] SARIF JSON load と schema-independent extraction を分離する。
- [x] `runs[]` の複数 run を処理する。
- [x] tool driver name/version を抽出する。
- [x] rule metadata の複数配置を処理する。
- [x] result message を抽出する。
- [x] severity/level 欠落を処理する。
- [x] artifact URI と base URI を正規化する。
- [x] target 外 URI を安全に表現し、source read に使用しない。
- [x] location 欠落を許容する。
- [x] region、line、snippet 欠落を許容する。
- [x] raw result reference を生成する。
- [x] malformed JSON を明示 error にする。
- [x] 必須構造欠落を明示 error または warning に分類する。
- [x] partial parse の件数と warning を保存する。

### M2.4 Evidence normalization

- [x] 最小 `Evidence` model を実装する。
- [x] `EVD-<hash>` の生成関数を実装する。
- [x] path、rule ID、claim の正規化を定義する。
- [x] content hash と scanner fingerprint を保存する。
- [x] provenance に Semgrep run ID と raw URI を保存する。
- [x] confidence を `deterministic-static` とする。
- [x] stable fingerprint による重複検出を実装する。
- [x] raw SARIF を保持したまま `evidence/evidence.jsonl` を生成する。
- [x] JSONL 書込みを atomic / append-safe にする。

### M2.5 Scan / ingest CLI

- [x] `whitebox-audit scan --target ... --scanner semgrep` を実装する。
- [x] prepared run を指定して scan できるようにする。
- [x] 未 prepare target の扱いを決定し、一貫させる。
- [x] scanner failure を終了コード 5 とする。
- [x] SARIF parse failure を終了コード 6 とする。
- [x] run を `degraded` または `failed` へ更新する規則を実装する。
- [x] `make scan TARGET=...` を追加する。
- [x] `ingest-sarif --tool-name <name> --input <file>` の基本実装を追加する。
- [x] ingest input path を安全に検証する。

### M2.6 Fixture とゲート

- [x] vulnerable Semgrep fixture を作成する。
- [x] benign counterpart fixture を作成する。
- [x] realistic SARIF fixture を追加する。
- [x] optional field 欠落 SARIF fixture を追加する。
- [x] multiple runs SARIF fixture を追加する。
- [x] malformed SARIF fixture を追加する。
- [x] fake Semgrep success integration test を追加する。
- [x] fake Semgrep failure integration test を追加する。
- [x] fake Semgrep timeout integration test を追加する。
- [x] Semgrep availability gate を確認する（現環境は unavailable のため real smoke test を明示 skip）。
- [x] vulnerable fixture から期待 Evidence が生成されることを確認する。
- [x] benign fixture に seeded issue が出ないことを確認する。
- [x] scanner failure が最終状態に残ることを確認する。
- [x] formatter、linter、typecheck、unit/security test を実行する。
- [x] Milestone 2 の coverage と制限事項を文書化する。

## Milestone 3: Canonical Evidence Model と手動 Hypothesis

### M3.1 Canonical models

- [x] `SecurityInvariant` model を実装する。
- [x] Invariant の `source.derivation`（declared / inferred）、`source.origin`、`source_evidence` を検証する。
- [x] inferred Invariant を declared requirement としてserialize/reportできない制約を追加する。
- [x] `Evidence` model の全フィールドを仕様へ合わせる。
- [x] `Hypothesis` model を実装する。
- [x] CounterEvidence を Evidence の link role として実装する。
- [x] `VerificationCase` model の共通部分を実装する。
- [x] `VerificationResult` model を実装する。
- [x] `Finding` model を実装する。
- [x] 全 model に `schema_version` を持たせる。
- [x] relative path、symbol、line range、content hash を共通 location model にする。
- [x] provenance model を実装する。
- [x] redaction metadata model を実装する。

### M3.2 Stable IDs と参照整合性

- [x] `INV-`、`HYP-`、`EVD-`、`VER-`、`FND-` の prefix を検証する。
- [x] normalized content から deterministic ID を生成する。
- [x] 時刻と絶対 host path を ID 入力から除外する。
- [x] foreign ID の存在確認を行う Evidence Store API を作成する。
- [x] target tree hash が異なる Evidence の混在を拒否または明示する。
- [x] duplicate Evidence の merge 規則を定義する。
- [x] object の immutable history または revision 方針を決定する。

### M3.3 Finding state machine

- [x] 7 status を enum として定義する。
- [x] 許可 transition を中央で管理する。
- [x] `hypothesis -> rejected` を実装する。
- [x] `hypothesis -> needs-verification` を実装する。
- [x] `needs-verification -> verified` に proved result を要求する。
- [x] `needs-verification -> high-confidence-static` に trace と反証を要求する。
- [x] `needs-verification -> rejected` を実装する。
- [x] `verified/high-confidence-static -> accepted-risk` を実装する。
- [x] `verified/high-confidence-static -> duplicate` を実装する。
- [x] Discovery/LLM origin からの direct verified construction を拒否する。
- [x] `not-proved` が一般的な安全証明にならないよう API 名と文書を整える。

### M3.4 Evidence Store

- [x] run-relative repository interface を定義する。
- [x] JSON と JSONL serializer を実装する。
- [x] atomic write と fsync 方針を決定する。
- [x] malformed record を行番号付きで報告する。
- [x] unknown schema version を拒否する。
- [x] evidence list/filter を実装する。
- [x] Evidence ID lookup を実装する。
- [x] Invariant list/lookup を実装する。
- [x] Hypothesis list/lookup を実装する。

### M3.5 Manual workflow CLI

- [x] `whitebox-audit invariant add/list --run-id <id>` を実装する。
- [x] operator supplied Invariant と根拠資料を declared Invariant / Evidence としてimportする。
- [x] `whitebox-audit hypothesis add/list --run-id <id> --file <yaml-or-json>` を実装する。
- [x] required Hypothesis fields の欠落を拒否する。
- [x] supporting/counter Evidence の参照を検証する。
- [x] attacker、entry、path、falsification、verification plan を検証する。
- [x] `whitebox-audit evidence list --run-id <id>` を実装する。
- [x] `whitebox-audit show-evidence <id> --run-id <id>` を実装する。
- [x] human-readable と JSON 出力を提供する。

### M3.6 Model test とゲート

- [x] 全 model の valid round-trip test を追加する。
- [x] unknown field rejection test を追加する。
- [x] invalid ID prefix test を追加する。
- [x] dangling Evidence reference test を追加する。
- [x] target fingerprint mismatch test を追加する。
- [x] invalid state transition test を追加する。
- [x] LLM origin が verified Finding を作れない test を追加する。
- [x] proved result ありの verified construction test を追加する。
- [x] stable ID reproduction test を追加する。
- [x] JSONL malformed line test を追加する。
- [x] formatter、linter、typecheck、unit/security test を実行する。
- [x] schema と例を仕様書へ同期する。

## Milestone 4: Independent Verifier

### M4.1 Verifier policy と threat model

- [ ] `config/verifier-policy.yaml` の schema を定義する。
- [ ] unknown verifier policy key を拒否する。
- [ ] network、filesystem、capability、resource、timeout の上限を定義する。
- [ ] case の要求が policy を緩和できない設計にする。
- [ ] Verifier code と Discovery output の trust boundary を文書化する。
- [ ] verifier image identity と policy fingerprint を結果へ記録する。

### M4.2 HTTP VerificationCase DSL

- [ ] `schema_version=1` を定義する。
- [ ] runtime profile reference を検証する。
- [ ] fixture/seed ID を allowlist 検証する。
- [ ] actor identity を adapter 定義から検証する。
- [ ] HTTP method allowlist を定義する。
- [ ] path を local target service の相対 URL に制限する。
- [ ] header allowlist と Authorization template を定義する。
- [ ] request body のサイズと形式を制限する。
- [ ] status oracle を実装する。
- [ ] JSON assertion oracle の安全な部分集合を実装する。
- [ ] arbitrary shell、host path、environment reference を schema で拒否する。
- [ ] limits が policy 上限を超えないことを検証する。

### M4.3 Runtime Adapter

- [ ] Runtime Adapter schema を定義する。
- [ ] image、`command_id`、health check、fixtures、identities、ports を検証する。
- [ ] `command_id` を固定の image command へ解決する。
- [ ] target 由来の任意 start command を拒否する。
- [ ] adapter image の version/digest を記録する。
- [ ] health check timeout を実装する。
- [ ] fixture seed の deterministic identity/token 発行を実装する。
- [ ] ephemeral service lifecycle を controller で管理する。

### M4.4 Fixture application

- [ ] TypeScript / Next.js App Router / PostgreSQL のMVP fixtureを作成する。
- [ ] Node base imageをreview済みdigestでpinする。
- [ ] Nodeとpackage managerのversion、直接依存、lock fileを固定する。
- [ ] package lockのregistry URLとintegrity fieldをcontrollerが実行前に検証する。
- [ ] dependency installはcredentialなしのisolated buildで行い、lifecycle scriptを既定で無効にする。
- [ ] install時networkをapproved package registryへ限定し、runtime/verifier external egressを禁止する。
- [ ] fixture applicationのCycloneDX SBOMを生成する。
- [ ] tenant A と tenant B を持つ disposable app を作成する。
- [ ] low-privilege tenant A user を用意する。
- [ ] tenant B invoice を用意する。
- [ ] 意図的に vulnerable な cross-tenant endpoint を実装する。
- [ ] tenant scope を適用した fixed endpoint/version を実装する。
- [ ] health endpoint を実装する。
- [ ] seed data を deterministic にする。
- [ ] fixture が production credential/network を必要としないようにする。

### M4.5 Verifier sandbox

- [ ] `verifier/Dockerfile` を作成する。
- [ ] verifier entrypoint を固定する。
- [ ] container root filesystem を read-only にする。
- [ ] `/tmp` を `noexec,nosuid,nodev` tmpfs にする。
- [ ] target mount を read-only にする。
- [ ] case mount を read-only にする。
- [ ] output mount だけを書込み可能にする。
- [ ] `--cap-drop ALL` を適用する。
- [ ] `no-new-privileges` を適用する。
- [ ] PID limit を適用する。
- [ ] memory limit を適用する。
- [ ] CPU limit を適用する。
- [ ] wall-clock timeout を適用する。
- [ ] Docker socket を mount しない。
- [ ] host home、SSH、cloud、registry config を mount しない。
- [ ] 既定 `--network none` を実装する。
- [ ] HTTP fixture 用の外部 egress なし ephemeral network を実装する。
- [ ] timeout/exception 後に container と network を cleanup する。

### M4.6 Verifier execution と verdict

- [ ] case schema validation を実行前に行う。
- [ ] setup、action、oracle を固定順序で実行する。
- [ ] HTTP response status を observation に保存する。
- [ ] response body は必要最小限を redaction して artifact 化する。
- [ ] body hash を保存する。
- [ ] expected secure behavior と observed behavior を比較する。
- [ ] `proved/not-proved/inconclusive/policy-rejected/error` を区別する。
- [ ] setup failure を `not-proved` にしない。
- [ ] Verifier のみが result file を生成できるようにする。
- [ ] result に target tree hash と policy fingerprint を保存する。
- [ ] output artifact の content hash を保存する。
- [ ] case/result/log を run directory に保存する。

### M4.7 Verify CLI

- [ ] `whitebox-audit verify --run-id <id> --case <id>` を実装する。
- [ ] run target と case target の fingerprint を照合する。
- [ ] policy rejection を終了コード 4 とする。
- [ ] verifier execution failure を終了コード 5 とする。
- [ ] Finding promotion を Verifier result 経由だけにする。
- [ ] `make verify TARGET=...` または run ID ベースの Make target を追加する。

### M4.8 Isolation test とゲート

- [ ] vulnerable fixture が `proved` になる test を追加する。
- [ ] fixed fixture が `not-proved` になる test を追加する。
- [ ] target source write が失敗する test を追加する。
- [ ] verifier code write が失敗する test を追加する。
- [ ] arbitrary shell field が拒否される test を追加する。
- [ ] host absolute path が拒否される test を追加する。
- [ ] external egress が失敗する test を追加する。
- [ ] Docker socket が存在しない test を追加する。
- [ ] fake host credential が見えない test を追加する。
- [ ] fork/huge allocation が resource limit で停止する test を追加する。
- [ ] timeout 後に container/network が残らない test を追加する。
- [ ] forged `proved` result が受理されない test を追加する。
- [ ] repeated run の verdict が再現することを確認する。
- [ ] formatter、linter、typecheck、unit/security/integration test を実行する。
- [ ] Verifier limitation を文書化する。

## Milestone 5: Agentic Audit Skill と安全なナビゲーション

### M5.1 Repository map

- [ ] inventory から bounded repository map を生成する。
- [ ] route/entry-point 候補を列挙する。
- [ ] authn/authz middleware 候補を列挙する。
- [ ] service/repository/ORM 候補を列挙する。
- [ ] queue/cache/webhook/state-machine 候補を列挙する。
- [ ] map output の件数・サイズ上限を設定する。
- [ ] `whitebox-audit map --run-id <id>` を実装する。

### M5.2 Safe source navigation

- [ ] `source <relative-path> --lines <start:end>` を実装する。
- [ ] source path を target root 内へ confinement する。
- [ ] line range の正値・順序・最大行数を検証する。
- [ ] binary file の source read を拒否する。
- [ ] oversized line/file の表示上限を設ける。
- [ ] source content hash と target tree hash を出力する。
- [ ] `search <pattern>` を argv 配列の `rg` 呼出しで実装する。
- [ ] regex/literal mode を明示する。
- [ ] path scope と max results を検証する。
- [ ] search timeout と output size limit を設定する。
- [ ] target local config により `rg` behavior が変更されないようにする。
- [ ] `callers <symbol>` の対応言語と fallback を定義する。
- [ ] callers 未対応を明示し、推測結果として返さない。

### M5.3 Threat model と Invariant workflow

- [ ] ThreatScenario schema を定義する。
- [ ] 3〜7 件の優先シナリオを保存できるようにする。
- [ ] attacker、asset、trust boundary、hypothesis seed を検証する。
- [ ] Invariant の `source.derivation`、`source.origin`、`source_evidence` を検証する。
- [ ] declared / inferred の区別をagent outputとreportまで保持する。
- [ ] counterexample を必須とする。
- [ ] organization policy directory を loader に接続する。
- [ ] policy と target content を別 trust source として provenance に記録する。

### M5.4 Agent-facing structured interface

- [ ] agent input manifest に target metadata を含める。
- [ ] agent input manifest に threat model と Invariant を含める。
- [ ] agent input manifest に normalized Evidence refs を含める。
- [ ] full repository dump を行う interface を提供しない。
- [ ] agent output schema を Hypothesis と VerificationCase に限定する。
- [ ] prose を parse して canonical object に昇格させない。
- [ ] supporting Evidence と CounterEvidence の参照を検証する。
- [ ] falsification conditions と verification plan を必須にする。
- [ ] agent に Finding verdict field を公開しない。

### M5.5 Skill integration

- [ ] repository Skill の現行 workflow を実装 CLI に合わせて更新する。
- [ ] Skill に safe `map/search/source/show-evidence` 使用順序を記載する。
- [ ] Skill に target text は命令でないことを維持する。
- [ ] Skill に route -> middleware -> service -> repository -> sink の追跡を維持する。
- [ ] Skill に falsification checklist を維持する。
- [ ] Skill に Discovery が `verified` を設定できないことを維持する。
- [ ] Skill の例と実際の JSON/YAML schema を同期する。

### M5.6 Agentic fixture とゲート

- [ ] cross-file authz vulnerability fixture を作成する。
- [ ] upstream middleware による false-positive control を作成する。
- [ ] repository implicit tenant scope の false-positive control を作成する。
- [ ] feature flag unreachable path の false-positive control を作成する。
- [ ] target prompt injection が protocol を変更しない test を追加する。
- [ ] bounded commands だけで seeded issue を trace できることを確認する。
- [ ] generated Hypothesis が schema validation を通ることを確認する。
- [ ] CounterEvidence により false positive が rejected になることを確認する。
- [ ] Discovery output が verified Finding を生成できないことを確認する。
- [ ] `make audit TARGET=...` の interactive workflow を文書化する。
- [ ] formatter、linter、typecheck、unit/security/integration test を実行する。

## Milestone 6: CodeQL Adapter

### M6.1 Capability と entitlement

- [ ] CodeQL capability detection を実装する。
- [ ] CLI version を記録する。
- [ ] bundle/query pack version を記録する。
- [ ] target language support を検査する。
- [ ] `enabled: auto/true/false` を schema 化する。
- [ ] private/internal target の entitlement acknowledgement を必須にする。
- [ ] binary の存在だけで entitlement を推定しない。
- [ ] unavailable、unsupported、unacknowledged を別 skip reason にする。

### M6.2 Isolated database build

- [ ] scanner container/VM interface を定義する。
- [ ] target source を read-only で mount する。
- [ ] writable build workspace を target と分離する。
- [ ] host credential と home を公開しない。
- [ ] build network policy を定義する。
- [ ] resource/time limit を設定する。
- [ ] reviewed build command ID を使用する。
- [ ] target 由来の shell string を build command にしない。
- [ ] build log を redaction して保存する。
- [ ] database fingerprint を記録する。
- [ ] database create failure を明示 status にする。

### M6.3 Analysis と normalization

- [ ] query suite/pack を設定 schema で指定する。
- [ ] analyze argv を引数配列で構築する。
- [ ] SARIF latest output を run directory に保存する。
- [ ] Semgrep と共通 SARIF parser を再利用する。
- [ ] CodeQL-specific provenance を保存する。
- [ ] cross-scanner duplicate fingerprint 規則を実装する。
- [ ] supporting evidence と counter-evidence の両方に利用できることを確認する。

### M6.4 CodeQL CLI とゲート

- [ ] `scan --scanner codeql` を実装する。
- [ ] `scan --scanner all` を実装する。
- [ ] CodeQL skip を人間向け・JSON 出力へ明示する。
- [ ] entitlement 未確認 test を追加する。
- [ ] unsupported language test を追加する。
- [ ] isolated build failure test を追加する。
- [ ] host build が実行されない test を追加する。
- [ ] Semgrep/CodeQL Evidence merge test を追加する。
- [ ] duplicate corruption がない test を追加する。
- [ ] CodeQL が利用可能な環境で realistic integration test を実行する。
- [ ] 言語別 build limitation を文書化する。
- [ ] formatter、linter、typecheck、unit/security/integration test を実行する。

## Milestone 7: Reporting と Patch Workflow

### M7.1 Finding composition

- [ ] Hypothesis、Invariant、Evidence、VerificationResult から Finding を構築する service を実装する。
- [ ] status gate を再検証する。
- [ ] attacker preconditions を必須にする。
- [ ] entry/control/sink trace を必須にする。
- [ ] falsification summary を必須にする。
- [ ] verification limitation を明示する。
- [ ] CWE の配列と根拠を保存する。

### M7.2 Severity engine

- [ ] required privileges を入力要因にする。
- [ ] user interaction を入力要因にする。
- [ ] cross-user/cross-tenant/system scope を入力要因にする。
- [ ] confidentiality/integrity/availability impact を入力要因にする。
- [ ] exploit reliability を入力要因にする。
- [ ] environmental preconditions を入力要因にする。
- [ ] organization severity threshold を設定可能にする。
- [ ] LLM の自由な severity 文字列を拒否する。
- [ ] CVSS は optional auxiliary field とする。
- [ ] severity 算定根拠を出力する。

### M7.3 Markdown/JSON/SARIF report

- [ ] report data transfer model を canonical objects から構築する。
- [ ] target fingerprint と run metadata を描画する。
- [ ] tool/version/rules/query/coverage を描画する。
- [ ] skipped/failed scanner と理由を描画する。
- [ ] scope、exclusions、limitations を描画する。
- [ ] ThreatScenario と Invariant summary を描画する。
- [ ] status/severity 別 Finding summary を描画する。
- [ ] Evidence refs と CounterEvidence を描画する。
- [ ] VerificationResult と deterministic reproduction を描画する。
- [ ] rejected hypothesis count を描画する。
- [ ] Markdown を structured data だけから生成する。
- [ ] JSON report を生成する。
- [ ] verified/high-confidence-static Finding の SARIF export を実装する。
- [ ] secrets と host absolute path を redaction する。
- [ ] source snippet を最小化する。
- [ ] renderer の snapshot/golden test を追加する。

### M7.4 Patch workflow

- [ ] `patch --finding <FND-ID>` を実装する。
- [ ] patch input に target fingerprint を要求する。
- [ ] remediation proposal を別 artifact に保存する。
- [ ] unified diff を `reports/<run-id>/patches/` に保存する。
- [ ] target source へ直接書き込まない。
- [ ] regression test recommendation を生成する。
- [ ] patch artifact に origin、hash、review status を持たせる。
- [ ] human review 前に apply されないことを test する。
- [ ] fixed target に対する verifier rerun 手順を文書化する。

### M7.5 CLI とゲート

- [ ] `whitebox-audit report --run-id ... --format markdown` を実装する。
- [ ] `--format json` を実装する。
- [ ] `--format sarif` を実装する。
- [ ] `make report TARGET=...` または run ID workflow を追加する。
- [ ] verified Finding の必須項目欠落を拒否する test を追加する。
- [ ] static-only report が verified を含まない test を追加する。
- [ ] scanner failure が report に表示される test を追加する。
- [ ] secret redaction test を追加する。
- [ ] target no-write test を追加する。
- [ ] formatter、linter、typecheck、unit/security/integration test を実行する。

## Milestone 8: Evaluation Harness

### M8.1 Fixture schema と dataset

- [ ] fixture expected schema を定義する。
- [ ] vulnerable commit と fixed commit の pair を表現する。
- [ ] non-vulnerability control を表現する。
- [ ] CWE、expected entry、expected effect を記録する。
- [ ] fixture authorization と安全な使用条件を記録する。
- [ ] IDOR fixture を追加する。
- [ ] tenant isolation fixture を追加する。
- [ ] missing role check fixture を追加する。
- [ ] state transition bypass fixture を追加する。
- [ ] password reset misuse fixture を追加する。
- [ ] cache isolation fixture を追加する。
- [ ] background job privilege confusion fixture を追加する。
- [ ] webhook trust boundary fixture を追加する。
- [ ] SSRF chain fixture を追加する。
- [ ] injection baseline fixture を追加する。
- [ ] 各カテゴリに false-positive control を追加する。

### M8.2 Experiment runners

- [ ] Semgrep-only runner を実装する。
- [ ] CodeQL-only runner を実装する。
- [ ] deterministic union runner を実装する。
- [ ] Codex navigation without scanner evidence runner を定義する。
- [ ] Codex + deterministic evidence runner を定義する。
- [ ] Codex + evidence + falsification runner を定義する。
- [ ] full pipeline + independent verifier runner を定義する。
- [ ] tool/model/config version を experiment metadata に保存する。
- [ ] run resume と partial failure の扱いを定義する。

### M8.3 Metrics

- [ ] Verified Precision を計算する。
- [ ] Known Vulnerability Recall を計算する。
- [ ] False Positive Rate を計算する。
- [ ] Unique Finding Lift を計算する。
- [ ] SAST Overlap を計算する。
- [ ] Verification Rate を計算する。
- [ ] Reproduction Success を計算する。
- [ ] scanner/verifier/wall-clock time を計測する。
- [ ] model usage が利用可能な場合に記録する。
- [ ] Cost per Verified Finding を計算する。
- [ ] rejected/duplicate/accepted-risk を集計する。

### M8.4 Backtest とゲート

- [ ] vulnerable commit で expected finding が出ることを確認する。
- [ ] fixed commit で finding が停止することを確認する。
- [ ] fixed commit に regression case を再利用する。
- [ ] verifier result の second-run 再現性を確認する。
- [ ] fixture ごとの raw result を保持する。
- [ ] metrics report を machine-readable と Markdown で生成する。
- [ ] model prompt 最適化前の baseline を保存する。
- [ ] formatter、linter、typecheck、unit/security/eval test を実行する。

## Milestone 9: Non-interactive Codex Orchestration

### M9.1 Orchestration ADR

- [ ] `codex exec` と Codex SDK の capability を比較する。
- [ ] 公式仕様と対応バージョンを再確認する。
- [ ] structured output の保証方法を決定する。
- [ ] model、reasoning、token/time budget 方針を決定する。
- [ ] resume、retry、cancellation 方針を決定する。
- [ ] audit-phase network off を維持できることを確認する。
- [ ] target content が instruction chain に入らない起動方法を確認する。

### M9.2 Structured task execution

- [ ] agent task input schema を固定する。
- [ ] target metadata、Invariant、Evidence refs、budget だけを入力する。
- [ ] safe navigation command allowlist を適用する。
- [ ] agent output を Hypothesis/VerificationCase schema で検証する。
- [ ] invalid/free-form output を canonical store へ入れない。
- [ ] bounded source reads と search result limits を強制する。
- [ ] agent run log から secrets を redaction する。
- [ ] agent run ID と model/tool version を記録する。
- [ ] agent が final verdict API へ到達できないようにする。

### M9.3 Resume と失敗回復

- [ ] navigation state を structured checkpoint として保存する。
- [ ] 同一 target fingerprint の場合だけ resume する。
- [ ] Evidence 更新時の invalidation 規則を定義する。
- [ ] retry 回数と backoff を上限管理する。
- [ ] budget 超過を `inconclusive/degraded` として扱う。
- [ ] cancellation 後に verifier/scanner resource を cleanup する。
- [ ] partial Hypothesis を完成品として report しない。

### M9.4 End-to-end gate

- [ ] `whitebox-audit run --target ... --profile ...` を実装する。
- [ ] Phase 0〜7 の状態遷移を audit log に記録する。
- [ ] target prompt injection fixture で protocol が維持されることを確認する。
- [ ] agent が target を変更できないことを確認する。
- [ ] agent が fake verified result を注入できないことを確認する。
- [ ] budget/timeout/cancellation test を追加する。
- [ ] interrupted run resume test を追加する。
- [ ] full fixture で end-to-end report を生成する。
- [ ] formatter、linter、typecheck、unit/security/e2e test を実行する。

## Milestone 10: Production Hardening

### M10.1 Supply chain

- [x] direct dependency と build dependency を exact pin する。
- [x] lock file の更新手順を定義する。
- [x] native CLIでdirect URL/VCS/file dependency、alternate index、unapproved lock sourceを拒否する。
- [x] lock artifactのapproved HTTPS hostとSHA-256 recordを検査する。
- [x] 72時間のdependency publication cooldownを適用する。
- [x] offline lock freshness checkを通常の`make check`に組み込む。
- [x] host toolのversion、resolved executable path、SHA-256をDoctor metadataに記録する。
- [ ] scanner/verifier image を digest pin する。
- [ ] release artifact の checksum/signature 方針を定義する。
- [x] audit harness の CycloneDX SBOM を生成する。
- [ ] dependency/license review を自動化する。
- [ ] Project CodeGuard version を audit metadata に記録する。
- [ ] production baseline の plugin update review 手順を定義する。

### M10.2 CI

- [ ] formatter check job を追加する。
- [ ] lint/typecheck job を追加する。
- [ ] unit test job を追加する。
- [ ] path/prompt-injection security test job を追加する。
- [ ] fake scanner integration job を追加する。
- [ ] verifier isolation job を専用 runner 条件付きで追加する。
- [ ] fixture/eval regression job を追加する。
- [ ] secret を fork/untrusted fixture job に渡さない。
- [ ] target build/install script を CI host で実行しない。
- [ ] artifact retention と redaction を設定する。

### M10.3 Governance と変更管理

- [ ] verifier policy、Skill、security model に CODEOWNERS を設定する。
- [ ] SECURITY.md を作成する。
- [ ] vulnerability disclosure 手順を定義する。
- [ ] schema/config migration framework を実装する。
- [ ] append-only audit log または改ざん検知 hash chain を検討・実装する。
- [ ] release notes と changelog を導入する。
- [ ] backward compatibility policy を定義する。
- [ ] upstream reference の再確認手順を release checklist に追加する。

### M10.4 Report security と retention

- [ ] configurable retention policy を実装する。
- [ ] local-only を既定にする。
- [ ] explicit export 操作を実装する。
- [ ] run ID 単位の安全な削除を実装する。
- [ ] deletion target を validated `work/<run-id>` に confinement する。
- [ ] broad recursive delete を拒否する。
- [ ] deletion audit event を記録する。
- [ ] source snippet 最小化を検証する。
- [ ] token/secret location と fingerprint のみを report する。
- [ ] proprietary path の redaction policy を実装する。

### M10.5 Runtime Adapter 運用

- [ ] adapter authoring guide を作成する。
- [ ] adapter review checklist を作成する。
- [ ] image pinning と更新手順を作成する。
- [ ] fixture/identity/seed の秘密管理方針を定義する。
- [ ] production endpoint を拒否する guard を実装する。
- [ ] allowed verification techniques を adapter metadata に記録する。
- [ ] high-risk mode の VM/microVM 移行条件を文書化する。

### M10.6 Production-readiness gate

- [ ] clean supported host でセットアップを再現する。
- [ ] `make doctor` が成功する。
- [ ] formatter、linter、typecheck、全 test が成功する。
- [ ] prompt-injection fixture suite が成功する。
- [ ] verifier isolation suite が成功する。
- [ ] scanner failure が final report に表示される。
- [ ] no-target-write が全 workflow で確認される。
- [ ] structured evidence から report が再生成できる。
- [ ] run ID と target commit/tree hash で結果を再現できる。
- [ ] 一つの実 application family が reviewed Runtime Adapter で起動する。
- [ ] 一つの authz/tenant finding を end-to-end で independently verify する。
- [ ] fixed version で同一 finding が再現しない。
- [ ] false-positive regression fixture が成功する。
- [ ] 未解決リスクと運用制限を release notes に記載する。

## 横断タスク

### 設定と schema

- [ ] `config/audit.default.yaml` を実装する。
- [ ] `config/scanners.yaml` を実装する。
- [ ] `config/verifier-policy.yaml` を実装する。
- [ ] CLI > profile > local config > default の優先順位を実装する。
- [ ] unknown key を既定で拒否する。
- [ ] effective config から secrets を除外して fingerprint 化する。
- [ ] schema compatibility と migration test を追加する。

### Logging と observability

- [ ] structured log schema を定義する。
- [ ] run ID、component、event、timestamp を含める。
- [ ] secret redaction を logger の共通層で実装する。
- [ ] scanner stdout/stderr と harness log を分離する。
- [ ] verifier observations と verbose logs を分離する。
- [ ] debug mode でも credential を出力しない test を追加する。
- [ ] wall-clock、scanner time、verifier time を metrics に保存する。

### Documentation

- [ ] README の Status を実装状況に合わせて更新する。
- [ ] `docs/01-SETUP.md` のコマンドを実機確認する。
- [ ] `docs/02-ARCHITECTURE.md` を実装 module 構成に同期する。
- [ ] `docs/03-AUDIT-PROTOCOL.md` を CLI workflow に同期する。
- [ ] `docs/05-VERIFIER-SANDBOX.md` を実際の container flags に同期する。
- [ ] `docs/06-EVIDENCE-MODEL.md` を schema に同期する。
- [ ] `docs/12-OPERATIONS.md` を end-to-end 実行で検証する。
- [ ] ADR と未決定事項を相互リンクする。
- [ ] 実装済み、experimental、stub、unsupported を明示する。

## v1 最終チェックリスト

- [ ] クリーン環境でインストールできる。
- [ ] `make doctor` が必要 capability を正しく判定する。
- [ ] target validation が悪意ある path と symlink を拒否する。
- [ ] target fingerprint と inventory を再現可能に保存する。
- [ ] Semgrep SARIF を raw 保存し Evidence へ正規化する。
- [ ] scanner failure と malformed SARIF が可視化される。
- [ ] manual Hypothesis から Verifier へ進める。
- [ ] HTTP VerificationCase DSL が任意 shell を拒否する。
- [ ] Verifier が read-only、no egress、least privilege で動作する。
- [ ] vulnerable fixture は `proved`、fixed fixture は `not-proved` になる。
- [ ] Discovery Agent が `verified` を自己認定できない。
- [ ] bounded navigation で cross-file authz issue を追跡できる。
- [ ] prompt injection fixture が監査手順を変更できない。
- [ ] CodeQL は optional で、entitlement と isolation を強制する。
- [ ] report が canonical objects から生成される。
- [ ] report に target、tools、coverage、failures、limitations が含まれる。
- [ ] patch は別 artifact として生成され、target を変更しない。
- [ ] known-vulnerable / fixed / false-positive fixture が評価に含まれる。
- [ ] precision、recall、verification、reproduction metrics が出力される。
- [ ] 一つの reviewed Runtime Adapter が実アプリケーション系統で動作する。
- [ ] 全 formatter、linter、typecheck、unit、security、integration、eval test が成功する。
- [ ] 未解決リスク、unsupported 機能、degraded 条件が文書化される。
