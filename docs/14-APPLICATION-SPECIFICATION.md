# 14 - Whitebox AI Audit アプリケーション詳細仕様書

## 1. 文書情報

| 項目 | 内容 |
|---|---|
| 製品名 | Whitebox AI Audit |
| CLI 名 | `whitebox-audit` |
| Python パッケージ名 | `whitebox_audit` |
| 文書種別 | アプリケーション詳細仕様書 |
| 文書日付 | 2026-08-12 |
| 対象バージョン | 初期実装から v1 まで |
| 現在の実装状態 | Milestone 0〜2完了。安全なtarget prepare、Semgrep/SARIF Evidence vertical slice、開発・テスト基盤を実装済み |
| 主要実装言語 | Python 3.12 以上 |

本書は、既存の `README.md`、`AGENTS.md`、`docs/01-SETUP.md` から
`docs/13-UPSTREAM-REFERENCES.md` までを統合し、実装・テスト・受入判定に使用できる
製品仕様として再構成したものである。

既存文書と本書に矛盾がある場合は、次の順で判断する。

1. `AGENTS.md` の安全規則と実装規則
2. セキュリティ境界を定める `docs/05-VERIFIER-SANDBOX.md` と `docs/07-SECURITY-MODEL.md`
3. 正規データと状態を定める `docs/06-EVIDENCE-MODEL.md`
4. 監査手順を定める `docs/03-AUDIT-PROTOCOL.md`
5. 本書
6. その他の補助文書

本書における「必須」「禁止」「推奨」は、それぞれ RFC 2119 の MUST、MUST NOT、SHOULD
に相当する規範的な表現として扱う。

## 2. 製品概要

Whitebox AI Audit は、監査対象リポジトリのソースコードを利用して脆弱性を調査する、
証拠駆動型のホワイトボックス AppSec 監査ハーネスである。

本製品は、LLM にリポジトリ全体を入力して脆弱性の列挙を求める方式を採用しない。
セキュリティ上の仮説を起点として関連コードだけを追跡し、決定論的スキャナー、ソース上の
直接証拠、反証調査、隔離されたランタイム検証を組み合わせて判定する。

基本パイプラインは次のとおりである。

```text
監査対象の安全な登録
  -> 攻撃面・脅威モデルの整理
  -> セキュリティ不変条件の定義
  -> Semgrep / CodeQL / 既存 SARIF による証拠収集
  -> Codex による限定的なコードナビゲーション
  -> 脆弱性仮説の作成
  -> 反証の探索
  -> 独立した検証環境での再現
  -> Finding の確定
  -> レポート / 修正差分 / 回帰テスト
```

LLM は推論とナビゲーションを担当するが、単独で脆弱性を証明する権限を持たない。
`verified` 判定は、独立した Verifier が機械的に観測可能な証拠を生成した場合にのみ許可する。

## 3. 目的と成功条件

### 3.1 目的

- 認可、IDOR、テナント分離、業務状態遷移など、一般的な SAST だけでは見落としやすい
  脆弱性を、再現可能な証拠とともに検出する。
- 未信頼の監査対象を扱っても、オペレーターのホスト、認証情報、ネットワーク、対象コードを
  保護できる監査環境を提供する。
- 決定論的解析とエージェント推論を共通の証拠モデル上で結合する。
- 誤検知を積極的な反証と独立検証によって抑制する。
- 監査結果を、対象コミット、ツールバージョン、証拠、再現手順に結び付ける。

### 3.2 v1 の成功条件

v1 は、少なくとも次の条件をすべて満たした場合にのみ「利用可能」とする。

1. サポート対象のクリーン環境でセットアップと `make doctor` が成功する。
2. Semgrep の SARIF を保存し、正規化した Evidence を生成できる。
3. Python および JavaScript/TypeScript の対象を安全なコマンドで限定的にナビゲートできる。
4. レビュー済み Runtime Adapter を使い、少なくとも一つの実アプリケーション系統を起動できる。
5. 認可またはテナント分離の既知脆弱性を、独立 Verifier でエンドツーエンドに再現できる。
6. 修正版では同じ VerificationCase が `proved` にならないことを確認できる。
7. プロンプトインジェクション、パス逸脱、対象書込み、任意シェル実行、外部通信を防ぐテストが通る。
8. スキャナーの未実行、スキップ、失敗が最終レポートに明示される。
9. Markdown レポートが構造化データから再現可能に生成される。
10. 実行 ID と対象コミットまたは tree hash から監査結果を特定できる。

## 4. 対象範囲

### 4.1 v1 の対象

- ローカルの Git または非 Git ソースリポジトリ
- Python、JavaScript、TypeScript のコードナビゲーション
- 最初のRuntime Adapterおよび検証fixtureとしてTypeScript / Next.js App Router / PostgreSQL
- Semgrep CE によるベースライン静的解析
- 既存 SARIF の取込み
- 利用条件と安全なビルド環境を満たす場合の CodeQL
- HTTP ベースの認可・テナント分離検証
- オペレーターがレビューした Runtime Adapter
- fixture / disposable target image による CI・評価
- Markdown、JSON、必要に応じた SARIF のレポート出力
- 修正差分を対象外の成果物として生成するパッチワークフロー

### 4.2 初期リリースの対象外

- 任意フレームワークの完全自動起動
- 監査対象の依存関係をホスト上で自動インストールする機能
- 対象の build、test、install スクリプトをホスト上で実行する機能
- 外部インターネットへ自由に接続する PoC 実行
- Discovery Agent による最終 verdict の自己認定
- 自動的な本番環境への攻撃・状態変更
- SCA、IaC、コンテナスキャンを中心とする汎用スキャナー統合基盤
- すべての言語・フレームワークに対する CodeQL 自動ビルド
- Web UI または常駐 SaaS。v1 はローカル CLI を主インターフェースとする
- 複雑な自律マルチエージェントオーケストレーション

## 5. 利用者と役割

| 役割 | 主な責務 | 許可される操作 |
|---|---|---|
| Audit Operator | 監査の認可、対象・範囲・ツール・検証条件の決定 | prepare、scan、audit、verify、report、承認操作 |
| Security Reviewer | 仮説、反証、証拠、Finding、修正案のレビュー | 読取り、トリアージ、accepted-risk / duplicate 判定 |
| Target Owner | Runtime Adapter、テストデータ、テストID、業務不変条件の提供 | レビュー済み設定・fixture の提供 |
| Discovery Agent | 脅威整理、限定検索、トレース、仮説と検証ケースの提案 | 読取り、構造化 Hypothesis / VerificationCase の出力 |
| Verifier | 宣言的ケースの検査・実行と結果判定 | 固定ポリシー下の実行、VerificationResult の生成 |
| Reporter | 正規データからレポートを描画 | Finding、Evidence、実行メタデータの読取り |

Discovery Agent は `verified` を設定できない。Verifier は対象ソース、検証オラクル、Verifier
自身のコードを実行中に変更できない。

## 6. 前提条件と実行環境

### 6.1 サポートホスト

- 推奨: Linux x86_64
- 推奨: macOS + Docker Desktop または同等のコンテナランタイム
- Windows: WSL2 を推奨。Native Windows は個別機能が明示的に対応・試験されるまで同等保証しない
- CodeQL 実行環境として Alpine Linux は非対応

### 6.2 必須ツール

| ツール | 用途 |
|---|---|
| Python 3.12+ | オーケストレーター |
| Docker | 独立 Verifier と隔離された実行環境 |
| Semgrep CE | 必須ベースライン SAST |
| Codex CLI | 実装支援および目標指向ナビゲーション |
| Project CodeGuard | 基本的なセキュアコーディング知識 |
| Git | 対象フィンガープリント取得 |
| ripgrep | 限定検索 |
| jq | JSON の運用確認 |
| curl | セットアップおよび診断 |
| make | 標準タスク実行 |
| uv または pipx | Python 環境・ツール管理 |

CodeQL は任意である。未導入、対象言語非対応、利用権限未確認、または安全なビルド抽出が
できない場合でも、理由を明示して CodeQL をスキップし、他の監査処理を継続可能とする。

## 7. システムコンテキストと信頼境界

```text
信頼される領域
  Audit Operator
  Harness repository / policy / verifier code
  Reviewed Runtime Adapter
  Canonical evidence store
        |
        | 厳格に検証された入力・読取り専用マウント
        v
未信頼領域
  Target repository contents
  Target build files and lifecycle scripts
  Scanner input and scanner output
  Agent-generated hypothesis / verification request
  Runtime responses and artifacts
```

監査対象の全ファイルはデータとして扱う。対象内の `AGENTS.md`、`CLAUDE.md`、README、
コメント、プロンプト、テストデータ、設定は、監査手順を変更する命令として解釈してはならない。

Codex は必ず監査ハーネスのルートから起動し、対象リポジトリを Codex のプロジェクトルートに
してはならない。

## 8. 論理アーキテクチャ

### 8.1 Target Controller

責務:

- 対象パスを絶対パスへ解決する。
- 対象がハーネス自身でないことを確認する。
- シンボリックリンクなどによる対象ルート外への逸脱を検出する。
- Git commit と tree hash、または非 Git 対象用の安定した tree fingerprint を取得する。
- 言語、マニフェスト、主要ディレクトリをコード実行なしで列挙する。
- run ID と run directory を作成する。
- 後続コンポーネントに読取り専用対象として公開する。

### 8.2 Scanner Adapters

Semgrep、CodeQL、既存 SARIF を共通インターフェースで扱う。

```python
class Scanner(Protocol):
    def doctor(self) -> ScannerCapability: ...
    def run(self, target: Target, run_dir: Path) -> ScannerRun: ...
    def normalize(self, output: Path) -> list[Evidence]: ...
```

アダプターは実行引数、タイムアウト、最小環境、リソース制限、stdout/stderr、終了コード、
ツールバージョン、raw 出力保存、正規化を所有する。

### 8.3 Evidence Store

Evidence Store は監査判断の正規情報源である。LLM の会話文や Markdown を正規データとして
扱わない。全成果物は run ID と対象 fingerprint に結び付ける。

### 8.4 Security Model Builder / Invariant Engine

対象の攻撃面、主体、資産、信頼境界、テナント軸、外部連携、状態遷移を整理し、一般的な
脆弱性分類ではなく、対象固有のテスト可能な SecurityInvariant を生成する。

### 8.5 Agentic Navigator

Codex は Target メタデータ、脅威モデル、Invariant、Evidence、現在の Hypothesis、既知の
トレースを入力として、必要なファイルと行範囲だけを調査する。

出力は、追加 Evidence、CounterEvidence、コードトレース、次の検索、VerificationCase 候補を
含む構造化データとする。任意の自由文を直接 Finding として取り込まない。

### 8.6 Verifier Controller / Sandbox

Verifier Controller は VerificationCase のスキーマとポリシーを検査し、使い捨て環境で固定の
setup、action、oracle を実行する。Verifier だけが `VerificationResult.status = proved` を生成できる。

### 8.7 Reporter / Patch Workflow

Reporter は正規オブジェクトから Markdown、JSON、任意の SARIF を生成する。Patch Workflow は
修正案と回帰テスト案を別成果物として生成し、対象を自動的に上書きしない。

## 9. 監査ワークフロー仕様

### 9.1 Phase 0: 対象隔離と入力強化

入力は絶対または相対ディレクトリパスである。内部では必ず `Path.resolve(strict=True)` 相当で
正規化し、ディレクトリの存在と読取り可能性を確認する。

成功時は `Target`、対象 inventory、run directory を作成する。次の場合は拒否する。

- 対象が存在しない、ディレクトリでない、読取り不能
- 対象がハーネスのルートと同一、または安全上禁止された包含関係にある
- 対象内で列挙対象となるパスがシンボリックリンク等によりルート外へ逸脱する
- run directory が対象内に配置される
- 許容できないパス表現またはマウント構成である

対象内のスクリプトは実行しない。子プロセスには許可リスト方式の最小環境だけを渡す。

### 9.2 Phase 1: マップと脅威モデル

次の攻撃面を、対象全体をモデルへ投入せずに調査する。

- HTTP/API route、RPC handler、CLI/admin entry point
- 認証・認可 middleware
- tenant context の生成・伝播
- service、repository、ORM、database access
- privileged background job、queue、cache
- webhook、external integration
- 業務状態遷移

出力は優先度付き 3～7 件の ThreatScenario を標準とする。各シナリオは attacker、asset、
trust boundary、想定される違反経路を持つ。

### 9.3 Phase 2: SecurityInvariant

各重要シナリオを「常に成立すべき性質」へ変換する。Invariant には scope、statement、source、
confidence、期待される安全動作、反例を含める。

代表例:

- 非管理者は所有者または明示的な委譲先である場合だけリソースを更新できる。
- tenant-owned データの read/write は request-supplied ID だけでなく trusted tenant context で制約される。
- 支払状態は許可された遷移だけを行い、例外経路は権限と監査証跡を必要とする。
- パスワードリセットトークンは対象アカウント・操作に束縛され、有効期限付き、単回使用である。

### 9.4 Phase 3: 決定論的証拠収集

Semgrep を既定スキャナーとして実行し、利用可能かつ許可された場合は CodeQL を実行する。
対象チームから提供された SARIF も取り込める。

各スキャナーについて次を保存する。

- 実行ツールとバージョン
- 引数配列。シークレットは保存しない
- 開始・終了時刻、所要時間
- 終了コードと解釈済み status
- stdout / stderr。シークレットを redaction する
- raw SARIF 等の出力
- 正規化結果と parse error
- 適用 ruleset / query pack / language / coverage
- timeout、resource policy、skip/failure reason

スキャナー所見は Finding ではなく Evidence であり、候補の種、反証、攻撃チェーンのノードに
利用する。既知 SAST 所見もエージェント分析から除外しない。

### 9.5 Phase 4: 目標指向ナビゲーション

各 Invariant について次の順で経路を追跡する。

1. route / entry point
2. authentication / authorization middleware
3. identity と tenant context の出所
4. service call
5. repository / data access
6. sink または state transition
7. 必要な場合のみ reverse callers

無制限のファイル読取り、対象全体のコンテキスト投入、ファイル名や関数名だけを根拠とする報告を
禁止する。

### 9.6 Phase 5: 仮説と反証

Hypothesis は次をすべて含む場合のみ受理する。

- 対応する SecurityInvariant
- attacker capability / preconditions
- entry point
- expected vulnerable path
- 調査対象 file / symbol
- supporting Evidence
- 反証となる条件と確認対象
- Verification plan

VerificationCase 作成前に、到達可能性、上流 middleware、集中認可、ORM 暗黙スコープ、入力制約、
feature flag、framework protection、下流チェック、transaction guard、テストデータ前提を調査する。

反証が成立した Hypothesis は `rejected` とし、削除せず保持する。

### 9.7 Phase 6: 独立ランタイム検証

Discovery Agent が宣言的 VerificationCase を提案し、Verifier Controller がスキーマとポリシーを
検査する。許可された case のみ使い捨て sandbox で実行する。

Verifier は、レスポンス、DB 状態、状態遷移、ローカル callback、クラッシュ、認可ログなどを
機械的に観測し、固定 oracle と比較する。実行していない PoC、LLM の主張、scanner severity、
README やコメントはランタイム証拠にならない。

### 9.8 Phase 7: トリアージ、修正、回帰

`verified` または `high-confidence-static` の Finding について、CWE、違反 Invariant、攻撃前提、
entry-to-sink trace、反証、再現、修正方針、回帰戦略を記録する。

修正差分は `reports/<run-id>/patches/FND-....diff` 等の別成果物として生成する。適用は人間の
レビュー後に別操作で行い、監査中に対象を上書きしない。修正後は同一ケースを再実行する。

## 10. 機能要件

### 10.1 診断

| ID | 要件 |
|---|---|
| FR-DOC-001 | `whitebox-audit doctor` と `make doctor` を提供する。 |
| FR-DOC-002 | git、curl、jq、rg、Python、Docker daemon、make、Codex、CodeGuard、Semgrep を検査する。 |
| FR-DOC-003 | CodeQL は optional として検査し、未導入を warning とする。 |
| FR-DOC-004 | 各ツールのバージョンと使用可否を表示する。 |
| FR-DOC-005 | 必須項目の欠落または Docker daemon 利用不能では nonzero 終了する。 |
| FR-DOC-006 | 診断処理はホスト、設定、対象を変更しない。 |

### 10.2 対象準備

| ID | 要件 |
|---|---|
| FR-TGT-001 | `prepare --target <path>` で対象を登録する。 |
| FR-TGT-002 | パスを絶対・実在・正規化済みのディレクトリとして検証する。 |
| FR-TGT-003 | ハーネス自身を対象として拒否する。 |
| FR-TGT-004 | Git commit、tree hash、言語、マニフェスト、target ID を記録する。 |
| FR-TGT-005 | 非 Git 対象にも再現可能な tree fingerprint を生成する。 |
| FR-TGT-006 | シンボリックリンクによるルート外逸脱を既定で追跡・読取り対象にしない。 |
| FR-TGT-007 | 対象内へファイルを作成・更新・削除しない。 |
| FR-TGT-008 | 一意な run ID と `work/<run-id>/` を作成する。 |

### 10.3 スキャンと SARIF

| ID | 要件 |
|---|---|
| FR-SCN-001 | `scan --target ... --scanner semgrep` を提供する。 |
| FR-SCN-002 | subprocess は引数配列、`shell=False`、timeout、最小環境で実行する。 |
| FR-SCN-003 | raw SARIF と実行メタデータを保存する。 |
| FR-SCN-004 | SARIF の複数 runs、optional field 欠落、URI 差異、snippet 欠落を許容して parse する。 |
| FR-SCN-005 | 不正 SARIF と scanner failure を明示的な error として保持し、黙って無視しない。 |
| FR-SCN-006 | `ingest-sarif --tool-name <name> --input <file>` を提供する。 |
| FR-SCN-007 | CodeQL は entitlement acknowledgement がない private/internal 対象では拒否または明示スキップする。 |
| FR-SCN-008 | CodeQL build extraction はホスト上で対象 build を実行しない。 |
| FR-SCN-009 | 同一内容の Evidence を安定 fingerprint で重複判定できる。 |

### 10.4 安全なナビゲーションと仮説管理

| ID | 要件 |
|---|---|
| FR-NAV-001 | `map`、`search`、`source`、`show-evidence`、`callers` 相当の限定操作を提供する。 |
| FR-NAV-002 | source path は常に対象ルート内へ confinement する。 |
| FR-NAV-003 | source read は相対パスと有限の行範囲を要求または既定上限で制限する。 |
| FR-NAV-004 | search は結果件数・読取り量を上限管理する。 |
| FR-NAV-005 | Target のテキストを命令として処理しないことをエージェント契約に含める。 |
| FR-HYP-001 | `hypothesis add --file <yaml-or-json>` でスキーマ検証済み Hypothesis を登録する。 |
| FR-HYP-002 | Invariant、attacker、entry point、path、support、falsification、verification plan の欠落を拒否する。 |
| FR-HYP-003 | supporting Evidence と CounterEvidence の参照整合性を検証する。 |
| FR-HYP-004 | rejected Hypothesis を履歴として保持する。 |

### 10.5 独立検証

| ID | 要件 |
|---|---|
| FR-VER-001 | v1 は HTTP action と JSON/status oracle の宣言 DSL を提供する。 |
| FR-VER-002 | 任意 shell command フィールドを受理しない。 |
| FR-VER-003 | Runtime Adapter の `command_id` はレビュー済みイメージ内コマンドへ解決する。 |
| FR-VER-004 | target、case、verifier code を read-only とし、output だけを書込み可能にする。 |
| FR-VER-005 | network none、または外部 egress のない専用 ephemeral network を使用する。 |
| FR-VER-006 | capability、privilege、PID、memory、CPU、timeout を制限する。 |
| FR-VER-007 | Docker socket、host home、cloud/SSH/package credentials を mount しない。 |
| FR-VER-008 | timeout 時に container と network を確実に停止・破棄する。 |
| FR-VER-009 | observation、oracle comparison、artifact hash、logs を VerificationResult に保存する。 |
| FR-VER-010 | `status=proved` は Verifier のみが生成可能とする。 |
| FR-VER-011 | destructive、production-reaching、policy-violating な動作を検出した場合は停止し、最小限の証拠を保持する。 |

### 10.6 Finding、レポート、パッチ

| ID | 要件 |
|---|---|
| FR-FND-001 | Finding status は定義済み 7 状態のいずれか一つだけを持つ。 |
| FR-FND-002 | `verified` は `proved` の VerificationResult が参照される場合だけ許可する。 |
| FR-FND-003 | runtime 検証なしでは `high-confidence-static`、`needs-verification`、`rejected` 等を使用する。 |
| FR-FND-004 | Severity は明示的要因から算出し、LLM の直感だけで設定しない。 |
| FR-RPT-001 | `report` は canonical object から Markdown と JSON を生成する。 |
| FR-RPT-002 | レポートに対象 fingerprint、ツール、coverage、skip/failure、scope、limitations を含める。 |
| FR-RPT-003 | 秘密値は再掲せず、場所・fingerprint・redacted 表現を使用する。 |
| FR-PAT-001 | `patch --finding <id>` は対象外に diff と回帰案を生成する。 |
| FR-PAT-002 | パッチを対象へ自動適用しない。 |

## 11. CLI 仕様

最終的な CLI は次の形へ収束させる。Milestone に応じて段階的に追加してよい。

```text
whitebox-audit doctor
whitebox-audit prepare --target <absolute-or-resolvable-path> [--profile <name>]
whitebox-audit scan --target <path> [--scanner semgrep|codeql|all]
whitebox-audit ingest-sarif --tool-name <name> --input <sarif-file>
whitebox-audit map [--run-id <id>]
whitebox-audit search <pattern> [--path <relative-path>] [--max-results <n>]
whitebox-audit source <relative-path> --lines <start:end>
whitebox-audit callers <symbol>
whitebox-audit evidence list [--kind <kind>]
whitebox-audit show-evidence <evidence-id>
whitebox-audit invariant list
whitebox-audit hypothesis add --file <yaml-or-json>
whitebox-audit verify [--run-id <id>] [--case <verification-id>]
whitebox-audit report [--run-id <id>] [--format markdown|json|sarif]
whitebox-audit patch --finding <finding-id>
whitebox-audit run --target <path> --profile <name>
```

`run` による完全オーケストレーションは後期 Milestone とし、個別ステップの証拠モデルが安定する
までは実装しない。

標準 Make target は次を提供する。

```text
make doctor
make prepare TARGET=/absolute/path/to/target
make scan TARGET=/absolute/path/to/target
make audit TARGET=/absolute/path/to/target
make verify TARGET=/absolute/path/to/target
make report TARGET=/absolute/path/to/target
make test
```

### 11.1 CLI 共通動作

- machine-readable 出力が必要なコマンドは `--format json` を提供する。
- エラーは stderr、正常な成果物・要約は stdout に出力する。
- path、run ID、object ID を検証してからファイルアクセスする。
- 秘密情報や認証ヘッダーを既定ログへ出力しない。
- 冪等な読取り操作は同一入力で同一の意味結果を返す。
- 破損した既存 run を上書きせず、エラーまたは新規 run とする。

### 11.2 終了コード

| コード | 意味 |
|---|---|
| 0 | 要求処理が成功 |
| 1 | 一般的な処理失敗 |
| 2 | CLI 引数または構造化入力の検証失敗 |
| 3 | 必須 capability 不足 |
| 4 | 安全ポリシーによる拒否 |
| 5 | scanner / verifier の実行失敗 |
| 6 | artifact parse またはデータ整合性失敗 |

実装時に変更する場合は、CLI help、運用文書、テストを同時に更新する。

## 12. 設定仕様

設定はリポジトリ内の既定値と、オペレーター管理のローカル設定を分離する。秘密情報を
リポジトリ設定へ保存しない。優先順位は CLI option、明示 profile、ローカル設定、既定設定とする。

想定ファイル:

```text
config/audit.default.yaml
config/scanners.yaml
config/verifier-policy.yaml
policies/authz/
policies/tenancy/
policies/payments/
policies/pii/
policies/framework/
```

概念例:

```yaml
schema_version: 1

audit:
  target_read_only: true
  network: off
  max_threat_scenarios: 7
  retention_days: null

semgrep:
  enabled: true
  timeout_seconds: 1800
  rulesets:
    - auto

codeql:
  enabled: auto
  entitlement_acknowledged: false

navigation:
  max_source_lines: 200
  max_search_results: 100

verifier:
  network: none
  timeout_seconds: 30
  memory: 1g
  cpus: 1
  pids_limit: 256
```

設定スキーマ外のキーは、セキュリティに影響する typo の見逃しを防ぐため既定で拒否する。
設定変更は run metadata に反映し、秘密値を除いた有効設定の fingerprint を保存する。

## 13. データモデル

### 13.1 ID 仕様

安定 ID は次の prefix を使用する。

```text
INV-<hash>  SecurityInvariant
HYP-<hash>  Hypothesis
EVD-<hash>  Evidence
VER-<hash>  VerificationCase / VerificationResult の関連ID
FND-<hash>  Finding
```

hash は、対象 fingerprint、正規化済み path/symbol、Invariant、rule ID、claim など、意味的に安定した
内容から生成する。時刻、絶対ホストパス、表示順のような不安定要素を可能な限り除外する。

### 13.2 Target

| フィールド | 型 | 必須 | 説明 |
|---|---|---|---|
| target_id | string | yes | 対象の安定 ID |
| root | absolute path | yes | 解決済み対象ルート。外部出力時は必要に応じて redaction |
| git_commit | string/null | yes | Git commit。非 Git では null |
| tree_hash | string | yes | 監査対象内容の fingerprint |
| languages | string[] | yes | 検出言語 |
| manifests | path[] | yes | 実行せずに検出した manifest |
| prepared_at | datetime | yes | 準備時刻 |
| read_only | boolean | yes | ハーネス上の取扱い宣言。常に true |

### 13.3 ScannerRun

| フィールド | 型 | 必須 | 説明 |
|---|---|---|---|
| run_id | string | yes | スキャナー実行 ID |
| target_id | string | yes | 対象参照 |
| scanner | object | yes | name、version、bundle/query version |
| argv | string[] | yes | 実行引数。秘密値は除外 |
| started_at / finished_at | datetime | yes | 実行時刻 |
| returncode | integer/null | yes | 未実行では null |
| status | enum | yes | succeeded / skipped / failed / timed-out |
| reason | string/null | yes | skip/failure reason |
| raw_artifacts | ref[] | yes | SARIF、log 等 |
| resource_policy | object | yes | timeout、sandbox 等 |

### 13.4 SecurityInvariant

| フィールド | 型 | 必須 | 説明 |
|---|---|---|---|
| id | INV ID | yes | 安定 ID |
| title | string | yes | 短い名称 |
| scope | string[]/object | yes | resource、operation、tenant 等 |
| statement | string | yes | 常に成立すべき性質 |
| source | enum | yes | inferred / policy / operator |
| confidence | enum | yes | low / medium / high |
| counterexample | object | yes | actor、action、forbidden effect |

### 13.5 Evidence

| フィールド | 型 | 必須 | 説明 |
|---|---|---|---|
| id | EVD ID | yes | 安定 ID |
| kind | enum | yes | source / static-analysis / runtime / config / test |
| location | object/null | yes | relative path、line、symbol |
| claim | string | yes | 当該 Evidence が直接支える事実 |
| artifact_ref | string | yes | raw artifact への run-relative 参照 |
| content_hash | string | yes | 内容整合性用 hash |
| confidence | enum | yes | observed-runtime / deterministic-static / direct-source-trace / inferred / operator-asserted |
| provenance | object | yes | tool/run/raw URI または source tree hash |
| redactions | object[] | yes | redaction の有無と種別。秘密値は含めない |

CounterEvidence は別種の真偽値ではなく Evidence を Hypothesis へ反証の役割でリンクしたものとする。

### 13.6 Hypothesis

| フィールド | 型 | 必須 | 説明 |
|---|---|---|---|
| id | HYP ID | yes | 安定 ID |
| invariant_id | INV ID | yes | 対応 Invariant |
| title | string | yes | 仮説名 |
| attacker_preconditions | string[] | yes | 必要権限・知識・位置 |
| entry_point | location/object | yes | 到達入口 |
| suspected_path | trace node[] | yes | entry-to-sink 経路 |
| files_symbols_to_inspect | location[] | yes | 限定調査対象 |
| supporting_evidence | EVD ID[] | yes | 支持 Evidence |
| counter_evidence | EVD ID[] | yes | 発見済み反証。空配列可 |
| falsification_conditions | string[] | yes | 仮説を棄却する条件 |
| verification_plan | object | yes | 検証方法と期待違反 |
| status | finding-status subset | yes | hypothesis / needs-verification / rejected 等 |

### 13.7 VerificationCase

v1 の HTTP DSL は次を持つ。

| フィールド | 型 | 必須 | 説明 |
|---|---|---|---|
| schema_version | integer | yes | 初期値 1 |
| id | VER ID | yes | case ID |
| hypothesis_id | HYP ID | yes | 対象仮説 |
| runtime_profile | string | yes | レビュー済み adapter 名 |
| setup | object | yes | 許可済み fixture / seed ID |
| actor | object | yes | fixture 上の identity |
| action | object | yes | protocol、method、path、許可済み header/body |
| oracle | object | yes | expected secure behavior と forbidden condition |
| limits | object | yes | timeout 等。ポリシー上限を超えられない |

テンプレート変数は fixture が公開する値だけを参照できる。環境変数、host path、任意 command への
展開を禁止する。

### 13.8 VerificationResult

| フィールド | 型 | 必須 | 説明 |
|---|---|---|---|
| verification_id | VER ID | yes | 対応 case |
| verifier_run_id | string | yes | 実行 ID |
| target_tree_hash | string | yes | 検証した対象 |
| status | enum | yes | proved / not-proved / inconclusive / policy-rejected / error |
| observations | object[] | yes | response、state、hash、artifact ref |
| oracle | object | yes | 期待と観測の比較、violated |
| started_at / finished_at | datetime | yes | 実行時刻 |
| verifier_version | string | yes | 判定コードの版 |
| policy_fingerprint | string | yes | 適用ポリシー |

`not-proved` は「安全であることの一般的証明」ではなく、宣言ケースで禁止条件が観測されなかった
ことだけを意味する。setup failure や観測不能は `inconclusive` または `error` と区別する。

### 13.9 Finding

| フィールド | 型 | 必須 | 説明 |
|---|---|---|---|
| id | FND ID | yes | 安定 ID |
| hypothesis_id | HYP ID | yes | 元仮説 |
| status | enum | yes | 定義済み 7 状態 |
| title | string | yes | Finding 名 |
| severity | enum/object | yes | policy による severity と根拠 |
| cwe | string[] | yes | CWE。該当なしは空配列と理由 |
| invariant_id | INV ID | yes | 違反 Invariant |
| evidence | EVD ID[] | yes | 根拠 |
| verification_result_id | VER ID/null | yes | verified では必須 |
| attacker_preconditions | string[] | yes | 攻撃前提 |
| impact | object | yes | C/I/A、scope、reliability 等 |
| falsification_summary | object | yes | 調査した counter controls |
| remediation | object | yes | 最小修正と注意点 |
| regression | object | yes | 回帰方法 |

## 14. 状態モデル

Finding 候補の status は、次のいずれか一つだけである。

```text
hypothesis
needs-verification
verified
high-confidence-static
rejected
accepted-risk
duplicate
```

許可される主な遷移:

```text
hypothesis
  -> rejected
  -> needs-verification

needs-verification
  -> verified                 # VerificationResult.status == proved が必須
  -> high-confidence-static   # 完全な静的 trace と反証分析が必須
  -> rejected

verified / high-confidence-static
  -> accepted-risk
  -> duplicate
```

禁止事項:

- VerificationResult なしに `verified` へ遷移すること
- scanner severity または LLM prose だけで `verified` とすること
- 実行不能な PoC を実行済みとして扱うこと
- `not-proved` を対象全体が安全である証拠として扱うこと
- 過去状態と判定根拠を監査履歴から削除すること

## 15. 永続化と成果物レイアウト

```text
work/<run-id>/
├── run.json
├── target.json
├── inventory.json
├── effective-config.json
├── scanner-runs/
│   ├── semgrep/
│   │   ├── run.json
│   │   ├── result.sarif
│   │   ├── stdout.log
│   │   └── stderr.log
│   └── codeql/
├── evidence/
│   └── evidence.jsonl
├── threat-model/
│   └── scenarios.json
├── invariants/
│   └── invariants.jsonl
├── hypotheses/
│   └── hypotheses.jsonl
├── verification/
│   └── <verification-id>/
│       ├── case.json
│       ├── result.json
│       └── artifacts/
└── reports/
    ├── report.md
    ├── findings.json
    └── findings.sarif

reports/<run-id>/
└── patches/
    └── <finding-id>.diff
```

`work/` は生成物であり既定では commit しない。raw source は必要な場合を除き複製しない。
参照は可能な限り run-relative にし、外部出力へホストの絶対パスを漏らさない。

各 JSON / JSONL record は `schema_version` を持つ。将来の非互換変更には明示的な migration を
用意し、未知の新しい schema を暗黙に読み替えない。

## 16. Scanner 詳細仕様

### 16.1 Semgrep

- v1 の必須ベースラインとする。
- `semgrep scan` を引数配列で起動し、SARIF を run directory に直接保存する。
- ruleset は設定可能とし、実際に使った設定 ID または fingerprint を記録する。
- target exclusion policy を記録し、coverage から除外したパスを説明可能にする。
- return code を Semgrep の仕様に従って解釈し、findings と実行失敗を混同しない。
- custom rule は `rules/semgrep/authz`、`tenancy`、`framework` 等に分離し、各 rule に positive / negative test を持たせる。

### 16.2 CodeQL

- optional / recommended とする。
- binary の存在だけから利用権限を推定しない。
- private/internal 対象ではローカル設定の明示的 acknowledgement を必須とする。
- supported language、bundle、query pack、database fingerprint を記録する。
- compiled language の build extraction は scanner container / VM で行う。
- target source は read-only、build workspace は分離、host credential は非公開、network は制御する。
- 不明な対象 build command を shell string として渡さない。
- 未実行・非対応・権限未確認・build failure を異なる reason として保存する。

### 16.3 SARIF normalization

- SARIF は scanner interchange format とし、内部 truth model にはしない。
- `runs[]` をすべて処理する。
- rule metadata の保存場所差異、artifact URI、base URI、region 欠落を許容する。
- location がない result も、message、rule、raw reference を持つ Evidence として表現可能にする。
- raw result への参照と normalized content hash を保持する。
- parse できない必須構造は失敗として記録し、部分成功時は件数と warning を明示する。

## 17. Verifier と Runtime Adapter 詳細仕様

### 17.1 コンテナポリシー

基準ポリシーは次と同等以上とする。

```text
--network none
--read-only
--cap-drop ALL
--security-opt no-new-privileges
--pids-limit 256
--memory 1g
--cpus 1
--tmpfs /tmp:rw,noexec,nosuid,nodev,size=128m
target mount: read-only
case mount: read-only
output mount: write-only/read-write as required
```

Docker socket、host home、SSH/cloud/Kubernetes/package manager credential、production config を
mount してはならない。

### 17.2 ネットワークモード

- 既定: `none`
- HTTP fixture: target、test DB、必要な queue/cache、verifier client だけを ephemeral network へ接続する
- ephemeral network から外部 egress は許可しない
- 外部 network 対応は v1 対象外。将来追加時は destination allowlist、DNS、method、callback ownership、logging を必須とする

### 17.3 Runtime Adapter

Runtime Adapter は対象チームと監査側がレビューした application family ごとの契約である。

```yaml
schema_version: 1
name: typescript-nextjs-postgres
image: org/whitebox-runtime-nextjs:2026-08
start:
  command_id: start-app
health:
  type: http
  url: http://app:8080/health
fixtures:
  - seed-db
identities:
  - anonymous
  - tenant_a_user
  - tenant_b_user
  - admin
ports:
  - 8080
network:
  egress: none
```

`command_id` は adapter image 内の固定コマンドを指し、対象や agent が提供する任意文字列ではない。
adapter は image identity、health check、seed data、test identities、port、依存サービス、許可された
state mutation を明示する。

### 17.4 検証モード

| モード | 用途 | 許可される最終状態 |
|---|---|---|
| Static-only | runtime がない場合 | rejected / needs-verification / high-confidence-static |
| Operator-provided Runtime Adapter | 実アプリケーション監査 | verifier 結果に応じ verified 可 |
| Fixture / disposable image | CI・評価 | verifier 結果に応じ verified 可 |

## 18. セキュリティ要件

| ID | 要件 |
|---|---|
| SEC-001 | 対象リポジトリの全内容を未信頼データとして扱う。 |
| SEC-002 | 対象ローカルの agent instruction を命令チェーンへ入れない。 |
| SEC-003 | Codex の root を対象へ変更しない。 |
| SEC-004 | 監査中の既定 network を off とする。 |
| SEC-005 | child process へ `os.environ` 全体を継承せず allowlist 環境を渡す。 |
| SEC-006 | cloud、SSH、browser、registry、production credential を監査環境へ公開しない。 |
| SEC-007 | 対象の build/install/test/lifecycle script をホスト上で実行しない。 |
| SEC-008 | subprocess で `shell=True` を使用せず、untrusted value を command string に連結しない。 |
| SEC-009 | 全 path を resolve し、root confinement を検証する。 |
| SEC-010 | scanner と verifier を別の権限・環境として分離する。 |
| SEC-011 | Discovery Agent は verifier verdict を生成・変更できない。 |
| SEC-012 | verifier oracle は実行中に不変とする。 |
| SEC-013 | source、case、verifier code を read-only にする。 |
| SEC-014 | verifier に Docker socket、privileged mode、追加 capability を付与しない。 |
| SEC-015 | report と log の secret、token、credential を redaction する。 |
| SEC-016 | report は機密成果物として local-only を既定とし、外部 export を明示操作にする。 |
| SEC-017 | dependency を pin し、tool/version/config fingerprint を run に記録する。 |
| SEC-018 | scanner crash、parse failure、timeout を監査証跡に残す。 |
| SEC-019 | production system、real customer data、cloud metadata、第三者サービスへの到達を検知した検証は停止する。 |
| SEC-020 | `--dangerously-bypass-approvals-and-sandbox` 等の無制限モードを標準化しない。 |

## 19. 非機能要件

### 19.1 再現性

- run ID、target fingerprint、tool version、rules/query version、effective config、policy fingerprint を保存する。
- 同一 fixture と固定ツール版による再実行で同じ verifier verdict を得られることを評価する。
- raw scanner output を保持し、normalization bug を後から調査可能にする。

### 19.2 信頼性

- scanner failure、partial parse、timeout、adapter startup failure を成功として扱わない。
- 途中失敗時も、それまでの immutable artifact とエラー状態を保持する。
- cleanup は timeout や例外でも実行し、ephemeral container/network を残さない。

### 19.3 性能とコンテキスト効率

- search と source read に上限を設ける。
- エージェントは entry-to-sink の必要範囲だけを読む。
- wall-clock、scanner time、verifier time、利用可能なら model usage を run metrics に記録する。
- 品質指標が得られる前に token 削減だけを最適化しない。

### 19.4 可搬性

- orchestration は Python 3.12+ とし、標準ライブラリを優先する。
- target language にオーケストレーターを依存させない。
- Docker を初期隔離基盤とし、将来の VM / microVM 実装と置換可能な controller interface を保つ。

### 19.5 保守性

- parsing と subprocess execution を分離する。
- Scanner、Runtime Adapter、Reporter は明確な interface を持つ。
- machine-readable schema を canonical とし、Markdown は renderer とする。
- direct dependency を最小化し、lock file を commit する。
- direct/build dependency は exact pin とし、URL/VCS/file reference と代替indexを拒否する。
- dependency install は committed lock に拘束し、新規公開packageに72時間のcooldownを適用する。
- lock内のsource、artifact host、SHA-256、schema、freshnessをnative CLIで検査する。
- host tool provenanceとしてversion、resolved executable path、executable SHA-256を記録する。
- audit harnessのCycloneDX SBOMを生成可能にする。
- Next.js fixtureはNode/package manager/direct dependency/lockを固定し、registry URLとintegrityを
  controllerが実行前に検査する。
- Next.js fixtureのdependency installはcredentialを渡さないisolated build内だけで許可し、package
  lifecycle scriptは既定で無効、package registry以外へのegressは禁止する。
- scanner、verifier、runtimeのcontainer imageはproduction利用前にreview済みdigestでpinする。
- security policy、verifier、skill の変更は高いレビュー強度を要求できる構造にする。

### 19.6 プライバシーと保持

- raw source は既定で複製しない。
- scanner output、runtime request/response、PoC artifact は retention policy に従う。
- token や secret は削除または不可逆 fingerprint 化する。
- run ID 単位で安全に削除できる機能を将来提供する。
- 削除対象は必ず `work/<validated-run-id>` 等へ confinement し、広い recursive target を使用しない。

## 20. Severity 仕様

Severity は組織 policy に基づき、少なくとも次の要因を明示的に評価する。

- required privileges
- attacker position と user interaction
- cross-user / cross-tenant / system-wide scope
- confidentiality / integrity / availability impact
- exploit reliability
- environmental preconditions
- blast radius と recoverability

CVSS は補助スコアとして生成できるが、組織 policy より優先しない。Severity record には入力要因と
算定根拠を保存し、LLM が根拠なしに `high` 等を選択できないようにする。

## 21. レポート仕様

最終 Markdown レポートには次を含める。

1. run ID、対象 ID、Git commit/tree hash、監査日時
2. 監査範囲、対象言語、除外範囲、制限事項
3. ツール名・バージョン・rules/query、実行結果
4. 未実行・skip・failure と理由
5. 脅威モデルと SecurityInvariant の要約
6. status 別 Finding 一覧
7. 各 Finding の severity、CWE、攻撃前提、違反 Invariant
8. entry point、control path、sink/effect の trace
9. Supporting Evidence と調査済み CounterEvidence
10. VerificationResult と再現方法。該当しない場合は静的判定の限界
11. 修正方針と回帰戦略
12. rejected hypothesis 数と、必要に応じた要約
13. redaction と evidence retention に関する注記

`verified` Finding は、影響コンポーネント、攻撃前提、違反 Invariant、source/entry、security control
path、sink/effect、反証、独立 verifier result、決定論的再現、remediation、regression をすべて持つ。

## 22. エラー処理と degraded 状態

監査全体の run status は少なくとも次を区別する。

```text
created
prepared
running
completed
degraded
failed
cancelled
```

- 必須の対象準備またはデータ整合性が失敗した場合は `failed` とする。
- Semgrep は製品 capability として必須だが、個別監査で利用不能・失敗した場合、ポリシーが許せば
  run を `degraded` として限定継続できる。レポートでは静的 coverage 欠落を目立つ形で表示する。
- CodeQL の正当な skip は run failure としない。
- 検証 setup failure は脆弱性の棄却ではなく `inconclusive` / verifier error とする。
- 予期しない外部到達や破壊的挙動は verification を中止し、run を degraded または failed とする。
- 例外の stack trace は debug artifact に保存できるが、標準レポートでは秘密と内部 host path を redaction する。

## 23. テスト仕様

### 23.1 Unit test

- 全 canonical model の validation と JSON round trip
- 安定 ID と fingerprint
- Finding state transition、特に不正な `verified`
- SARIF optional field、複数 run、URI、location/snippet 欠落
- scanner return code と failure classification
- config validation と unknown key rejection
- secret redaction

### 23.2 Path / input security test

- `..`、absolute path、symlink escape
- nested repository / worktree / mount confusion
- ハーネス自身を対象にする入力
- 対象内 agent instruction、README、comment の prompt injection
- 不正 run ID、artifact reference、template expansion
- VerificationCase の arbitrary shell / host path / environment access 要求

### 23.3 Scanner integration test

- fake scanner の成功、findings、timeout、nonzero、malformed output
- vulnerable fixture から期待 Evidence を生成
- benign fixture で seeded issue を生成しない
- Semgrep がある場合だけ実 scanner smoke test
- CodeQL skip reason と entitlement gate

### 23.4 Verifier policy test

- vulnerable tenant fixture は `proved`
- fixed fixture は `not-proved`
- target/source へ書込み不能
- arbitrary command injection を schema/policy で拒否
- external egress 不可
- Docker socket / host secrets 不可
- PID、memory、CPU、timeout 制限
- timeout 後の container/network cleanup
- discovery-generated fake verdict の拒否

### 23.5 評価 fixture

少なくとも次を vulnerable / fixed / false-positive control として用意する。

- IDOR
- tenant isolation
- missing role check
- state transition bypass
- password reset misuse
- cache isolation
- background job privilege confusion
- webhook trust boundary
- SSRF chain
- injection baseline

### 23.6 品質指標

- Verified Precision
- Known Vulnerability Recall
- False Positive Rate
- Unique Finding Lift
- SAST Overlap
- Verification Rate
- Reproduction Success
- wall-clock time
- Cost per Verified Finding

比較対象は Semgrep、CodeQL、決定論的 union、Codex 単独ナビゲーション、Codex + Evidence、
反証あり、独立 Verifier ありの各構成とする。

## 24. 受入基準

各実装変更は、完了報告前に次を満たす。

1. formatter / linter が成功する。
2. unit test が成功する。
3. 変更箇所に対応する security-relevant test が成功する。
4. 動作変更時は文書と CLI help が更新される。
5. 実装済みと stub / 未実装が明確に区別される。
6. scanner / agent / verifier の動作は、実行結果または現実的 fixture coverage がある場合だけ成功と表現する。
7. 対象ファイルが変更されていないことを確認する。
8. scanner failure、verification limitation、skipped capability が隠されていないことを確認する。

Release quality gate:

- clean setup が再現可能
- `make doctor`、formatter、linter、test が成功
- prompt-injection fixture が成功
- verifier isolation test が成功
- report が structured evidence から生成される
- 文書のコマンドと実装が一致
- no-target-write が確認済み

## 25. 実装順序

実装は次の順序を維持する。

| Milestone | 内容 | 主な完了条件 |
|---|---|---|
| 0 | Python project、CLI、doctor、tests | `make doctor`, `make test` |
| 1 | Safe Target Controller | malicious path 拒否、target metadata 永続化 |
| 2 | Semgrep vertical slice | raw SARIF、Evidence、明示的 failure |
| 3 | Evidence model、manual Hypothesis | 状態制約と schema test |
| 4 | Independent Verifier | vulnerable/fixed fixture、isolation test |
| 5 | Agentic audit skill integration | 限定 navigation、schema 済み Hypothesis |
| 6 | CodeQL adapter | entitlement gate、isolated build、Evidence merge |
| 7 | Reporting / patch workflow | canonical rendering、separate diff |
| 8 | Evals | precision、recall、lift、reproducibility |
| 9 | Non-interactive Codex orchestration | strict schema、budget、resume、no verdict authority |
| 10 | Production hardening | pinned image、SBOM、CI、audit log、redaction |

Evidence pipeline と Verifier が成立する前に、複雑な LLM orchestration を実装しない。

## 26. 現在の実装状態

2026-08-12 時点で、Milestone 0〜2として次を実装済みである。

- Python 3.12+ package、`whitebox-audit` CLI、`doctor` / `supply-chain check` command
- human-readable / JSON capability report と安定した終了コード
- minimal child environment、timeout、診断出力の長さ制限とredaction
- project-local `.venv`、`uv.lock`、Ruff、mypy、pytest、Make targets
- native `supply-chain check`、exact dependency pin、72-hour cooldown、artifact hash/source policy
- tool executable provenance と CycloneDX SBOM生成
- `Target`、`Inventory`、`AuditRun` canonical model と `prepare` CLI
- directory-FD/no-follow走査、symlink/mount/Git metadataのfail-closed検証
- deterministic target fingerprint、manifest/language/route inventory、atomic run metadata persistence
- `Scanner` abstraction、Semgrep adapter、raw SARIFとscanner実行metadata
- defensive SARIF parser、stable Evidence ID/fingerprint、atomic/deduplicating JSONL store
- `scan` / `ingest-sarif` CLI、fake scannerによる成功/失敗/timeout/改変検知fixture
- ADR、要件トレーサビリティ、Milestone 0〜2実行結果
- 70件のunit/integration/security test

次は未実装である。

- CodeQL adapter
- Evidence以外のcanonical modelとmanual Hypothesis workflow
- Next.js / PostgreSQL fixtureとVerifier image / controller / DSL
- Reporter、patch workflow、evaluation harness

`hypothesis`、Verifier、agent navigation、report、patch系CLIは現時点では実装目標および受入仕様である。
Semgrep実行は現在host adapterであり、OS-level network deny/read-only mountは未実装である。

## 27. 未決定事項

以下は実装時に ADR または設定スキーマで確定する。安全側の既定値を維持する限り、Milestone 0～2
の開始を妨げない。

1. Milestone 3以降の外部schema validationにPydanticを追加するか
2. JSONL record の厳密な migration mechanism
3. 非 Git 対象の tree fingerprint で除外するファイルと symlink の扱い
4. run status と object state transition の永続 audit log 形式
5. Severity policy の具体的な組織閾値
6. report retention の既定期間と安全な run deletion UX
7. HTTP DSL で許可する body、header、JSONPath の厳密な部分集合
8. scanner container の配布・署名・pinning 方式
9. 非対話 Codex 実行での model budget、resume、失敗回復ポリシー

これらを決定する際も、対象をホスト上で実行しないこと、Discovery と Verifier を分離すること、
`verified` を機械的証拠に限定することは変更不可の制約である。

## 28. 要件トレーサビリティ

| 仕様領域 | 主な根拠文書 |
|---|---|
| セットアップ・doctor | `docs/01-SETUP.md` |
| 論理アーキテクチャ | `docs/02-ARCHITECTURE.md` |
| 監査 Phase | `docs/03-AUDIT-PROTOCOL.md` |
| Semgrep / CodeQL / SARIF | `docs/04-DETERMINISTIC-ANALYSIS.md` |
| Verifier / Runtime Adapter | `docs/05-VERIFIER-SANDBOX.md` |
| Canonical object / status | `docs/06-EVIDENCE-MODEL.md` |
| 脅威・セキュリティ要件 | `docs/07-SECURITY-MODEL.md` |
| 品質指標・fixture | `docs/08-EVALUATION.md` |
| Milestone・Done criteria | `docs/09-IMPLEMENTATION-PLAN.md`、`AGENTS.md` |
| ツール選定 | `docs/11-TOOL-DECISIONS.md` |
| 人手運用 | `docs/12-OPERATIONS.md` |
