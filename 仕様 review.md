確認したところ、continuous-appsec はすでに「SAST＋AI」の実験ではなく、かなり本格的な Evidence-driven White-box Security Audit Harness の仕様になっています。設計思想そのものはかなり良いです。ただし、仕様として見ると v1に対して少し広がりすぎている部分 と、逆に 今のうちに境界を明文化した方がよい部分 があります。

総合評価

8.5 / 10。方向性は非常に強い。v1のスコープ整理をすれば実用性がかなり上がる、という評価です。

特に優れているのは、

LLMに「脆弱性を見つけろ」と丸投げせず、
Hypothesis → Evidence → Falsification → Independent Verification

という設計です。

READMEでも、LLMは仮説生成とナビゲーションを担当し、最終的な verified は独立Verifierの機械観測可能な証拠だけで決定する、と明示されています。

これは今後のAIネイティブなソースコード診断の設計として筋が良いです。

⸻

最も良いところ：責務分離が明確

現在の論理構造は、

Target
  ↓
Threat Model
  ↓
Security Invariants
  ↓
Semgrep / CodeQL / SARIF
  ↓
Evidence Store
  ↓
Codex navigation
  ↓
Hypothesis
  ↓
Falsification
  ↓
Verification Case
  ↓
Independent Verifier
  ↓
Finding

となっています。

特に

Discovery Agent ≠ Verifier

をHard Boundaryにしているのは非常に重要です。

Discovery Agentは、

* reasoning
* search
* trace
* PoC提案
* patch提案

まではできるが、

自分自身で「脆弱性確定」と宣言できない。

Verifierだけが固定されたOracleを使って proved を生成する設計です。

これはAIエージェント特有の

* hallucination
* confirmation bias
* reward hacking
* self-certification

への対策として優秀です。

⸻

一方で、一番大きな問題

現在、

「continuous-appsec」というリポジトリ名と、実際の製品仕様がかなり乖離し始めています。

実体はもう、

Continuous AppSec Platform

というより、

AI-assisted White-box Security Auditor

です。

仕様書でも正式名称が

Whitebox AI Audit

CLIが

whitebox-audit

になっています。

これは単なる名前の問題ではありません。

continuous-appsec という名前から期待されるものは普通、

IDE
 ↓
pre-commit
 ↓
PR
 ↓
CI
 ↓
SAST/SCA/Secrets/IaC
 ↓
DAST
 ↓
Runtime
 ↓
Vulnerability Management

のContinuous Securityです。

ところが現在のシステムは、

Repository
 ↓
White-box security investigation
 ↓
Evidence
 ↓
AI reasoning
 ↓
Verification
 ↓
Finding

です。

別物です。

ここは今の段階で整理した方がいいです。

⸻

P0：仕様上、一番修正したい点

「Audit」と「Continuous AppSec」の責務を切り分ける

今の仕様に「continuous」という概念はほとんどありません。

例えば、

* PR incremental scan
* changed-lines analysis
* baseline comparison
* previous finding state
* new / fixed / regressed
* CI event
* scheduled audit
* risk acceptance expiration

などがありません。

なので、このPJの目的を

人間が行っていた高度なホワイトボックス脆弱性診断をAI＋決定論的解析＋検証で再構築する

と明確に定義した方が良いです。

これなら今のアーキテクチャに完全に合います。

Continuous化は後段として、

Whitebox Audit Engine
        ↓
finding.json
        ↓
Continuous AppSec
        ↓
PR / CI / scheduled / regression

と外側から呼び出せばいい。

つまり、

                ┌────────────────────┐
                │ Continuous AppSec  │
                │ Orchestrator       │
                └─────────┬──────────┘
                          │
                          ▼
┌──────────────────────────────────────────┐
│        Whitebox Audit Engine             │
│                                          │
│ Semgrep / CodeQL                         │
│       ↓                                  │
│ Evidence → Agent → Falsification         │
│                        ↓                 │
│                    Verifier              │
└──────────────────────────────────────────┘

です。

こちらの方が責務が綺麗です。

⸻

P0：もう1つ重要な問題

Threat Model → Invariant が少し魔法になっている

現在、

Threat Model
    ↓
Security Invariants
    ↓
Hypothesis

となっています。

Invariantの思想そのものは非常に良いです。

例えば仕様には、

A non-admin principal may read an invoice only when
principal.tenant_id == invoice.tenant_id.

のような例があります。

問題は、

そのInvariantを誰がどうやって正しいと判断するのか

です。

ここはWhite-box Auditの核心になります。

AIがコードだけを見て、

tenant_id must match

というInvariantを生成すると、

「現実の仕様なのか」
「AIが推測した仕様なのか」

が分からなくなります。

なのでInvariantには最低でも、

source:
  type: inferred | declared | framework | operator
confidence: 0.92
evidence:
  - ...

を持たせるべきです。

もっと重要なのは、

Declared Invariant

と

Inferred Invariant

を分離することです。

例えば、

Product requirements
       ↓
Declared invariant ─────┐
                        │
Code / Routes / DB      │
       ↓                │
Inferred invariant ─────┤
                        ↓
                    Hypothesis

です。

これによって、

実装が仕様に違反している

のか、

実装自体からAIが推測したセキュリティ期待値に違反している

のかを区別できます。

かなり重要です。

⸻

P1：Evidence Modelをさらに中心に据えるべき

現在もEvidence StoreをCanonical source of truthとしているのは良い設計です。

ただし将来的には、

Scanner Finding

ではなく、

Evidence Graph

に寄せた方が強いと思います。

例えばIDORなら、

HTTP Route
   ↓
Controller
   ↓
Service
   ↓
Repository
   ↓
SQL Query

のtraceがあります。

そこに、

Auth Middleware
       ↓
Principal
       ↓
tenant_id

が接続する。

つまり、

Principal
   │
   ▼
Route → Handler → Service → DB query → Resource
                     │
                     X
                Tenant check absent

というグラフになります。

Semgrep/CodeQL/Codexは、

Findingを出すものではなく、GraphにEvidenceを足すもの

と考える。

この抽象化はかなり強いです。

⸻

P1：Verifier DSLは大正解。ただし最初はHTTPだけでいい

仕様ではVerifierを、

* HTTP request DSL
* Browser DSL
* SQL assertion
* filesystem assertion
* process assertion

まで広げる構想があります。

方向性は良いのですが、v1では広すぎます。

v1は、

HTTP Request
+
HTTP Response Oracle

だけで十分だと思います。

例えば、

actor: tenant_a_user
request:
  method: GET
  path: /api/invoices/{tenant_b_invoice}
expect_secure:
  status:
    - 403
    - 404
prove_if:
  status: 200
  json:
    tenant_id: tenant_b

これだけでも、

* IDOR
* horizontal privilege escalation
* vertical privilege escalation
* tenant isolation
* state-transition bypass

のかなりの範囲を検証できます。

Verifier DSLを早期に汎用化すると、DSLそのものの設計PJになります。

⸻

P1：CodeQLはv1からさらに下げてもいい

仕様ではSemgrepをbaseline、CodeQLをoptionalにしています。

これは正しい判断です。

むしろv1は、

Semgrep
+
existing SARIF

までで十分です。

CodeQLは、

* DB作成
* build extraction
* language differences
* licensing / execution constraints
* malicious build isolation

まで考える必要があります。

このプロジェクトの本当の差別化要因はCodeQLではありません。

差別化要因は、

Evidence
    ↓
AI Hypothesis
    ↓
Counter Evidence
    ↓
Independent Verification

だからです。

CodeQL対応に工数を取られない方がいいです。

⸻

P1：Project CodeGuardを「必須ツール」にしているのは外したい

仕様書では必須ツールに

Project CodeGuard — 基本的なセキュアコーディング知識

と入っています。

これは少し危険です。

Whitebox Auditのコアが、

外部Agent Skill

に依存して見えてしまいます。

CodeGuardは、

optional knowledge provider

あるいは

baseline policy pack

程度がよいでしょう。

例えば、

Policy Providers
Built-in
 ├─ OWASP
 ├─ CWE
 └─ local rules
Optional
 ├─ Project CodeGuard
 ├─ organization policy
 └─ custom Agent Skills

です。

Audit EngineとSecurity Knowledgeを疎結合にする。

この方が将来性があります。

⸻

かなり良いので残すべき仕様

Security Modelはかなり出来ています。

特に未信頼リポジトリについて、

* target-local AGENTS.md を命令として扱わない
* targetをCodex project rootにしない
* hostでtarget buildを走らせない
* target write禁止
* network default deny
* host credentials mount禁止
* Verifier arbitrary shell禁止

という原則が一貫しています。

これはこのPJの重要な思想なので、

Security Constitution

くらいの位置付けにしてもいいです。

⸻

Evaluation仕様も非常に良い

特にこの比較は残すべきです。

A. Semgrep only
B. CodeQL only
C. deterministic union
D. Codex only
E. Codex + deterministic evidence
F. + falsification
G. + independent verifier

これは研究的にも実務的にも価値があります。

最終的に、

AIを追加したことで
本当に何が増えたのか？

を測定できます。

中でも

Unique Finding Lift

verified findings not directly reported by baseline SAST

は、このシステムの価値を示す最重要KPIになり得ます。

⸻

私ならv1をここまで削ります

Target Repository
        │
        ▼
┌─────────────────┐
│ Target Mapper   │
└────────┬────────┘
         ▼
 Route / Auth / DB / Model inventory
         │
         ▼
┌─────────────────┐
│ Semgrep / SARIF │
└────────┬────────┘
         ▼
     Evidence
         │
         ▼
┌──────────────────────┐
│ Codex Investigator   │
│                      │
│ hypothesis           │
│ trace                │
│ counter-evidence     │
└──────────┬───────────┘
           ▼
 VerificationCase
           │
           ▼
┌──────────────────────┐
│ HTTP Verifier        │
└──────────┬───────────┘
           ▼
 PROVED / REJECTED
           │
           ▼
      Finding JSON
           │
           ▼
        Report

対象も最初は、

Next.js + PostgreSQL + HTTP Authorization

だけで構いません。

そして、

「SASTでは直接見つからなかった認可/tenant isolation脆弱性を、AIがEvidenceから発見し、独立Verifierで証明できる」

これを North Star にします。

これが1件でも再現性高く成立すれば、このPJはかなり面白いものになります。

⸻

仕様全体を一文で再定義すると

今の continuous-appsec は、

LLMを脆弱性判定器として使うのではなく、決定論的解析から得られた証拠を基にセキュリティ仮説を構築・反証し、独立した実行環境によって脆弱性を証明するEvidence-driven White-box Security Audit Engine

です。

この定義なら、今ある仕様がほぼ全部一本につながります。

そして個人的には、「Continuous AppSec」を作ろうとするより、このWhite-box Audit Engineに集中した方が、このリポジトリの独自性はずっと高いと思います。Continuous化は、このEngineが完成してからCI/PR/定期実行という外側のOrchestrationとして載せればよいです。
