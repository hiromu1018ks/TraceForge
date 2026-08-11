# Phase 5 YARA-X 編: ファイルパターンで不審な Evidence を検知する

## 1. このフェーズで何を作ったか

Phase 5 共通編（T5-001〜T5-003）で Rule file の読込基盤（`RuleRegistry`）を作り、Sigma 編（T5-010〜T5-017）でイベントログ評価エンジンを作りました。Phase 5 YARA-X 編（T5-020〜T5-027）では、3つ目の検知経路として **YARA-X ファイルパターンスキャンエンジン**を実装しました。

YARA はファイル内容のバイトパターンを記述するための業界標準の言語です。マルウェアの署名、不審な文字列の有無、ファイルヘッダの構造などをルールとして記述します。YARA-X は YARA の純 Rust 実装で、オリジナルの C 実装と99%互換性があります。TraceForge は YARA-X を使い、Evidence の中身（Verified Snapshot のバイト列）をスキャンして不審なパターンを検知します。

Sigma 編と YARA-X 編の違い:

| 観点 | Sigma | YARA-X |
|---|---|---|
| 評価対象 | Event（時系列ログ） | Evidence file のバイト内容 |
| ルール形式 | YAML | 独自の YARA 構文 |
| 実装方法 | 自前の evaluator | 外部 crate `yara-x` へ委譲 |
| Match 拡張 field | `logsource_mapping` | `matched_patterns` |

## 2. 新しく作ったファイル

### YARA-X engine（`crates/engines/src/yara/`）

4つのモジュールで構成されています:

- `mod.rs`: 公開 API の再エクスポート
- `compiler.rs`: Rule file を YARA-X の compiled Rules へ変換（T5-020・T5-021・T5-023）
- `scanner.rs`: Verified Snapshot bytes へのスキャンと mode 切替（T5-024・T5-025・T5-026・T5-027）
- `match.rs`: スキャン結果から Schema §5.7 の Match 型への変換（T5-022）

### Fuzz target（`fuzz/fuzz_targets/yara_x.rs`）

破損した YARA Rule や巨大な入力で panic しないことを継続的 fuzzing で検証します（F-025・規範 §9.4）。

### 統合テスト（`crates/engines/tests/yara_x_tests.rs`）

T5-020〜T5-027 の受け入れ条件を end-to-end で検証します。全18テスト。

## 3. 設計のポイント

### T5-020: YARA-X crate pin と Cargo.lock checksum

互換性仕様 §7 は「TraceForge release は使用する YARA-X crate の**完全 version** と Cargo.lock checksum を Manifest へ記録する。`latest` を互換性識別子として使用してはならない」と定めています。

ワークスペースの `Cargo.toml` で `yara-x = "1.19"` を指定し、`Cargo.lock` が完全 version（1.19.0）と checksum へ pin します。cargo-deny が再現性と供給連鎖安全を担保します。

実行時には `tf_engines::yara_x_engine_version()` が `yara_x::VERSION` 定数（例: `"1.19.0"`）を返します。Phase 7 の Manifest 生成時にこの値を記録します。

### T5-021: `.yar` / `.yara` file の読込

共通編の `RuleRegistry` が既に directory 再帰走査・raw bytes 1回読み込み・SHA-256 計算を実装済みです。YARA-X 編では、registry が読み込んだ `LoadedRuleFile` の `raw_bytes()` を yara-x の `Compiler::add_source` へ渡すだけです。これが規範 §14「同じ bytes を使う」の要件を満たします。

```rust
let source_bytes = loaded.raw_bytes();
let _ = compiler.add_source(source_bytes);
```

### T5-023: compile error 時の file 全体無効化

規範 §15.2 は「Rule compile error が1件でもある Rule file は、その file 全体を無効とする」と定めています。これを実現するため、**ファイル毎に独立した `Compiler` を構築**します。

```rust
for loaded in registry.iter() {
    let mut compiler = yara_x::Compiler::new();
    compiler.enable_includes(false);
    let _ = compiler.add_source(loaded.raw_bytes());

    let errors = compiler.errors();
    if !errors.is_empty() {
        // file 全体を無効化し、他 file は継続
        return Err(YaraCompileError { ... });
    }
    // 成功した file のみ ruleset へ追加
}
```

`enable_includes(false)` も重要です。YARA の `include` 文は解析ホストの file system へアクセスするため、規範 §14「Rule file は1回だけ読み込む」原則に違反します。本 engine は include を全て禁止します。

### T5-024: Verified Snapshot のみ scan

規範 §15.2 は「YARA-X は Verified Snapshot だけを scan する。scan 対象を実行、load、shell open してはならない」と定めています。

これを実現するため、`YaraScanner::scan` は **`&[u8]` のみ**を受け取り、file I/O を一切行いません。呼出側（Phase 7 CLI や Phase 6 Finding pipeline）が、`SnapshotOutcome.snapshot_path` から bytes を読み込み、`YaraEvidenceScanTarget` へ渡します。

```rust
pub struct YaraEvidenceScanTarget<'a> {
    pub evidence_id: String,
    pub snapshot_bytes: &'a [u8],  // ← file path ではなく bytes
}
```

### T5-025: 3つの scan mode

Schema §8.3 は `yara.mode` を `all / suspicious / explicit` の3種類定義します:

- **all**: 全 Verified Snapshot を scan
- **suspicious**: Finding / Correlation が参照する Evidence ID のみ scan
- **explicit**: 利用者が明示した Evidence ID のみ scan

`select_evidence_for_mode` 関数が mode に応じた Evidence 一覧を返します。

### T5-026: host path 推測 scan 禁止（§21-13）

規範 §21-13 は重要な受け入れ条件です:

> YARA-X suspicious mode が Evidence ID へ解決できない host path を scan しない。

Event 内の Windows path（例: `C:\Windows\System32\evil.exe`）を見つけた際、**その path を手掛かりにホストの file system から file を探して scan してはいけません**。 Evidence ID でのみ解決します。

実装としては、`select_evidence_for_mode` は Evidence ID list のみを受け付けます。Windows path 文字列は一切受け取りません。未解決の Evidence ID は Warning として記録し、推測で scan 対象を増やすことはありません。

### T5-027: `max_yara_scan_file_size_bytes`

Schema §8.2 の limit（既定 1 GiB）を scan 対象の byte 数へ適用します。上限を超える Evidence は skip し、規範 §18「上限を超えた結果を黙って切り捨てない」に従い `YaraScanSkip` 記録を残します。

```rust
let size = target.snapshot_bytes.len() as u64;
if size > self.max_scan_file_size_bytes {
    results.skipped.push(YaraScanSkip {
        evidence_id: target.evidence_id.clone(),
        code: "TF-W-LIMIT-MAX-YARA-SCAN-FILE-SIZE-BYTES".into(),
        message: format!("YARA scan size ({size}) が上限 ({limit}) を超えるため skip"),
    });
    continue;
}
```

### T5-022: tags / meta / namespace / matched pattern identifier

YARA-X が検知した Match から、Schema §5.7 の Match 型（`match_type=yara_x`）を構築します。YARA 固有の情報を `matched_patterns` 拡張 field へ保持します:

```json
{
  "rule": {
    "identifier": "suspicious_exe",
    "namespace": "default",
    "tags": ["attack.execution", "attack.t1059"],
    "metadata": { "author": "TraceForge", "severity": 5 }
  },
  "patterns": [
    { "identifier": "$a", "kind": "text" },
    { "identifier": "$b", "kind": "hex" }
  ]
}
```

## 4. 決定性（規範 §13）

YARA-X の `Rules` は `!Send` / `!Sync` であるため、thread をまたいだ共有ができません。本 engine は **single-thread** で動作します。並列化は Phase 7 の CLI 層で別途検討します。

決定的な出力順序を保証するため、次の3層で sort します:

1. **file 順**: `RuleRegistry` の SHA-256 昇順（共通編が既に実装）
2. **Evidence 順**: `evidence_id` の UTF-8 byte 昇順
3. **pattern 順**: `matched_patterns` 内の identifier を alphabetical sort

これにより、同じ Rule と同じ Evidence を与えれば、常に同じ Match ID・同じ JSON 出力が得られます（規範 §13.1）。

## 5. 依存関係の変化

### 追加した依存

- **`yara-x = "1.19"`**: workspace dependencies へ追加。default features（default-modules 含む）を有効化し、一般的な forensic YARA Rule との互換性を確保。

### cargo-deny の advisory 例外

`yara-x v1.19.0` の間接依存に起因する3つの advisory を例外登録しました（`deny.toml` の `[advisories] ignore`）:

| Advisory | 対象 | 理由 |
|---|---|---|
| RUSTSEC-2023-0071 | rsa 0.9.10 | Marvin Attack（network timing）。本プロジェクトは offline forensic tool で network exposure なし |
| RUSTSEC-2026-0222 | wasmtime 43.0.2 | 複数 engine 間の型混同。yara-x は単一 engine 使用のため影響なし。yara-x が wasmtime へ hard-pin しており個別 update 不可 |

新 version の yara-x で解消されたら例外から外します。

### ライセンス

`yara-x` 本体は BSD-3-Clause（既に deny.toml の許可リスト入り）。依存先も MIT / Apache-2.0 / BSD-3-Clause 等の許可ライセンス。`cargo deny check licenses` は追加許可なしで通過します。

## 6. テスト

### Unit test（`crates/engines/src/yara/*.rs`）

各モジュール毎に合計40テスト以上。コンパイル経路・scan 経路・mode 切替・決定性・panic 安全性を検証。

### 統合テスト（`crates/engines/tests/yara_x_tests.rs`）

T5-020〜T5-027 の受け入れ条件を end-to-end で検証する18テスト。

### Fuzz target（`fuzz/fuzz_targets/yara_x.rs`）

破損 YARA Rule で compile と scan の両経路を fuzzing し、panic しないことを継続的に検証（F-025）。

### ワークスペース全体

YARA-X 編追加後、ワークスペース全テストは **972件合格**（tf-engines 単体では lib 182 + acceptance 13 + sigma 25 + yara_x 18 = 238テスト）。

## 7. YARA-X Match が Finding へどう流れるか

Phase 6 の Finding 統合（T6-001〜）で次のように使われます:

```text
[YARA Rule file]                [Verified Snapshot bytes]
       │                                │
       ▼                                │
  RuleRegistry                          │
       │                                │
       ▼                                │
  YaraRuleset                           │
  ::compile_from_registry               │
       │                                │
       ▼                                ▼
  YaraScanner::scan(&[YaraEvidenceScanTarget { ... }])
       │
       ▼
  YaraScanResults { matches: Vec<YaraMatchResult>, ... }
       │
       ▼
  Vec<Match> (match_type=YaraX, matched_patterns=Some(...))
       │
       ▼
  Finding Merger（Phase 6 T6-001）
       │
       ▼
  Finding（複数の Sigma / YARA-X Match を統合）
```

## 8. 次のステップ

Phase 5 検知エンジンは **Sigma と YARA-X が揃いました**。残るは Correlation 編（T5-030〜T5-042）です。Correlation は複数 Event の時系列パターンを評価する経路で、Sigma・YARA-X とは独立して動作します。

Sigma と YARA-X は「単一 Event / 単一 Evidence」の検知ですが、Correlation は「複数 Event の組み合わせ」を検知します。例えば「同一ユーザーが5分以内に3回ログイン失敗した」「特定プロセスの起動直後に不審なネットワーク接続が発生した」等のパターンです。Correlation が揃えば Phase 5 は完了し、Phase 6 Finding 統合へ進めます。
