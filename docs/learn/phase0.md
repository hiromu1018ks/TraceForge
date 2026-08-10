# Phase 0 学習ノート: プロジェクト基盤をつくる

> 対象読者: Rust と Cargo を使い始めたレベルの初学者。TraceForge の開発に参加したい人。

Phase 0 は、TraceForge のコードを1行も書かずに、**今後8つの Phase を通じて開発していくための土台**を整えるフェーズでした。このノートでは、Phase 0 で何を作り、なぜそれが必要なのかを、Rust・Cargo の基礎から解説します。

---

## 1. Cargo workspace: 1つのプロジェクトを複数の部品に分ける

### 何を作ったか

TraceForge は1つのプロジェクトですが、内部は **8個の crate**（Rust のコンパイル単位）に分割しました。

```
TraceForge/
  Cargo.toml              ← workspace 全体をまとめる親設定
  crates/
    core/                 ← データモデル・ID・時刻（Phase 1 で実装）
    evidence/             ← 証拠ファイルの読み込み（Phase 2）
    store/                ← Event の保存と Timeline（Phase 3）
    parsers/              ← 7 種のファイル形式 parser（Phase 4）
    engines/              ← 検知エンジン（Phase 5）
    findings/             ← 検知結果の統合（Phase 6）
    export/               ← 出力形式（Phase 7）
    cli/                  ← コマンドライン入口（Phase 7）
```

### なぜ分けるのか

もし全コードを1つの crate に詰め込むと:

- **コンパイルが遅くなる** — 1行変えるだけで全体を再コンパイル
- **責任が混ざる** — 「データ構造」「ファイル読み込み」「出力」がごちゃ混ぜ
- **再利用・テストが難しい** — 一部だけ取り出して使えない

crate に分けると、各部品が **明確な役割** を持ち、変更の影響を局所化できます。例えば「LNK parser を直すときは `parsers` crate だけ見ればよい」ようになります。

### workspace とは

複数の crate を1つのプロジェクトとして管理する仕組みです。ルートの `Cargo.toml` が:

```toml
[workspace]
members = ["crates/core", "crates/evidence", ...]
```

と宣言し、各 crate が `.workspace = true` で親の設定（Rust edition や version など）を継承します。これで共通設定を1箇所にまとめられます。

> **初学者のポイント**: `crates/core/Cargo.toml` の `version.workspace = true` は「親 workspace の version を使う」という意味です。各 crate に同じ version をコピペしなくて済みます。

---

## 2. rust-toolchain.toml と mise: Rust のバージョンを固定する

### 何を作ったか

```toml
# rust-toolchain.toml
[toolchain]
channel = "1.97.1"
profile = "minimal"
components = ["rustfmt", "clippy"]
```

と `.mise.toml` で、Rust 1.97.1 を使うよう固定しました。

### なぜ固定するのか

Rust は6週間ごとに新バージョンが出ます。もし「Aさんは Rust 1.95、Bさんは 1.97」だと:

- **再現性がなくなる** — Aさんの環境で動いたコードが Bさんで動かない
- **CI と手元で違う** — ローカルで通った test が CI で落ちる

TraceForge は**決定性**（同じ入力なら必ず同じ出力）を最重要視する forensics ツールです（規範 §13）。バージョンが違うと決定性が壊れる可能性があります。だから「全員が同じ Rust バージョンを使う」ことを強制します。

### `rust-toolchain.toml` と `.mise.toml` の違い

| ファイル | 役割 |
|---|---|
| `rust-toolchain.toml` | **rustup 標準**。CI（GitHub Actions）でもローカルでも、このファイルを読んで自動的にツールチェーンを選ぶ |
| `.mise.toml` | **mise 専用**。mise というバージョン管理ツールを使う人のための設定。rustup を使う人は無視してよい |

両方とも Rust 1.97.1 を指定しています。mise を使う開発者は `.mise.toml`、rustup 直接派は `rust-toolchain.toml` に従います。**どちらも同じバージョンに合わせる**ことが重要です（AGENTS.md 参照）。

### `profile = "minimal"` とは

Rust のツールチェーンには「profile」があり、`minimal` は最小構成（コンパイラ + cargo + 標準ライブラリ）です。そこに `components = ["rustfmt", "clippy"]` で、コードフォーマッタとリンタを追加しています。CI を速くするための工夫です。

---

## 3. CI（継続的インテグレーション）: 自動で品質を守る

### 何を作ったか

`.github/workflows/ci.yml` に、コードを push するたびに自動で走る **7個の検査ジョブ** を定義しました。

```
push / pull_request
        │
        ├─ fmt    : cargo fmt --all --check     （フォーマット確認）
        ├─ clippy : cargo clippy -- -D warnings （リンタ、警告はエラー）
        ├─ test   : cargo test                   （テスト実行）
        ├─ doc    : cargo doc --no-deps          （ドキュメント生成）
        ├─ deny   : cargo deny check             （依存の安全性）
        ├─ fuzz   : fuzz target のビルド確認
        └─ bench  : benchmark のビルド確認
```

### なぜ CI が必要か

人間はうっかりミスをします。「フォーマットを忘れた」「警告を出すコードを書いた」「テストを追加し忘れた」。これらを push のたびに機械的に検出すれば、品質が下がるのを防げます。

TraceForge は仕様が厳格（規範・互換・Schema の4仕様書）なので、**機械的に検証できるものは全て CI に任せる**方針です。

### 各ジョブの役割

- **fmt**: インデントやスペースが Rust の標準スタイルに合うか（`rustfmt`）
- **clippy**: Rust の「より良い書き方」を提案するリンタ。`-D warnings` で警告をエラー扱い
- **test**: 自動テストが通るか
- **doc**: ドキュメントコメント（`///` や `//!`）から HTML を生成できるか
- **deny**: 依存 crate のライセンス・セキュリティ問題をチェック
- **fuzz / bench**: 後述

> **初学者のポイント**: 「CI が緑（通る）」= 品質基準を満たしている、という安心感が得られます。Phase 0 の目標は「空実装でも CI が緑になること」でした。

---

## 4. cargo-deny: 依存関係を安全に保つ

### 何を作ったか

`deny.toml` で、4つの検査を設定しました。

| 検査 | 内容 |
|---|---|
| advisories | 既知のセキュリティ脆弱性（RustSec データベース）を持つ crate を弾く |
| licenses | 許可したライセンス（MIT, Apache-2.0 等）以外の crate を弾く |
| bans | 複数バージョンの混在や、不審なワイルドカード依存を警告 |
| sources | crates.io 以外からの依存を禁止（供給連鎖攻撃対策） |

### なぜ必要か

Rust の crate は、別の crate に依存し、それがまた別の crate に依存します（依存の依存の…）。これを手作業で全部確認するのは不可能です。

TraceForge は forensics ツールで、**依存のライセンスや脆弱性が結果の信頼性に関わる**ため（互換 §11）、機械的にチェックします。

> **初学者のポイント**: `cargo deny check` が通る = 「依存 crate に危険なものや、想定外のライセンスのものがない」という保証。Phase 0 では依存が少ない（criterion と libfuzzer-sys のみ）ので、未使用ライセンスの警告が出ますが、Phase 1 以降で依存が増えれば解消されます。

---

## 5. cargo-fuzz と criterion: 壊れないコード・速いコードを科学的に測る

### fuzz（ランダム入力で耐性を試す）

`fuzz/` ディレクトリに、libfuzzer を使った fuzz target の雏形を作りました。

```rust
// fuzz/fuzz_targets/core.rs
#![no_main]
use libfuzzer_sys::fuzz_target;

fuzz_target!(|_data: &[u8]| {
    // Phase 1 以降で、core の関数にランダムな _data を投げて
    // 「クラッシュしないか」を試す
});
```

forensics ツールは、**壊れた入力ファイル**を扱います。悪意のあるファイルでクラッシュしてはいけません（規範: 破損入力で panic しない）。fuzz は、ランダムなバイト列を入力として大量に投げ、クラッシュしないか自動検査します。

Phase 0 では「fuzz がビルドできる」ことだけ確認します。中身は Phase 1 以降で詰めます。

### criterion（処理速度を正確に測る）

`crates/core/benches/smoke.rs` に、criterion benchmark の雏形を作りました。

```rust
use criterion::{Criterion, black_box, criterion_group, criterion_main};

fn smoke_benchmark(c: &mut Criterion) {
    c.bench_function("smoke", |b| b.iter(|| black_box(1u32 + 1u32)));
}
```

criterion は、処理速度を統計的に正確に測る道具です。「前回より速くなったか遅くなったか」を検出できます。Phase 1 で ID 生成や JSON 処理を実装したら、それらの速度を benchmark に追加します。

> **初学者のポイント**: `black_box` は「コンパイラに最適化させない」ための関数です。`1 + 1` は定数なので、ふつうならコンパイル時に計算されて消えてしまいます。`black_box` で囲むと、実行時に必ず計算させられます。

### Windows での fuzz ビルドについて

libfuzzer（fuzz の心臓部）は本来 Linux/macOS 向けです。Windows ではリンク時にエラーが出ます（エントリポイントの問題）。これは**コードのバグではなく環境の制約**です。CI は Linux で走るので、link の確認は CI に任せます。手元（Windows）では `cargo check` で「コンパイルが通る」ことだけ確認します。

---

## 6. fixture 管理と収集計画: テスト用データを正しく扱う

### fixture とは

forensics ツールのテストには、**実際の証拠ファイル**（LNK ファイルや EVTX ログ等）が必要です。これを「fixture」と呼びます。

Phase 0 では2つの文書を作りました:

1. **`tests/fixtures/README.md`**（T0-012）— fixture の管理ルール
   - どこに置くか（`tests/fixtures/<種類>/<名前>/`）
   - 各 fixture に必ず `manifest.toml`（SHA-256・生成 OS・取得方法を記録）
   - センシティブデータは絶対にコミットしない

2. **`docs/traceforge_fixture_collection_plan_v1.0.md`**（T0-013）— 収集計画
   - Windows 7 / 10 / 11 の3世代で収集
   - 7種のファイル形式について、正常系と異常系を集める

### なぜ文書化だけなのか

実ファイルの収集には**実 Windows 環境**が必要です（VM を用意して操作して採取）。Phase 0 は「土台作り」が目的なので、収集計画を文書化するところまでにします。実収集は Phase 4（Parser 実装）で随時行います。

### 互換性仕様書 §12 との関係

「Supported（対応済み）」と名乗るには、互換 §12 の8条件を全部満たす必要があります。その第5条件が「fixture の SHA-256・生成 OS・取得方法・期待結果を記録する」です。`manifest.toml` はこの条件を満たすための仕組みです。

---

## 7. 検証結果: Phase 0 の完了条件

roadmap §5 が定める Phase 0 の完了条件:

- ✅ **空実装で CI（fmt / clippy / test / doc）が通る**
- ✅ **fuzz / bench 雏形が動作する**

実際に確認したこと:

| 確認項目 | 結果 |
|---|---|
| `cargo build --workspace` | 8 crate がコンパイル成功 |
| `cargo test` | 全 crate で test 実行（0 件、エラーなし）|
| `cargo fmt --all --check` | フォーマット準拠 |
| `cargo clippy --all-targets -- -D warnings` | 警告ゼロ |
| `cargo doc --no-deps` | ドキュメント生成成功 |
| `cargo bench --no-run` | criterion benchmark ビルド成功 |
| `cargo check --manifest-path fuzz/Cargo.toml` | fuzz target コンパイル成功 |
| `cargo deny check` | advisories / licenses / bans / sources 全て ok |

> Phase 0 は「中身が空でも、枠組みが正しく動くこと」が目標です。各 crate の `src/lib.rs` には、Phase 1 以降で何を実装するかをコメントで書いただけです。

---

## 8. 次のフェーズ（Phase 1）で何が始まるか

Phase 1 は **コアデータモデルと Schema** です。いよいよ `tf-core` crate に中身を書いていきます:

- **決定的 ID** — 同じ入力から必ず同じ ID を生成（UUID や乱数は禁止）
- **時刻モデル** — 不明な時刻を勝手に UTC にしない等、forensics ならではの厳しさ
- **Windows path** — `PathBuf` を使わず独自の `WindowsPathValue` で扱う
- **canonical JSON** — キー順を固定して、常にバイト単位で同じ出力になるようにする
- **Schema validator** — 出力が仕様を満たすか機械的に検証

これらは**全機能の土台**になるため、Phase 1 でしっかり固定します（roadmap §3.1: Schema-first）。

初学者の方へ: Phase 1 からは本格的な Rust コードが出てきます。`enum`、`struct`、`trait`、`BTreeMap` 等の基本文法に不安があれば、[The Rust Programming Language](https://doc.rust-lang.org/book/) の前半（1〜10章）を眺めてから取り組むとよいでしょう。TraceForge の各型は、仕様書（Schema §4〜§5）に Rust 構造体の例が載っているので、それを出発点にします。

---

## 9. まとめ: Phase 0 が終わって分かったこと

- **土台作りは地味だが重要** — バージョン固定・CI・依存管理を先にやると、後の Phase が安心して進められる
- **「空実装で通る CI」の価値** — 中身を書き始める前に枠組みが壊れていないことを確認できる
- **Windows と Linux の違い** — fuzz のリンク問題等、環境固有の制約を把握し、CI で補完する設計にした
- **文書化の意義** — fixture 管理方針・収集計画を先に書くことで、Phase 4 で迷わず収集できる

次は Phase 1 で、TraceForge の「心臓」であるデータモデルを設計します。
