# Phase 4 共通検証 学習ノート: 全 Parser の横断検証（T4-090〜T4-092）

> 対象読者: Phase 4 後半 Jump Lists Parser（phase4g.md）を読み終えた人。Rust で `trait` / `Result` / `enum` / `match` / 再帰関数を一通り書けるレベル。

Phase 4 後半はこれで全7種 Parser が実装できました（LNK / Prefetch / USN / EVTX / Registry / Amcache / Jump Lists）。本ノートは Phase 4 の最後、**全 Parser へ共通する品質保証**を追加する**共通検証**を解説します。各 Parser の個別実装は終わっているので、コードの変更はほとんどなく、**テストと fuzz target の追加**が中心です。これで Phase 4 が完全に完了し、マイルストーン M3（全 Parser 完成）へ到達します。

---

## 1. 共通検証とは何か・なぜ必要か

### 各 Parser 単体のテストだけでは足りない理由

Phase 4 後半の各フェーズでは、Parser 1種毎に acceptance test 8条件（互換 §12）を書いてきました。例えば LNK なら「正常 fixture から期待 Event を生成する」「truncated で panic しない」等を8つ検証しました。

しかし、これは「LNK Parser が LNK 形式へ対応できているか」を LNK 単体で見ているだけです。次のような**横断的な**問いにはまだ答えられていません:

- **本当に7種全部が同じ品質基準を満たしているか?**（ある Parser は `ByteRange` を使うが、別の Parser は `LogicalPath` を使う、という違いを含めて、どちらも「元 record へ到達できる」とはどういうことか）
- **複数 thread で同時に動かしても大丈夫か?**（`std::thread` で4並列に動かしたら、たまたま解析順が変わって結果が変わるような隠れた状態がないか）
- **乱雑な byte 列を投げても本当に panic しないか?**（各 Parser の acceptance test では「truncated・bad magic」程度しか試していないが、現実の破損 file はもっと奇妙な byte 列になり得る）

共通検証（T4-090〜T4-092）はこれら3つの問いに答えるためのテストを、**全 Parser へ一斉に**適用する作業です。

### 今回の成果物

| タスク | 成果物 | ファイル |
|---|---|---|
| T4-090 | thread 数 1/複数一致 test（互換 §12-4） | `crates/parsers/tests/thread_consistency_tests.rs`（新規）|
| T4-091 | Provenance 到達 test（互換 §12-3） | `crates/parsers/tests/provenance_reachability_tests.rs`（新規）|
| T4-092 | 全 Parser fuzz target（F-025） | `fuzz/fuzz_targets/{lnk,prefetch,usn,evtx,registry,amcache,jump_lists}.rs`（新規7件） |

実装（`crates/parsers/src/`）と framework（`framework.rs`・`sink.rs`）は**一切変更しません**。テストと fuzz target の追加だけです。

---

## 2. T4-090: thread 数 1/複数一致 test（決定性）

### 「決定的」とは

「決定的（deterministic）」とは、**同じ入力を与えれば、いつ・何度実行しても同じ出力が得られる**性質です（規範 §13）。フォレンジック分析では、この性質が極めて重要です:

- ある analyst が「この Event は notepad.exe の実行痕跡だ」と結論したとする
- 別の analyst が同じ Evidence を解析して違う結論になったら、再現性がない＝科学的でない

ところが、Rust の `HashMap` は反復順序がランダム（`RandomState`）です。もし Parser が内部で `HashMap` を使って Event を組み立てると、実行のたびに Event 順序が変わり、最終的な出力 file の byte 列まで変わってしまいます。これは「非決定的」であり、規範 §13.2 で禁止されています。

TraceForge はこれを防ぐため、全 Parser で次を徹底しています:

- **`BTreeMap<String, Value>`** を使う（`HashMap` ではなく、key が常に byte 順に整列する）
- **`EventStore` の iteration は timestamp group → Event ID 順**（規範 §10）

### テストの構成

`thread_consistency_tests.rs` は「1 thread で1回」「4 thread で同時」の3パターン（＋ もう1回 baseline）で同一 Parser を走らせ、**canonical JSON 文字列**が完全一致することを検証します:

```rust
// 1) 単一 thread 基準 run
let baseline = run_once(...);

// 2) N 並列 thread で同時実行。各 thread の結果が baseline へ一致すること。
let results: Vec<RunResult> = std::thread::scope(|scope| {
    let mut handles = Vec::new();
    for _ in 0..THREAD_COUNT {
        let handle = scope.spawn(move || run_once(...));
        handles.push(handle);
    }
    handles.into_iter().map(|h| h.join().unwrap()).collect()
});

// 3) 全 thread の canonical JSON が baseline と一致するか検証
for (i, result) in results.iter().enumerate() {
    assert_eq!(result.len(), baseline.len(), ...);
    for (a, b) in result.iter().zip(baseline.iter()) {
        assert_eq!(a, b, "canonical JSON が不一致");
    }
}
```

### なぜ `std::thread` なのか

外部 crate（`Rayon` 等）を使うと便利ですが、本プロジェクトでは「依存 crate を増やさない」方針（PROMPT.md 制約）を守るため、標準ライブラリの [`std::thread`] のみを使います。`std::thread::scope` は Rust 1.63 以降で使える、thread safe な scoped thread API です。

### Event ID の整列集合だけでは不十分

単純な「Event ID set が一致する」だけでは不十分です。同じ Event ID でも内容（attribute・message 等）が違う場合があるため、**canonical JSON 文字列全体**で比較します。これは規範 §13.3「canonical 出力の byte 一致」を直接検証することに相当します。

### なぜ `Box<dyn ArtifactParser>` なのか

テスト関数へ Parser を「ファクトリ関数」として渡すため、`Box<dyn Fn() -> Box<dyn ArtifactParser>>` という少し複雑な型を使います。これは各 Parser を同じ枠組みで扱うための工夫です:

```rust
assert_thread_consistency(
    "LNK",
    &bytes,
    "notepad.lnk",
    LNK_ID,
    LNK_VER,
    ArtifactSource::Lnk,
    || Box::new(LnkParser::new()),  // Parser を作る関数
);
```

クロージャ `|| Box::new(LnkParser::new())` が「Parser を作る関数」で、これを `thread::scope` の中で各 thread が呼び出します。

### Parser は Send + Sync

並列 thread へ Parser を渡すためには、Parser 型が `Send`（別 thread へ移動できる）と `Sync`（複数 thread から同時に参照できる）である必要があります。各 Parser は共有可変状態を持たない（`ArtifactParser::parse` は `&self` のみ）ので、自動的に `Send + Sync` になります。これをコンパイル時に保証するテストも追加しました:

```rust
#[test]
fn parser_implementations_are_send_and_sync() {
    fn assert_send<T: Send>() {}
    fn assert_sync<T: Sync>() {}
    assert_send::<LnkParser>();
    assert_sync::<LnkParser>();
    // ... 全 Parser で同じ
}
```

---

## 3. T4-091: Provenance 到達 test（traceability）

### 「到達できる」とは

Event には「この Event はどの Evidence のどの部分から来たか」を示す `Provenance` という field があります（Schema §5.5）。これには次の情報が含まれます:

- `evidence_id`: どの Evidence から
- `artifact_id`: どの Artifact（Parser 適用結果）から
- `source_locator`: 元 file の path（例: `Security.evtx`）
- `source_sha256`: snapshot の SHA-256（規範 §5.5）
- `parser_id` / `parser_version`: どの Parser が生成したか
- `record_locator`: 元 record の位置（**ここが重要**）
- `source_ordinal`: 同一 record からの何番目の Event か

`record_locator` は「元 record へ戻るための住所」です。Schema は5種類の `record_locator` を定義します:

| 型 | 意味 | 例 |
|---|---|---|
| `RecordId` | 記録 ID（文字列） | EVTX record ID = "5" |
| `ByteOffset` | 先頭からの byte 位置 | 1024 byte 目から |
| `ByteRange` | byte 範囲 `[start, end)` | `[0, 76)` = header 全体 |
| `LogicalPath` | 論理 path（stream 名等） | `["DestList"]` |
| `SourceOrdinal` | 「分かるのは順序だけ」（最弱） | 3番目 |

互換 §12-3「Provenance が元 record へ到達する」は、**この住所が実際に意味のある位置を指していること**を要求します。例えば `ByteRange { start: 0, end: 76 }` と書いてあっても、snapshot file が 50 byte しかなければ、その範囲は存在しません（「到達できない」）。

### 既存 acceptance test の限界

各 Parser の acceptance test では `record_locator` の型だけを確認していました:

```rust
assert!(matches!(prov.record_locator, RecordLocator::ByteRange { .. }));
```

これは「`ByteRange` 型であること」は検証しますが、「start < end」「end が snapshot size 以内」「実際に bytes が読める」は検証しません。T4-091 はこれらを**全 Parser で網羅的**に検証します。

### テストが検証すること

`provenance_reachability_tests.rs` は次を検証します:

1. **Provenance 全 field が context の値へ一致**（`evidence_id` / `artifact_id` / `source_locator` / `source_sha256` / `parser_id` / `parser_version`）
2. **`ByteRange { start, end }`** が `start < end <= snapshot.len()` を満たす
3. **`ByteRange` が指す bytes** が実際に snapshot から読めて、空でない
4. **`LogicalPath(parts)`** の各要素が非空文字列
5. **`ByteOffset(off)`** が `off < snapshot.len()`
6. **`RecordId(id)`** の `id` が非空
7. **EventStore 経由でも同一 Provenance**（Parser → sink → EventStore → iter の経路で情報が欠落しないこと）

特に 2・3 は「ByteRange が物理的に snapshot bytes へ到達できること」の直接検証です。これにより「Parser が適当な値を `ByteRange` へ入れても通る」ような抜け道を防ぎます。

### 全 Parser の record_locator 型

7種 Parser が生成する Event の `record_locator` は、本 test で次の通り確認できます:

| Parser | 主な `record_locator` 型 | 意味 |
|---|---|---|
| LNK | `ByteRange { 0, 76 }` | header 全体 |
| Prefetch | `ByteRange` | run time FILETIME の位置 |
| USN | `ByteRange` | USN record 先頭からの範囲 |
| EVTX | `ByteRange` | record の byte 範囲 |
| Registry | `ByteRange` | cell の byte 範囲 |
| Amcache | `ByteRange` | cell の byte 範囲 |
| Jump Lists | `LogicalPath` / `ByteRange` | stream 名（`"DestList"`・`"1"` 等）|

Jump Lists は CFB container 内の「stream」という論理的な単位で管理するため `LogicalPath` になります。それ以外は byte 範囲で直接指せます。

---

## 4. T4-092: 全 Parser fuzz target（F-025）

### fuzz とは

fuzz test（fuzzing）は、**ランダムな byte 列**を関数へ大量に投げて、panic や異常動作を引き起こさないかを調べるテスト手法です。libFuzzer（C/C++ 用）や cargo-fuzz（Rust 用）が代表的なツールです。

通常の unit test は「こういう入力ならこういう出力になるはず」を検証しますが、fuzz は「どういう入力でも panic しないはず」を検証します。これは特にバイナリフォーマットを解析する Parser で威力を発揮します。実世界の破損 file や悪意のある file は、プログラマが想定もしない奇妙な byte 列になります。

### なぜ全 Parser に fuzz target が必要か

各 Parser の acceptance test（互換 §12-2）は「truncated」「invalid magic」「unknown version」等の**人間が想定した破損**を試します。しかし、現実の破損パターンは無限にあります:

- FAT chain が途中で自己参照する（無限ループ）
- size field が `u32::MAX` を宣言する（過大メモリ確保）
- UTF-16 文字列が surrogate pair の途中で切れる
- binxml の substitution 配列が template より長い
-...

これらを人間が全部リストアップするのは不可能です。fuzz は**機械的に探索**してくれます。1時間動かして数百万 case を試すと、プログラマが想像もしなかった入力で panic が起きることがあります。

### cargo-fuzz の構成

TraceForge の fuzz crate は `fuzz/` ディレクトリへ独立 workspace として置かれています:

```text
fuzz/
├── Cargo.toml          # libfuzzer-sys への依存・各 [[bin]] の宣言
├── fuzz_targets/
│   ├── core.rs         # tf-core の fuzz target（Phase 0 雛形）
│   ├── lnk.rs          # LNK Parser（T4-092 で追加）
│   ├── prefetch.rs     # Prefetch Parser（T4-092 で追加）
│   ├── usn.rs          # USN Parser（T4-092 で追加）
│   ├── evtx.rs         # EVTX Parser（T4-092 で追加）
│   ├── registry.rs     # Registry Parser（T4-092 で追加）
│   ├── amcache.rs      # Amcache Parser（T4-092 で追加）
│   └── jump_lists.rs   # Jump Lists Parser（T4-092 で追加）
└── target/             # ビルド成果物
```

### fuzz target のコード

各 fuzz target は50行程度のシンプルなコードです。例えば LNK 版:

```rust
#![no_main]  // 通常の main 関数ではなく、libFuzzer へ制御を渡す

use std::io::Cursor;
use libfuzzer_sys::fuzz_target;
use tf_parsers::framework::{ParseContext, ParseSink, ReadSeek, SinkError, run_parser_catching_panic};
use tf_parsers::lnk::{LnkParser, PARSER_ID, PARSER_VERSION};

// Event・Issue を全て捨てる sink（fuzz では panic しないことだけを見る）
struct NullSink;
impl ParseSink for NullSink {
    fn emit_event(&mut self, _event: tf_core::event::Event) -> Result<(), SinkError> { Ok(()) }
    fn emit_issue(&mut self, _issue: tf_core::issue::Issue) -> Result<(), SinkError> { Ok(()) }
}

fuzz_target!(|data: &[u8]| {
    // 決定的 ID 生成（規範 §12）のため、size から evidence_id を決める
    let context = make_context(data.len() as u64);
    let parser = LnkParser::new();
    let mut cursor = Cursor::new(data);
    let mut sink = NullSink;
    let _ = run_parser_catching_panic(&parser, &mut cursor as &mut dyn ReadSeek, &context, &mut sink);
});
```

重要なのは [`run_parser_catching_panic`] を経由することです。これは Parser 内部で万が一 panic が起きても、`catch_unwind` で捕捉して Fatal Issue へ変換する最終安全網です（規範 §9.4）。fuzz target はこれを経由するため、Parser に不具合があっても fuzz プロセス自体は落ちません。

### Windows MSVC では link できない

libfuzzer-sys は C 言語の libFuzzer library へリンクしますが、Windows MSVC 環境では link に失敗します（libFuzzer のエントリポイント制約）。そのため本プロジェクトでは:

- **Windows 開発時**: `cargo check --manifest-path fuzz/Cargo.toml` で**ビルドできること**だけを検証
- **Linux CI**: 実際に `cargo build --manifest-path fuzz/Cargo.toml` でビルド、将来的には `cargo fuzz run` で長時間実行

これが AGENTS.md の「fuzz target の link は Windows MSVC 環境で失敗するため、Linux CI で担保する」の意味です。

### 決定的 ID 生成を守る

fuzz target でも規範 §12「ID は決定的生成のみ」を守る必要があります。`uuid::Uuid::new_v4()` や `SystemTime::now()` のような乱数・時刻由来の ID は禁止です。fuzz target では固定 SHA-256（`"0".repeat(64)`）を使い、size から `id::evidence_id` で決定的に生成します。これは fuzz では Provenance の中身の正確性までは検証せず「panic しないこと」だけを見るためです。

---

## 5. 今回追加したテストの内訳

### `thread_consistency_tests.rs`（9テスト）

| テスト | 検証内容 |
|---|---|
| `parser_implementations_are_send_and_sync` | 全 Parser 型が Send + Sync（コンパイル時検証）|
| `lnk_thread_consistency` | LNK を1/4 thread で実行し一致 |
| `prefetch_thread_consistency` | Prefetch を1/4 thread で実行し一致 |
| `usn_thread_consistency` | USN を1/4 thread で実行し一致 |
| `evtx_thread_consistency` | EVTX を1/4 thread で実行し一致 |
| `registry_thread_consistency` | Registry を1/4 thread で実行し一致 |
| `amcache_thread_consistency` | Amcache を1/4 thread で実行し一致 |
| `jump_lists_thread_consistency` | Jump Lists を1/4 thread で実行し一致 |
| `all_parsers_emit_btremap_sorted_attributes` | attribute key が byte 順（規範 §13.2）|
| `multiple_parsers_in_sequence_remain_deterministic` | 複数 Parser を連続実行しても決定的 |

### `provenance_reachability_tests.rs`（10テスト）

| テスト | 検証内容 |
|---|---|
| `lnk_provenance_reachability` | LNK の全 Event の Provenance が元 record へ到達 |
| `prefetch_provenance_reachability` | 同上（Prefetch）|
| `usn_provenance_reachability` | 同上（USN）|
| `evtx_provenance_reachability` | 同上（EVTX）|
| `registry_provenance_reachability` | 同上（Registry）|
| `amcache_provenance_reachability` | 同上（Amcache）|
| `jump_lists_provenance_reachability` | 同上（Jump Lists）|
| `source_ordinals_are_consistent_across_runs` | `source_ordinal` が run 間で一貫 |
| `source_sha256_matches_snapshot_actual_hash` | `source_sha256` が snapshot の実際の SHA-256 へ一致 |

各 Parser のテストでは `assert_full_provenance_reachability` ヘルパーを呼び、7種類の検証（field 一致・ByteRange 妥当性・LogicalPath 妥当性・ByteOffset 範囲・RecordId 非空・EventStore 経由で同一）をまとめて実行します。

### fuzz target（7ファイル）

各 Parser につき1つの fuzz target binary。`NullSink` + `run_parser_catching_panic` の組合せで、破損入力で panic しないことを検証します。

---

## 6. なぜ実装を変更しないのか

PROMPT.md の制約:

> Parser framework・各 Parser の実装は変更しない（test と fuzz target の追加のみ）。

これは重要な方針です。各 Parser は Phase 4 の各フェーズで acceptance test（互換 §12 全8項目）を通過して本 commit 済みです。共通検証は「実装が悪かったから直す」のではなく「実装が本当に堅牢かを横断的に再確認する」作業です。

実際、本作業で実装コード（`crates/parsers/src/`）は1行も変更していません。これは Phase 4 全フェーズで積み上げてきた設計が**最初から横断検証に耐える**ことを示しています。各 Parser が `BTreeMap` を使い、`ByteRange` の `start < end` を保証し、sink 型 interface（`ParseSink`）で状態を持たない、という各フェーズでの選択が、共通検証で改めて正しかったと確認できました。

---

## 7. 品質ゲートの最終確認

Phase 4 共通検証の完了に当たり、AGENTS.md「コマンド」の全ての品質ゲートが通ることを確認します:

| 操作 | 結果 |
|---|---|
| `cargo fmt --all --check` | ✅ |
| `cargo fmt --manifest-path fuzz/Cargo.toml --check` | ✅ |
| `cargo clippy --all-targets -- -D warnings` | ✅ |
| `cargo test` | ✅（484 テスト合格・Phase 4 開始時 465 → +19）|
| `cargo doc --no-deps` | ✅ |
| `cargo deny check`（advisories/bans/licenses/sources）| ✅ |
| `cargo build --workspace` | ✅ |
| `cargo check --manifest-path fuzz/Cargo.toml` | ✅ |
| `cargo bench --no-run` | ✅ |

fuzz crate へ `tf-parsers = { path = "../crates/parsers" }` への依存を追加しましたが、cargo-deny は workspace の `Cargo.lock` を見るため、`fuzz/Cargo.lock` への影響は別途管理されます（fuzz は独立 workspace のため）。

---

## 8. マイルストーン M3 到達

Phase 4 共通検証の完了により、**マイルストーン M3（全 Parser 完成）** へ到達しました（roadmap §6）:

> | M3 | 全 Parser 完成 | 7 Parser が acceptance test 合格 | 4 |

M3 は「7 Parser が互換性仕様 §12 の acceptance test 全8項目に合格すること」が条件です。Phase 4 後半で7種 Parser を実装し、本共通検証で thread 一致性・Provenance 到達性・fuzz 対応を横断的に保証しました。これで TraceForge は Windows の主要な forensic artifact（LNK / Prefetch / USN / EVTX / Registry / Amcache / Jump Lists）をすべて解析できることになります。

---

## 9. 次のステップ（Phase 5）

Phase 4 が完了したので、次は **Phase 5: 検知エンジン** です。roadmap §5 では Sigma subset・YARA-X・Correlation の3経路の検知を実装します。Phase 4 で作った Event 群を入力として、ルールベース検知を行います。

Phase 5 の最初のタスクは T5-001〜T5-003（Rule file の取扱・決定性・validation error 処理）です。これらは Sigma・YARA-X・Correlation 全てへ共通する基盤です。次は T5-001 から Phase 5 を始めます。

---

## 10. まとめ: Phase 4 を終えて

Phase 4 は TraceForge で最も長いフェーズでした（前半 + 後半7種 + 共通検証）。ここまでで:

- **Parser framework**（`ArtifactParser` trait・`ParseSink`・panic 境界）が堅牢であることを確認
- **7種 Parser** がすべて互換 §12 acceptance test 8項目へ合格
- **決定的出力**（規範 §13）を thread 間・run 間で保証
- **Provenance 到達性**（互換 §12-3）を物理的な byte 範囲まで検証
- **fuzz 対応**（F-025）で未知の破損入力へも備える

特に Phase 4 を通じて「観測型 Event」の方針（規範 §7.1）を一貫して守ったことが重要です。LNK timestamp・Prefetch 実行痕跡・USN 変更・Registry value は全て「観測」であり、「実行した」「削除した」等の断定ではありません。これにより TraceForge の Event は科学的に慎重な表現を保ちます。

次の Phase 5 では、これらの観測 Event を入力として検知ルールを評価し、Finding（脅威判定）を生成します。
