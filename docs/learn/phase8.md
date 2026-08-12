# Phase 8: 品質保証とリリース（初学者向け解説）

## このフェーズの目的

TraceForge は Phase 0〜7 で全機能を実装した。Phase 8 は「品質保証とリリース」であり、製品として v1.0 Stable（M6）へ到達するための最終確認を行う。

新機能は追加しない。代わりに、これまでに作った機能が本当に品質基準を満たしているかを検証し、リリース記録を残す。

## 品質保証とは何か

ソフトウェアの「品質」とは、「仕様通りに動くこと」「壊れにくいこと」「再現可能であること」の3つに分けられる。Phase 8 はこれらを自動テストで検証する。

### 1. 決定性・再現性（規範 §13）

「決定性」とは「同じ入力から常に同じ結果が得られること」である。TraceForge では、同じ Evidence・同じ設定・同じ Rule から、いつでも同じ分析結果が得られなければならない。

なぜこれが重要か。フォレンジック調査では、分析結果が法廷や監査で証拠として使われる。もし実行するたびに結果が変わったら、「この分析は正しいのか？」と疑われる。

#### 決定性を保証する仕組み

- **決定的 ID**（規範 §12）: UUID や乱数を使わず、SHA-256 hash で ID を生成する。同じ入力からは常に同じ ID になる。
- **BTreeMap**（規範 §13.2）: 順序付き map を使うことで、hash table の iteration 順に依存しない。
- **明示 sort**（規範 §13.2）: 出力前に必ず sort する。構築順序に出力が依存しない。
- **run metadata 分離**（規範 §13.1）: 実行時刻等の「その実行でしか変わらない値」を分析レコードから分離する。

#### T8-001: golden determinism test

threads 1・threads 2・自動 thread 数で同じ fixture を解析し、出力が byte 単位で一致することを検証する。これが「thread 数に依存しない決定性」の証明になる。

実装: `crates/cli/tests/phase8_determinism_tests.rs`

### 2. 耐性・安全性（製品 §4.5・§13.2）

「耐性」とは「壊れた入力でもクラッシュしないこと」である。フォレンジック調査では、部分的に壊れたファイルや、マルウェアが意図的に壊したファイルを扱うことがある。TraceForge はこれらで停止してはならない。

#### 耐性を保証する仕組み

- **panic 境界**（規範 §9.4）: Parser 内の panic を捕捉し、Fatal issue へ変換する。
- **sink 型 interface**（規範 §9.1）: 全 Event を一度に `Vec` で保持しない。メモリを使い切らない。
- **安全な skip**（規範 §9.2）: 壊れた record は skip し、正常な record の解析を継続する。

#### T8-010: 破損 fixture 群での panic 非発生

様々な破損パターンのファイル（truncated・巨大 header size・不正 CLSID・空ファイル・ランダム bytes）を含む directory を解析し、Exit Code 10（panic）にならないことを検証する。

#### T8-013: resource limit 到達

max_files 等の上限へ到達した場合、安全に停止し、Manifest の `complete` を `false` にする。これを「黙って切り捨てない」と呼ぶ（規範 §18）。

#### T8-015: path traversal 対策

入力 directory 配下への出力を拒否する。これにより、悪意のある入力が解析結果で重要なファイルを上書きするのを防ぐ（規範 §5.4）。

### 3. 互換性・リリース（互換 §11・§12）

「互換性」とは「対応していると宣言した機能が、本当に仕様通りに動くこと」である。TraceForge は「この形式へ対応している」と宣言する前に、必須テストを全て通さなければならない（互換 §12）。

#### T8-020: compatibility acceptance 8 項目

互換 §12 は8項目の必須テストを定める:

1. 正常 fixture から期待 Event を生成する
2. 破損入力で panic しない
3. Provenance が元 record へ到達する
4. thread 数によらず出力が一致する
5. fixture の SHA-256・生成方法を記録する
6. 外部仕様の revision を記録する
7. 非対応要素を黙って無視しない
8. Event type で観測していない行為を断定しない

#### T8-022: Schema validator での Golden output 検証

analyze 出力の全 JSONL 行が Schema version 1.0.0 へ適合することを検証する。これで「出力が仕様通りの形式であること」を保証する。

## Fuzzing とは（T8-011・F-025）

「Fuzzing」とは、ランダムな入力を大量にプログラムへ投げて、クラッシュしないかを調べるテスト手法である。

TraceForge は libfuzzer（libfuzzer-sys crate）を使い、12 種の fuzz target を用意する:

- 各 Parser（LNK・Prefetch・USN・EVTX・Registry・Amcache・Jump Lists）
- コア関数（決定的 ID・canonical JSON・Windows path）
- Rule evaluator（Sigma・YARA-X・Correlation）

各 fuzz target は `run_parser_catching_panic` 経由で panic を捕捉するため、破損入力でも安全に終了する。

### corpus とは

fuzzer は完全にランダムな入力から始めると、なかなか意味のある入力へ到達しない。そこで、「seed」となる入力をあらかじめ用意する。これを「corpus」と呼ぶ。

TraceForge は `fuzz/corpus/<target>/` 配下へ各 target の初期 seed を格納する。corpus には「正常な最小入力」と「破損/境界値入力」の両方を含める。

Windows MSVC 環境では libfuzzer の link が失敗するため、実際の fuzz 実行は Linux CI で行う。Windows では `cargo check --manifest-path fuzz/Cargo.toml` でビルド検証のみ実施する。

## Release Gate とは（T8-027・roadmap §8）

「Release Gate」とは、v1.0 Stable としてリリースする前に満たさなければならない条件のチェックリストである。roadmap §8 が次を定める:

- 対応対象が互換性仕様書で明示されている
- Schema validation が成功する
- thread 数によらず分析レコードが byte 一致する
- 破損 fixture と fuzz corpus で panic がない
- Parser issue・limit 到達・skip が Manifest へ残る
- README の例が実際の fixture から生成されている
- benchmark 値が測定条件付きで実測値として掲載される

これらが全て合格してはじめて「v1.0 Stable（M6）」へ到達する。

## README 例の自動生成（T8-024）

製品仕様書 §13.2 は「README 等の例が実際の fixture から生成されている」ことを求める。手書きの例は「実際の動作と違う」可能性があるため、使ってはならない。

TraceForge は `docs/examples/generate_examples.ps1` スクリプトで合成 LNK fixture への解析を実行し、各形式（JSONL・JSON・Text・CSV・Timesketch）の出力を自動生成する。

## このフェーズで何を学べるか

Phase 8 は「コードを書く」フェーズではなく、「コードが正しいことを証明する」フェーズである。ソフトウェア工学において、品質保証（QA）は実装と同じくらい重要である。特にフォレンジックツールでは、分析結果の信頼性が調査全体の信頼性へ直結する。

重要な教訓:

1. **決定性は設計で作る**: 後から決定性を追加するのは難しい。最初から BTreeMap・明示 sort・決定的 ID を使う。
2. **壊れた入力を前提とする**: 全ての入力は信頼できない。panic しない・過大 allocation しない・path traversal を防ぐ。
3. **例は自動生成する**: 手書きの例は古くなる。実際の出力から生成すれば、常に最新かつ正確である。
4. **リリース条件を明文化する**: 「いつ完成か」を主観で判断しない。チェックリストで客観的に判断する。
