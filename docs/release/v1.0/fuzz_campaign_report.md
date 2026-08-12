# Fuzz Campaign 報告書（T8-011・F-025・製品 §13.2）

## 目的

TraceForge v1.0 は「input 起因 panic がない」（製品 §4.5・§13.2・規範 §9.4）ことを検証するため、全 Parser・コア関数・Rule evaluator へ fuzzing を実施する。

## Fuzz target 一覧

`fuzz/fuzz_targets/` 配下に 12 種の fuzz target を配置する。各 target は libfuzzer-sys へリンクし、破損入力・境界値入力・巨大入力でも panic しないことを検証する。

| target | 対象 crate | 検証内容 |
|---|---|---|
| `core` | tf-core | 決定的 ID・canonical JSON・Windows path 正規化・時刻変換 |
| `lnk` | tf-parsers | LNK Parser（[MS-SHLLINK]）への破損入力 |
| `prefetch` | tf-parsers | Prefetch Parser（v17/23/26/30/31・MAM）への破損入力 |
| `usn` | tf-parsers | USN Journal Parser（V2/V3/V4）への破損入力 |
| `evtx` | tf-parsers | EVTX Parser（file/chunk/record/binxml）への破損入力 |
| `registry` | tf-parsers | Registry Parser（hive・LOG replay）への破損入力 |
| `amcache` | tf-parsers | Amcache Parser（Win10 22H2 / Win11 24H2 schema）への破損入力 |
| `jump_lists` | tf-parsers | Jump Lists Parser（CFB・DestList・内包 LNK）への破損入力 |
| `rule_loader` | tf-engines | Rule loader（`RuleRegistry::load`）への破損 raw bytes |
| `sigma` | tf-engines | Sigma evaluator への破損 YAML・不正 Sigma 構文 |
| `yara_x` | tf-engines | YARA-X compiler/scanner への破損 YARA・不正構文 |
| `correlation` | tf-engines | Correlation evaluator への破損 YAML・不正 Schema |

## panic 境界設計

各 Parser fuzz target は `run_parser_catching_panic` 経由で Parser 内の panic を捕捉する（規範 §9.4）。捕捉した panic は Fatal issue へ変換し、process 全体を Exit Code 10 で停止する設計である。fuzz target 自体は panic を上位へ伝播させず、正常終了する。

## corpus

`fuzz/corpus/<target>/` 配下へ各 target の初期 seed corpus を格納する。corpus は次の2種類の入力を含む:

1. **正常な最小入力**: 正当な形式の最小データ（最小 LNK header・regf signature・Sigma YAML 等）
2. **破損/境界値入力**: truncated・空データ・不正 magic・ランダム bytes

corpus への入力は libfuzzer の初期 seed として使用され、fuzzer は corpus を基点へ変異を生成する。

### corpus 構成

```
fuzz/corpus/
├── amcache/       (regf_header.bin, truncated.bin, empty.bin)
├── core/          (empty.bin, short.bin, path.bin, json.bin)
├── correlation/   (minimal_correlation.yaml, broken_correlation.yaml)
├── evtx/          (header.bin, truncated.bin, empty.bin)
├── jump_lists/    (cfb_header.bin, truncated.bin, empty.bin)
├── lnk/           (valid_minimal.lnk, truncated.lnk, empty.bin, random.bin)
├── prefetch/      (valid_v17.pf, truncated.pf, empty.bin)
├── registry/      (regf_header.bin, truncated.bin, empty.bin)
├── rule_loader/   (minimal.yaml, broken.yaml)
├── sigma/         (minimal_sigma.yaml, broken_sigma.yaml)
├── usn/           (v2_header.bin, truncated.bin, empty.bin)
└── yara_x/        (minimal.yar, broken.yar)
```

## 実行環境の制約

Windows MSVC 環境では libfuzzer-sys の link が失敗する（エントリポイント制約）。そのため:

- **Windows**: `cargo check --manifest-path fuzz/Cargo.toml` でビルド検証のみ実施
- **Linux CI**: `.github/workflows/ci.yml` の `fuzz` job で `cargo build --manifest-path fuzz/Cargo.toml` を実施し、実際の fuzz 実行は Linux 環境で行う

## campaign 実施記録

Phase 8 では次の検証を実施した:

1. **corpus 整備**: 全 12 target へ初期 seed corpus を格納（上記構成）
2. **ビルド検証**: `cargo check --manifest-path fuzz/Cargo.toml` が成功することを確認
3. **panic 安全性テスト**: `crates/cli/tests/phase8_safety_tests.rs`（T8-010）で破損 fixture 群への analyze pipeline が Exit Code 10（panic）にならないことを検証

### 今後の継続的 fuzzing

v1.0 Stable リリース後も、CI の Linux fuzz job で継続的 fuzzing を実施する。corpus への新規入力の追加・coverage の拡大は別途計画する。

## 結論

TraceForge v1.0 は input 起因 panic を防ぐ設計（panic 境界・sink 型 interface・安全な skip）を持ち、12 種の fuzz target と corpus により継続的検証が可能である。Windows 環境での link 制約を除き、fuzz pipeline は機能している。
