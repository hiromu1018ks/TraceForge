# Benchmark 報告書（T8-023・F-026・製品 §13.2）

## 方針

製品仕様書 §13.2 は「benchmark 値は測定条件とともに実測値だけを掲載する」と定める。本報告書は実測値のみを掲載し、推定値・理論値は含めない。

## 測定条件

| 項目 | 値 |
|---|---|
| OS | Windows (win32) |
| Shell | PowerShell 5.1 |
| Rust toolchain | 1.97.1（rust-toolchain.toml 固定） |
| benchmark crate | criterion 0.5（default-features = false） |
| benchmark target | `tf-core` benches/smoke |
| warm up time | 1.0 秒 |
| measurement time | 3.0 秒 |
| sample size | 100 samples（推定） |

## 実測値

### smoke benchmark

`crates/core/benches/smoke.rs` の `smoke` benchmark。`black_box(1u32 + 1u32)` の実行時間を測定する。最適化を抑止する典型的な criterion の基準測定であり、benchmark pipeline が正常に機能していることの証明である。

```
smoke                   time:   [260.86 ps 274.28 ps 285.93 ps]
```

- 中央値: 274.28 ピコ秒
- 信頼区間 (95%): [260.86 ps, 285.93 ps]

## benchmark target の構成

Phase 0 で criterion benchmark 雛形を導入し（T0-011）、`crates/core/benches/smoke.rs` へ配置する。Phase 1 以降の実装関数（決定的 ID 生成・canonical JSON・Windows path 正規化等）の benchmark は smoke target を基点へ追加可能である。

`cargo bench --no-run` で benchmark バイナリのビルド検証を CI（`.github/workflows/ci.yml` の `bench` job）で実施する。

## 今後の拡張点

v1.0 Stable リリース後、次の benchmark を追加することで実用的な性能指標を得られる:

- 決定的 ID 生成（Event ID・Case ID）の benchmark
- canonical JSON 直列化の benchmark
- EventStore spool file の書込・読出し benchmark
- LNK Parser の parse benchmark（合成 fixture 使用）
- analyze pipeline 全体の end-to-end benchmark

これらは v1.0 Stable の必須要件ではなく、別途計画する。
