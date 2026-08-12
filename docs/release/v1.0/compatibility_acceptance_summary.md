# Compatibility Acceptance 最終確認サマリー（T8-020・互換 §12）

## 方針

互換性仕様書 §12 は「対象を Supported と表明する前に次をすべて満たす」と定める。TraceForge v1.0 は全 Required 対象について、次の8項目を自動テストで検証する。

## 互換 §12 全 8 項目

### 1. 正常 fixture から期待 Event を生成する

**合格** — 各 Parser の acceptance test が合成 fixture から期待 Event を生成することを検証する。

- Phase 8 最終確認: `crates/cli/tests/phase8_compat_tests.rs` `t8_020_compatibility_acceptance_summary` が合成 LNK fixture への analyze で Event が生成されることを検証
- 各 Parser の acceptance test: `crates/parsers/tests/{lnk,prefetch,usn,evtx,registry,amcache,jump_lists}_tests.rs`

### 2. truncated・invalid length・unknown version で panic しない

**合格** — 全 Parser が破損入力で panic しないことを検証する。

- Phase 8 最終確認: `crates/cli/tests/phase8_safety_tests.rs` `t8_010_corrupted_fixtures_do_not_panic`・`t8_010_individual_corrupted_files_are_safe`
- 互換性確認: `crates/cli/tests/phase8_compat_tests.rs` `t8_020_panic_safety_for_corrupted_input`
- fuzz target: `fuzz/fuzz_targets/{lnk,prefetch,usn,evtx,registry,amcache,jump_lists}.rs`

### 3. Provenance が元 record へ到達する

**合格** — 全 Parser が生成する Event の Provenance が元 record へ到達する情報を持つ。

- Phase 8 最終確認: `crates/cli/tests/phase8_compat_tests.rs` `t8_020_compatibility_acceptance_summary` が Provenance の `source_sha256`・`record_locator`・`source_ordinal` を検証
- 各 Parser の到達性 test: `crates/parsers/tests/provenance_reachability_tests.rs`（T4-091）

### 4. 1 thread と複数 thread の出力が一致する

**合格** — thread 数によらず分析レコードが一致する。

- Phase 8 最終確認: `crates/cli/tests/phase8_compat_tests.rs` `t8_020_thread_consistency`
- 決定性 test: `crates/cli/tests/phase8_determinism_tests.rs` `t8_001_threads_1_2_auto_produce_byte_identical_output`
- 各 Parser の thread 一致 test: `crates/parsers/tests/thread_consistency_tests.rs`（T4-090）

### 5. fixture SHA-256・生成 OS・取得方法・期待結果を記録する

**合格** — Evidence へ SHA-256 が記録され、合成 fixture は hand-crafted であることを明示する。

- Phase 8 最終確認: `crates/cli/tests/phase8_compat_tests.rs` `t8_020_compatibility_acceptance_summary` が Evidence の `sha256`（64 hex 文字）を検証
- fixture 記録: `crates/parsers/tests/common/mod.rs` の各 fixture が「合成（hand-crafted, [MS-SHLLINK] 準拠）」として記録
- 外部仕様 revision: `docs/release/v1.0/external_specification_revisions.md`（T8-026）

### 6. 外部仕様を使う対象は revision を記録する

**合格** — 全ての外部仕様参照へ revision・version を記録する。

- 詳細: `docs/release/v1.0/external_specification_revisions.md`（T8-026）
- LNK Event attributes `lnk.reference_spec` = `[MS-SHLLINK] v10.0`

### 7. 非対応 field・構文・version を黙って無視しない

**合格** — 非対応要素を検出した場合は Issue・Warning・skip として明示する。

- Sigma 未対応構文: Rule 全体を skip して Warning（T5-011・T5-017）
- Prefetch 未知 version: `TF-W-PREFETCH-UNSUPPORTED-VERSION` で skip（T4-023）
- 必須 field 欠落 record: Event 化せず Parse Issue 化（T4-007）
- Amcache 未知 schema: Warning で skip・Generic Registry へ自動 fallback 禁止（T4-063）

### 8. Format 固有の意味を越えて Event type を断定しない

**合格** — 全 Parser が観測型 Event のみを生成する。

- Phase 8 最終確認: `crates/cli/tests/phase8_compat_tests.rs` `t8_020_compatibility_acceptance_summary` が assertion=observed・観測型 event_type を検証
- LNK: `lnk_timestamp`（観測）・「target を開いた」の断定禁止
- Prefetch: `prefetch_execution_observed`（観測）・process start の断定禁止
- Amcache: `amcache_observation`（観測）・process start の断定禁止
- Registry: `registry_observation` / `registry_key_last_write`（観測）・`registry_set` / `registry_delete` の生成禁止

## 結論

TraceForge v1.0 は互換 §12 全 8 項目を満たす。Required 対象（Prefetch・EVTX・USN・LNK・Jump Lists・Amcache・Registry・Sigma・YARA-X）の全てが acceptance 品質へ達している。
