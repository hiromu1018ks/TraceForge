# PROMPT.md — 実装開始プロンプト（ひな形）

新しい実装セッションを開始するときに使うプロンプトの雛形。
下記コードブロックをそのままコピーして使用する。次フェーズ以降は「対象フェーズ・タスク」「成果物」「完了条件」を該当フェーズのものへ差し替える（差し替え元は `docs/traceforge_implementation_roadmap_v1.0.md` と `docs/traceforge_implementation_tasks_v1.0.md`）。

このファイルは **Phase 4 後半（Parser 群: EVTX）＝ 次回実装開始** 用に記入済み。
Phase 1（コアデータモデルと Schema）は完了済み（`tf-core` に決定的 ID・時刻・path・Schema validator・Config・Error 型を実装、122 テスト合格）。
Phase 2（Evidence パイプライン）は完了済み（`tf-evidence` に source_locator 正規化・決定的 discovery・snapshot + 同時 SHA-256・入出力分離・Artifact 識別 framework・resource limit framework を実装、79 テスト合格）。
Phase 3（Event Store と Timeline）は完了済み（`tf-store` に length-delimited spool file EventStore・Schema validation・Event ID 一意制約・commit marker・所有者限定 permission・決定的 iteration・external merge sort・Timeline 5 group 順序・filter / summary・最小 JSONL / Manifest 出力を実装、47 テスト合格）。
Phase 4 前半（Parser framework + LNK）は完了済み（`tf-parsers` に `ArtifactParser` / `ParseSink` / `ParseSummary`・panic 境界・sanitize Issue helper・`EventStoreSink`・LNK Parser（[MS-SHLLINK]・観測型 `lnk_timestamp` Event）・合成 fixture + acceptance test 8条件・M2 縦割り（LNK → EventStore → Timeline → Case JSON + Manifest）を実装、93 テスト合格）。
Phase 4 後半 Prefetch（T4-020〜T4-025）は完了済み（`tf-parsers` に Prefetch Parser（format version 17/23/26/30/31・MAM 圧縮展開（純 Rust XPRESS Huffman）・観測型 `prefetch_execution_observed` Event・未知 version の `TF-W-PREFETCH-UNSUPPORTED-VERSION` skip）・合成 Prefetch fixture ビルダ・literal-only MAM 圧縮ヘルパ・acceptance test 8条件（Prefetch 版）・Prefetch 縦割り（→ Case JSONL + Manifest）を実装、`tf-parsers` 全テスト 152 合格）。
Phase 4 後半 USN Journal（T4-030〜T4-037）は完了済み（`tf-parsers` に USN Journal Parser（USN_RECORD_COMMON_HEADER で V2/V3/V4 を判定・128-bit file reference 切詰めなし・rename OLD_NAME/NEW_NAME 結合（同一 reference + 近接 USN + 対応 reason の3条件）・同一 Evidence set 内のみの path reconstruction（host 検索禁止）・観測型 `usn_change_observed` Event・未知 MajorVersion の安全 skip + Warning・record-stream 型での部分成功（中間 record 破損は Issue 化し前後の正常 record から Event 生成））・合成 USN V2/V3/V4 fixture ビルダ・acceptance test 8条件（USN 版）・USN 縦割り（→ Case JSONL + Manifest）を実装、`tf-parsers` 全テスト 223 合格）。

Phase 4 後半は残り4種の Parser（EVTX / Registry / Amcache / Jump Lists）を順次実装する。次回は **EVTX（T4-040〜T4-046）** を実装することを推奨する。EVTX は USN に続く record-stream 型（chunk 内に複数 record）であり、binxml decoder と partial chunk recovery が新しい課題になる。互換 §4.2 は typed mapping（4624/4625/4688/4689/7045）で「Event ID だけで mapping せず channel・provider・必須 field を同時検証」を求めている点に注意。

```text
TraceForge の実装を開始します。以下の指示に従って Phase 4 後半（Parser 群: EVTX）を実装してください。

## 最初に読むもの（この順で）

1. AGENTS.md — 開発ワークフロー・仕様書の優先順位・禁止事項
2. docs/traceforge_implementation_roadmap_v1.0.md §5 Phase 4 — 範囲と完了条件
3. docs/traceforge_implementation_tasks_v1.0.md §7.5 — 対象タスク一覧（T4-040〜T4-046）
4. docs/traceforge_compatibility_v1.0.md §4.2 — EVTX 互換性要件（typed mapping・必須 fixture 含む）
5. docs/traceforge_compatibility_v1.0.md §12 — Parser acceptance test 基準
6. crates/parsers/src/framework.rs — Phase 4 前半で実装済みの Parser framework（再利用）
7. crates/parsers/src/usn/ — USN Parser の実装例（record-stream 型・部分成功・観測型 Event の参考）
8. crates/parsers/tests/common/mod.rs — 合成 fixture ビルダの拡張ポイント

## 対象フェーズ・タスク

- Phase 4 後半: Parser 群（EVTX を今回実装、残り3種は以降へ継承）
- タスク（今回）: T4-040 〜 T4-046（EVTX Parser）
- 今回は EVTX だけを実装すること。Registry 以降の3種へ踏み込まない。

## 成果物（tf-parsers crate の evtx/ へ集中）

- EVTX Parser（`.evtx` standalone file、互換 §4.2）:
  - file header / chunk / record 境界検証（T4-040）
  - binxml decoder 実装（T4-041）。純 Rust で新外部依存 crate を増やさない方針を優先
  - record ID・provider・channel・computer・Event ID・EventData/SystemData 保持（互換 §4.2・§5 必須 field）
  - typed mapping 5種（4624 / 4625 / 4688 / 4689 / 7045）。**Event ID だけで mapping してはならず**、channel + provider + 必須 field を同時検証する（互換 §4.2）
  - PowerShell Operational / Sysmon Operational 対応（channel + raw field 保持、対応 field mapping 適用）
  - partial chunk・bad checksum・truncated record の部分回復（境界を特定できる破損は前後の正常 record を保持、規範 §9.2・§21-5）
  - Legacy `.evt` は EVTX として解析しない（Unsupported、互換 §4.2）
  - Localized message rendering は Optional（resource DLL 無しでも raw XML/data を失わない）
- EVTX fixture + acceptance test（互換 §4.2・§12）
- Parser framework は Phase 4 前半のものを再利用（新 trait や新 sink は作らない）

## 制約・ルール

- 応答・ドキュメント・コード内コメントはすべて日本語
- 仕様書4文書（schemas / normative / compatibility / product）へ実装範囲・進捗を追記しない（製品 §15）
- 実装後は必ずセルフレビューし、問題があれば修正してから完了とする
- 既存の CI（fmt / clippy / test / doc / deny / fuzz / bench）が引き続き通ること
- Parser は全 Event を `Vec` で返してはならない（sink 型 interface、規範 §9.1）。Phase 4 前半の `ParseSink`・`EventStoreSink` を再利用
- EVTX は record-stream 型（chunk 内に複数 record）。中間 record / chunk の破損は Issue 化し、前後の正常 record から Event を生成し続ける（規範 §9.2・§21-5）。境界を特定できない破損だけ Partial 終了
- 観測していない行為を Event type で断定しない（規範 §7.1）。typed mapping で `login` / `process_start` 等の型名を使う場合でも、channel + provider + 必須 field を同時検証し、検証失敗時は汎用 Event へ戻す（断定禁止）
- 破損入力で panic しない。未対応形式・version を既知形式として推測しない
- 新たな外部依存 crate を追加しない（既存の chrono・serde_json・thiserror で足りる想定。追加が必要なら deny.toml と AGENTS.md へ反映すること）
- 完了時に次をすべて行う:
  1. docs/learn/ に Phase 4 後半（EVTX）の初学者向け解説 md を作成する（phase4d.md 等の別ファイル、phase4c.md の続編として）
  2. docs/traceforge_implementation_tasks_v1.0.md の該当タスク checkbox を [x] に更新する（タスク ID の再利用・欠番の詰め替えは禁止）
  3. 導入したコマンド・依存・lint 設定を AGENTS.md「コマンド」節へ追記する（EVTX で新依存を追加した場合のみ）
  4. 実装完了後（上記 1〜3 まで完了・ローカルで fmt / clippy / test / doc / deny が通ることを確認した段階）でコミットする。ユーザーへの個別確認は不要（本プロジェクトの既定、AGENTS.md 開発ワークフロー 5）。push はユーザーの明示要求時のみ。
  5. 次に取り組むべきフェーズ・タスクの提言と、次回そのまま使えるプロンプト（このファイルと同形式）を出力する

## 完了条件（roadmap §5 Phase 4 より）

- 正常 fixture から期待 Event を生成する（typed mapping 5種を含む）
- truncated・invalid length・unknown version・bad checksum で panic しない
- Provenance が元 record へ到達する
- 1 thread と複数 thread の出力が一致する
- EVTX のみで analyze → Case JSON + Manifest が生成される（Phase 4 前半の LNK・Prefetch・USN 縦割りと同じ経路で検証）
- partial chunk recovery（破損 chunk 前後の正常 record 保持）が検証できる
- Event ID 単独ではなく channel + provider + 必須 field の同時検証が検証できる
```

## 運用メモ

- 各セッションの完了時には、チャットへプロンプトを出力せず **本ファイルを次フェーズ用へ更新** する（AGENTS.md 開発ワークフロー 6）。更新した本ファイルは実装完了時のコミットへ含める。
- プロンプト本文へ仕様の細則をコピーしない。正本は常に docs/ の仕様書4文書とし、プロンプトは参照と範囲の指定に留める。
- Phase 1 の成果（`tf-core`）は Phase 4 以降も前提となる。Event・Provenance・RecordLocator 型、決定的 ID・時刻・path モデル、Schema validator、Config、Exit Code を再利用すること。
- Phase 2 の成果（`tf-evidence`）は Phase 4 以降も前提となる。EvidenceItem・snapshot・source_locator・probe framework・limit framework を再利用すること。
- Phase 3 の成果（`tf-store`）は Phase 4 以降も前提となる。EventStore・TimelineKey・SortedEventIter・最小 JSONL / Manifest 出力を再利用すること。Parser が生成した Event は ParseSink 経由で EventStore へ逐次保存する。
- Phase 4 前半の成果（`tf-parsers` の framework・sink・issue helper・LNK Parser）は Phase 4 後半以降も前提となる。`ArtifactParser` trait・`ParseSink` trait・`EventStoreSink`・`run_parser_catching_panic`・`sanitize_issue_message`・安定 Issue code 定数を再利用すること。各 Parser は `crates/parsers/src/<name>/` へ配置し、`lib.rs` へ公開する。合成 fixture は `tests/common/mod.rs` のヘルパーを拡張する方針。
- Phase 4 後半 Prefetch の成果（`tf-parsers` の Prefetch Parser・`prefetch/` 配下の header/fileinfo/metrics/volume/mam 各 module・XPRESS Huffman 展開器・合成 Prefetch fixture ビルダ・`make_artifact_with_source`・literal-only MAM 圧縮ヘルパ）は以降も前提となる。record-stream 型 Parser（USN・EVTX）では、Phase 4 前半の framework「部分成功」と Prefetch の観測型 Event 設計を参考にすること。
- Phase 4 後半 USN Journal の成果（`tf-parsers` の USN Parser・`usn/` 配下の header/record/reason/combine/path 各 module・合成 USN V2/V3/V4 fixture ビルダ・`filetime_to_datetime` 再利用）は以降も前提となる。EVTX でも record-stream 型（chunk 内複数 record）での部分成功・観測型 Event 設計を参考にすること。typed mapping では「Event ID だけでは断定せず channel + provider + 必須 field を同時検証」の規範（互換 §4.2）を厳守すること。
