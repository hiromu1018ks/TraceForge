//! TraceForge Parser 群 crate。
//!
//! Phase 4 で 7 種 Parser を互換性仕様の acceptance 品質で実装する（roadmap §5 Phase 4）:
//! - Parser framework（[`framework`]・[`issue`]・[`sink`]、規範 §9）
//! - LNK（[`lnk`]、[MS-SHLLINK]、互換 §4.4）— M2 縦割りスライス対象
//! - Prefetch（[`prefetch`]、libyal PF format、互換 §4.1）— MAM 圧縮展開付き
//! - USN Journal（[`usn`]、Microsoft USN_RECORD_V2/V3/V4、互換 §4.3）— record-stream 型
//! - EVTX（[`evtx`]、libyal libevtx 仕様、互換 §4.2）— binxml decoder 付き record-stream 型
//! - Registry（[`registry`]、MS-RRMF / libyal libregf、互換 §4.7）— hive 構造 + LOG1/LOG2 dual view
//! - Amcache（[`amcache`]、MS-RRMF hive + Inventory schema、互換 §4.6）— Win10 22H2 / Win11 24H2
//! - Jump Lists（[`jump_lists`]、[MS-CFB] + [MS-DESTS] + 内包 [MS-SHLLINK]、互換 §4.5）—
//!   AutomaticDestinations / CustomDestinations・3 OS 世代対応
//!
//! ## 設計の要点
//!
//! - **sink 型 interface**: Parser は全 Event を `Vec` で返さず [`framework::ParseSink`] へ
//!   1件ずつ出力する（規範 §9.1・§21-6）。
//! - **panic 境界**: [`framework::run_parser_catching_panic`] が Parser 内の panic を捕捉し、
//!   Fatal issue + [`framework::ParseSummary::failed`] へ変換する（規範 §9.4）。
//! - **観測型 Event**: 観測していない行為を Event type で断定しない（規範 §7.1）。
//!   例えば LNK の timestamp は `lnk_timestamp`、Prefetch の実行痕跡は
//!   `prefetch_execution_observed`（観測）であり、`file_opened`・`process_start` 等の断定ではない。
//!   EVTX も汎用は `event_logged`（観測）とし、typed mapping は channel+provider+必須 field の
//!   同時検証を満たした場合のみ適用する（互換 §4.2）。Registry は `registry_observation`
//!   と `registry_key_last_write`（観測）とし、`registry_set` / `registry_delete` は生成しない
//!   （互換 §4.7）。
//! - **Amcache**: Amcache.hve への record の存在は観測であり process start へは断定しない。
//!   `amcache_observation`（観測）のみを生成する（互換 §4.6）。未知 schema は Warning で
//!   skip し、Generic Registry Parser への自動 fallback は行わない（互換 §4.6・§4.7）。
//! - **Jump Lists**: AutomaticDestinations は CFB container・DestList stream・内包 LNK から成る。
//!   CustomDestinations は独自形式 + 内包 LNK。本 Parser は
//!   `jump_list_observation`（観測）のみを生成し、target を「開いた」「起動した」と断定
//!   しない（互換 §4.5）。内包 LNK は物理 Evidence へ登録せず Jump List 内の ArtifactInstance
//!   として扱い、stream 名 + offset を Provenance へ保存する。未知 DestList version は
//!   Warning Issue へ記録し container 全体を誤解析しない（互換 §4.5）。
//! - **EventStoreSink**: [`sink::EventStoreSink`] が [`tf_store::EventStore`] への
//!   [`framework::ParseSink`] 適応を提供し、Parser → Event Store の縦割りを結ぶ。

pub mod amcache;
pub mod evtx;
pub mod framework;
pub mod issue;
pub mod jump_lists;
pub mod lnk;
pub mod prefetch;
pub mod registry;
pub mod sink;
pub mod usn;

// よく使う主要型をルートへ再公開。
pub use amcache::{
    AMCACHE_OBSERVATION_EVENT_TYPE, AMCACHE_REFERENCE, AmcacheParser,
    PARSER_ID as AMCACHE_PARSER_ID, PARSER_VERSION as AMCACHE_PARSER_VERSION,
};
pub use evtx::mapping::EVENT_LOGGED_TYPE as EVTX_EVENT_LOGGED_TYPE;
pub use evtx::{
    EVTX_REFERENCE, EvtxParser, PARSER_ID as EVTX_PARSER_ID, PARSER_VERSION as EVTX_PARSER_VERSION,
};
pub use framework::{
    ArtifactParser, ParseContext, ParseSink, ParseSummary, ReadSeek, SinkError,
    run_parser_catching_panic,
};
pub use jump_lists::{
    JUMP_LIST_OBSERVATION_EVENT_TYPE, JUMP_LIST_REFERENCE, JumpListParser,
    PARSER_ID as JUMP_LIST_PARSER_ID, PARSER_VERSION as JUMP_LIST_PARSER_VERSION,
};
pub use lnk::{LnkParser, PARSER_ID as LNK_PARSER_ID, PARSER_VERSION as LNK_PARSER_VERSION};
pub use prefetch::{
    PARSER_ID as PREFETCH_PARSER_ID, PARSER_VERSION as PREFETCH_PARSER_VERSION, PrefetchParser,
};
pub use registry::{
    HiveType, PARSER_ID as REGISTRY_PARSER_ID, PARSER_VERSION as REGISTRY_PARSER_VERSION,
    REGISTRY_KEY_LAST_WRITE_EVENT_TYPE, REGISTRY_OBSERVATION_EVENT_TYPE, REGISTRY_REFERENCE,
    RegistryParser,
};
pub use usn::{
    PARSER_ID as USN_PARSER_ID, PARSER_VERSION as USN_PARSER_VERSION,
    USN_CHANGE_OBSERVED_EVENT_TYPE, USN_REFERENCE, UsnParser,
};
