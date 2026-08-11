//! TraceForge Parser 群 crate。
//!
//! Phase 4 で 7 種 Parser を互換性仕様の acceptance 品質で実装する（roadmap §5 Phase 4）:
//! - Parser framework（[`framework`]・[`issue`]・[`sink`]、規範 §9）
//! - LNK（[`lnk`]、[MS-SHLLINK]、互換 §4.4）— M2 縦割りスライス対象
//! - Prefetch（[`prefetch`]、libyal PF format、互換 §4.1）— MAM 圧縮展開付き
//! - USN Journal（[`usn`]、Microsoft USN_RECORD_V2/V3/V4、互換 §4.3）— record-stream 型
//! - EVTX（[`evtx`]、libyal libevtx 仕様、互換 §4.2）— binxml decoder 付き record-stream 型
//! - Registry（[`registry`]、MS-RRMF / libyal libregf、互換 §4.7）— hive 構造 + LOG1/LOG2 dual view
//! - 残り2種（Amcache / Jump Lists）は順次追加
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
//! - **EventStoreSink**: [`sink::EventStoreSink`] が [`tf_store::EventStore`] への
//!   [`framework::ParseSink`] 適応を提供し、Parser → Event Store の縦割りを結ぶ。

pub mod evtx;
pub mod framework;
pub mod issue;
pub mod lnk;
pub mod prefetch;
pub mod registry;
pub mod sink;
pub mod usn;

// よく使う主要型をルートへ再公開。
pub use evtx::mapping::EVENT_LOGGED_TYPE as EVTX_EVENT_LOGGED_TYPE;
pub use evtx::{
    EVTX_REFERENCE, EvtxParser, PARSER_ID as EVTX_PARSER_ID, PARSER_VERSION as EVTX_PARSER_VERSION,
};
pub use framework::{
    ArtifactParser, ParseContext, ParseSink, ParseSummary, ReadSeek, SinkError,
    run_parser_catching_panic,
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
