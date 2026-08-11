//! TraceForge Parser 群 crate。
//!
//! Phase 4 で 7 種 Parser を互換性仕様の acceptance 品質で実装する（roadmap §5 Phase 4）:
//! - Parser framework（[`framework`]・[`issue`]・[`sink`]、規範 §9）
//! - LNK（[`lnk`]、[MS-SHLLINK]、互換 §4.4）— M2 縦割りスライス対象
//! - Prefetch（[`prefetch`]、libyal PF format、互換 §4.1）— MAM 圧縮展開付き
//! - 残り5種（USN / EVTX / Registry / Amcache / Jump Lists）は順次追加
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
//! - **EventStoreSink**: [`sink::EventStoreSink`] が [`tf_store::EventStore`] への
//!   [`framework::ParseSink`] 適応を提供し、Parser → Event Store の縦割りを結ぶ。

pub mod framework;
pub mod issue;
pub mod lnk;
pub mod prefetch;
pub mod sink;

// よく使う主要型をルートへ再公開。
pub use framework::{
    ArtifactParser, ParseContext, ParseSink, ParseSummary, ReadSeek, SinkError,
    run_parser_catching_panic,
};
pub use lnk::{LnkParser, PARSER_ID as LNK_PARSER_ID, PARSER_VERSION as LNK_PARSER_VERSION};
pub use prefetch::{
    PARSER_ID as PREFETCH_PARSER_ID, PARSER_VERSION as PREFETCH_PARSER_VERSION, PrefetchParser,
};
