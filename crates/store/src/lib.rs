//! TraceForge Event Store・Timeline crate。
//!
//! Phase 3 で決定的な Event 永続化・反復の基盤を実装する（roadmap §5 Phase 3）:
//!
//! - length-delimited spool file Event Store（規範 §10）
//! - 書き込み時 Schema validation・Event ID 一意制約・commit marker（規範 §10）
//! - timestamp group + Event ID による決定的 iteration（規範 §10・§6.3）
//! - memory budget 超過時の external merge sort（規範 §10）
//! - Timeline 5 group の順序付け（規範 §6.3:
//!   UtcInstant → timezone 付き LocalTime → timezone 不明 LocalTime → Range → Unknown）
//! - 縦割り用の最小 JSON / Manifest 出力（M2 用、正式版は Phase 7 へ引き継ぐ）
//!
//! 仕様書の優先順位（AGENTS.md）: schemas > normative > compatibility > product。
//! Runtime の Case へ `Vec<Event>` を保持してはならない（規範 §10）。
//! 本 crate は [`EventStore`] へ逐次保存・逐次読取を行い、API が `Vec<Event>` を要求しない。

pub mod error;
pub mod external_sort;
pub mod output;
pub mod store;
pub mod timeline;

// よく使う主要型をルートへ再公開。
pub use error::{OutputError, StoreError};
pub use store::{EventIter, EventStore, SortedEventIter};
pub use timeline::{TimelineFilter, TimelineGroup, TimelineKey, TimelineSummary};
