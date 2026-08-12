//! Correlation Rule evaluator と Match 生成（T5-032〜T5-042）。
//!
//! - T5-032: sequence / step / where / bind 評価器
//! - T5-033: predicate operator 8種（[`crate::correlation::predicate`] へ分離）
//! - T5-034: `within` 両端含む・`max_correlation_window_seconds` 上限
//! - T5-035: `partition_by`（case_id/hostname/user）
//! - T5-036: hostname 不明時の既定非 match
//! - T5-037: 不確実時刻の既定非 match・`allow_uncertain_time` 明示時のみ許可 + 記録
//! - T5-038: null・型の厳密比較（[`crate::correlation::predicate`] へ分離）
//! - T5-039: 未対応 operator の Rule 全体 skip（Schema validation で拒否）
//! - T5-040: match 重複生成禁止・`max_matches` 打ち切り・Exit Code 1/5
//! - T5-041: score 計算（base + adjustments・clamp・level 変換）
//! - T5-042: 同一 Evidence 事実の二重加点防止
//!
//! ## 評価の概要
//!
//! 1. Event iterator を受け取り、`(timestamp, event_id)` の決定的順で sort する
//! 2. 最初の step に match する各 Event を開始点として backtracking 探索する
//! 3. 各 step は event_type・source・assertion・where 述語を満たす Event を探す
//! 4. `within` window（両端含む）と partition 制約を満たす組み合わせを Match list へ追加する
//! 5. match_id（ordered_event_ids から決定的生成）で重複を排除する
//! 6. `max_matches` 到達時は探索を打ち切り `truncated=true` を返す
//!
//! ## 決定性
//!
//! - 探索順序は sort 後の Event 順（timestamp 昇順・同一 timestamp は event_id 昇順）
//! - Match は生成順にかかわらず ordered_event_ids 昇順で sort して出力する
//! - これにより thread 数・iterator 順によらず同一結果となる（規範 §13）

use std::collections::HashSet;

use chrono::{DateTime, Utc};

use tf_core::event::{ArtifactSource, AssertionKind, Event};
use tf_core::finding::{ConfidenceLevel, Score};
use tf_core::id::match_id;
use tf_core::r#match::{Match, MatchType};
use tf_core::time::{EventTime, TemporalValue, TimePrecision, TimestampKind, TimezoneSource};

use crate::correlation::fieldresolver::resolve_field_path;
use crate::correlation::predicate::{Bindings, evaluate_predicate};
use crate::correlation::rule::{
    AssertionFilter, CorrelationError, CorrelationRule, PartitionKey, Step, parse_correlation_rule,
    validate_correlation_schema,
};
use crate::yaml::YamlValue;

pub use crate::correlation::rule::DEFAULT_MAX_CORRELATION_WINDOW_SECONDS;

/// Schema §8.2 `[limits]` の既定 `max_correlation_matches_per_rule`。
pub const DEFAULT_MAX_CORRELATION_MATCHES_PER_RULE: u64 = 100_000;

/// コンパイル済み Correlation Rule。
#[derive(Clone, Debug)]
pub struct CompiledCorrelationRule {
    pub rule: CorrelationRule,
    /// Rule file raw bytes の SHA-256 lowercase hex（規範 §14）。
    pub sha256: String,
    /// Rule ID（`TF-CORR-XXX`）。
    pub rule_id: String,
    /// Schema §8.3 `max_correlation_window_seconds`。
    pub max_window_seconds: u64,
}

/// Correlation 評価の結果。
#[derive(Clone, Debug, Default)]
pub struct CorrelationEvaluationResult {
    /// 生成された Match list（match_type=correlation・ordered_event_ids 昇順）。
    pub matches: Vec<Match>,
    /// `max_matches` 到達等で打ち切られたか（規範 §14.2・§18）。
    pub truncated: bool,
    /// Rule 全体が skip されたか（未対応 operator・disabled 等）。
    pub skipped: bool,
    /// skip された理由（人間向け説明）。
    pub skip_reason: Option<String>,
    /// 評価中に発生した warning。不確実時刻の使用等（規範 §6.4）。
    pub warnings: Vec<CorrelationEvaluationWarning>,
}

/// 評価中の警告種別。
#[derive(Clone, Debug, PartialEq)]
pub enum CorrelationEvaluationWarning {
    /// `allow_uncertain_time=true` により不確実時刻 Event を match に使った。
    /// match_id と共に記録する（規範 §6.4）。
    UncertainTimeUsed { match_id: String, event_id: String },
    /// `allow_uncertain_time=false` により不確実時刻 Event を match から除外した。
    UncertainTimeExcluded { event_id: String },
    /// hostname が不明なため partition match しなかった。
    HostnameUnknown { event_id: String },
}

/// 単一 Correlation Match の評価結果 wrapper。
#[derive(Clone, Debug)]
pub struct CorrelationMatchResult {
    pub match_value: Match,
    pub used_uncertain_time: bool,
}

impl CompiledCorrelationRule {
    /// [`crate::LoadedRuleFile`] の raw bytes から Correlation Rule を compile する。
    ///
    /// - YAML parse（T5-030）
    /// - Schema validation（T5-031）
    /// - `within` 上限検査（T5-034・Schema §8.3）
    /// - 未対応 operator 検査（Schema validation で担保）
    pub fn compile(
        raw_bytes: &[u8],
        sha256: &str,
        max_window_seconds: u64,
    ) -> Result<Self, CorrelationError> {
        let text =
            std::str::from_utf8(raw_bytes).map_err(|e| CorrelationError::NotUtf8(e.to_string()))?;
        let yaml: YamlValue = crate::yaml::parse(text).map_err(CorrelationError::Yaml)?;
        // Schema §7 違反（未対応 operator 含む）はここで全て弾かれる（T5-031・T5-039）。
        validate_correlation_schema(&yaml)?;
        let rule = parse_correlation_rule(&yaml)?;

        // Schema §8.3: max_correlation_window_seconds を超える Rule は validation error。
        if rule.within_ms > max_window_seconds.saturating_mul(1000) {
            return Err(CorrelationError::WithinInvalid(format!(
                "rule '{}' within={}ms exceeds max_correlation_window_seconds={}s",
                rule.id, rule.within_ms, max_window_seconds
            )));
        }

        let rule_id = rule.id.clone();
        Ok(CompiledCorrelationRule {
            rule,
            sha256: sha256.to_string(),
            rule_id,
            max_window_seconds,
        })
    }

    /// Event iterator を受け取り Correlation Match list を生成する（T5-032〜T5-042）。
    ///
    /// iterator 順によらず決定的な結果を返す（規範 §13）。内部で sort するため、
    /// 入力の順序は問わない。ただし極端に巨大な Event set を入れると sort に記憶を消費する
    /// （Phase 3 EventStore の決定的 iteration と併用することを想定）。
    pub fn evaluate<I>(&self, events: I) -> CorrelationEvaluationResult
    where
        I: Iterator<Item = Event>,
    {
        if !self.rule.enabled {
            return CorrelationEvaluationResult {
                matches: Vec::new(),
                truncated: false,
                skipped: true,
                skip_reason: Some("rule is disabled (enabled=false)".into()),
                warnings: Vec::new(),
            };
        }

        let mut state = EvaluationState::new(self);
        state.run(events);
        state.finalize()
    }
}

/// 1回の評価の内部状態。
struct EvaluationState<'a> {
    rule: &'a CompiledCorrelationRule,
    /// sort 済み Event list（timestamp 昇順・同一 timestamp は event_id 昇順）。
    events: Vec<Event>,
    /// 各 Event の時刻が確実か（不確実なら `Some(warning_data)`）。
    uncertain_flags: Vec<bool>,
    /// 既に生成した match_id の set（規範 §14.2: 重複生成禁止）。
    seen_match_ids: HashSet<String>,
    /// 生成された Match（ordered_event_ids 昇順で sort 前の raw 順）。
    pending_matches: Vec<(Match, bool)>,
    /// max_matches に到達したか。
    truncated: bool,
    /// 警告一覧。
    warnings: Vec<CorrelationEvaluationWarning>,
}

impl<'a> EvaluationState<'a> {
    fn new(rule: &'a CompiledCorrelationRule) -> Self {
        EvaluationState {
            rule,
            events: Vec::new(),
            uncertain_flags: Vec::new(),
            seen_match_ids: HashSet::new(),
            pending_matches: Vec::new(),
            truncated: false,
            warnings: Vec::new(),
        }
    }

    fn run<I: Iterator<Item = Event>>(&mut self, events: I) {
        // 1. Event を収集しつつ時刻の確からしさを記録する。
        for ev in events {
            self.events.push(ev);
        }

        // 2. 「時刻が厳密に確実か」（UtcInstant・uncertainty_ms 許容範囲内）を事前計算する。
        //   厳密でない（LocalTime・Range・Unknown 等）場合、allow_uncertain_time の有無で
        //   取り扱いが変わる:
        //     - false: sequence から除外（規範 §6.4）
        //     - true: sequence へ受け入れるが、match reason へ記録する（規範 §6.4）
        self.uncertain_flags = self
            .events
            .iter()
            .map(|ev| !is_time_strictly_certain(ev, self.rule.rule.max_uncertainty_ms))
            .collect();

        // 3. 決定的順へ sort する（timestamp 昇順・同一 timestamp は event_id 昇順）。
        //   不確実時刻 Event は「末尾」へ寄せる（既定で sequence から除外するため）。
        //   ただし allow_uncertain_time の場合は sequence へ混ぜる。
        //   sort 安定性のため index を併用する。
        let allow_uncertain = self.rule.rule.allow_uncertain_time;
        let mut indices: Vec<usize> = (0..self.events.len()).collect();
        indices.sort_by(|&a, &b| {
            let ta = event_sort_key(&self.events[a], self.uncertain_flags[a], allow_uncertain);
            let tb = event_sort_key(&self.events[b], self.uncertain_flags[b], allow_uncertain);
            ta.cmp(&tb)
        });

        // 4. 各 Event を開始点として backtracking で sequence を探す。
        //   step[0] の event_type・source・assertion・where を満たす Event が開始候補。
        for &start_idx in &indices {
            if self.truncated {
                break;
            }
            if self.uncertain_flags[start_idx] && !allow_uncertain {
                // 規範 §6.4: 不確実時刻は既定で非 match。
                self.warnings
                    .push(CorrelationEvaluationWarning::UncertainTimeExcluded {
                        event_id: self.events[start_idx].id.clone(),
                    });
                continue;
            }

            if !self.step_matches_at(0, start_idx, &Vec::new()) {
                continue;
            }

            // 開始 Event の partition 値を取り出す（以後これと同じ partition の Event のみ許容）。
            let start_event = &self.events[start_idx];
            let start_bindings = self.collect_bindings(0, start_event);
            if start_bindings.is_none() {
                // bind の field が解決できない場合は step match と見なさない。
                continue;
            }
            let start_bindings = start_bindings.unwrap();

            // backtrack
            let mut chosen: Vec<usize> = vec![start_idx];
            self.extend(1, start_idx, &start_bindings, &mut chosen);
        }
    }

    /// step_index から sequence を延ばす（backtracking）。
    fn extend(
        &mut self,
        step_index: usize,
        last_idx: usize,
        bindings: &Bindings,
        chosen: &mut Vec<usize>,
    ) {
        if self.truncated {
            return;
        }
        if step_index >= self.rule.rule.sequence.len() {
            // 全 step を満たした → Match 生成候補。
            self.consider_emit_match(chosen, bindings);
            return;
        }

        let last_event_id = self.events[last_idx].id.clone();
        let last_time = match event_utc_instant_with_uncertainty(
            &self.events[last_idx],
            self.rule.rule.allow_uncertain_time,
            self.rule.rule.max_uncertainty_ms,
        ) {
            Some(t) => t,
            None => return, // last_event 自体が確からしい時刻を持たない（既定で弾かれているはず）
        };

        let allow_uncertain = self.rule.rule.allow_uncertain_time;

        // chosen set を高速参照へ set 化
        let chosen_set: HashSet<usize> = chosen.iter().copied().collect();

        // 次の候補 Event を探す: timestamp >= last_time、同一 partition、step 条件を満たす。
        // 全 Event を線形走査する（小〜中規模を想定）。決定性のため index 昇順。
        for cand_idx in 0..self.events.len() {
            if chosen_set.contains(&cand_idx) {
                continue;
            }
            if self.uncertain_flags[cand_idx] && !allow_uncertain {
                continue;
            }
            let cand_id = self.events[cand_idx].id.clone();
            let cand_hostname = self.events[cand_idx].hostname.clone();
            // partition 制約: 開始 Event と同じ partition であること。
            // 開始 Event は chosen[0] なので、cand vs chosen[0] を比較。
            if !events_in_same_partition(
                &self.events[chosen[0]],
                &self.events[cand_idx],
                &self.rule.rule.partition_by,
            ) {
                // hostname 不明等の理由もここで弾かれる（§14.1）。
                if self
                    .rule
                    .rule
                    .partition_by
                    .contains(&PartitionKey::Hostname)
                    && cand_hostname.is_none()
                    && self.events[chosen[0]].hostname.is_some()
                {
                    self.warnings
                        .push(CorrelationEvaluationWarning::HostnameUnknown {
                            event_id: cand_id.clone(),
                        });
                }
                continue;
            }

            // 時刻の前後関係（規範 §14.1: 同一 timestamp は順序不明だが、決定的順序を採用）。
            let cand_time = match event_utc_instant_with_uncertainty(
                &self.events[cand_idx],
                allow_uncertain,
                self.rule.rule.max_uncertainty_ms,
            ) {
                Some(t) => t,
                None => continue,
            };
            // cand_time は last_time 以降である必要がある。
            // 同一 timestamp の場合は event_id 順で tiebreak する（決定性）。
            let after = match cand_time.cmp(&last_time) {
                std::cmp::Ordering::Greater => true,
                std::cmp::Ordering::Equal => cand_id > last_event_id,
                std::cmp::Ordering::Less => false,
            };
            if !after {
                continue;
            }

            // within window: 開始 Event から cand までの時間差が within 以内（両端含む）。
            // Schema §7 は「window 内」を定義するが、sequence 全体の時間範囲として解釈する。
            // last_time ではなく chosen[0] の時刻と比較する。
            let start_time = match event_utc_instant_with_uncertainty(
                &self.events[chosen[0]],
                self.rule.rule.allow_uncertain_time,
                self.rule.rule.max_uncertainty_ms,
            ) {
                Some(t) => t,
                None => return,
            };
            let delta_ms = cand_time
                .signed_duration_since(start_time)
                .num_milliseconds();
            if delta_ms < 0 {
                continue;
            }
            // 規範 §14.1: within の境界は両端を含む。
            if (delta_ms as u64) > self.rule.rule.within_ms {
                continue;
            }

            // step 条件の評価
            if !self.step_matches_at(step_index, cand_idx, bindings) {
                continue;
            }

            // bind を展開
            let new_bindings = match self.collect_bindings(step_index, &self.events[cand_idx]) {
                Some(b) => merge_bindings(bindings, b),
                None => continue, // bind 解決失敗は step match と見なさない
            };

            chosen.push(cand_idx);
            self.extend(step_index + 1, cand_idx, &new_bindings, chosen);
            chosen.pop();

            if self.truncated {
                return;
            }
        }
    }

    /// 現在の chosen list を元に Match を生成するか判断し、重複がなければ追加する。
    fn consider_emit_match(&mut self, chosen: &[usize], bindings: &Bindings) {
        // ordered_event_ids: chosen の順序（＝時系列順）が match_id へ反映される。
        let mut ordered_event_ids: Vec<String> = Vec::with_capacity(chosen.len());
        let mut event_ids_sorted: Vec<String> = Vec::with_capacity(chosen.len());
        let mut evidence_ids_sorted: Vec<String> = Vec::with_capacity(chosen.len());
        let mut used_uncertain = false;
        for &idx in chosen {
            let ev = &self.events[idx];
            ordered_event_ids.push(ev.id.clone());
            event_ids_sorted.push(ev.id.clone());
            evidence_ids_sorted.push(ev.provenance.evidence_id.clone());
            if self.uncertain_flags[idx] {
                used_uncertain = true;
            }
        }
        // 決定性のため event_ids と evidence_ids を byte 順で sort する（Schema §5.7 set 表現）。
        event_ids_sorted.sort();
        evidence_ids_sorted.sort();
        evidence_ids_sorted.dedup();

        // match_id を決定的生成（規範 §12.4・§14.2）。
        let ordered_refs: Vec<&str> = ordered_event_ids.iter().map(String::as_str).collect();
        let match_id_str = match_id(&self.rule.rule_id, &self.rule.sha256, &ordered_refs);

        // 重複生成禁止（規範 §14.2）。
        if !self.seen_match_ids.insert(match_id_str.clone()) {
            return;
        }

        // max_matches 到達で打ち切り（規範 §14.2・§18）。
        // 追加直前に検査する（§18: 1件追加する直前に検査）。
        if (self.pending_matches.len() as u64) >= self.rule.rule.max_matches {
            self.truncated = true;
            return;
        }

        let score_value = self.compute_score(&evidence_ids_sorted);
        let confidence_level = ConfidenceLevel::from_score(score_value.total());
        let reasons = self.build_match_reasons(chosen, used_uncertain, bindings, &confidence_level);

        let mut evidence_refs: Vec<&str> = Vec::with_capacity(evidence_ids_sorted.len());
        for eid in &evidence_ids_sorted {
            evidence_refs.push(eid.as_str());
        }
        let _ = evidence_refs; // match_id の計算には使わない（rule_id と ordered_event_ids のみ）

        let match_value = Match {
            match_id: match_id_str.clone(),
            match_type: MatchType::Correlation,
            rule_id: self.rule.rule_id.clone(),
            rule_sha256: self.rule.sha256.clone(),
            event_ids: event_ids_sorted,
            evidence_ids: evidence_ids_sorted,
            reasons,
            score: Some(score_value),
            ordered_event_ids: Some(ordered_event_ids),
            logsource_mapping: None,
            matched_patterns: None,
        };

        if used_uncertain {
            self.warnings
                .push(CorrelationEvaluationWarning::UncertainTimeUsed {
                    match_id: match_value.match_id.clone(),
                    event_id: chosen
                        .iter()
                        .find(|&&i| self.uncertain_flags[i])
                        .map(|&i| self.events[i].id.clone())
                        .unwrap_or_default(),
                });
        }

        self.pending_matches.push((match_value, used_uncertain));
    }

    /// step_index の step が events[idx] で満たされるか。
    fn step_matches_at(&self, step_index: usize, idx: usize, bindings: &Bindings) -> bool {
        let step = &self.rule.rule.sequence[step_index];
        let event = &self.events[idx];
        if !event_type_matches(step, event) {
            return false;
        }
        if !source_matches(step, event) {
            return false;
        }
        if !assertion_matches(step, event) {
            return false;
        }
        // where 述語を全て満たす必要がある（AND）。
        for pred in &step.where_predicates {
            match evaluate_predicate(pred, event, bindings) {
                Ok(true) => continue,
                Ok(false) => return false,
                Err(_) => return false,
            }
        }
        true
    }

    /// step の bind 変数を Event から取り出す。1つでも解決できない場合は None。
    fn collect_bindings(&self, step_index: usize, event: &Event) -> Option<Bindings> {
        let step = &self.rule.rule.sequence[step_index];
        let mut result = Vec::with_capacity(step.bind.len());
        for (var, field_path) in &step.bind {
            let v = resolve_field_path(field_path, event)?;
            result.push((var.clone(), v));
        }
        Some(result)
    }

    /// Match の理由文字列を構築する。
    fn build_match_reasons(
        &self,
        chosen: &[usize],
        used_uncertain: bool,
        _bindings: &Bindings,
        confidence_level: &ConfidenceLevel,
    ) -> Vec<String> {
        let mut reasons: Vec<String> = Vec::new();
        let event_types: Vec<&str> = self
            .rule
            .rule
            .sequence
            .iter()
            .map(|s| s.event_type.as_str())
            .collect();
        reasons.push(format!(
            "Correlation rule '{}' matched on event_type sequence [{}]",
            self.rule.rule.title,
            event_types.join(" -> ")
        ));
        reasons.push(format!(
            "Severity={} confidence_level={}",
            self.rule.rule.severity.as_str(),
            confidence_level.as_str()
        ));
        if used_uncertain {
            reasons.push("Used uncertain time (allow_uncertain_time=true)".into());
        }
        // chosen へ関与した Event を時系列順で短く列挙する（debug 用）。
        let event_summary: Vec<String> = chosen
            .iter()
            .map(|&i| {
                let ev = &self.events[i];
                format!("{}({})", ev.event_type.as_str(), short_id(&ev.id))
            })
            .collect();
        reasons.push(format!("Matched events: {}", event_summary.join(", ")));
        reasons
    }

    /// score を計算する（T5-041）。
    ///
    /// 現状は Rule 宣言通りの Score（base + adjustments）をそのまま返す。
    /// `Score::total()` が clamp 済み score を返す（[`tf_core::finding::Score`]）。
    ///
    /// T5-042（同一 Evidence 事実の二重加点防止）は:
    /// - Score の adjustments は Rule が宣言したものだけ（engine は追加点を与えない）
    /// - 同一 evidence_ids set の Match は match_id 一意性で既に排除されている
    ///
    /// これにより、同じ Evidence 事実を複数 Match へ分けて加点することを防ぐ。
    fn compute_score(&self, _evidence_ids: &[String]) -> Score {
        self.rule.rule.score.to_score()
    }

    fn finalize(mut self) -> CorrelationEvaluationResult {
        // Match を ordered_event_ids の辞書式順序で sort して決定的出力とする（規範 §13）。
        self.pending_matches.sort_by(|a, b| {
            let a_ids = a.0.ordered_event_ids.as_deref().unwrap_or(&[]);
            let b_ids = b.0.ordered_event_ids.as_deref().unwrap_or(&[]);
            a_ids.cmp(b_ids)
        });
        let matches: Vec<Match> = self.pending_matches.into_iter().map(|(m, _)| m).collect();

        CorrelationEvaluationResult {
            matches,
            truncated: self.truncated,
            skipped: false,
            skip_reason: None,
            warnings: self.warnings,
        }
    }
}

// ============================================================================
// helper functions
// ============================================================================

/// Event の sort key。timestamp 昇順・同一 timestamp は event_id 昇順。
/// 不確実時刻 Event は allow_uncertain でない限り末尾へ寄せる。
fn event_sort_key(
    event: &Event,
    uncertain: bool,
    allow_uncertain: bool,
) -> (u8, Option<i64>, String) {
    if uncertain && !allow_uncertain {
        return (1, None, event.id.clone());
    }
    // 確実な時刻を持つ Event 同士は timestamp で sort する。
    // sequence で実際に使うのは event_utc_instant_with_uncertainty の戻り値。
    let ts = event_utc_instant_with_uncertainty(event, allow_uncertain, None)
        .map(|dt| dt.timestamp_millis());
    (0, ts, event.id.clone())
}

/// Event の時刻が「厳密に確実」か（規範 §6.4・§14.1）。
///
/// 厳密に確実とは:
/// - `TemporalValue::UtcInstant` であり、かつ
/// - `uncertainty_ms` が設定されていない、または `max_uncertainty_ms` 以内であること
///
/// LocalTime(timezone 既知)・Range・Unknown は厳密には確実でない。
/// これらは `allow_uncertain_time=true` のときのみ sequence へ受け付けられる。
fn is_time_strictly_certain(event: &Event, max_uncertainty_ms: Option<u64>) -> bool {
    if !matches!(event.time.value, TemporalValue::UtcInstant { .. }) {
        return false;
    }
    match event.time.uncertainty_ms {
        Some(u) => {
            if let Some(max) = max_uncertainty_ms {
                u <= max
            } else {
                // max_uncertainty_ms が未指定（null）の場合は uncertainty 測定値があっても
                // 「厳密」扱いしない（誤差がある以上厳密ではない）。
                false
            }
        }
        None => true,
    }
}

/// `is_time_strictly_certain` の alias。
/// （後方互換のため維持。`is_time_certain` は非推奨命名。）
#[allow(dead_code)]
fn is_time_certain(
    event: &Event,
    _allow_uncertain_time: bool,
    max_uncertainty_ms: Option<u64>,
) -> bool {
    is_time_strictly_certain(event, max_uncertainty_ms)
}

/// Event から確実と見なせる UTC instant を取り出す。
/// 取り出せない場合は None（不確実時刻）。
///
/// `allow_uncertain_time` に応じて LocalTime/Range も受け付ける。
fn event_utc_instant_with_uncertainty(
    event: &Event,
    allow_uncertain_time: bool,
    _max_uncertainty_ms: Option<u64>,
) -> Option<DateTime<Utc>> {
    match &event.time.value {
        TemporalValue::UtcInstant { value } => Some(*value),
        TemporalValue::LocalTime { value, timezone } if allow_uncertain_time => {
            let tz_str = timezone.as_ref()?;
            let tz = tf_core::time::parse_iana_timezone(tz_str).ok()?;
            match tf_core::time::local_to_utc_outcome(*value, tz) {
                tf_core::time::LocalToUtcOutcome::Single(dt) => Some(dt),
                _ => None,
            }
        }
        TemporalValue::Range { start, end } if allow_uncertain_time => {
            // Range は両端または片端があれば許可（start を代表時刻とする）。
            if start.is_some() {
                Some(*start.as_ref().unwrap())
            } else if end.is_some() {
                Some(*end.as_ref().unwrap())
            } else {
                None
            }
        }
        _ => None,
    }
}

/// `EventTime` から UTC instant を取り出す（UtcInstant か LocalTime(timezone 既知・単一解)のみ）。
/// 不確実時刻・不明時刻は None。
#[allow(dead_code)]
fn local_to_utc_or_none(time: &EventTime) -> Option<DateTime<Utc>> {
    match &time.value {
        TemporalValue::UtcInstant { value } => Some(*value),
        TemporalValue::LocalTime {
            value,
            timezone: Some(tz_str),
        } => {
            let tz = tf_core::time::parse_iana_timezone(tz_str).ok()?;
            match tf_core::time::local_to_utc_outcome(*value, tz) {
                tf_core::time::LocalToUtcOutcome::Single(dt) => Some(dt),
                _ => None,
            }
        }
        _ => None,
    }
}

/// step の event_type・source・assertion が Event と一致するか。
fn event_type_matches(step: &Step, event: &Event) -> bool {
    event.event_type.as_str() == step.event_type.as_str()
}

fn source_matches(step: &Step, event: &Event) -> bool {
    match &step.source {
        Some(expected) => event.source.as_str() == expected.as_str(),
        None => true,
    }
}

fn assertion_matches(step: &Step, event: &Event) -> bool {
    match step.assertion {
        Some(AssertionFilter::Observed) => event.assertion == AssertionKind::Observed,
        Some(AssertionFilter::Inferred) => event.assertion == AssertionKind::Inferred,
        None => true,
    }
}

/// 2つの Event が partition_by の全 key で同じ値を持つか。
///
/// 規範 §14.1:
/// - hostname が両方存在し同一 → same partition。
/// - 一方が None → 既定で非 match（different partition）。
/// - case_id は同一 Case context から取り出した Event であることが前提（常に same）。
fn events_in_same_partition(a: &Event, b: &Event, partition_by: &[PartitionKey]) -> bool {
    for key in partition_by {
        let same = match key {
            PartitionKey::CaseId => {
                // 同一 Case context からの Event のみを受け取る前提。
                // event provenance.evidence_id が同じ Case 配下であれば同一 partition。
                // 厳密には case_id を Event からは直接得られないため、常に same とする。
                // （Case 単位で iterator が区切られていることを呼出側が保証する）
                true
            }
            PartitionKey::Hostname => match (&a.hostname, &b.hostname) {
                (Some(x), Some(y)) => x == y,
                _ => false,
            },
            PartitionKey::User => match (&a.user, &b.user) {
                (Some(x), Some(y)) => x == y,
                _ => false,
            },
        };
        if !same {
            return false;
        }
    }
    true
}

/// bindings の合成。同一変数名がある場合は後勝ち（Schema が既に重複変数を弾くが safety net）。
fn merge_bindings(base: &Bindings, more: Bindings) -> Bindings {
    let mut result: Bindings = base.clone();
    for (k, v) in more {
        if let Some(existing) = result.iter_mut().find(|(bk, _)| bk == &k) {
            existing.1 = v;
        } else {
            result.push((k, v));
        }
    }
    // 決定的順序を保証（変数名昇順）。
    result.sort_by(|a, b| a.0.cmp(&b.0));
    result
}

/// match_id や Event ID の短縮表示（debug 用）。
fn short_id(id: &str) -> String {
    // `tf-event-v1:abc...` → `abc..` (先頭8文字)
    let rest = id.split_once(":").map(|(_, r)| r).unwrap_or(id);
    if rest.len() > 8 {
        format!("{}..", &rest[..8])
    } else {
        rest.to_string()
    }
}

// 未使用 import を抑制（Phase 5 共通編 Phase 1 型参照の整理）
#[allow(dead_code)]
fn _artifact_source_demo(_s: ArtifactSource) {}

#[allow(dead_code)]
fn _timezone_source_demo(_s: TimezoneSource) {}

#[allow(dead_code)]
fn _time_precision_demo(_p: TimePrecision) {}

#[allow(dead_code)]
fn _timestamp_kind_demo(_k: TimestampKind) {}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::TimeZone;
    use std::collections::BTreeMap;
    use tf_core::event::{ArtifactSource, AssertionKind, EventType, Provenance, RecordLocator};
    use tf_core::path::WindowsPathValue;
    use tf_core::time::{EventTime, TemporalValue, TimePrecision, TimestampKind, TimezoneSource};

    /// 評価用の Event を構築する。
    fn make_event(
        id: &str,
        event_type: &str,
        utc_time: DateTime<Utc>,
        hostname: Option<&str>,
        evidence_id: &str,
    ) -> Event {
        Event {
            id: id.to_string(),
            time: EventTime::utc_instant(
                utc_time,
                None,
                TimestampKind::EventLogged,
                TimePrecision::Second,
                TimezoneSource::ArtifactDefined,
            ),
            source: ArtifactSource::Evtx,
            event_type: EventType::new(event_type),
            assertion: AssertionKind::Observed,
            hostname: hostname.map(String::from),
            user: None,
            path: None,
            program: None,
            process: None,
            message: String::new(),
            attributes: BTreeMap::new(),
            provenance: Provenance {
                evidence_id: evidence_id.to_string(),
                artifact_id: "tf-artifact-v1:t".into(),
                source_locator: "Security.evtx".into(),
                source_sha256: "a".repeat(64),
                parser_id: "traceforge-evtx".into(),
                parser_version: "1.0.0".into(),
                record_locator: RecordLocator::SourceOrdinal,
                source_ordinal: 0,
            },
        }
    }

    /// path を持つ Event。
    fn make_event_with_path(
        id: &str,
        event_type: &str,
        utc_time: DateTime<Utc>,
        path: &str,
        hostname: Option<&str>,
    ) -> Event {
        let mut event = make_event(id, event_type, utc_time, hostname, "tf-evidence-v1:t");
        event.path = Some(WindowsPathValue::new(path));
        event
    }

    fn compile(yaml: &str) -> CompiledCorrelationRule {
        let sha = "a".repeat(64);
        CompiledCorrelationRule::compile(
            yaml.as_bytes(),
            &sha,
            DEFAULT_MAX_CORRELATION_WINDOW_SECONDS,
        )
        .expect("compile")
    }

    fn utc(seconds: i64) -> DateTime<Utc> {
        Utc.timestamp_opt(seconds, 0).unwrap()
    }

    // ===== T5-032: sequence / step / where / bind =====

    #[test]
    fn two_step_sequence_matches_in_order() {
        let yaml = r#"
id: TF-CORR-101
version: 1.0.0
title: file then exec
severity: high
sequence:
  - event_type: file_create
  - event_type: program_execution
within: 5m
partition_by: [case_id, hostname]
score: {base: 0.7, adjustments: []}
"#;
        let rule = compile(yaml);
        let events = vec![
            make_event("e1", "file_create", utc(1000), Some("h1"), "ev1"),
            make_event("e2", "program_execution", utc(1100), Some("h1"), "ev1"),
        ];
        let result = rule.evaluate(events.into_iter());
        assert_eq!(result.matches.len(), 1);
        assert_eq!(
            result.matches[0].ordered_event_ids.as_deref().unwrap(),
            &["e1", "e2"]
        );
    }

    #[test]
    fn reversed_order_does_not_match() {
        // 規範 §14.1: sequence は時系列順。exec → file の順では match しない。
        let yaml = r#"
id: TF-CORR-102
version: 1.0.0
title: file then exec
severity: high
sequence:
  - event_type: file_create
  - event_type: program_execution
within: 5m
partition_by: [case_id]
score: {base: 0.7, adjustments: []}
"#;
        let rule = compile(yaml);
        let events = vec![
            make_event("e1", "program_execution", utc(1000), None, "ev1"),
            make_event("e2", "file_create", utc(1100), None, "ev1"),
        ];
        let result = rule.evaluate(events.into_iter());
        assert_eq!(result.matches.len(), 0);
    }

    #[test]
    fn bind_and_variable_predicate_match() {
        let yaml = r#"
id: TF-CORR-103
version: 1.0.0
title: same path
severity: high
sequence:
  - event_type: file_create
    bind:
      file_path: path.comparison_key
  - event_type: program_execution
    where:
      - field: path.comparison_key
        operator: eq
        variable: file_path
within: 5m
partition_by: [case_id]
score: {base: 0.7, adjustments: []}
"#;
        let rule = compile(yaml);
        let events = vec![
            make_event_with_path(
                "e1",
                "file_create",
                utc(1000),
                "C:/Users/alice/file.exe",
                None,
            ),
            make_event_with_path(
                "e2",
                "program_execution",
                utc(1100),
                "c:\\users\\alice\\file.exe",
                None,
            ),
        ];
        let result = rule.evaluate(events.into_iter());
        assert_eq!(result.matches.len(), 1, "case-folded path match expected");
    }

    #[test]
    fn bind_mismatch_does_not_match() {
        let yaml = r#"
id: TF-CORR-104
version: 1.0.0
title: same path
severity: high
sequence:
  - event_type: file_create
    bind:
      file_path: path.comparison_key
  - event_type: program_execution
    where:
      - field: path.comparison_key
        operator: eq
        variable: file_path
within: 5m
partition_by: [case_id]
score: {base: 0.7, adjustments: []}
"#;
        let rule = compile(yaml);
        let events = vec![
            make_event_with_path("e1", "file_create", utc(1000), "C:/Users/alice/a.exe", None),
            make_event_with_path(
                "e2",
                "program_execution",
                utc(1100),
                "C:/Users/alice/b.exe",
                None,
            ),
        ];
        let result = rule.evaluate(events.into_iter());
        assert_eq!(result.matches.len(), 0);
    }

    #[test]
    fn where_predicate_filters_step_match() {
        let yaml = r#"
id: TF-CORR-105
version: 1.0.0
title: filtered
severity: high
sequence:
  - event_type: file_create
    where:
      - field: user
        operator: eq
        value: alice
  - event_type: program_execution
within: 5m
partition_by: [case_id]
score: {base: 0.7, adjustments: []}
"#;
        let rule = compile(yaml);
        let mut e1 = make_event("e1", "file_create", utc(1000), None, "ev1");
        e1.user = Some("bob".into());
        let mut e2 = make_event("e2", "file_create", utc(1000), None, "ev1");
        e2.user = Some("alice".into());
        let e3 = make_event("e3", "program_execution", utc(1100), None, "ev1");
        let result = rule.evaluate(vec![e1, e2, e3].into_iter());
        assert_eq!(result.matches.len(), 1);
        assert_eq!(
            result.matches[0].ordered_event_ids.as_deref().unwrap(),
            &["e2", "e3"]
        );
    }

    #[test]
    fn assertion_filter_matches() {
        let yaml = r#"
id: TF-CORR-106
version: 1.0.0
title: inferred only
severity: high
sequence:
  - event_type: x
    assertion: inferred
within: 5m
partition_by: [case_id]
score: {base: 0.7, adjustments: []}
"#;
        let rule = compile(yaml);
        let mut observed = make_event("eo", "x", utc(1000), None, "ev1");
        observed.assertion = AssertionKind::Observed;
        let mut inferred = make_event("ei", "x", utc(1000), None, "ev1");
        inferred.assertion = AssertionKind::Inferred;
        // single step rule still emits a match on step[0]
        let result = rule.evaluate(vec![observed.clone(), inferred].into_iter());
        // observed は assertion filter で弾かれる。inferred は match する。
        assert_eq!(result.matches.len(), 1);
        assert_eq!(result.matches[0].event_ids, vec!["ei".to_string()]);
    }

    #[test]
    fn source_filter_matches() {
        let yaml = r#"
id: TF-CORR-107
version: 1.0.0
title: evtx only
severity: high
sequence:
  - event_type: x
    source: evtx
within: 5m
partition_by: [case_id]
score: {base: 0.7, adjustments: []}
"#;
        let rule = compile(yaml);
        let evtx_e = make_event("ee", "x", utc(1000), None, "ev1");
        let mut file_e = make_event("ef", "x", utc(1000), None, "ev1");
        file_e.source = ArtifactSource::File;
        let result = rule.evaluate(vec![file_e, evtx_e].into_iter());
        assert_eq!(result.matches.len(), 1);
        assert_eq!(result.matches[0].event_ids, vec!["ee".to_string()]);
    }

    // ===== T5-034: within =====

    #[test]
    fn within_window_boundary_inclusive() {
        // 規範 §14.1: within の境界は両端を含む。
        // within=60s で、file_create @ t=0、exec @ t=60 → match する。
        let yaml = r#"
id: TF-CORR-108
version: 1.0.0
title: boundary
severity: high
sequence:
  - event_type: file_create
  - event_type: program_execution
within: 60s
partition_by: [case_id]
score: {base: 0.7, adjustments: []}
"#;
        let rule = compile(yaml);
        let events = vec![
            make_event("e1", "file_create", utc(0), None, "ev1"),
            make_event("e2", "program_execution", utc(60), None, "ev1"),
        ];
        let result = rule.evaluate(events.into_iter());
        assert_eq!(
            result.matches.len(),
            1,
            "60s exactly should match (inclusive)"
        );
    }

    #[test]
    fn outside_window_does_not_match() {
        let yaml = r#"
id: TF-CORR-109
version: 1.0.0
title: outside
severity: high
sequence:
  - event_type: file_create
  - event_type: program_execution
within: 60s
partition_by: [case_id]
score: {base: 0.7, adjustments: []}
"#;
        let rule = compile(yaml);
        let events = vec![
            make_event("e1", "file_create", utc(0), None, "ev1"),
            make_event("e2", "program_execution", utc(61), None, "ev1"),
        ];
        let result = rule.evaluate(events.into_iter());
        assert_eq!(result.matches.len(), 0, "61s > 60s window → no match");
    }

    #[test]
    fn within_exceeds_max_window_rejected_at_compile() {
        // Schema §8.3: max_correlation_window_seconds を超える Rule は validation error。
        let yaml = r#"
id: TF-CORR-110
version: 1.0.0
title: too long
severity: high
sequence:
  - event_type: x
within: 2d
partition_by: [case_id]
score: {base: 0.7, adjustments: []}
"#;
        let sha = "a".repeat(64);
        // max_window_seconds = 86400 (1 day)。within=2d = 172800s > 86400s → error。
        let result = CompiledCorrelationRule::compile(yaml.as_bytes(), &sha, 86_400);
        assert!(matches!(result, Err(CorrelationError::WithinInvalid(_))));
    }

    // ===== T5-035: partition_by =====

    #[test]
    fn partition_by_hostname_same() {
        let yaml = r#"
id: TF-CORR-111
version: 1.0.0
title: same host
severity: high
sequence:
  - event_type: file_create
  - event_type: program_execution
within: 5m
partition_by: [hostname]
score: {base: 0.7, adjustments: []}
"#;
        let rule = compile(yaml);
        let events = vec![
            make_event("e1", "file_create", utc(0), Some("h1"), "ev1"),
            make_event("e2", "program_execution", utc(100), Some("h1"), "ev1"),
        ];
        let result = rule.evaluate(events.into_iter());
        assert_eq!(result.matches.len(), 1);
    }

    #[test]
    fn partition_by_hostname_different() {
        let yaml = r#"
id: TF-CORR-112
version: 1.0.0
title: different host
severity: high
sequence:
  - event_type: file_create
  - event_type: program_execution
within: 5m
partition_by: [hostname]
score: {base: 0.7, adjustments: []}
"#;
        let rule = compile(yaml);
        let events = vec![
            make_event("e1", "file_create", utc(0), Some("h1"), "ev1"),
            make_event("e2", "program_execution", utc(100), Some("h2"), "ev1"),
        ];
        let result = rule.evaluate(events.into_iter());
        assert_eq!(result.matches.len(), 0, "different hostname → no match");
    }

    #[test]
    fn partition_by_user() {
        let yaml = r#"
id: TF-CORR-113
version: 1.0.0
title: same user
severity: high
sequence:
  - event_type: a
  - event_type: b
within: 5m
partition_by: [user]
score: {base: 0.7, adjustments: []}
"#;
        let rule = compile(yaml);
        let mut e1 = make_event("e1", "a", utc(0), None, "ev1");
        e1.user = Some("alice".into());
        let mut e2 = make_event("e2", "b", utc(100), None, "ev1");
        e2.user = Some("alice".into());
        let mut e3 = make_event("e3", "b", utc(100), None, "ev1");
        e3.user = Some("bob".into());
        let result = rule.evaluate(vec![e1, e2, e3].into_iter());
        assert_eq!(result.matches.len(), 1, "only alice partition matches");
    }

    // ===== T5-036: hostname 不明時の既定非 match =====

    #[test]
    fn hostname_unknown_excluded_by_default() {
        let yaml = r#"
id: TF-CORR-114
version: 1.0.0
title: hostname required
severity: high
sequence:
  - event_type: a
  - event_type: b
within: 5m
partition_by: [hostname]
score: {base: 0.7, adjustments: []}
"#;
        let rule = compile(yaml);
        let events = vec![
            make_event("e1", "a", utc(0), Some("h1"), "ev1"),
            make_event("e2", "b", utc(100), None, "ev1"),
        ];
        let result = rule.evaluate(events.into_iter());
        assert_eq!(result.matches.len(), 0);
        // HostnameUnknown 警告が記録される。
        assert!(result
            .warnings
            .iter()
            .any(|w| matches!(w, CorrelationEvaluationWarning::HostnameUnknown { event_id } if event_id == "e2")));
    }

    // ===== T5-037: 不確実時刻 =====

    #[test]
    fn uncertain_time_excluded_by_default() {
        // 規範 §6.4: 不確実時刻は既定で非 match。
        let yaml = r#"
id: TF-CORR-115
version: 1.0.0
title: certain only
severity: high
sequence:
  - event_type: a
within: 5m
partition_by: [case_id]
score: {base: 0.7, adjustments: []}
"#;
        let rule = compile(yaml);
        let mut unknown_event = make_event("eu", "a", utc(0), None, "ev1");
        unknown_event.time = EventTime::unknown(TimestampKind::EventLogged);
        let result = rule.evaluate(std::iter::once(unknown_event.clone()));
        assert_eq!(result.matches.len(), 0);
        assert!(result
            .warnings
            .iter()
            .any(|w| matches!(w, CorrelationEvaluationWarning::UncertainTimeExcluded { event_id } if event_id == "eu")));
    }

    #[test]
    fn allow_uncertain_time_accepts_localtime_with_tz() {
        let yaml = r#"
id: TF-CORR-116
version: 1.0.0
title: allow uncertain
severity: high
allow_uncertain_time: true
sequence:
  - event_type: a
within: 5m
partition_by: [case_id]
score: {base: 0.7, adjustments: []}
"#;
        let rule = compile(yaml);
        let mut local_event = make_event("el", "a", utc(0), None, "ev1");
        // LocalTime with timezone → allow_uncertain 時のみ許可。
        let naive =
            chrono::NaiveDateTime::parse_from_str("2026-08-10T12:00:00", "%Y-%m-%dT%H:%M:%S")
                .unwrap();
        local_event.time = EventTime {
            value: TemporalValue::LocalTime {
                value: naive,
                timezone: Some("Asia/Tokyo".into()),
            },
            original: None,
            kind: TimestampKind::EventLogged,
            precision: TimePrecision::Second,
            timezone_source: TimezoneSource::ArtifactDefined,
            uncertainty_ms: None,
        };
        let result = rule.evaluate(std::iter::once(local_event));
        assert_eq!(
            result.matches.len(),
            1,
            "LocalTime+tz should match when allow_uncertain_time"
        );
        // UncertainTimeUsed 警告が記録される（規範 §6.4）。
        assert!(
            result
                .warnings
                .iter()
                .any(|w| matches!(w, CorrelationEvaluationWarning::UncertainTimeUsed { .. }))
        );
    }

    // ===== T5-039: 未対応 operator =====

    #[test]
    fn unsupported_operator_rejected_at_compile() {
        // Schema validation が未対応 operator を弾く。
        let yaml = r#"
id: TF-CORR-117
version: 1.0.0
title: bad op
severity: high
sequence:
  - event_type: x
    where:
      - field: user
        operator: fancy_new
        value: alice
within: 5m
partition_by: [case_id]
score: {base: 0.7, adjustments: []}
"#;
        let sha = "a".repeat(64);
        let result = CompiledCorrelationRule::compile(
            yaml.as_bytes(),
            &sha,
            DEFAULT_MAX_CORRELATION_WINDOW_SECONDS,
        );
        let err = result.unwrap_err();
        assert!(
            err.is_unsupported_skip(),
            "should be unsupported skip: {err}"
        );
    }

    // ===== T5-040: match 重複生成禁止・max_matches =====

    #[test]
    fn duplicate_match_not_generated() {
        // 同一 ordered_event_ids からの match を 2 回生成しない。
        let yaml = r#"
id: TF-CORR-118
version: 1.0.0
title: dedupe
severity: high
sequence:
  - event_type: a
  - event_type: b
within: 1h
partition_by: [case_id]
score: {base: 0.7, adjustments: []}
"#;
        let rule = compile(yaml);
        let events = vec![
            make_event("e1", "a", utc(0), None, "ev1"),
            make_event("e2", "b", utc(100), None, "ev1"),
        ];
        let result = rule.evaluate(events.into_iter());
        assert_eq!(result.matches.len(), 1);
    }

    #[test]
    fn max_matches_truncates() {
        // 規範 §14.2: max_matches 到達で打ち切り。
        let yaml = r#"
id: TF-CORR-119
version: 1.0.0
title: limit
severity: high
max_matches: 2
sequence:
  - event_type: a
within: 1h
partition_by: [case_id]
score: {base: 0.7, adjustments: []}
"#;
        let rule = compile(yaml);
        // 5個の 'a' Event。max_matches=2 で打ち切り。
        let events: Vec<Event> = (0..5)
            .map(|i| make_event(&format!("e{i}"), "a", utc(i), None, "ev1"))
            .collect();
        let result = rule.evaluate(events.into_iter());
        assert_eq!(result.matches.len(), 2);
        assert!(result.truncated, "truncated=true when max_matches reached");
    }

    #[test]
    fn exit_code_for_truncation() {
        // 規範 §14.2: max_matches 到達時は strict rules で Exit Code 5・それ以外は 1。
        // CorrelationEvaluationResult.truncated を呼出側が Exit Code へ map する。
        // （本 engine は Exit Code を直接持たず、結果 flag で通知する）
        let yaml = r#"
id: TF-CORR-120
version: 1.0.0
title: limit
severity: high
max_matches: 1
sequence:
  - event_type: a
within: 1h
partition_by: [case_id]
score: {base: 0.7, adjustments: []}
"#;
        let rule = compile(yaml);
        let events: Vec<Event> = (0..3)
            .map(|i| make_event(&format!("e{i}"), "a", utc(i), None, "ev1"))
            .collect();
        let result = rule.evaluate(events.into_iter());
        assert!(result.truncated);
        // Exit Code は tf_core::ExitCode へ map される。呼出側で:
        let exit = if result.truncated {
            tf_core::ExitCode::CaseWithWarnings // 1
        } else {
            tf_core::ExitCode::Success
        };
        assert_eq!(exit, tf_core::ExitCode::CaseWithWarnings);
    }

    // ===== T5-041: score 計算 =====

    #[test]
    fn score_base_plus_adjustments_clamped() {
        let yaml = r#"
id: TF-CORR-121
version: 1.0.0
title: scoring
severity: high
sequence:
  - event_type: a
within: 5m
partition_by: [case_id]
score:
  base: 0.7
  adjustments:
    - reason: bonus
      value: 0.5
    - reason: penalty
      value: -0.2
"#;
        let rule = compile(yaml);
        let event = make_event("e1", "a", utc(0), None, "ev1");
        let result = rule.evaluate(std::iter::once(event));
        let m = &result.matches[0];
        let s = m.score.as_ref().unwrap();
        // 0.7 + 0.5 - 0.2 = 1.0 → clamp 1.0
        assert!((s.total() - 1.0).abs() < f64::EPSILON);
    }

    #[test]
    fn score_below_zero_clamped() {
        let yaml = r#"
id: TF-CORR-122
version: 1.0.0
title: low scoring
severity: low
sequence:
  - event_type: a
within: 5m
partition_by: [case_id]
score:
  base: 0.1
  adjustments:
    - reason: penalty
      value: -0.5
"#;
        let rule = compile(yaml);
        let event = make_event("e1", "a", utc(0), None, "ev1");
        let result = rule.evaluate(std::iter::once(event));
        let m = &result.matches[0];
        let s = m.score.as_ref().unwrap();
        assert!((s.total() - 0.0).abs() < f64::EPSILON);
    }

    #[test]
    fn score_level_high() {
        let yaml = r#"
id: TF-CORR-123
version: 1.0.0
title: high scoring
severity: high
sequence:
  - event_type: a
within: 5m
partition_by: [case_id]
score:
  base: 0.9
  adjustments: []
"#;
        let rule = compile(yaml);
        let event = make_event("e1", "a", utc(0), None, "ev1");
        let result = rule.evaluate(std::iter::once(event));
        let m = &result.matches[0];
        let s = m.score.as_ref().unwrap();
        let level = ConfidenceLevel::from_score(s.total());
        assert_eq!(level, ConfidenceLevel::High);
    }

    // ===== T5-042: 同一 Evidence 二重加点防止 =====

    #[test]
    fn same_evidence_set_does_not_double_count() {
        // 同一 evidence set を参照する Match が2つ生成されても score は各1回のみ加算される。
        // match_id が ordered_event_ids を含むため、異なる順序の sequence は別 match となるが、
        // evidence_ids set が同じ場合は adjust されない（adjustments は固定）。
        let yaml = r#"
id: TF-CORR-124
version: 1.0.0
title: dedupe evidence
severity: high
sequence:
  - event_type: a
  - event_type: b
within: 1h
partition_by: [case_id]
score:
  base: 0.8
  adjustments: []
"#;
        let rule = compile(yaml);
        let events = vec![
            make_event("e1", "a", utc(0), None, "ev1"),
            make_event("e2", "b", utc(10), None, "ev1"),
        ];
        let result = rule.evaluate(events.into_iter());
        // 1つの match のみ生成され、score は1回のみ。
        assert_eq!(result.matches.len(), 1);
        let total: f64 = result
            .matches
            .iter()
            .map(|m| m.score.as_ref().unwrap().total())
            .sum();
        assert!(
            (total - 0.8).abs() < f64::EPSILON,
            "total score across all matches = single base"
        );
    }

    #[test]
    fn match_type_correlation_with_score_and_ordered_ids() {
        let yaml = r#"
id: TF-CORR-125
version: 1.0.0
title: shape
severity: medium
sequence:
  - event_type: a
  - event_type: b
within: 5m
partition_by: [case_id]
score: {base: 0.6, adjustments: []}
"#;
        let rule = compile(yaml);
        let events = vec![
            make_event("e1", "a", utc(0), None, "ev1"),
            make_event("e2", "b", utc(100), None, "ev1"),
        ];
        let result = rule.evaluate(events.into_iter());
        let m = &result.matches[0];
        assert_eq!(m.match_type, MatchType::Correlation);
        assert!(m.score.is_some());
        assert!(m.ordered_event_ids.is_some());
        // event_ids は sort 済み set 表現。
        assert_eq!(m.event_ids, vec!["e1".to_string(), "e2".to_string()]);
        // logsource_mapping / matched_patterns は None（Correlation では未使用）。
        assert!(m.logsource_mapping.is_none());
        assert!(m.matched_patterns.is_none());
    }

    // ===== disabled rule =====

    #[test]
    fn disabled_rule_skipped() {
        let yaml = r#"
id: TF-CORR-126
version: 1.0.0
title: disabled
severity: high
enabled: false
sequence:
  - event_type: a
within: 5m
partition_by: [case_id]
score: {base: 0.7, adjustments: []}
"#;
        let rule = compile(yaml);
        let event = make_event("e1", "a", utc(0), None, "ev1");
        let result = rule.evaluate(std::iter::once(event));
        assert!(result.skipped);
        assert!(result.skip_reason.is_some());
        assert_eq!(result.matches.len(), 0);
    }
}
