//! rename OLD_NAME/NEW_NAME 結合ロジック（互換 §4.3、T4-034）。
//!
//! 互換 §4.3:
//! > Rename の `OLD_NAME` と `NEW_NAME` は、同一 file reference、近接 USN、
//! > 対応 reason を満たす場合だけ 1 変更として結合する。結合できない場合は
//! > 独立した Observed Event として保持する。
//!
//! ## 結合条件（3つすべてを満たす場合のみ）
//!
//! 1. **同一 file reference**: OLD_NAME 候補と NEW_NAME 候補の `file_reference` が完全一致。
//! 2. **近接 USN**: 両者の USN の差が `0` または `1`（同一トランザクション or 直後）。
//!    実際の Windows では rename の OLD/NEW は同じ USN を持つことが多いが、
//!    安全側へ「差 1 まで」を許容する。差 2 以上は別変更の可能性があるため結合しない。
//! 3. **対応 reason**: 直近候補が `RENAME_OLD_NAME`、新 record が `RENAME_NEW_NAME`。
//!
//! ## 結合できない場合
//!
//! いずれか1つでも欠ければ **独立 Event** として扱う（規範 §7.1: 断定禁止）。
//! 例えば OLD_NAME が出たあと別ファイルの変更が挟まった場合、OLD_NAME 単独の Event になる。

use crate::usn::reason::flags;
use crate::usn::record::UsnRecord;

/// 「近接 USN」と判定する差の上限（ inclusive ）。同一トランザクションまたは直後。
pub const PROXIMATE_USN_DELTA: i64 = 1;

/// 結合済み observation。1以上の record から成る（rename 結合時は2要素）。
#[derive(Clone, Debug)]
pub struct UsnObservation {
    /// この observation を構成する record 群（時系列順）。
    pub records: Vec<UsnRecord>,
    /// rename 結合したか（`OLD_NAME` + `NEW_NAME`）。
    pub rename_combined: bool,
}

impl UsnObservation {
    /// 単独 record から成る observation を作る。
    pub fn single(record: UsnRecord) -> Self {
        UsnObservation {
            records: vec![record],
            rename_combined: false,
        }
    }

    /// OLD_NAME + NEW_NAME を結合した observation を作る。
    pub fn combined_rename(old: UsnRecord, new: UsnRecord) -> Self {
        UsnObservation {
            records: vec![old, new],
            rename_combined: true,
        }
    }

    /// 先頭 record を返す（時刻・Provenance の基準）。
    pub fn first(&self) -> &UsnRecord {
        &self.records[0]
    }
}

/// record 列から observation 列へ変換する（rename 結合を適用）。
///
/// 入力 `records` は USN 昇順（`$J` の自然な並び）を前提とする。
pub fn combine_records(records: Vec<UsnRecord>) -> Vec<UsnObservation> {
    let mut out: Vec<UsnObservation> = Vec::with_capacity(records.len());
    // 直近の「未確定 OLD_NAME 候補」。結合されなければ独立 Event へ確定する。
    let mut pending_old: Option<UsnRecord> = None;

    for rec in records {
        // 直近候補と結合可能か？
        if let Some(old) = pending_old.take() {
            if let Some(combined) = try_combine_rename(&old, &rec) {
                out.push(combined);
                continue;
            }
            // 結合できなければ OLD_NAME 候補を独立 Event へ。
            out.push(UsnObservation::single(old));
        }

        // この record が新たな OLD_NAME 候補になるか、即独立 Event か。
        if is_rename_old_candidate(&rec) {
            pending_old = Some(rec);
        } else {
            out.push(UsnObservation::single(rec));
        }
    }

    // 末尾に未確定候補が残っていれば独立 Event へ。
    if let Some(old) = pending_old {
        out.push(UsnObservation::single(old));
    }

    out
}

/// record が「rename 結合の OLD_NAME 候補」として保留できるか。
/// RENAME_OLD_NAME flag が立っていて、filename がある（V2/V3）もの。
fn is_rename_old_candidate(rec: &UsnRecord) -> bool {
    rec.reason & flags::RENAME_OLD_NAME != 0 && rec.file_name.is_some()
}

/// OLD_NAME 候補と次 record を rename 結合できるか判定し、可能なら observation を返す。
fn try_combine_rename(old: &UsnRecord, new: &UsnRecord) -> Option<UsnObservation> {
    // 条件3: NEW_NAME でなければ結合しない。
    if new.reason & flags::RENAME_NEW_NAME == 0 {
        return None;
    }
    // NEW_NAME 側も filename が無ければ結合しない（独立 Event）。
    new.file_name.as_ref()?;
    // 条件1: 同一 file reference。
    if old.file_reference != new.file_reference {
        return None;
    }
    // 条件2: 近接 USN（差が PROXIMATE_USN_DELTA 以下）。
    let delta = (new.usn - old.usn).abs();
    if delta > PROXIMATE_USN_DELTA {
        return None;
    }
    Some(UsnObservation::combined_rename(old.clone(), new.clone()))
}

#[cfg(test)]
mod tests {
    use super::super::header::CommonHeader;
    use super::super::record::{FileReference, UsnRecord};
    use super::*;

    fn rec(version: u16, file_ref: u64, usn: i64, reason: u32, name: Option<&str>) -> UsnRecord {
        UsnRecord {
            header: CommonHeader {
                record_length: 60,
                major_version: version,
                minor_version: 0,
            },
            file_reference: FileReference::V2(file_ref),
            parent_reference: FileReference::V2(file_ref),
            usn,
            time_filetime: 0,
            reason,
            source_info: 0,
            security_id: 0,
            file_attributes: 0,
            file_name: name.map(|s| s.to_string()),
            range_tracking: None,
            record_offset: 0,
        }
    }

    #[test]
    fn rename_pair_same_usn_same_ref_is_combined() {
        let old = rec(2, 0x100, 100, flags::RENAME_OLD_NAME, Some("old.txt"));
        let new = rec(2, 0x100, 100, flags::RENAME_NEW_NAME, Some("new.txt"));
        let obs = combine_records(vec![old, new]);
        assert_eq!(obs.len(), 1);
        assert!(obs[0].rename_combined);
        assert_eq!(obs[0].records.len(), 2);
    }

    #[test]
    fn rename_pair_proximate_usn_delta_1_is_combined() {
        let old = rec(2, 0x100, 100, flags::RENAME_OLD_NAME, Some("old.txt"));
        let new = rec(2, 0x100, 101, flags::RENAME_NEW_NAME, Some("new.txt"));
        let obs = combine_records(vec![old, new]);
        assert_eq!(obs.len(), 1);
        assert!(obs[0].rename_combined);
    }

    #[test]
    fn rename_pair_far_usn_delta_not_combined() {
        let old = rec(2, 0x100, 100, flags::RENAME_OLD_NAME, Some("old.txt"));
        let new = rec(2, 0x100, 110, flags::RENAME_NEW_NAME, Some("new.txt"));
        let obs = combine_records(vec![old, new]);
        assert_eq!(obs.len(), 2, "USN 差 10 は結合しない");
        assert!(!obs[0].rename_combined);
        assert!(!obs[1].rename_combined);
    }

    #[test]
    fn rename_pair_different_ref_not_combined() {
        let old = rec(2, 0x100, 100, flags::RENAME_OLD_NAME, Some("old.txt"));
        let new = rec(2, 0x200, 100, flags::RENAME_NEW_NAME, Some("new.txt"));
        let obs = combine_records(vec![old, new]);
        assert_eq!(obs.len(), 2, "file reference が違えば結合しない");
    }

    #[test]
    fn old_name_alone_becomes_independent_event() {
        let old = rec(2, 0x100, 100, flags::RENAME_OLD_NAME, Some("old.txt"));
        let obs = combine_records(vec![old]);
        assert_eq!(obs.len(), 1);
        assert!(!obs[0].rename_combined);
    }

    #[test]
    fn non_rename_records_stay_independent() {
        let r1 = rec(2, 0x100, 100, flags::FILE_CREATE, Some("a.txt"));
        let r2 = rec(2, 0x200, 101, flags::DATA_EXTEND, Some("b.txt"));
        let obs = combine_records(vec![r1, r2]);
        assert_eq!(obs.len(), 2);
        assert!(obs.iter().all(|o| !o.rename_combined));
    }

    #[test]
    fn rename_pair_split_by_other_record_not_combined() {
        // OLD_NAME → 別ファイル変更 → NEW_NAME は結合しない。
        let old = rec(2, 0x100, 100, flags::RENAME_OLD_NAME, Some("old.txt"));
        let other = rec(2, 0x200, 101, flags::FILE_CREATE, Some("other.txt"));
        let new = rec(2, 0x100, 102, flags::RENAME_NEW_NAME, Some("new.txt"));
        let obs = combine_records(vec![old, other, new]);
        assert_eq!(obs.len(), 3);
        assert!(obs.iter().all(|o| !o.rename_combined));
    }

    #[test]
    fn v4_without_filename_does_not_become_old_candidate() {
        // V4 は filename 無し。OLD_NAME が立っていても候補化しない。
        let mut v4 = rec(4, 0x100, 100, flags::RENAME_OLD_NAME, None);
        v4.file_reference = FileReference::V3V4([0; 16]);
        v4.parent_reference = FileReference::V3V4([0; 16]);
        let obs = combine_records(vec![v4]);
        assert_eq!(obs.len(), 1);
        assert!(!obs[0].rename_combined);
    }
}
