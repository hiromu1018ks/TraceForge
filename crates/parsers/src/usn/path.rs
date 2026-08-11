//! path reconstruction（互換 §4.3、T4-035）。
//!
//! 互換 §4.3:
//! > USN path reconstruction は、同じ Evidence set 内に安全に利用できる
//! > 親 directory mapping がある場合だけ行う。取得できない親を host filesystem
//! > から検索してはならない。
//!
//! ## 設計
//!
//! 1. `$J` ストリーム内の全 record を走査し、`file_reference → (filename, parent_reference)`
//!    の mapping を構築する。これが「安全に利用できる親 directory mapping」。
//!    V4 は filename を持たないため mapping へ加えられない（他 record の親として参照される
//!    ことはあるが、自身の名前は解決できない）。
//! 2. 各 observation について、自身の名前 + 親を再帰的に辿って path を組み立てる。
//! 3. 解決できない親が現れたら、そこで止めて partial path を返す（host の MFT 等へ
//!    検索しに行かない、規範 §8）。ループを防ぐため深さは内部上限（32 段）まで。

use std::collections::HashMap;

use tf_core::WindowsPathValue;

use crate::usn::combine::UsnObservation;
use crate::usn::record::{FileReference, UsnRecord};

/// 親 directory の再帰解決の最大深さ。これを超えたら打ち切る（ループ回避）。
const MAX_DEPTH: usize = 32;

/// 1件の file reference に対応する名前と親参照。
#[derive(Clone, Debug)]
struct NameEntry {
    name: String,
    parent: FileReference,
}

/// `$J` ストリーム全体の file reference → (name, parent) mapping。
/// 同一 Evidence set 内でのみ構築する（host filesystem へ検索しない、互換 §4.3）。
#[derive(Clone, Debug, Default)]
pub struct PathResolver {
    name_map: HashMap<FileReference, NameEntry>,
}

impl PathResolver {
    /// record 列から resolver を構築する。
    /// 同一 reference が複数回出現する場合（rename 等）は最初の出現を採用する。
    pub fn from_records<'a>(records: impl Iterator<Item = &'a UsnRecord>) -> Self {
        let mut name_map: HashMap<FileReference, NameEntry> = HashMap::new();
        for r in records {
            // V4 は filename が無い。name_map へ加えない。
            if let Some(name) = &r.file_name
                && !name.is_empty()
            {
                name_map
                    .entry(r.file_reference.clone())
                    .or_insert(NameEntry {
                        name: name.clone(),
                        parent: r.parent_reference.clone(),
                    });
            }
        }
        PathResolver { name_map }
    }

    /// observation から path を構築する。
    /// 自身の名前が無い（V4）場合は [`None`] を返す（断定的な path を推測しない、規範 §8）。
    /// 親が mapping に無い場合は、自身の名前だけを path として返す（host 検索禁止）。
    pub fn resolve(&self, observation: &UsnObservation) -> Option<WindowsPathValue> {
        let first = observation.first();
        let self_name = first.file_name.clone()?;

        // コンポーネントを子→親の順に集める。
        let mut components: Vec<String> = vec![self_name];
        // 訪問済み reference（ループ回避）。
        let mut visited: Vec<FileReference> = Vec::new();
        let mut current_ref = first.parent_reference.clone();

        for _ in 0..MAX_DEPTH {
            if visited.contains(&current_ref) {
                break;
            }
            visited.push(current_ref.clone());
            let Some(entry) = self.name_map.get(&current_ref) else {
                break;
            };
            if entry.name.is_empty() {
                break;
            }
            components.push(entry.name.clone());
            current_ref = entry.parent.clone();
        }

        // 子→親の順で集めたので、親→子（NTFS の左から右）へ反転。
        components.reverse();
        let joined = components.join("\\");
        Some(WindowsPathValue::new(joined))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::usn::combine::UsnObservation;
    use crate::usn::header::CommonHeader;
    use crate::usn::record::{FileReference, UsnRecord};

    fn rec(file_ref: u64, parent: u64, name: Option<&str>) -> UsnRecord {
        UsnRecord {
            header: CommonHeader {
                record_length: 60,
                major_version: 2,
                minor_version: 0,
            },
            file_reference: FileReference::V2(file_ref),
            parent_reference: FileReference::V2(parent),
            usn: 0,
            time_filetime: 0,
            reason: 0,
            source_info: 0,
            security_id: 0,
            file_attributes: 0,
            file_name: name.map(|s| s.to_string()),
            range_tracking: None,
            record_offset: 0,
        }
    }

    #[test]
    fn empty_records_make_empty_resolver() {
        let r = PathResolver::from_records(std::iter::empty());
        assert!(r.name_map.is_empty());
    }

    #[test]
    fn resolve_self_name_only_when_parent_unknown() {
        // 親 dir の record が Evidence set 内に無い。
        let file = rec(0x100, 0x50, Some("note.txt"));
        let resolver = PathResolver::from_records(std::iter::once(&file));
        let observation = UsnObservation::single(file);
        let path = resolver.resolve(&observation).unwrap();
        // 親が解決できなければ自身の名前のみ。
        assert_eq!(path.original, "note.txt");
    }

    #[test]
    fn resolve_one_level_parent() {
        let dir = rec(0x50, 0x05, Some("Docs"));
        let file = rec(0x100, 0x50, Some("note.txt"));
        let resolver = PathResolver::from_records([&dir, &file].into_iter());
        let observation = UsnObservation::single(file);
        let path = resolver.resolve(&observation).unwrap();
        assert_eq!(path.original, "Docs\\note.txt");
    }

    #[test]
    fn resolve_multi_level_parent() {
        // 3階層: root(05) → Windows → System32 → kernel32.dll
        let win = rec(0x10, 0x05, Some("Windows"));
        let sys = rec(0x20, 0x10, Some("System32"));
        let dll = rec(0x30, 0x20, Some("kernel32.dll"));
        let resolver = PathResolver::from_records([&win, &sys, &dll].into_iter());
        let observation = UsnObservation::single(dll);
        let path = resolver.resolve(&observation).unwrap();
        assert_eq!(path.original, "Windows\\System32\\kernel32.dll");
    }

    #[test]
    fn resolve_stops_at_missing_parent() {
        // 中間の親 (System32) が mapping に無い場合はそこで止まる。
        let win = rec(0x10, 0x05, Some("Windows"));
        let dll = rec(0x30, 0x20, Some("kernel32.dll")); // 0x20 は記録無し
        let resolver = PathResolver::from_records([&win, &dll].into_iter());
        let observation = UsnObservation::single(dll);
        let path = resolver.resolve(&observation).unwrap();
        // 0x20 が解決できないため、dll 名のみ。
        assert_eq!(path.original, "kernel32.dll");
    }

    #[test]
    fn resolve_returns_none_for_v4_without_filename() {
        // V4 は filename 無し。path 構築不可。
        let mut v4 = rec(0x100, 0x50, None);
        v4.header.major_version = 4;
        v4.file_reference = FileReference::V3V4([0; 16]);
        v4.parent_reference = FileReference::V3V4([0; 16]);
        let resolver = PathResolver::from_records(std::iter::once(&v4));
        let observation = UsnObservation::single(v4);
        assert!(resolver.resolve(&observation).is_none());
    }

    #[test]
    fn resolve_handles_reference_loop_safely() {
        // A の親が B、B の親が A（あり得ないが安全確認）。
        let a = rec(0x10, 0x20, Some("A"));
        let b = rec(0x20, 0x10, Some("B"));
        let resolver = PathResolver::from_records([&a, &b].into_iter());
        let observation = UsnObservation::single(a);
        // ループしても panic せず、何らかの path が返る。
        let path = resolver.resolve(&observation).unwrap();
        assert!(!path.original.is_empty());
    }
}
