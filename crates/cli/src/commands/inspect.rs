//! `traceforge inspect <file>` command（製品 §12・T7-029）。
//!
//! 単一 Evidence / Artifact file の安全な概要を stdout へ出力する。
//! 読み取り専用・実行しない・内容を推測しない（規範 §2・§5.5）。

use std::fs;
use std::path::Path;

use sha2::{Digest, Sha256};
use tf_core::error::ExitCode;

use crate::args::InspectArgs;
use crate::commands::CommandResult;
use crate::runtime::RunContext;

/// `inspect` command の実行。
pub fn run(args: &InspectArgs, _ctx: &mut RunContext) -> CommandResult {
    let path = Path::new(&args.file);
    if !path.exists() {
        return CommandResult::err(
            ExitCode::InputOrDiscoveryError,
            format!("file が存在しない: {}", path.display()),
        );
    }

    let meta = match fs::symlink_metadata(path) {
        Ok(m) => m,
        Err(e) => {
            return CommandResult::err(
                ExitCode::InputOrDiscoveryError,
                format!("metadata 取得失敗: {e}"),
            );
        }
    };
    if meta.is_symlink() {
        return CommandResult::err(
            ExitCode::InputOrDiscoveryError,
            "symlink は inspect できない（規範 §5.3・§5.5）".to_string(),
        );
    }

    let is_dir = meta.is_dir();
    let size = meta.len();

    let mut stdout = String::new();
    stdout.push_str(&format!("file: {}\n", path.display()));
    stdout.push_str(&format!("size: {} bytes\n", size));
    stdout.push_str(&format!("is_directory: {}\n", is_dir));
    stdout.push_str("read_only: true（規範 §2）\n");

    if is_dir {
        stdout.push_str("sha256: (directory は hash 対象外)\n");
        stdout.push_str(
            "note: directory の中身を再帰的に表示しない（inspect は単一 file の概要のみ）\n",
        );
    } else {
        // file の SHA-256 を計算（規範 §2: SHA-256 mandatory）。
        match fs::read(path) {
            Ok(bytes) => {
                let mut hasher = Sha256::new();
                hasher.update(&bytes);
                let digest = hex::encode(hasher.finalize());
                stdout.push_str(&format!("sha256: {digest}\n"));
                // magic 判定（先頭数 byte を見て Evidence 種別を推定）。
                if bytes.len() >= 8 {
                    stdout.push_str(&format!(
                        "magic (first 8 bytes hex): {}\n",
                        bytes
                            .iter()
                            .take(8)
                            .map(|b| format!("{b:02x}"))
                            .collect::<String>()
                    ));
                }
                if let Some(kind) = detect_artifact_kind(&bytes) {
                    stdout.push_str(&format!("probable_kind: {kind}\n"));
                }
            }
            Err(e) => {
                return CommandResult::err(
                    ExitCode::InputOrDiscoveryError,
                    format!("file 読込失敗: {e}"),
                );
            }
        }
    }

    // Evidence として扱う場合は `analyze` command を推奨。
    stdout.push_str("\nhint: 詳細な解析は `traceforge analyze` を使用してください。\n");

    CommandResult::ok_with_stdout(stdout)
}

/// 先頭 bytes から Evidence 種別を推定する（補助情報・確定ではない）。
fn detect_artifact_kind(bytes: &[u8]) -> Option<&'static str> {
    if bytes.len() >= 8 && &bytes[..8] == b"ElfFile\x00" {
        return Some("unknown-elf");
    }
    // EVTX file header: "ElfFile\0" + 1 byte version + ...
    if bytes.len() >= 8 && &bytes[..7] == b"ElfFile" {
        return Some("evtx");
    }
    // Windows Registry hive: "regf" magic。
    if bytes.len() >= 4 && &bytes[..4] == b"regf" {
        return Some("registry-hive");
    }
    // CFB container（Jump Lists AutomaticDestinations）: D0 CF 11 E0 A1 B1 1A E1
    if bytes.len() >= 8 && bytes[..8] == [0xd0, 0xcf, 0x11, 0xe0, 0xa1, 0xb1, 0x1a, 0xe1] {
        return Some("cfb-container (jump-list?)");
    }
    // LNK: 先頭4 byte が 0x4C 0x00 0x00 0x00。
    if bytes.len() >= 4 && bytes[..4] == [0x4c, 0x00, 0x00, 0x00] {
        return Some("lnk (推定)");
    }
    // Prefetch: MAM header (SCCA)。
    if bytes.len() >= 4 && (&bytes[..4] == b"MAMA" || &bytes[..4] == b"MAM\x00") {
        return Some("prefetch (MAM 圧縮の可能性)");
    }
    None
}
