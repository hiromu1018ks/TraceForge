//! SHA-256 lowercase hex digest ユーティリティ（Schema §2.1、規範 §12）。
//!
//! TraceForge の決定的 ID は全て SHA-256 の 64 文字 lowercase hex を suffix とする
//! （規範 §12.1）。本モジュールは hash 入力 bytes からその suffix への変換と、
//! digest 文字列の検証を提供する。

use sha2::{Digest, Sha256};

/// `bytes` の SHA-256 を計算し、64 文字 lowercase hex 文字列を返す（Schema §2.1）。
///
/// `sha2::Sha256` で digest を計算し、`hex::encode` で lowercase hex へ変換する。
/// 出力は常に 64 文字の `[0-9a-f]` となり、[`is_lowercase_sha256_hex`] を満たす。
pub fn sha256_hex(bytes: &[u8]) -> String {
    let digest = Sha256::digest(bytes);
    hex::encode(digest)
}

/// 文字列が 64 文字 lowercase hex であるか検証する（Schema §2.1）。
///
/// 大文字 hex や 64 文字以外の長さを拒否する。
pub fn is_lowercase_sha256_hex(s: &str) -> bool {
    s.len() == 64
        && s.bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// SHA-256 は常に 64 文字 lowercase hex（Schema §2.1）。
    #[test]
    fn sha256_hex_is_lowercase_64() {
        let got = sha256_hex(b"");
        // 空入力の SHA-256 は既知の定数値。
        assert_eq!(
            got,
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
        assert!(is_lowercase_sha256_hex(&got));
    }

    #[test]
    fn sha256_hex_deterministic() {
        // 同一入力は同一 digest（決定性、規範 §13）。
        assert_eq!(sha256_hex(b"traceforge"), sha256_hex(b"traceforge"));
    }

    #[test]
    fn is_lowercase_sha256_hex_rejects_uppercase() {
        assert!(!is_lowercase_sha256_hex("ABCDEF"));
        assert!(!is_lowercase_sha256_hex(
            &"E3B0C44298FC1C149AFBF4C8996FB92427AE41E4649B934CA495991B7852B855"
                .to_lowercase()
                .to_uppercase()
        ));
    }
}
