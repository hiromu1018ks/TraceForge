//! CRC-32（IEEE 802.3 polynomial 反転、EVTX header / chunk checksum 検証用、T4-040）。
//!
//! EVTX file header（offset 124）・chunk header（offset 504）・records checksum（offset 52）
//! は全て CRC-32（初期値 0xFFFFFFFF・最終 XOR 0xFFFFFFFF・多項式 0xEDB88320）を用いる。
//!
//! 外部依存 crate を増やさず、純 Rust で実装する（PROMPT.md 制約: 新依存追加なし）。

/// CRC-32 多項式の反転表現（bit-reversed 0x04C11DB7）。
const CRC32_POLY: u32 = 0xEDB88320;

/// CRC-32 を計算する（IEEE 802.3 / libyal libevtx の checksum と同一算法）。
///
/// 初期値 `0xFFFFFFFF`、最終 XOR `0xFFFFFFFF`、bit-reversed polynomial。
/// EVTX の各 checksum は全てこの算法で求まる。
pub fn crc32(data: &[u8]) -> u32 {
    let mut crc: u32 = 0xFFFF_FFFF;
    for &b in data {
        crc ^= b as u32;
        for _ in 0..8 {
            if crc & 1 != 0 {
                crc = (crc >> 1) ^ CRC32_POLY;
            } else {
                crc >>= 1;
            }
        }
    }
    !crc
}

/// 2 つの slice を連結した上で CRC-32 を計算する。
///
/// EVTX の一部 checksum は「bytes 0..N1 と N2..N3 のように途中を飛ばした領域」を
/// cover する。本関数は2つの連続 slice へ適用できるよう、first と second を結合した
/// 扱いで CRC を算出する（両者を1つの stream として扱う）。
pub fn crc32_sequential(first: &[u8], second: &[u8]) -> u32 {
    let mut crc: u32 = 0xFFFF_FFFF;
    for &b in first {
        crc = crc32_update(crc, b);
    }
    for &b in second {
        crc = crc32_update(crc, b);
    }
    !crc
}

fn crc32_update(mut crc: u32, b: u8) -> u32 {
    crc ^= b as u32;
    for _ in 0..8 {
        if crc & 1 != 0 {
            crc = (crc >> 1) ^ CRC32_POLY;
        } else {
            crc >>= 1;
        }
    }
    crc
}

#[cfg(test)]
mod tests {
    use super::*;

    /// RFC 3385 / IEEE 規格のテストベクタ: "123456789" → 0xCBF43926。
    #[test]
    fn crc32_known_vector() {
        let v = crc32(b"123456789");
        assert_eq!(v, 0xCBF4_3926);
    }

    /// 空文字列は 0。
    #[test]
    fn crc32_empty() {
        let v = crc32(b"");
        assert_eq!(v, 0);
    }

    /// sequential 版が単一 slice 版と一致することを確認。
    #[test]
    fn crc32_sequential_matches_single_slice() {
        let combined = b"Hello, world!";
        let (a, b) = combined.split_at(7);
        assert_eq!(crc32_sequential(a, b), crc32(combined));
    }

    /// EVTX の header checksum 計算（bytes 0..120 + bytes 128..4096）の動作確認。
    #[test]
    fn crc32_sequential_models_evtx_header_layout() {
        let mut buf = vec![0u8; 4096];
        for (i, b) in buf.iter_mut().enumerate() {
            *b = (i & 0xFF) as u8;
        }
        // bytes 0..120 + bytes 128..4096 を cover。
        let computed = crc32_sequential(&buf[0..120], &buf[128..4096]);
        // 同じ内容を1つの slice へ詰め直して計算した値と一致する。
        let mut flattened = Vec::new();
        flattened.extend_from_slice(&buf[0..120]);
        flattened.extend_from_slice(&buf[128..4096]);
        assert_eq!(computed, crc32(&flattened));
    }
}
