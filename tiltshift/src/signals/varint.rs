use crate::types::{Region, Signal, SignalKind};

/// Minimum consecutive multi-byte LEB128 values to emit a signal.
const LEB128_MIN_MULTIBYTE: usize = 5;
/// Minimum consecutive UTF-8 multi-byte codepoints (no ASCII break) to emit.
const UTF8_MIN_CODEPOINTS: usize = 5;
/// Maximum VarInt signals to emit.  Files saturated with high bytes (compressed
/// data, 16-bit pixel samples) can produce hundreds of thousands of LEB128 runs;
/// cap to keep session caches manageable.
const MAX_VARINT_SIGNALS: usize = 500;

/// Scan for variable-length integer encoding patterns.
///
/// Detects two encodings:
///
/// **LEB128 unsigned** — sequences of Little-Endian Base-128 integers where
/// multiple consecutive values are multi-byte (start with a continuation byte
/// 0x80–0xFF, end with a terminal byte 0x00–0x7F).  Common in WebAssembly
/// sections, protobuf wire format, DWARF debug info, Android DEX, and other
/// compact binary formats.  Only multi-byte values are counted — single-byte
/// LEB128 (any byte < 0x80) is too common to be a useful signal on its own.
///
/// **UTF-8 multi-byte runs** — consecutive non-ASCII UTF-8 characters (2–4
/// bytes each) with no ASCII bytes between them.  Suggests an internationalized
/// string field or a dense block of CJK / non-Latin text embedded in a binary
/// format.
pub fn scan_varint(data: &[u8]) -> Vec<Signal> {
    let mut signals = Vec::new();
    scan_leb128(data, &mut signals);
    scan_utf8_multibyte(data, &mut signals);
    signals
}

// ── LEB128 ───────────────────────────────────────────────────────────────────

/// Decode one unsigned LEB128 value at `data[pos]`.
/// Returns `(decoded_value, bytes_consumed)` or `None` if malformed / truncated.
/// Capped at 10 bytes (70 bits; anything longer is treated as malformed).
fn decode_leb128_u(data: &[u8], pos: usize) -> Option<(u64, usize)> {
    let mut value: u64 = 0;
    let mut shift = 0u32;
    for (k, &byte) in data[pos..].iter().enumerate() {
        if k >= 10 {
            return None; // too many continuation bytes
        }
        value |= ((byte & 0x7F) as u64) << shift;
        shift += 7;
        if byte & 0x80 == 0 {
            return Some((value, k + 1));
        }
    }
    None // truncated mid-value
}

fn scan_leb128(data: &[u8], out: &mut Vec<Signal>) {
    let start_len = out.len();
    let mut i = 0;
    while i < data.len() {
        if out.len() - start_len >= MAX_VARINT_SIGNALS {
            break;
        }
        // Only start a run at a continuation byte (MSB=1) — first byte of a
        // multi-byte LEB128 value.  Single-byte values (< 0x80) are skipped.
        if data[i] & 0x80 == 0 {
            i += 1;
            continue;
        }

        let run_start = i;
        let mut j = i;
        let mut count = 0usize;

        loop {
            // Require each value in the run to start with a continuation byte.
            if j >= data.len() || data[j] & 0x80 == 0 {
                break;
            }
            match decode_leb128_u(data, j) {
                Some((_, width)) if width >= 2 => {
                    count += 1;
                    j += width;
                }
                _ => break,
            }
        }

        if count >= LEB128_MIN_MULTIBYTE {
            let run_bytes = j - run_start;
            let avg_width = run_bytes as f64 / count as f64;
            let reason = format!(
                "{count} consecutive multi-byte LEB128 values \
                 ({run_bytes} bytes, avg {avg_width:.1} bytes/value)"
            );
            out.push(Signal::new(
                Region::new(run_start, run_bytes),
                SignalKind::VarInt {
                    encoding: "leb128-unsigned".to_string(),
                    count,
                    bytes_consumed: run_bytes,
                    avg_width,
                },
                leb128_confidence(count),
                reason,
            ));
            i = j;
        } else {
            i += 1;
        }
    }
}

fn leb128_confidence(count: usize) -> f64 {
    // 5 values → 0.55; 20+ values → 0.80
    let t = ((count - LEB128_MIN_MULTIBYTE) as f64 / 15.0).min(1.0);
    0.55 + 0.25 * t
}

// ── UTF-8 multi-byte ─────────────────────────────────────────────────────────

/// Decode one UTF-8 multi-byte codepoint (non-ASCII) starting at `data[pos]`.
/// Returns `bytes_consumed` (2, 3, or 4) or `None` for ASCII or invalid bytes.
fn decode_utf8_multibyte(data: &[u8], pos: usize) -> Option<usize> {
    let b0 = *data.get(pos)?;
    let (width, min_cp): (usize, u32) = match b0 {
        0xC2..=0xDF => (2, 0x80),
        0xE0..=0xEF => (3, 0x800),
        0xF0..=0xF4 => (4, 0x10000),
        _ => return None, // ASCII (< 0x80) or invalid/overlong lead byte
    };
    if pos + width > data.len() {
        return None;
    }
    for &b in &data[pos + 1..pos + width] {
        if !(0x80..=0xBF).contains(&b) {
            return None; // invalid continuation byte
        }
    }
    // Decode and validate the codepoint
    let mask: u8 = match width {
        2 => 0x1F,
        3 => 0x0F,
        _ => 0x07,
    };
    let mut cp = (b0 & mask) as u32;
    for &b in &data[pos + 1..pos + width] {
        cp = (cp << 6) | ((b & 0x3F) as u32);
    }
    if cp < min_cp || cp > 0x10FFFF || (0xD800..=0xDFFF).contains(&cp) {
        return None; // overlong, surrogate half, or out-of-range
    }
    Some(width)
}

fn scan_utf8_multibyte(data: &[u8], out: &mut Vec<Signal>) {
    let start_len = out.len();
    let mut i = 0;
    while i < data.len() {
        if out.len() - start_len >= MAX_VARINT_SIGNALS {
            break;
        }
        let run_start = i;
        let mut count = 0usize;

        while let Some(w) = decode_utf8_multibyte(data, i) {
            count += 1;
            i += w;
        }

        if count >= UTF8_MIN_CODEPOINTS {
            let run_bytes = i - run_start;
            let avg_width = run_bytes as f64 / count as f64;
            let reason = format!(
                "{count} consecutive UTF-8 multi-byte codepoints \
                 ({run_bytes} bytes, avg {avg_width:.1} bytes/char)"
            );
            out.push(Signal::new(
                Region::new(run_start, run_bytes),
                SignalKind::VarInt {
                    encoding: "utf8-multibyte".to_string(),
                    count,
                    bytes_consumed: run_bytes,
                    avg_width,
                },
                utf8_confidence(count),
                reason,
            ));
        } else if i == run_start {
            i += 1;
        }
    }
}

fn utf8_confidence(count: usize) -> f64 {
    // 5 chars → 0.70; 20+ chars → 0.88
    let t = ((count - UTF8_MIN_CODEPOINTS) as f64 / 15.0).min(1.0);
    0.70 + 0.18 * t
}

#[cfg(test)]
mod tests {
    use super::*;

    // ── decode_leb128_u ───────────────────────────────────────────────────────

    #[test]
    fn leb128_single_byte() {
        assert_eq!(decode_leb128_u(b"\x05", 0), Some((5, 1)));
        assert_eq!(decode_leb128_u(b"\x7F", 0), Some((127, 1)));
    }

    #[test]
    fn leb128_two_bytes() {
        // 0x80 0x01 = 128
        assert_eq!(decode_leb128_u(b"\x80\x01", 0), Some((128, 2)));
    }

    #[test]
    fn leb128_three_bytes_wikipedia_example() {
        // 624485 encoded as E5 8E 26
        assert_eq!(decode_leb128_u(b"\xe5\x8e\x26", 0), Some((624_485, 3)));
    }

    #[test]
    fn leb128_truncated_returns_none() {
        // Continuation byte with no terminal
        assert_eq!(decode_leb128_u(b"\x80", 0), None);
    }

    #[test]
    fn leb128_too_long_returns_none() {
        // 11 continuation bytes — exceeds 10-byte cap
        let data = vec![0x80u8; 11];
        assert_eq!(decode_leb128_u(&data, 0), None);
    }

    // ── scan_leb128 ───────────────────────────────────────────────────────────

    #[test]
    fn detects_leb128_run() {
        // 5 consecutive 2-byte LEB128 values (0x80 0x01 = 128, repeated)
        let mut data = Vec::new();
        for _ in 0..5 {
            data.extend_from_slice(&[0x80, 0x01]);
        }
        let sigs = scan_varint(&data);
        let leb: Vec<_> = sigs
            .iter()
            .filter(|s| {
                matches!(&s.kind, SignalKind::VarInt { encoding, .. } if encoding == "leb128-unsigned")
            })
            .collect();
        assert_eq!(leb.len(), 1);
        match &leb[0].kind {
            SignalKind::VarInt {
                count,
                bytes_consumed,
                ..
            } => {
                assert_eq!(*count, 5);
                assert_eq!(*bytes_consumed, 10);
            }
            _ => panic!("wrong kind"),
        }
    }

    #[test]
    fn leb128_ignores_run_below_min() {
        // Only 4 multi-byte values — below LEB128_MIN_MULTIBYTE
        let mut data = Vec::new();
        for _ in 0..4 {
            data.extend_from_slice(&[0x80, 0x01]);
        }
        let sigs = scan_varint(&data);
        assert!(sigs
            .iter()
            .all(|s| !matches!(&s.kind, SignalKind::VarInt { encoding, .. } if encoding == "leb128-unsigned")));
    }

    #[test]
    fn leb128_ignores_single_byte_only() {
        // All bytes < 0x80 — single-byte LEB128 only, no multi-byte
        let data = vec![0x42u8; 32];
        let sigs = scan_varint(&data);
        assert!(sigs
            .iter()
            .all(|s| !matches!(&s.kind, SignalKind::VarInt { encoding, .. } if encoding == "leb128-unsigned")));
    }

    #[test]
    fn leb128_confidence_increases_with_count() {
        assert!(leb128_confidence(20) > leb128_confidence(LEB128_MIN_MULTIBYTE));
    }

    // ── decode_utf8_multibyte ─────────────────────────────────────────────────

    #[test]
    fn utf8_decodes_two_byte() {
        // U+00E9 'é' = C3 A9
        assert_eq!(decode_utf8_multibyte(b"\xC3\xA9", 0), Some(2));
    }

    #[test]
    fn utf8_decodes_three_byte() {
        // U+4E2D '中' = E4 B8 AD
        assert_eq!(decode_utf8_multibyte(b"\xE4\xB8\xAD", 0), Some(3));
    }

    #[test]
    fn utf8_decodes_four_byte() {
        // U+1F600 😀 = F0 9F 98 80
        assert_eq!(decode_utf8_multibyte(b"\xF0\x9F\x98\x80", 0), Some(4));
    }

    #[test]
    fn utf8_rejects_ascii() {
        assert_eq!(decode_utf8_multibyte(b"\x41", 0), None);
    }

    #[test]
    fn utf8_rejects_invalid_continuation() {
        // 0xC3 followed by a non-continuation byte
        assert_eq!(decode_utf8_multibyte(b"\xC3\x28", 0), None);
    }

    #[test]
    fn utf8_rejects_overlong_lead() {
        // 0xC0 and 0xC1 are disallowed lead bytes (overlong ASCII range)
        assert_eq!(decode_utf8_multibyte(b"\xC0\x80", 0), None);
        assert_eq!(decode_utf8_multibyte(b"\xC1\xBF", 0), None);
    }

    #[test]
    fn utf8_rejects_surrogate() {
        // U+D800 = ED A0 80
        assert_eq!(decode_utf8_multibyte(b"\xED\xA0\x80", 0), None);
    }

    // ── scan_utf8_multibyte ───────────────────────────────────────────────────

    #[test]
    fn detects_cjk_run() {
        // 6 CJK characters → each 3 bytes
        let s = "中文日本語한";
        let sigs = scan_varint(s.as_bytes());
        let utf8: Vec<_> = sigs
            .iter()
            .filter(|s| {
                matches!(&s.kind, SignalKind::VarInt { encoding, .. } if encoding == "utf8-multibyte")
            })
            .collect();
        assert_eq!(utf8.len(), 1);
        match &utf8[0].kind {
            SignalKind::VarInt { count, .. } => assert!(*count >= 5),
            _ => panic!("wrong kind"),
        }
    }

    #[test]
    fn utf8_ignores_run_below_min() {
        // Only 3 multi-byte codepoints — below UTF8_MIN_CODEPOINTS
        let s = "日本語"; // 3 chars
        let sigs = scan_varint(s.as_bytes());
        assert!(sigs
            .iter()
            .all(|s| !matches!(&s.kind, SignalKind::VarInt { encoding, .. } if encoding == "utf8-multibyte")));
    }

    #[test]
    fn utf8_ignores_plain_ascii() {
        let sigs = scan_varint(b"hello world this is a long string of plain ASCII bytes");
        assert!(sigs
            .iter()
            .all(|s| !matches!(&s.kind, SignalKind::VarInt { encoding, .. } if encoding == "utf8-multibyte")));
    }

    #[test]
    fn utf8_confidence_increases_with_count() {
        assert!(utf8_confidence(20) > utf8_confidence(UTF8_MIN_CODEPOINTS));
    }

    // ── misc ──────────────────────────────────────────────────────────────────

    #[test]
    fn no_signals_for_empty() {
        assert!(scan_varint(&[]).is_empty());
    }
}
