use crate::types::{Region, Signal, SignalKind};

/// Minimum printable-byte run to emit a string signal (small files).
const MIN_LEN: usize = 4;

/// For files larger than this threshold, require longer strings to cut down on
/// noise from raw pixel / sample data.  Each doubling of file size raises the
/// minimum by 4 bytes, capped at 32.
const LARGE_FILE_THRESHOLD: usize = 65_536; // 64 KiB

/// Scan `data` for null-terminated ASCII strings.
///
/// DESIGN rationale: null-terminated strings are structural anchors — they
/// appear at known offsets with known lengths and give semantic hints about
/// surrounding structure (field names, format identifiers, paths, etc.).
/// Confidence scales with length: a 4-char string could be noise; a 20-char
/// string is almost certainly intentional.
/// Effective minimum string length for this file.
///
/// Each doubling of file size above 64 KiB raises the minimum by 4 bytes, capped
/// at 32.  A 27 MB BMP requires strings ≥ 24 bytes; a 256 KB file requires ≥ 8.
fn effective_min_len(file_len: usize) -> usize {
    if file_len <= LARGE_FILE_THRESHOLD {
        return MIN_LEN;
    }
    let doublings = (file_len / LARGE_FILE_THRESHOLD).ilog2() as usize;
    (MIN_LEN + doublings * 4).min(32)
}

pub fn scan_null_terminated(data: &[u8]) -> Vec<Signal> {
    let min_len = effective_min_len(data.len());
    let mut signals = Vec::new();
    let mut i = 0;

    while i < data.len() {
        // Find run of printable ASCII bytes.
        let run_start = i;
        while i < data.len() && is_printable(data[i]) {
            i += 1;
        }
        let run_len = i - run_start;

        // Must be followed by a null terminator and meet minimum length.
        if run_len >= min_len && i < data.len() && data[i] == 0x00 {
            let content = String::from_utf8_lossy(&data[run_start..i]).into_owned();
            let confidence = string_confidence(run_len, min_len);
            let reason = format!(
                "{} printable ASCII bytes followed by null terminator",
                run_len
            );
            // Include the null byte in the region so callers know the full
            // extent consumed by this string (offset + len points past '\0').
            signals.push(Signal::new(
                Region::new(run_start, run_len + 1),
                SignalKind::NullTerminatedString { content },
                confidence,
                reason,
            ));
            i += 1; // skip the null
        } else {
            // Not a qualifying string; advance past whatever stopped us.
            i = i.max(run_start + 1);
        }
    }

    signals
}

fn is_printable(b: u8) -> bool {
    (0x20..=0x7e).contains(&b)
}

/// Confidence in [0.55, 0.95] scaling with string length relative to minimum.
fn string_confidence(len: usize, min_len: usize) -> f64 {
    // min_len chars → 0.55 (could be noise), min_len+28+ chars → 0.95 (very likely real)
    let t = ((len - min_len) as f64 / 28.0).min(1.0);
    0.55 + 0.40 * t
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn finds_simple_string() {
        let data = b"hello\x00";
        let sigs = scan_null_terminated(data);
        assert_eq!(sigs.len(), 1);
        match &sigs[0].kind {
            SignalKind::NullTerminatedString { content } => assert_eq!(content, "hello"),
            _ => panic!("wrong kind"),
        }
        assert_eq!(sigs[0].region, Region::new(0, 6));
    }

    #[test]
    fn ignores_short_strings() {
        let data = b"hi\x00";
        assert!(scan_null_terminated(data).is_empty());
    }

    #[test]
    fn finds_multiple_strings() {
        let data = b"IHDR\x00\x00\x00sRGB\x00";
        let sigs = scan_null_terminated(data);
        assert_eq!(sigs.len(), 2);
    }

    #[test]
    fn non_null_terminated_not_emitted() {
        // printable run but no null at end
        let data = b"hello world";
        assert!(scan_null_terminated(data).is_empty());
    }

    #[test]
    fn mixed_binary_and_strings() {
        let mut data = vec![0xff, 0xfe];
        data.extend_from_slice(b"format_name\x00");
        data.extend_from_slice(&[0x00, 0x01, 0x02]);
        let sigs = scan_null_terminated(&data);
        assert_eq!(sigs.len(), 1);
        assert_eq!(sigs[0].region.offset, 2);
    }
}
