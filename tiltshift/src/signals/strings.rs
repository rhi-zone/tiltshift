use crate::types::{Region, Signal, SignalKind};

/// Minimum printable-byte run to emit a string signal.
const MIN_LEN: usize = 4;

/// Scan `data` for null-terminated ASCII strings.
///
/// DESIGN rationale: null-terminated strings are structural anchors — they
/// appear at known offsets with known lengths and give semantic hints about
/// surrounding structure (field names, format identifiers, paths, etc.).
/// Confidence scales with length: a 4-char string could be noise; a 20-char
/// string is almost certainly intentional.
pub fn scan_null_terminated(data: &[u8]) -> Vec<Signal> {
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
        if run_len >= MIN_LEN && i < data.len() && data[i] == 0x00 {
            let content = String::from_utf8_lossy(&data[run_start..i]).into_owned();
            let confidence = string_confidence(run_len);
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

/// Confidence in [0.55, 0.95] scaling with string length.
fn string_confidence(len: usize) -> f64 {
    // 4 chars → 0.55 (could be noise), 32+ chars → 0.95 (very likely real)
    let t = ((len - MIN_LEN) as f64 / 28.0).min(1.0);
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
