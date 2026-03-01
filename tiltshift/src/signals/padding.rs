use crate::types::{Region, Signal, SignalKind};

/// Minimum consecutive bytes to qualify as a padding run.
const MIN_RUN: usize = 4;

/// Scan `data` for runs of 0x00 or 0xFF long enough to be structural padding.
///
/// DESIGN rationale: alignment padding and struct spacers frequently manifest
/// as runs of a single repeated byte — usually 0x00 (zero-fill) or 0xFF
/// (erase-state fill for flash memory / ROM images). Runs of 4+ bytes are
/// uncommon in random data and serve as reliable structural anchors.
/// Confidence scales with run length; very long runs (≥ 64 bytes) are almost
/// certainly intentional.
pub fn scan_padding(data: &[u8]) -> Vec<Signal> {
    let mut signals = Vec::new();
    let mut i = 0;

    while i < data.len() {
        let b = data[i];
        if b != 0x00 && b != 0xFF {
            i += 1;
            continue;
        }

        // Extend the run.
        let run_start = i;
        while i < data.len() && data[i] == b {
            i += 1;
        }
        let run_len = i - run_start;

        if run_len >= MIN_RUN {
            let label = if b == 0x00 { "zero-fill" } else { "0xFF-fill" };
            let reason = format!("{run_len}-byte {label} run");
            signals.push(Signal::new(
                Region::new(run_start, run_len),
                SignalKind::Padding {
                    byte_value: b,
                    run_len,
                },
                padding_confidence(run_len),
                reason,
            ));
        }
    }

    signals
}

/// Confidence in [0.60, 0.95] scaling with run length.
fn padding_confidence(len: usize) -> f64 {
    // 4 bytes → 0.60, 64+ bytes → 0.95
    let t = ((len - MIN_RUN) as f64 / 60.0).min(1.0);
    0.60 + 0.35 * t
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detects_zero_run() {
        let data = [0x00u8; 8];
        let sigs = scan_padding(&data);
        assert_eq!(sigs.len(), 1);
        match &sigs[0].kind {
            SignalKind::Padding {
                byte_value,
                run_len,
            } => {
                assert_eq!(*byte_value, 0x00);
                assert_eq!(*run_len, 8);
            }
            _ => panic!("wrong kind"),
        }
        assert_eq!(sigs[0].region, Region::new(0, 8));
    }

    #[test]
    fn detects_ff_run() {
        let data = [0xFFu8; 16];
        let sigs = scan_padding(&data);
        assert_eq!(sigs.len(), 1);
        match &sigs[0].kind {
            SignalKind::Padding {
                byte_value,
                run_len,
            } => {
                assert_eq!(*byte_value, 0xFF);
                assert_eq!(*run_len, 16);
            }
            _ => panic!("wrong kind"),
        }
    }

    #[test]
    fn ignores_short_run() {
        let mut data = vec![0x01u8, 0x02];
        data.extend_from_slice(&[0x00u8; 3]); // only 3 zeros
        data.extend_from_slice(&[0x03u8, 0x04]);
        assert!(scan_padding(&data).is_empty());
    }

    #[test]
    fn ignores_non_padding_bytes() {
        // 0xAA is not a padding byte
        let data = [0xAAu8; 16];
        assert!(scan_padding(&data).is_empty());
    }

    #[test]
    fn finds_multiple_runs() {
        let mut data = vec![0x01u8];
        data.extend_from_slice(&[0x00u8; 8]);
        data.push(0x42);
        data.extend_from_slice(&[0xFFu8; 12]);
        let sigs = scan_padding(&data);
        assert_eq!(sigs.len(), 2);
        assert_eq!(sigs[0].region.offset, 1);
        assert_eq!(sigs[1].region.offset, 10); // 1 + 8 zeros + 1 = 10
    }

    #[test]
    fn confidence_scales_with_length() {
        let short = [0x00u8; 4];
        let long = [0x00u8; 64];
        let short_conf = scan_padding(&short)[0].confidence;
        let long_conf = scan_padding(&long)[0].confidence;
        assert!(long_conf > short_conf);
        assert!((short_conf - 0.60).abs() < 1e-9);
        assert!((long_conf - 0.95).abs() < 1e-9);
    }

    #[test]
    fn min_run_exactly_four() {
        let data = [0x00u8; 4];
        assert_eq!(scan_padding(&data).len(), 1);
    }
}
