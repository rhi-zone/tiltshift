//! Length-prefixed blob detector.
//!
//! Scans for u8 / u16 (LE+BE) / u32 (LE+BE) length prefixes whose declared
//! body length is in-bounds and is followed by plausible (mostly non-null)
//! data.  Strong signal when the body is printable ASCII — that combination
//! strongly suggests a length-prefixed string (Pascal string, DNS label, etc.).

use crate::types::{Region, Signal, SignalKind};

/// Minimum body length to emit a signal (avoid single-byte noise).
const MIN_BODY: usize = 4;

/// Stricter minimum for u8 prefixes, which fire very frequently by chance.
const MIN_BODY_U8: usize = 8;

/// Scan `data` for length-prefixed blobs.
///
/// For each prefix variant (u8, u16le, u16be, u32le, u32be) at every offset,
/// read the declared length N, check that the body fits in `data`, and assess
/// body quality.  Low-quality or out-of-bounds candidates are dropped.
pub fn scan_length_prefixed(data: &[u8]) -> Vec<Signal> {
    let mut signals = Vec::new();
    let len = data.len();

    for offset in 0..len {
        // ── u8 prefix ────────────────────────────────────────────────────────
        {
            let n = data[offset] as usize;
            if n >= MIN_BODY_U8 && offset + 1 + n <= len {
                let body = &data[offset + 1..offset + 1 + n];
                let (non_null, printable) = body_quality(body);
                // Stricter quality gate for u8: body must be almost entirely
                // printable, since a random byte ≥ 8 followed by 8+ non-null
                // bytes is extremely common otherwise.
                if non_null >= 0.90 && printable >= 0.85 {
                    let conf = confidence_u8(n, printable);
                    signals.push(Signal::new(
                        Region::new(offset, 1 + n),
                        SignalKind::LengthPrefixedBlob {
                            prefix_width: 1,
                            little_endian: true,
                            declared_len: n,
                            printable_ratio: printable,
                        },
                        conf,
                        format!(
                            "u8 prefix declares {} bytes; body {:.0}% printable",
                            n,
                            printable * 100.0
                        ),
                    ));
                }
            }
        }

        // ── u16 LE prefix ────────────────────────────────────────────────────
        if offset + 2 <= len {
            let n = u16::from_le_bytes([data[offset], data[offset + 1]]) as usize;
            if n >= MIN_BODY && offset + 2 + n <= len {
                let body = &data[offset + 2..offset + 2 + n];
                let (non_null, printable) = body_quality(body);
                if non_null >= 0.70 {
                    let conf = confidence_u16(n, printable);
                    signals.push(Signal::new(
                        Region::new(offset, 2 + n),
                        SignalKind::LengthPrefixedBlob {
                            prefix_width: 2,
                            little_endian: true,
                            declared_len: n,
                            printable_ratio: printable,
                        },
                        conf,
                        format!(
                            "u16le prefix declares {} bytes; body {:.0}% printable",
                            n,
                            printable * 100.0
                        ),
                    ));
                }
            }
        }

        // ── u16 BE prefix ────────────────────────────────────────────────────
        if offset + 2 <= len {
            let n = u16::from_be_bytes([data[offset], data[offset + 1]]) as usize;
            if n >= MIN_BODY && offset + 2 + n <= len {
                let body = &data[offset + 2..offset + 2 + n];
                let (non_null, printable) = body_quality(body);
                if non_null >= 0.70 {
                    let conf = confidence_u16(n, printable);
                    signals.push(Signal::new(
                        Region::new(offset, 2 + n),
                        SignalKind::LengthPrefixedBlob {
                            prefix_width: 2,
                            little_endian: false,
                            declared_len: n,
                            printable_ratio: printable,
                        },
                        conf,
                        format!(
                            "u16be prefix declares {} bytes; body {:.0}% printable",
                            n,
                            printable * 100.0
                        ),
                    ));
                }
            }
        }

        // ── u32 LE prefix ────────────────────────────────────────────────────
        if offset + 4 <= len {
            let n = u32::from_le_bytes([
                data[offset],
                data[offset + 1],
                data[offset + 2],
                data[offset + 3],
            ]) as usize;
            // Cap at file length to avoid huge false-positive windows.
            if n >= MIN_BODY && offset + 4 + n <= len {
                let body = &data[offset + 4..offset + 4 + n];
                let (non_null, printable) = body_quality(body);
                if non_null >= 0.40 {
                    let conf = confidence_u32(n, printable);
                    signals.push(Signal::new(
                        Region::new(offset, 4 + n),
                        SignalKind::LengthPrefixedBlob {
                            prefix_width: 4,
                            little_endian: true,
                            declared_len: n,
                            printable_ratio: printable,
                        },
                        conf,
                        format!(
                            "u32le prefix declares {} bytes; body {:.0}% printable",
                            n,
                            printable * 100.0
                        ),
                    ));
                }
            }
        }

        // ── u32 BE prefix ────────────────────────────────────────────────────
        if offset + 4 <= len {
            let n = u32::from_be_bytes([
                data[offset],
                data[offset + 1],
                data[offset + 2],
                data[offset + 3],
            ]) as usize;
            if n >= MIN_BODY && offset + 4 + n <= len {
                let body = &data[offset + 4..offset + 4 + n];
                let (non_null, printable) = body_quality(body);
                if non_null >= 0.40 {
                    let conf = confidence_u32(n, printable);
                    signals.push(Signal::new(
                        Region::new(offset, 4 + n),
                        SignalKind::LengthPrefixedBlob {
                            prefix_width: 4,
                            little_endian: false,
                            declared_len: n,
                            printable_ratio: printable,
                        },
                        conf,
                        format!(
                            "u32be prefix declares {} bytes; body {:.0}% printable",
                            n,
                            printable * 100.0
                        ),
                    ));
                }
            }
        }
    }

    signals
}

/// Returns (non_null_ratio, printable_ratio) for a body slice.
fn body_quality(body: &[u8]) -> (f64, f64) {
    if body.is_empty() {
        return (0.0, 0.0);
    }
    let n = body.len() as f64;
    let non_null = body.iter().filter(|&&b| b != 0).count() as f64;
    let printable = body.iter().filter(|&&b| (0x20..=0x7e).contains(&b)).count() as f64;
    (non_null / n, printable / n)
}

/// Confidence for a u8-prefixed blob in [0.30, 0.52].
///
/// Low ceiling because u8 prefixes fire frequently by chance; a high
/// printable ratio is the main distinguishing signal.
fn confidence_u8(body_len: usize, printable_ratio: f64) -> f64 {
    let len_boost = ((body_len.saturating_sub(8)) as f64 / 56.0).min(1.0) * 0.08;
    (0.30 + 0.14 * printable_ratio + len_boost).min(0.52)
}

/// Confidence for a u16-prefixed blob in [0.40, 0.68].
fn confidence_u16(body_len: usize, printable_ratio: f64) -> f64 {
    let len_boost = ((body_len.saturating_sub(4)) as f64 / 124.0).min(1.0) * 0.08;
    (0.40 + 0.20 * printable_ratio + len_boost).min(0.68)
}

/// Confidence for a u32-prefixed blob in [0.55, 0.82].
///
/// Higher floor because a random u32 value that happens to equal a valid
/// in-bounds length is relatively rare.
fn confidence_u32(body_len: usize, printable_ratio: f64) -> f64 {
    let len_boost = ((body_len.saturating_sub(4)) as f64 / 252.0).min(1.0) * 0.07;
    (0.55 + 0.20 * printable_ratio + len_boost).min(0.82)
}

// ── helpers ──────────────────────────────────────────────────────────────────

/// Format body bytes for display: quoted preview if mostly printable,
/// otherwise a bracketed summary.
pub fn body_preview(
    data: &[u8],
    offset: usize,
    prefix_width: usize,
    declared_len: usize,
) -> String {
    let body_start = offset + prefix_width;
    let body_end = (body_start + declared_len).min(data.len());
    let body = &data[body_start..body_end];
    let printable: Vec<u8> = body
        .iter()
        .take_while(|&&b| (0x20..=0x7e).contains(&b))
        .copied()
        .collect();
    let printable_ratio = if body.is_empty() {
        0.0
    } else {
        printable.len() as f64 / body.len() as f64
    };

    if printable_ratio >= 0.80 {
        let preview: String = printable.iter().take(40).map(|&b| b as char).collect();
        let suffix = if printable.len() < body.len() {
            "…"
        } else {
            ""
        };
        format!("{:?}{}", preview, suffix)
    } else {
        let non_null = body.iter().filter(|&&b| b != 0).count();
        format!(
            "[{} bytes, {:.0}% non-null]",
            body.len(),
            non_null as f64 / body.len().max(1) as f64 * 100.0
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::SignalKind;

    #[test]
    fn detects_u8_prefixed_string() {
        // u8 prefix = 9, followed by 9 printable bytes
        let mut data = vec![0x09u8];
        data.extend_from_slice(b"hello.txt");
        let sigs = scan_length_prefixed(&data);
        assert_eq!(sigs.len(), 1);
        match &sigs[0].kind {
            SignalKind::LengthPrefixedBlob {
                prefix_width,
                declared_len,
                ..
            } => {
                assert_eq!(*prefix_width, 1);
                assert_eq!(*declared_len, 9);
            }
            _ => panic!("wrong kind"),
        }
        assert_eq!(sigs[0].region, Region::new(0, 10));
    }

    #[test]
    fn detects_u16le_prefixed_blob() {
        // u16le prefix = 5, followed by 5 printable bytes
        let mut data = vec![0x05u8, 0x00]; // 5 in LE
        data.extend_from_slice(b"hello");
        // Pad so it doesn't accidentally also match as other prefix widths cleanly
        data.extend_from_slice(&[0x00; 4]);
        let sigs = scan_length_prefixed(&data);
        let u16le_sig = sigs.iter().find(|s| {
            matches!(
                &s.kind,
                SignalKind::LengthPrefixedBlob {
                    prefix_width: 2,
                    little_endian: true,
                    ..
                }
            )
        });
        assert!(u16le_sig.is_some(), "expected u16le signal");
        let sig = u16le_sig.unwrap();
        match &sig.kind {
            SignalKind::LengthPrefixedBlob { declared_len, .. } => assert_eq!(*declared_len, 5),
            _ => unreachable!(),
        }
    }

    #[test]
    fn detects_u32le_prefixed_blob() {
        // u32le prefix = 6, followed by 6 printable bytes
        let mut data = vec![0x06u8, 0x00, 0x00, 0x00]; // 6 in LE
        data.extend_from_slice(b"foobar");
        let sigs = scan_length_prefixed(&data);
        let u32le_sig = sigs.iter().find(|s| {
            matches!(
                &s.kind,
                SignalKind::LengthPrefixedBlob {
                    prefix_width: 4,
                    little_endian: true,
                    ..
                }
            )
        });
        assert!(u32le_sig.is_some(), "expected u32le signal");
    }

    #[test]
    fn rejects_out_of_bounds_body() {
        // u32le prefix claims 1000 bytes but only 4 follow
        let data = vec![0xe8u8, 0x03, 0x00, 0x00, 0x01, 0x02, 0x03, 0x04];
        let sigs = scan_length_prefixed(&data);
        // No u32le blob should be emitted (body doesn't fit)
        let u32le_sig = sigs.iter().find(|s| {
            matches!(
                &s.kind,
                SignalKind::LengthPrefixedBlob {
                    prefix_width: 4,
                    declared_len: 1000,
                    ..
                }
            )
        });
        assert!(u32le_sig.is_none());
    }

    #[test]
    fn rejects_body_below_min_length() {
        // u32le prefix = 3 (below MIN_BODY = 4)
        let data = vec![0x03u8, 0x00, 0x00, 0x00, b'a', b'b', b'c'];
        let sigs = scan_length_prefixed(&data);
        let u32le_sig = sigs.iter().find(|s| {
            matches!(
                &s.kind,
                SignalKind::LengthPrefixedBlob {
                    prefix_width: 4,
                    declared_len: 3,
                    ..
                }
            )
        });
        assert!(u32le_sig.is_none());
    }

    #[test]
    fn u32be_detected() {
        // u32be prefix = 5 (bytes: 00 00 00 05), followed by "world"
        let mut data = vec![0x00u8, 0x00, 0x00, 0x05];
        data.extend_from_slice(b"world");
        let sigs = scan_length_prefixed(&data);
        let be_sig = sigs.iter().find(|s| {
            matches!(
                &s.kind,
                SignalKind::LengthPrefixedBlob {
                    prefix_width: 4,
                    little_endian: false,
                    ..
                }
            )
        });
        assert!(be_sig.is_some(), "expected u32be signal");
    }
}
