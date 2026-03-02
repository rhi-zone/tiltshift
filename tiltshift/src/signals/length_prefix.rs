//! Length-prefixed blob sequence detector.
//!
//! Scans for **consecutive runs** of u8 / u16 (LE+BE) / u32 (LE+BE) length-
//! prefixed blobs where each blob's end byte is immediately followed by the
//! next blob's prefix.  A chain of ≥ 2 such blobs is emitted as a single
//! signal covering the entire run.
//!
//! ## Rationale
//!
//! A single length-prefix occurrence is coincidence-level evidence: any
//! 1-/2-/4-byte window in a file *could* happen to read as a plausible in-
//! bounds length.  Requiring two or more *consecutive* matching blobs means
//! the format is being observed rather than guessed — random data will not
//! produce the same consistent layout multiple times in a row.
//!
//! This eliminates the need for arbitrary body-size caps (which were a proxy
//! for "this is probably noise") and replaces them with a principled
//! structural test.

use crate::types::{Region, Signal, SignalKind};

/// Minimum body length (bytes) to consider a blob valid.
const MIN_BODY: usize = 4;

/// Stricter minimum for u8 prefixes, which match very frequently by chance.
const MIN_BODY_U8: usize = 8;

/// Minimum chain length required to emit a signal.
const MIN_SEQ: usize = 2;

/// Maximum bytes examined for per-blob body quality estimation.
///
/// Sampling a fixed prefix keeps scan time O(1) per candidate regardless of
/// the declared body length.
const QUALITY_SAMPLE: usize = 512;

// ── Configuration table ───────────────────────────────────────────────────────

/// (prefix_width_bytes, little_endian, min_body, min_non_null, min_printable)
const CONFIGS: &[(usize, bool, usize, f64, f64)] = &[
    // u8 — fires easily; demand high printable quality to filter noise.
    (1, true, MIN_BODY_U8, 0.90, 0.85),
    // u16 LE/BE
    (2, true, MIN_BODY, 0.70, 0.50),
    (2, false, MIN_BODY, 0.70, 0.50),
    // u32 LE/BE — a random u32 equalling a valid in-bounds length is rare,
    // so a slightly looser non-null threshold is acceptable here.
    (4, true, MIN_BODY, 0.70, 0.50),
    (4, false, MIN_BODY, 0.70, 0.50),
];

// ── Chain walking ─────────────────────────────────────────────────────────────

/// One validated blob within a chain.
struct BlobEntry {
    /// Byte offset of this blob's prefix within the file.
    offset: usize,
    /// Declared body length (bytes after the prefix).
    body_len: usize,
    /// Fraction of body bytes that are printable ASCII (from sample).
    printable_ratio: f64,
}

/// Try to read a length prefix of `width` bytes at `data[offset]`.
///
/// Returns `None` if there are not enough bytes remaining.
fn read_prefix(data: &[u8], offset: usize, width: usize, little_endian: bool) -> Option<usize> {
    match width {
        1 => data.get(offset).map(|&b| b as usize),
        2 => {
            if offset + 2 > data.len() {
                return None;
            }
            let bytes = [data[offset], data[offset + 1]];
            Some(if little_endian {
                u16::from_le_bytes(bytes) as usize
            } else {
                u16::from_be_bytes(bytes) as usize
            })
        }
        4 => {
            if offset + 4 > data.len() {
                return None;
            }
            let bytes: [u8; 4] = data[offset..offset + 4].try_into().unwrap();
            Some(if little_endian {
                u32::from_le_bytes(bytes) as usize
            } else {
                u32::from_be_bytes(bytes) as usize
            })
        }
        _ => None,
    }
}

/// Walk a chain of consecutive length-prefixed blobs starting at `start`.
///
/// Advances greedily: after each valid blob, the next prefix begins at the
/// first byte after the body.  Stops at the first failed quality check, OOB
/// condition, or prefix that reads below `min_body`.
///
/// Returns all valid blobs in the chain (may be empty or length 1 if no chain
/// can be formed).
fn try_walk(
    data: &[u8],
    start: usize,
    prefix_width: usize,
    little_endian: bool,
    min_body: usize,
    min_non_null: f64,
    min_printable: f64,
) -> Vec<BlobEntry> {
    let mut blobs = Vec::new();
    let mut offset = start;

    loop {
        let Some(n) = read_prefix(data, offset, prefix_width, little_endian) else {
            break;
        };
        if n < min_body {
            break;
        }
        let end = offset + prefix_width + n;
        if end > data.len() {
            break;
        }

        let body = &data[offset + prefix_width..end];
        let sample = &body[..body.len().min(QUALITY_SAMPLE)];
        let (non_null, printable) = body_quality(sample);
        if non_null < min_non_null || printable < min_printable {
            break;
        }

        blobs.push(BlobEntry {
            offset,
            body_len: n,
            printable_ratio: printable,
        });
        offset = end;
    }

    blobs
}

// ── Public scanner ─────────────────────────────────────────────────────────────

/// Scan `data` for length-prefixed blob sequences.
///
/// For each prefix configuration (u8, u16le, u16be, u32le, u32be), scans
/// left-to-right building the longest consecutive chain possible.  Only chains
/// of ≥ [`MIN_SEQ`] blobs emit a signal — isolated occurrences are discarded
/// as insufficient evidence.
pub fn scan_length_prefixed(data: &[u8]) -> Vec<Signal> {
    let mut signals = Vec::new();

    for &(prefix_width, little_endian, min_body, min_nn, min_pr) in CONFIGS {
        let mut offset = 0usize;

        while offset < data.len() {
            let blobs = try_walk(
                data,
                offset,
                prefix_width,
                little_endian,
                min_body,
                min_nn,
                min_pr,
            );

            if blobs.len() >= MIN_SEQ {
                let last = blobs.last().unwrap();
                let chain_start = blobs[0].offset;
                let chain_end = last.offset + prefix_width + last.body_len;
                let avg_printable =
                    blobs.iter().map(|b| b.printable_ratio).sum::<f64>() / blobs.len() as f64;
                let conf = confidence_seq(blobs.len(), prefix_width, avg_printable);
                let width_bits = prefix_width * 8;
                let endian_tag = if prefix_width == 1 {
                    String::new()
                } else if little_endian {
                    "le".to_string()
                } else {
                    "be".to_string()
                };
                signals.push(Signal::new(
                    Region::new(chain_start, chain_end - chain_start),
                    SignalKind::LengthPrefixedBlob {
                        prefix_width: prefix_width as u8,
                        little_endian,
                        blob_count: blobs.len(),
                        printable_ratio: avg_printable,
                    },
                    conf,
                    format!(
                        "{} consecutive u{}{} blobs chaining end-to-end; avg {:.0}% printable",
                        blobs.len(),
                        width_bits,
                        endian_tag,
                        avg_printable * 100.0
                    ),
                ));
                offset = chain_end;
            } else {
                offset += 1;
            }
        }
    }

    signals
}

// ── Helpers ───────────────────────────────────────────────────────────────────

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

/// Confidence for a length-prefixed sequence.
///
/// Floor scales with prefix width (wider prefix = lower coincidence rate).
/// Printable ratio and chain length both contribute bonuses.
///
/// Ranges (approximate):
/// - u8 : [0.45, 0.75]
/// - u16: [0.52, 0.80]
/// - u32: [0.62, 0.88]
fn confidence_seq(blob_count: usize, prefix_width: usize, avg_printable: f64) -> f64 {
    // Sequence length bonus saturates at ~10 blobs.
    let count_bonus = ((blob_count.saturating_sub(2)) as f64 / 8.0).min(1.0) * 0.20;
    let (floor, printable_weight) = match prefix_width {
        1 => (0.45, 0.10),
        2 => (0.52, 0.13),
        4 => (0.62, 0.13),
        _ => (0.52, 0.13),
    };
    (floor + printable_weight * avg_printable + count_bonus).min(0.88)
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::SignalKind;

    // ── u8 ────────────────────────────────────────────────────────────────────

    #[test]
    fn detects_u8_sequence() {
        // Two consecutive u8-prefixed strings: [9, "hello.txt", 9, "world.txt"]
        let mut data = vec![0x09u8];
        data.extend_from_slice(b"hello.txt");
        data.push(0x09);
        data.extend_from_slice(b"world.txt");
        let sigs = scan_length_prefixed(&data);
        let sig = sigs.iter().find(|s| {
            matches!(
                &s.kind,
                SignalKind::LengthPrefixedBlob {
                    prefix_width: 1,
                    ..
                }
            )
        });
        assert!(sig.is_some(), "expected u8 sequence signal");
        match &sig.unwrap().kind {
            SignalKind::LengthPrefixedBlob { blob_count, .. } => assert!(*blob_count >= 2),
            _ => unreachable!(),
        }
    }

    #[test]
    fn rejects_isolated_u8_blob() {
        // Single u8-prefixed string — chain length = 1, no signal expected.
        let mut data = vec![0x09u8];
        data.extend_from_slice(b"hello.txt");
        let sigs = scan_length_prefixed(&data);
        assert!(
            sigs.iter().all(|s| !matches!(
                &s.kind,
                SignalKind::LengthPrefixedBlob {
                    prefix_width: 1,
                    ..
                }
            )),
            "isolated u8 blob must not emit a signal"
        );
    }

    // ── u16 ───────────────────────────────────────────────────────────────────

    #[test]
    fn detects_u16le_sequence() {
        // Two u16le-prefixed blobs: [5, "hello", 5, "world"]
        let mut data = Vec::new();
        data.extend_from_slice(&5u16.to_le_bytes());
        data.extend_from_slice(b"hello");
        data.extend_from_slice(&5u16.to_le_bytes());
        data.extend_from_slice(b"world");
        let sigs = scan_length_prefixed(&data);
        let sig = sigs.iter().find(|s| {
            matches!(
                &s.kind,
                SignalKind::LengthPrefixedBlob {
                    prefix_width: 2,
                    little_endian: true,
                    ..
                }
            )
        });
        assert!(sig.is_some(), "expected u16le sequence signal");
        match &sig.unwrap().kind {
            SignalKind::LengthPrefixedBlob { blob_count, .. } => assert!(*blob_count >= 2),
            _ => unreachable!(),
        }
    }

    // ── u32 ───────────────────────────────────────────────────────────────────

    #[test]
    fn detects_u32le_sequence() {
        // Two u32le-prefixed blobs: [6, "foobar", 6, "barbaz"]
        let mut data = Vec::new();
        data.extend_from_slice(&6u32.to_le_bytes());
        data.extend_from_slice(b"foobar");
        data.extend_from_slice(&6u32.to_le_bytes());
        data.extend_from_slice(b"barbaz");
        let sigs = scan_length_prefixed(&data);
        let sig = sigs.iter().find(|s| {
            matches!(
                &s.kind,
                SignalKind::LengthPrefixedBlob {
                    prefix_width: 4,
                    little_endian: true,
                    ..
                }
            )
        });
        assert!(sig.is_some(), "expected u32le sequence signal");
    }

    #[test]
    fn u32be_sequence_detected() {
        // Two u32be-prefixed blobs: [5, "world", 5, "hello"]
        let mut data = Vec::new();
        data.extend_from_slice(&5u32.to_be_bytes());
        data.extend_from_slice(b"world");
        data.extend_from_slice(&5u32.to_be_bytes());
        data.extend_from_slice(b"hello");
        let sigs = scan_length_prefixed(&data);
        let sig = sigs.iter().find(|s| {
            matches!(
                &s.kind,
                SignalKind::LengthPrefixedBlob {
                    prefix_width: 4,
                    little_endian: false,
                    ..
                }
            )
        });
        assert!(sig.is_some(), "expected u32be sequence signal");
    }

    // ── Rejection cases ───────────────────────────────────────────────────────

    #[test]
    fn rejects_out_of_bounds_body() {
        // u32le prefix claims 1000 bytes but only 4 follow — chain length 0.
        let data = vec![0xe8u8, 0x03, 0x00, 0x00, 0x01, 0x02, 0x03, 0x04];
        let sigs = scan_length_prefixed(&data);
        let u32le = sigs.iter().find(|s| {
            matches!(
                &s.kind,
                SignalKind::LengthPrefixedBlob {
                    prefix_width: 4,
                    little_endian: true,
                    ..
                }
            )
        });
        assert!(u32le.is_none());
    }

    #[test]
    fn rejects_body_below_min_length() {
        // u32le prefix = 3 (below MIN_BODY = 4), followed by garbage.
        // Even if two such "blobs" appeared consecutively, they'd be below threshold.
        let mut data = Vec::new();
        data.extend_from_slice(&3u32.to_le_bytes());
        data.extend_from_slice(b"abc");
        data.extend_from_slice(&3u32.to_le_bytes());
        data.extend_from_slice(b"xyz");
        let sigs = scan_length_prefixed(&data);
        let u32le = sigs.iter().find(|s| {
            matches!(
                &s.kind,
                SignalKind::LengthPrefixedBlob {
                    prefix_width: 4,
                    blob_count: _,
                    ..
                }
            )
        });
        assert!(u32le.is_none());
    }

    #[test]
    fn longer_chain_higher_confidence() {
        // Build 5 consecutive u32le blobs and check confidence grows with chain length.
        fn make_chain(n: usize) -> f64 {
            let mut data = Vec::new();
            for _ in 0..n {
                data.extend_from_slice(&6u32.to_le_bytes());
                data.extend_from_slice(b"foobar");
            }
            let sigs = scan_length_prefixed(&data);
            sigs.iter()
                .find(|s| {
                    matches!(
                        &s.kind,
                        SignalKind::LengthPrefixedBlob {
                            prefix_width: 4,
                            little_endian: true,
                            ..
                        }
                    )
                })
                .map_or(0.0, |s| s.confidence)
        }

        let conf2 = make_chain(2);
        let conf5 = make_chain(5);
        assert!(conf2 > 0.0, "chain of 2 should emit");
        assert!(conf5 > conf2, "longer chain should have higher confidence");
    }
}
