//! TLV (Type-Length-Value) sequence detector.
//!
//! Scans for consecutive TLV records with consistent type/length field widths.
//! Common variants covered:
//!
//!   u8  type + u8  length  — DHCP options, Bluetooth HCI, USB descriptors
//!   u8  type + u16 length  — custom protocols with payloads > 255 bytes
//!   u8  type + u32 length  — TLS-record-adjacent, custom
//!   u16 type + u16 length  — netlink, some TLS extension tables
//!
//! A TLV *run* is a consecutive sequence of valid records with consistent header
//! widths whose body lengths fit within the file.  Smaller headers require
//! longer chains to control false positives.  Confidence scales with run length,
//! type diversity, and total body bytes.

use crate::types::{Region, Signal, SignalKind};
use std::collections::HashSet;

// ── Configuration ──────────────────────────────────────────────────────────────

/// (type_width_bytes, len_width_bytes, little_endian)
const CONFIGS: &[(u8, u8, bool)] = &[
    (1, 1, false), // u8 type + u8 length  (endian irrelevant for 1-byte fields)
    (1, 2, true),  // u8 type + u16le length
    (1, 2, false), // u8 type + u16be length
    (1, 4, true),  // u8 type + u32le length
    (1, 4, false), // u8 type + u32be length
    (2, 2, true),  // u16le type + u16le length
    (2, 2, false), // u16be type + u16be length
];

/// Minimum consecutive records required to emit a signal.
/// Smaller headers are easier to match by chance and need longer chains.
fn min_chain_len(type_width: u8, len_width: u8) -> usize {
    match type_width + len_width {
        2 => 6, // u8+u8 (2-byte header)
        3 => 4, // u8+u16 (3-byte header)
        4 => 3, // u16+u16 (4-byte header)
        5 => 3, // u8+u32 (5-byte header)
        _ => 4,
    }
}

// ── Record walking ─────────────────────────────────────────────────────────────

struct TlvRecord {
    type_value: u32,
    body_len: usize,
}

fn read_uint(data: &[u8], offset: usize, width: u8, little_endian: bool) -> Option<u32> {
    match width {
        1 => data.get(offset).map(|&b| b as u32),
        2 => {
            let arr: [u8; 2] = data.get(offset..offset + 2)?.try_into().ok()?;
            Some(if little_endian {
                u16::from_le_bytes(arr) as u32
            } else {
                u16::from_be_bytes(arr) as u32
            })
        }
        4 => {
            let arr: [u8; 4] = data.get(offset..offset + 4)?.try_into().ok()?;
            Some(if little_endian {
                u32::from_le_bytes(arr)
            } else {
                u32::from_be_bytes(arr)
            })
        }
        _ => None,
    }
}

fn try_walk_tlv(
    data: &[u8],
    start: usize,
    type_width: u8,
    len_width: u8,
    little_endian: bool,
) -> Vec<TlvRecord> {
    let header_size = type_width as usize + len_width as usize;
    let mut records = Vec::new();
    let mut pos = start;
    let mut consecutive_zero = 0usize;

    loop {
        if pos + header_size > data.len() {
            break;
        }

        let type_val = match read_uint(data, pos, type_width, little_endian) {
            Some(v) => v,
            None => break,
        };
        let body_len = match read_uint(data, pos + type_width as usize, len_width, little_endian) {
            Some(l) => l as usize,
            None => break,
        };

        // Body must fit within remaining data.
        let body_end = pos + header_size + body_len;
        if body_end > data.len() {
            break;
        }

        // Break on a sustained run of zero-length bodies — likely padding, not TLV.
        if body_len == 0 {
            consecutive_zero += 1;
            if consecutive_zero > 4 {
                break;
            }
        } else {
            consecutive_zero = 0;
        }

        records.push(TlvRecord {
            type_value: type_val,
            body_len,
        });
        pos = body_end;
    }

    records
}

// ── Confidence ─────────────────────────────────────────────────────────────────

fn tlv_confidence(record_count: usize, unique_types: usize, total_body_bytes: usize) -> f64 {
    // Base: 0.55 at the minimum chain length, up to 0.85 at ~20 records.
    let base = (0.55_f64 + 0.02 * record_count.saturating_sub(3) as f64).min(0.85);
    // More distinct type codes → stronger evidence of a real protocol.
    let div_boost = if unique_types > 3 {
        0.07
    } else if unique_types > 1 {
        0.03
    } else {
        0.0
    };
    // Larger total payload → less likely to be coincidental.
    let body_boost = if total_body_bytes > 64 {
        0.05
    } else if total_body_bytes > 16 {
        0.02
    } else {
        0.0
    };
    (base + div_boost + body_boost).min(0.92)
}

// ── Label ──────────────────────────────────────────────────────────────────────

/// Short human-readable label for a TLV header configuration.
pub fn tlv_label(type_width: u8, len_width: u8, little_endian: bool) -> &'static str {
    match (type_width, len_width, little_endian) {
        (1, 1, _) => "u8+u8",
        (1, 2, true) => "u8+u16le",
        (1, 2, false) => "u8+u16be",
        (1, 4, true) => "u8+u32le",
        (1, 4, false) => "u8+u32be",
        (2, 2, true) => "u16le+u16le",
        (2, 2, false) => "u16be+u16be",
        _ => "?+?",
    }
}

// ── Deduplication ──────────────────────────────────────────────────────────────

struct TlvCandidate {
    start: usize,
    end: usize,
    record_count: usize,
    type_width: u8,
    len_width: u8,
    little_endian: bool,
    type_samples: Vec<u32>,
    total_body_bytes: usize,
    unique_types: usize,
}

/// Greedily select non-overlapping candidates.
///
/// Primary sort: total bytes covered (more = better: correctly parses more of the file).
/// Tiebreak: record count (longer chain), then earlier start.
/// This ensures that a wide-header chain covering a large region beats a narrow-header
/// chain that spuriously matches a subset of the same bytes with more but smaller records.
fn select_non_overlapping(mut candidates: Vec<TlvCandidate>) -> Vec<TlvCandidate> {
    candidates.sort_by(|a, b| {
        let a_cov = a.end - a.start;
        let b_cov = b.end - b.start;
        b_cov
            .cmp(&a_cov)
            .then(b.record_count.cmp(&a.record_count))
            .then(a.start.cmp(&b.start))
    });
    let mut selected: Vec<TlvCandidate> = Vec::new();
    'outer: for cand in candidates {
        for sel in &selected {
            if cand.start < sel.end && cand.end > sel.start {
                continue 'outer;
            }
        }
        selected.push(cand);
    }
    selected.sort_by_key(|c| c.start);
    selected
}

// ── Public API ─────────────────────────────────────────────────────────────────

/// Scan `data` for TLV sequences.
///
/// Returns one signal per non-overlapping run of consecutive valid records.
pub fn scan_tlv(data: &[u8]) -> Vec<Signal> {
    if data.len() < 4 {
        return Vec::new();
    }

    let mut all_candidates: Vec<TlvCandidate> = Vec::new();

    for &(type_width, len_width, little_endian) in CONFIGS {
        let min_len = min_chain_len(type_width, len_width);
        let header_size = type_width as usize + len_width as usize;
        let mut skip_until = 0usize;

        for start in 0..data.len() {
            if start < skip_until {
                continue;
            }
            if start + header_size > data.len() {
                break;
            }

            let records = try_walk_tlv(data, start, type_width, len_width, little_endian);

            if records.len() < min_len {
                continue;
            }

            let total_body_bytes: usize = records.iter().map(|r| r.body_len).sum();
            // Reject chains where every body is zero-length — not convincing TLV.
            if total_body_bytes == 0 {
                continue;
            }

            let chain_bytes: usize = records.iter().map(|r| header_size + r.body_len).sum();
            let end = start + chain_bytes;

            let type_samples: Vec<u32> = records.iter().take(8).map(|r| r.type_value).collect();
            let unique_types: HashSet<u32> = records.iter().map(|r| r.type_value).collect();

            all_candidates.push(TlvCandidate {
                start,
                end,
                record_count: records.len(),
                type_width,
                len_width,
                little_endian,
                type_samples,
                total_body_bytes,
                unique_types: unique_types.len(),
            });

            skip_until = end;
        }
    }

    let selected = select_non_overlapping(all_candidates);

    selected
        .into_iter()
        .map(|c| {
            let conf = tlv_confidence(c.record_count, c.unique_types, c.total_body_bytes);
            let label = tlv_label(c.type_width, c.len_width, c.little_endian);
            let reason = format!(
                "{} records ({}); {} unique type code(s); {} body bytes",
                c.record_count, label, c.unique_types, c.total_body_bytes,
            );
            Signal::new(
                Region::new(c.start, c.end - c.start),
                SignalKind::TlvSequence {
                    type_width: c.type_width,
                    len_width: c.len_width,
                    little_endian: c.little_endian,
                    record_count: c.record_count,
                    type_samples: c.type_samples,
                },
                conf,
                reason,
            )
        })
        .collect()
}

// ── Tests ──────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::SignalKind;

    fn make_u8u8(records: &[(u8, &[u8])]) -> Vec<u8> {
        let mut data = Vec::new();
        for &(t, body) in records {
            data.push(t);
            data.push(body.len() as u8);
            data.extend_from_slice(body);
        }
        data
    }

    fn make_u8u16le(records: &[(u8, &[u8])]) -> Vec<u8> {
        let mut data = Vec::new();
        for &(t, body) in records {
            data.push(t);
            data.extend_from_slice(&(body.len() as u16).to_le_bytes());
            data.extend_from_slice(body);
        }
        data
    }

    fn make_u8u16be(records: &[(u8, &[u8])]) -> Vec<u8> {
        let mut data = Vec::new();
        for &(t, body) in records {
            data.push(t);
            data.extend_from_slice(&(body.len() as u16).to_be_bytes());
            data.extend_from_slice(body);
        }
        data
    }

    #[test]
    fn detects_u8_u8_sequence() {
        // 6 records (minimum for u8+u8), mixed body sizes.
        let data = make_u8u8(&[
            (0x01, &[0xAA, 0xBB]),
            (0x02, &[0x01, 0x02, 0x03]),
            (0x03, &[0xFF]),
            (0x04, &[0x00, 0x11]),
            (0x05, &[0x42]),
            (0x06, &[0xDE, 0xAD, 0xBE, 0xEF]),
        ]);
        let sigs = scan_tlv(&data);
        assert!(!sigs.is_empty(), "expected TLV signal");
        match &sigs[0].kind {
            SignalKind::TlvSequence {
                type_width,
                len_width,
                record_count,
                ..
            } => {
                assert_eq!(*type_width, 1);
                assert_eq!(*len_width, 1);
                assert!(*record_count >= 6);
            }
            _ => panic!("wrong kind"),
        }
        assert_eq!(sigs[0].region.offset, 0);
    }

    #[test]
    fn detects_u8_u16le_sequence() {
        // 4 records (minimum for u8+u16).
        let data = make_u8u16le(&[
            (0x01, &[0u8; 10]),
            (0x02, &[0u8; 20]),
            (0x03, &[0u8; 5]),
            (0x04, &[0xAA, 0xBB, 0xCC]),
        ]);
        let sigs = scan_tlv(&data);
        let tlv = sigs.iter().find(|s| {
            matches!(
                &s.kind,
                SignalKind::TlvSequence {
                    type_width: 1,
                    len_width: 2,
                    little_endian: true,
                    ..
                }
            )
        });
        assert!(tlv.is_some(), "expected u8+u16le signal");
        if let Some(s) = tlv {
            let SignalKind::TlvSequence { record_count, .. } = &s.kind else {
                unreachable!()
            };
            assert!(*record_count >= 4);
        }
    }

    #[test]
    fn detects_u8_u16be_sequence() {
        let data = make_u8u16be(&[
            (0x0A, &[1u8, 2, 3, 4, 5]),
            (0x0B, &[0u8; 8]),
            (0x0C, &[0xFF; 3]),
            (0x0D, &[0x12, 0x34]),
        ]);
        let sigs = scan_tlv(&data);
        let tlv = sigs.iter().find(|s| {
            matches!(
                &s.kind,
                SignalKind::TlvSequence {
                    type_width: 1,
                    len_width: 2,
                    little_endian: false,
                    ..
                }
            )
        });
        assert!(tlv.is_some(), "expected u8+u16be signal");
    }

    #[test]
    fn rejects_chain_below_min_length() {
        // Only 5 u8+u8 records — one short of the minimum of 6.
        let data = make_u8u8(&[
            (1, &[0xAA]),
            (2, &[0xBB]),
            (3, &[0xCC]),
            (4, &[0xDD]),
            (5, &[0xEE]),
        ]);
        let sigs = scan_tlv(&data);
        // Should find no u8+u8 signal.
        assert!(
            !sigs.iter().any(|s| matches!(
                &s.kind,
                SignalKind::TlvSequence {
                    type_width: 1,
                    len_width: 1,
                    ..
                }
            )),
            "should not emit signal for chain below minimum"
        );
    }

    #[test]
    fn rejects_all_zero_bodies() {
        // 6 u8+u8 records all with body_len=0.
        let data = make_u8u8(&[(1, &[]), (2, &[]), (3, &[]), (4, &[]), (5, &[]), (6, &[])]);
        let sigs = scan_tlv(&data);
        assert!(
            !sigs.iter().any(|s| matches!(
                &s.kind,
                SignalKind::TlvSequence {
                    type_width: 1,
                    len_width: 1,
                    ..
                }
            )),
            "should not emit signal when all bodies are empty"
        );
    }

    #[test]
    fn rejects_body_out_of_bounds() {
        // A single record that claims more body than the file contains.
        let mut data = vec![0x01u8, 0xFF, 0x00, 0x00]; // type=1, len=255 but only 2 body bytes
        data.extend_from_slice(&[0xAA, 0xBB]);
        let sigs = scan_tlv(&data);
        assert!(
            !sigs.iter().any(|s| matches!(
                &s.kind,
                SignalKind::TlvSequence {
                    type_width: 1,
                    len_width: 1,
                    ..
                }
            )),
            "should not emit signal when body is out of bounds"
        );
    }

    #[test]
    fn finds_two_separate_chains() {
        // Two distinct TLV regions separated by noise.
        let mut data = make_u8u8(&[
            (0x01, &[0xAA, 0xBB]),
            (0x02, &[0xCC, 0xDD]),
            (0x03, &[0xEE]),
            (0x04, &[0x11]),
            (0x05, &[0x22]),
            (0x06, &[0x33]),
        ]);
        // Noise bytes that won't form a valid TLV chain.
        data.extend_from_slice(&[0xFF, 0xFE, 0xFD, 0xFC, 0xFB, 0xFA, 0xF9, 0xF8]);
        let second_start = data.len();
        data.extend(make_u8u8(&[
            (0x0A, &[1u8, 2, 3]),
            (0x0B, &[4, 5, 6]),
            (0x0C, &[7, 8]),
            (0x0D, &[9]),
            (0x0E, &[10, 11]),
            (0x0F, &[12, 13, 14]),
        ]));

        let sigs = scan_tlv(&data);
        let u8u8_sigs: Vec<_> = sigs
            .iter()
            .filter(|s| {
                matches!(
                    &s.kind,
                    SignalKind::TlvSequence {
                        type_width: 1,
                        len_width: 1,
                        ..
                    }
                )
            })
            .collect();
        assert!(u8u8_sigs.len() >= 2, "expected two separate chains");
        // Second chain must start at or after the noise gap.
        assert!(
            u8u8_sigs[1].region.offset >= second_start,
            "second chain should start after the gap"
        );
    }

    #[test]
    fn confidence_grows_with_chain_length() {
        let short: Vec<(u8, &[u8])> = (1u8..=6).map(|i| (i, [0xAA].as_ref())).collect();
        let long: Vec<(u8, &[u8])> = (1u8..=20).map(|i| (i, [0xBB, 0xCC].as_ref())).collect();

        let short_data = make_u8u8(&short);
        let long_data = make_u8u8(&long);

        let short_sigs = scan_tlv(&short_data);
        let long_sigs = scan_tlv(&long_data);

        let short_conf = short_sigs
            .iter()
            .find(|s| {
                matches!(
                    &s.kind,
                    SignalKind::TlvSequence {
                        type_width: 1,
                        len_width: 1,
                        ..
                    }
                )
            })
            .map(|s| s.confidence)
            .unwrap_or(0.0);
        let long_conf = long_sigs
            .iter()
            .find(|s| {
                matches!(
                    &s.kind,
                    SignalKind::TlvSequence {
                        type_width: 1,
                        len_width: 1,
                        ..
                    }
                )
            })
            .map(|s| s.confidence)
            .unwrap_or(0.0);

        assert!(
            long_conf > short_conf,
            "longer chain should have higher confidence"
        );
    }

    #[test]
    fn type_samples_captured() {
        let data = make_u8u8(&[
            (0x11, &[1u8]),
            (0x22, &[2, 3]),
            (0x33, &[4]),
            (0x44, &[5, 6, 7]),
            (0x55, &[8]),
            (0x66, &[9, 10]),
        ]);
        let sigs = scan_tlv(&data);
        let sig = sigs
            .iter()
            .find(|s| {
                matches!(
                    &s.kind,
                    SignalKind::TlvSequence {
                        type_width: 1,
                        len_width: 1,
                        ..
                    }
                )
            })
            .expect("expected u8+u8 signal");
        match &sig.kind {
            SignalKind::TlvSequence { type_samples, .. } => {
                assert!(!type_samples.is_empty());
                assert!(type_samples.contains(&0x11));
                assert!(type_samples.contains(&0x22));
            }
            _ => unreachable!(),
        }
    }
}
