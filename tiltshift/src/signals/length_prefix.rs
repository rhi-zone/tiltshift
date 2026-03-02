//! Length-prefixed blob sequence detector.
//!
//! Two-pass approach:
//!
//! **Pass 1 — exact chains (gap = 0):** Greedy left-to-right walk; each
//! blob ends immediately where the next begins.  ≥ 2 blobs required.
//! Applies to u8 / u16 / u32 prefix widths.
//!
//! **Pass 2 — strided chains (gap > 0):** For u16/u32 prefix widths,
//! collect *all* valid candidate blobs in one sweep, histogram the
//! inter-blob gaps across consecutive non-overlapping candidates, then
//! build chains for each gap size that appears at least
//! [`MIN_GAP_OCCURRENCES`] times (guaranteeing ≥ [`MIN_SEQ_STRIDED`]
//! blobs with consistent gaps).  The dominant stride emerges from
//! frequency rather than enumeration.
//!
//! ## Rationale
//!
//! A single length-prefix occurrence is coincidence-level evidence.
//! Consecutive occurrences reinforce each other.  Exact chains require
//! the most precise coincidence (zero bytes between blobs) and are
//! therefore valid at ≥ 2 blobs.  Strided chains require confirmation
//! from at least two identical gaps, so ≥ 3 blobs.

use std::collections::{HashMap, HashSet};

use crate::types::{Region, Signal, SignalKind};

/// Minimum body length (bytes) to consider a blob valid.
const MIN_BODY: usize = 4;

/// Stricter minimum for u8 prefixes, which match very frequently by chance.
const MIN_BODY_U8: usize = 8;

/// Minimum chain length for exact (gap = 0) sequences.
const MIN_SEQ: usize = 2;

/// Minimum chain length for strided (gap > 0) sequences.
///
/// Requires two identical consecutive gaps to confirm the stride — a single
/// gap between two blobs is indistinguishable from coincidence.
const MIN_SEQ_STRIDED: usize = 3;

/// Maximum inter-blob gap (bytes) considered during strided scan.
const MAX_STRIDE_GAP: usize = 64;

/// A candidate gap must appear this many times in the inter-blob gap histogram
/// before chains are built for it.
const MIN_GAP_OCCURRENCES: usize = 2;

/// Maximum bytes examined for per-blob body quality estimation.
const QUALITY_SAMPLE: usize = 512;

// ── Configuration tables ──────────────────────────────────────────────────────

/// (prefix_width_bytes, little_endian, min_body, min_non_null, min_printable)
const CONFIGS_ALL: &[(usize, bool, usize, f64, f64)] = &[
    (1, true, MIN_BODY_U8, 0.90, 0.85),
    (2, true, MIN_BODY, 0.70, 0.50),
    (2, false, MIN_BODY, 0.70, 0.50),
    (4, true, MIN_BODY, 0.70, 0.50),
    (4, false, MIN_BODY, 0.70, 0.50),
];

/// Strided scan only on u16/u32 — u8 exact chains already cover Pascal
/// string tables and strided u8 blobs are both rare and expensive to scan.
const CONFIGS_WIDE: &[(usize, bool, usize, f64, f64)] = &[
    (2, true, MIN_BODY, 0.70, 0.50),
    (2, false, MIN_BODY, 0.70, 0.50),
    (4, true, MIN_BODY, 0.70, 0.50),
    (4, false, MIN_BODY, 0.70, 0.50),
];

// ── Shared types ──────────────────────────────────────────────────────────────

/// One validated blob within a chain.
struct BlobEntry {
    offset: usize,
    body_len: usize,
    printable_ratio: f64,
}

impl BlobEntry {
    fn end(&self, prefix_width: usize) -> usize {
        self.offset + prefix_width + self.body_len
    }
}

// ── Helpers ───────────────────────────────────────────────────────────────────

fn read_prefix(data: &[u8], offset: usize, width: usize, little_endian: bool) -> Option<usize> {
    match width {
        1 => data.get(offset).map(|&b| b as usize),
        2 => {
            if offset + 2 > data.len() {
                return None;
            }
            let b = [data[offset], data[offset + 1]];
            Some(if little_endian {
                u16::from_le_bytes(b) as usize
            } else {
                u16::from_be_bytes(b) as usize
            })
        }
        4 => {
            if offset + 4 > data.len() {
                return None;
            }
            let b: [u8; 4] = data[offset..offset + 4].try_into().unwrap();
            Some(if little_endian {
                u32::from_le_bytes(b) as usize
            } else {
                u32::from_be_bytes(b) as usize
            })
        }
        _ => None,
    }
}

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
/// Floor scales with prefix width; chain length and printable ratio
/// contribute bonuses.  Ranges (approximate): u8 [0.45, 0.75],
/// u16 [0.52, 0.80], u32 [0.62, 0.88].
fn confidence_seq(blob_count: usize, prefix_width: usize, avg_printable: f64) -> f64 {
    let count_bonus = ((blob_count.saturating_sub(2)) as f64 / 8.0).min(1.0) * 0.20;
    let (floor, pr_weight) = match prefix_width {
        1 => (0.45, 0.10),
        2 => (0.52, 0.13),
        4 => (0.62, 0.13),
        _ => (0.52, 0.13),
    };
    (floor + pr_weight * avg_printable + count_bonus).min(0.88)
}

// ── Pass 1: exact chains ──────────────────────────────────────────────────────

/// Walk a greedy chain of blobs where each blob ends immediately before the
/// next prefix (gap = 0).
fn try_walk_exact(
    data: &[u8],
    start: usize,
    prefix_width: usize,
    little_endian: bool,
    min_body: usize,
    min_nn: f64,
    min_pr: f64,
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
        let (nn, pr) = body_quality(sample);
        if nn < min_nn || pr < min_pr {
            break;
        }
        blobs.push(BlobEntry {
            offset,
            body_len: n,
            printable_ratio: pr,
        });
        offset = end;
    }
    blobs
}

fn scan_exact_chains(
    data: &[u8],
    prefix_width: usize,
    little_endian: bool,
    min_body: usize,
    min_nn: f64,
    min_pr: f64,
) -> Vec<Signal> {
    let mut signals = Vec::new();
    let mut offset = 0usize;
    let pw = prefix_width;

    while offset < data.len() {
        let blobs = try_walk_exact(data, offset, pw, little_endian, min_body, min_nn, min_pr);
        if blobs.len() >= MIN_SEQ {
            let last = blobs.last().unwrap();
            let chain_start = blobs[0].offset;
            let chain_end = last.end(pw);
            let avg_pr = blobs.iter().map(|b| b.printable_ratio).sum::<f64>() / blobs.len() as f64;
            let conf = confidence_seq(blobs.len(), pw, avg_pr);
            signals.push(make_signal(
                chain_start,
                chain_end,
                pw,
                little_endian,
                blobs.len(),
                0,
                avg_pr,
                conf,
            ));
            offset = chain_end;
        } else {
            offset += 1;
        }
    }
    signals
}

// ── Pass 2: strided chains ────────────────────────────────────────────────────

/// Collect every valid blob candidate at any offset (not just chain starts).
fn collect_candidates(
    data: &[u8],
    prefix_width: usize,
    little_endian: bool,
    min_body: usize,
    min_nn: f64,
    min_pr: f64,
) -> Vec<BlobEntry> {
    let mut out = Vec::new();
    for offset in 0..data.len() {
        let Some(n) = read_prefix(data, offset, prefix_width, little_endian) else {
            continue;
        };
        if n < min_body {
            continue;
        }
        let end = offset + prefix_width + n;
        if end > data.len() {
            continue;
        }
        let body = &data[offset + prefix_width..end];
        let sample = &body[..body.len().min(QUALITY_SAMPLE)];
        let (nn, pr) = body_quality(sample);
        if nn >= min_nn && pr >= min_pr {
            out.push(BlobEntry {
                offset,
                body_len: n,
                printable_ratio: pr,
            });
        }
    }
    out // already in offset order
}

/// Histogram of inter-blob gaps between consecutive non-overlapping candidates.
///
/// Greedy scan: once a candidate is "consumed" as the current blob, skip all
/// candidates that overlap its body before looking for the next one.  This
/// naturally groups candidates into discrete blocks and measures the gap
/// between those blocks, which is where the stride information lives.
fn gap_histogram(candidates: &[BlobEntry], prefix_width: usize) -> HashMap<usize, usize> {
    let mut hist = HashMap::new();
    let mut prev_end = 0usize;
    let mut have_prev = false;

    for cand in candidates {
        if cand.offset >= prev_end {
            if have_prev {
                let gap = cand.offset - prev_end;
                if (1..=MAX_STRIDE_GAP).contains(&gap) {
                    *hist.entry(gap).or_insert(0) += 1;
                }
            }
            prev_end = cand.end(prefix_width);
            have_prev = true;
        }
        // overlapping: keep prev_end at the max of what we've seen
        else {
            let e = cand.end(prefix_width);
            if e > prev_end {
                prev_end = e;
            }
        }
    }
    hist
}

fn scan_strided_chains(
    data: &[u8],
    prefix_width: usize,
    little_endian: bool,
    min_body: usize,
    min_nn: f64,
    min_pr: f64,
) -> Vec<Signal> {
    let candidates =
        collect_candidates(data, prefix_width, little_endian, min_body, min_nn, min_pr);
    if candidates.len() < MIN_SEQ_STRIDED {
        return vec![];
    }

    let hist = gap_histogram(&candidates, prefix_width);

    // Order gaps by descending frequency so the dominant stride wins covered slots.
    let mut qualifying: Vec<usize> = hist
        .into_iter()
        .filter(|(_, count)| *count >= MIN_GAP_OCCURRENCES)
        .map(|(gap, _)| gap)
        .collect();
    qualifying.sort_unstable();

    if qualifying.is_empty() {
        return vec![];
    }

    // Build a HashMap for O(1) offset → candidate index lookup.
    let by_offset: HashMap<usize, usize> = candidates
        .iter()
        .enumerate()
        .map(|(i, b)| (b.offset, i))
        .collect();

    let mut signals = Vec::new();
    let mut covered: HashSet<usize> = HashSet::new(); // candidate indices

    for gap in qualifying {
        for start_idx in 0..candidates.len() {
            if covered.contains(&start_idx) {
                continue;
            }
            let mut chain = vec![start_idx];
            let mut cur = start_idx;
            loop {
                let next_offset = candidates[cur].end(prefix_width) + gap;
                match by_offset.get(&next_offset) {
                    Some(&ni) if !covered.contains(&ni) => {
                        chain.push(ni);
                        cur = ni;
                    }
                    _ => break,
                }
            }
            if chain.len() < MIN_SEQ_STRIDED {
                continue;
            }
            let avg_pr = chain
                .iter()
                .map(|&i| candidates[i].printable_ratio)
                .sum::<f64>()
                / chain.len() as f64;
            let first = &candidates[chain[0]];
            let last = &candidates[*chain.last().unwrap()];
            // Slight confidence penalty: strided sequences require gap consistency
            // but still allow incidental byte matches at the gap positions.
            let conf = (confidence_seq(chain.len(), prefix_width, avg_pr) - 0.05).max(0.0);
            signals.push(make_signal(
                first.offset,
                last.end(prefix_width),
                prefix_width,
                little_endian,
                chain.len(),
                gap,
                avg_pr,
                conf,
            ));
            for i in chain {
                covered.insert(i);
            }
        }
    }
    signals
}

// ── Signal construction ───────────────────────────────────────────────────────

#[allow(clippy::too_many_arguments)]
fn make_signal(
    chain_start: usize,
    chain_end: usize,
    prefix_width: usize,
    little_endian: bool,
    blob_count: usize,
    inter_blob_gap: usize,
    printable_ratio: f64,
    confidence: f64,
) -> Signal {
    let width_bits = prefix_width * 8;
    let endian_tag = if prefix_width == 1 {
        String::new()
    } else if little_endian {
        "le".to_string()
    } else {
        "be".to_string()
    };
    let gap_desc = if inter_blob_gap == 0 {
        "end-to-end".to_string()
    } else {
        format!("{inter_blob_gap}-byte inter-blob gap")
    };
    Signal::new(
        Region::new(chain_start, chain_end - chain_start),
        SignalKind::LengthPrefixedBlob {
            prefix_width: prefix_width as u8,
            little_endian,
            blob_count,
            inter_blob_gap,
            printable_ratio,
        },
        confidence,
        format!(
            "{blob_count} u{width_bits}{endian_tag} blobs, {gap_desc}; avg {:.0}% printable",
            printable_ratio * 100.0
        ),
    )
}

// ── Public scanner ─────────────────────────────────────────────────────────────

/// Scan `data` for length-prefixed blob sequences (exact and strided).
pub fn scan_length_prefixed(data: &[u8]) -> Vec<Signal> {
    let mut signals = Vec::new();

    // Pass 1: exact end-to-end chains for all prefix widths.
    for &(pw, le, min_body, min_nn, min_pr) in CONFIGS_ALL {
        signals.extend(scan_exact_chains(data, pw, le, min_body, min_nn, min_pr));
    }

    // Pass 2: fixed-gap strided chains for u16/u32 only.
    for &(pw, le, min_body, min_nn, min_pr) in CONFIGS_WIDE {
        signals.extend(scan_strided_chains(data, pw, le, min_body, min_nn, min_pr));
    }

    signals
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::SignalKind;

    fn u8_seq(blobs: &[&[u8]]) -> Vec<u8> {
        let mut data = Vec::new();
        for b in blobs {
            assert!(b.len() < 256);
            data.push(b.len() as u8);
            data.extend_from_slice(b);
        }
        data
    }

    fn u32le_seq_with_gap(payloads: &[&[u8]], gap: usize) -> Vec<u8> {
        let mut data = Vec::new();
        for p in payloads {
            data.extend_from_slice(&(p.len() as u32).to_le_bytes());
            data.extend_from_slice(p);
            data.extend(std::iter::repeat_n(0xAA, gap));
        }
        data
    }

    // ── Exact chains ──────────────────────────────────────────────────────────

    #[test]
    fn detects_u8_sequence() {
        let data = u8_seq(&[b"hello.txt", b"world.txt"]);
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
            SignalKind::LengthPrefixedBlob {
                blob_count,
                inter_blob_gap,
                ..
            } => {
                assert!(*blob_count >= 2);
                assert_eq!(*inter_blob_gap, 0);
            }
            _ => unreachable!(),
        }
    }

    #[test]
    fn rejects_isolated_u8_blob() {
        let data = u8_seq(&[b"hello.txt"]);
        let sigs = scan_length_prefixed(&data);
        assert!(
            sigs.iter().all(|s| !matches!(
                &s.kind,
                SignalKind::LengthPrefixedBlob {
                    prefix_width: 1,
                    ..
                }
            )),
            "isolated blob must not emit"
        );
    }

    #[test]
    fn detects_u16le_sequence() {
        let mut data = Vec::new();
        for _ in 0..2 {
            data.extend_from_slice(&5u16.to_le_bytes());
            data.extend_from_slice(b"hello");
        }
        let sig = scan_length_prefixed(&data).into_iter().find(|s| {
            matches!(
                &s.kind,
                SignalKind::LengthPrefixedBlob {
                    prefix_width: 2,
                    little_endian: true,
                    ..
                }
            )
        });
        assert!(sig.is_some());
    }

    #[test]
    fn detects_u32le_sequence() {
        let mut data = Vec::new();
        for _ in 0..2 {
            data.extend_from_slice(&6u32.to_le_bytes());
            data.extend_from_slice(b"foobar");
        }
        assert!(scan_length_prefixed(&data).iter().any(|s| {
            matches!(
                &s.kind,
                SignalKind::LengthPrefixedBlob {
                    prefix_width: 4,
                    little_endian: true,
                    inter_blob_gap: 0,
                    ..
                }
            )
        }));
    }

    #[test]
    fn detects_u32be_sequence() {
        let mut data = Vec::new();
        for _ in 0..2 {
            data.extend_from_slice(&5u32.to_be_bytes());
            data.extend_from_slice(b"world");
        }
        assert!(scan_length_prefixed(&data).iter().any(|s| {
            matches!(
                &s.kind,
                SignalKind::LengthPrefixedBlob {
                    prefix_width: 4,
                    little_endian: false,
                    ..
                }
            )
        }));
    }

    #[test]
    fn longer_chain_higher_confidence() {
        fn conf(n: usize) -> f64 {
            let mut data = Vec::new();
            for _ in 0..n {
                data.extend_from_slice(&6u32.to_le_bytes());
                data.extend_from_slice(b"foobar");
            }
            scan_length_prefixed(&data)
                .iter()
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
        assert!(conf(2) > 0.0);
        assert!(conf(5) > conf(2));
    }

    // ── Strided chains ────────────────────────────────────────────────────────

    #[test]
    fn detects_strided_u32le_sequence() {
        // 3 blobs with a consistent 4-byte gap between each.
        let data = u32le_seq_with_gap(&[b"alpha_str", b"beta_stri", b"gamma_str"], 4);
        let sigs = scan_length_prefixed(&data);
        let strided = sigs.iter().find(|s| {
            matches!(
                &s.kind,
                SignalKind::LengthPrefixedBlob {
                    prefix_width: 4,
                    little_endian: true,
                    inter_blob_gap: 4,
                    blob_count,
                    ..
                } if *blob_count >= 3
            )
        });
        assert!(
            strided.is_some(),
            "expected strided u32le signal with gap=4"
        );
    }

    #[test]
    fn rejects_strided_with_only_two_blobs() {
        // Only 2 blobs with gap=4: need ≥ 3 for strided, so no strided signal.
        let data = u32le_seq_with_gap(&[b"alpha_str", b"beta_stri"], 4);
        assert!(!scan_length_prefixed(&data).iter().any(|s| {
            matches!(
                &s.kind,
                SignalKind::LengthPrefixedBlob {
                    inter_blob_gap: 4,
                    ..
                }
            )
        }));
    }

    // ── Rejection ─────────────────────────────────────────────────────────────

    #[test]
    fn rejects_out_of_bounds_body() {
        let data = vec![0xe8u8, 0x03, 0x00, 0x00, 0x01, 0x02, 0x03, 0x04];
        assert!(scan_length_prefixed(&data).iter().all(|s| !matches!(
            &s.kind,
            SignalKind::LengthPrefixedBlob {
                prefix_width: 4,
                little_endian: true,
                ..
            }
        )));
    }

    #[test]
    fn rejects_body_below_min_length() {
        // u32le prefix = 3 < MIN_BODY = 4
        let mut data = Vec::new();
        for _ in 0..3 {
            data.extend_from_slice(&3u32.to_le_bytes());
            data.extend_from_slice(b"abc");
        }
        assert!(scan_length_prefixed(&data).is_empty());
    }
}
