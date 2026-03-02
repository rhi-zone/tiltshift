//! Ngram frequency tables: bigram profile and stride pattern detection.
//!
//! **Bigram profile** — counts all consecutive byte pairs across the file and
//! computes their entropy.  The distribution discriminates data types better
//! than byte entropy alone because it captures *correlations* between adjacent
//! bytes:
//!
//!   - ASCII text:        high concentration in the printable × printable block
//!   - Sparse/structured: high concentration of null-containing pairs
//!   - Compressed/random: near-uniform distribution → high entropy
//!
//! **Stride pattern detection** — finds 4-byte patterns that recur at a
//! consistent stride (fixed gap between occurrences).  Regular strides suggest
//! arrays of structs: if byte pattern `AB CD EF 01` appears at offsets
//! 0, 12, 24, 36… the underlying record size is likely 12 bytes.

use std::collections::HashMap;

use crate::types::{Region, Signal, SignalKind};

// ── Bigram profile ────────────────────────────────────────────────────────────

/// Minimum file size for a meaningful bigram profile.
const MIN_PROFILE_BYTES: usize = 256;

/// Compute a bigram frequency profile over the whole file.
///
/// Returns `None` if the file is too small for reliable statistics.
fn bigram_profile(data: &[u8]) -> Option<Signal> {
    if data.len() < MIN_PROFILE_BYTES {
        return None;
    }

    // Flat 65536-entry table; index = (byte0 << 8) | byte1.
    // Heap-allocated to avoid overflowing the stack (256 KB).
    let mut counts = vec![0u32; 65536];
    let n = data.len() - 1; // number of consecutive bigrams

    for i in 0..n {
        let idx = ((data[i] as usize) << 8) | (data[i + 1] as usize);
        counts[idx] += 1;
    }

    // ── Bigram entropy ────────────────────────────────────────────────────────
    let n_f = n as f64;
    let bigram_entropy: f64 = counts
        .iter()
        .filter(|&&c| c > 0)
        .map(|&c| {
            let p = c as f64 / n_f;
            -p * p.log2()
        })
        .sum();

    // ── Top 5 bigrams ─────────────────────────────────────────────────────────
    // Collect only non-zero entries for sorting (avoids sorting 65536 zeros).
    let mut nonzero: Vec<(usize, u32)> = counts
        .iter()
        .enumerate()
        .filter(|(_, &c)| c > 0)
        .map(|(i, &c)| (i, c))
        .collect();
    nonzero.sort_unstable_by(|a, b| b.1.cmp(&a.1));

    let top_bigrams: Vec<String> = nonzero
        .iter()
        .take(5)
        .map(|(idx, count)| {
            let b0 = (idx >> 8) as u8;
            let b1 = (idx & 0xff) as u8;
            let pct = *count as f64 / n_f * 100.0;
            format!("{b0:02x} {b1:02x} ({pct:.1}%)")
        })
        .collect();

    // ── Data-type classification ───────────────────────────────────────────────
    // Fraction of bigrams with at least one null byte.
    let null_containing: u64 = {
        let mut c = 0u64;
        for b in 0..256usize {
            c += counts[b] as u64; // "00 b"
            c += counts[b << 8] as u64; // "b 00"
        }
        c -= counts[0] as u64; // "00 00" counted twice
        c
    };
    let null_ratio = null_containing as f64 / n_f;

    // Fraction of bigrams where both bytes are printable ASCII.
    let mut ascii_both: u64 = 0;
    for b0 in 0x20usize..=0x7e {
        for b1 in 0x20usize..=0x7e {
            ascii_both += counts[(b0 << 8) | b1] as u64;
        }
    }
    let ascii_ratio = ascii_both as f64 / n_f;

    let data_type_hint = classify(bigram_entropy, ascii_ratio, null_ratio).to_string();
    let conf = match data_type_hint.as_str() {
        "text" => 0.78,
        "sparse/structured" => 0.70,
        "compressed/random" => 0.72,
        _ => 0.45,
    };

    let reason = format!(
        "bigram entropy {bigram_entropy:.2} bits, ascii {:.0}%, null-pairs {:.0}% → {data_type_hint}",
        ascii_ratio * 100.0,
        null_ratio * 100.0,
    );

    Some(Signal::new(
        Region::new(0, data.len()),
        SignalKind::NgramProfile {
            bigram_entropy,
            top_bigrams,
            data_type_hint,
        },
        conf,
        reason,
    ))
}

fn classify(bigram_entropy: f64, ascii_ratio: f64, null_ratio: f64) -> &'static str {
    if ascii_ratio > 0.70 {
        "text"
    } else if null_ratio > 0.50 && bigram_entropy < 11.0 {
        "sparse/structured"
    } else if bigram_entropy > 14.0 {
        "compressed/random"
    } else {
        "mixed"
    }
}

// ── Stride pattern detection ──────────────────────────────────────────────────

/// Minimum number of times a pattern must appear to be a candidate.
const MIN_OCCURRENCES: u32 = 4;

/// Minimum stride (must be ≥ pattern width to exclude overlapping runs).
const MIN_STRIDE: usize = 4;

/// Fraction of inter-occurrence gaps that must equal the dominant stride.
const MIN_CONSISTENCY: f64 = 0.60;

/// A 4-byte pattern where all bytes are identical is just a run (already
/// covered by the Padding detector or entropy scanner).
fn is_boring(ng: &[u8; 4]) -> bool {
    ng[1] == ng[0] && ng[2] == ng[0] && ng[3] == ng[0]
}

/// Detect 4-byte patterns repeating at a consistent stride through the file.
///
/// Uses a two-pass approach to keep memory usage proportional to the number of
/// *frequent* patterns rather than all unique patterns:
///
///  1. Count every 4-byte ngram (single HashMap<[u8;4], u32> pass).
///  2. Collect offsets only for patterns that appeared ≥ MIN_OCCURRENCES times.
///  3. For each frequent pattern, find the dominant inter-occurrence gap.
fn stride_patterns(data: &[u8]) -> Vec<Signal> {
    if data.len() < MIN_STRIDE * MIN_OCCURRENCES as usize {
        return Vec::new();
    }

    let scan_end = data.len() - 3;

    // Pass 1: count all non-boring 4-byte patterns.
    let mut counts: HashMap<[u8; 4], u32> = HashMap::new();
    for i in 0..scan_end {
        let ng: [u8; 4] = data[i..i + 4].try_into().unwrap();
        if !is_boring(&ng) {
            *counts.entry(ng).or_default() += 1;
        }
    }

    // Keep only frequent patterns.
    let candidates: HashMap<[u8; 4], ()> = counts
        .into_iter()
        .filter(|(_, c)| *c >= MIN_OCCURRENCES)
        .map(|(ng, _)| (ng, ()))
        .collect();

    if candidates.is_empty() {
        return Vec::new();
    }

    // Pass 2: collect offsets for frequent patterns.
    let mut offsets: HashMap<[u8; 4], Vec<usize>> = HashMap::new();
    for i in 0..scan_end {
        let ng: [u8; 4] = data[i..i + 4].try_into().unwrap();
        if candidates.contains_key(&ng) {
            offsets.entry(ng).or_default().push(i);
        }
    }

    // Analyse each pattern's offset list.
    let raw: Vec<Signal> = offsets
        .into_iter()
        .filter_map(|(ng, offs)| stride_signal(&ng, &offs, data.len()))
        .collect();

    // Deduplicate by stride: multiple adjacent phase offsets often produce the
    // same stride (e.g., every byte position in a repeating struct).  Keep only
    // the highest-confidence representative per distinct stride value.
    let mut best: HashMap<usize, Signal> = HashMap::new();
    for sig in raw {
        let stride = match &sig.kind {
            SignalKind::RepeatedPattern { stride, .. } => *stride,
            _ => continue,
        };
        let entry = best.entry(stride).or_insert_with(|| sig.clone());
        // Prefer higher confidence; break ties by earlier start offset so the
        // most "canonical" phase of the pattern wins.
        if sig.confidence > entry.confidence
            || (sig.confidence == entry.confidence && sig.region.offset < entry.region.offset)
        {
            *entry = sig;
        }
    }

    // Return highest-confidence signals first.
    let mut signals: Vec<Signal> = best.into_values().collect();
    signals.sort_by(|a, b| b.confidence.partial_cmp(&a.confidence).unwrap());
    signals
}

/// Try to extract a stride signal from one pattern's offset list.
/// Returns `None` if no consistent stride is found.
fn stride_signal(ng: &[u8; 4], offsets: &[usize], file_len: usize) -> Option<Signal> {
    if offsets.len() < MIN_OCCURRENCES as usize {
        return None;
    }

    // Compute consecutive gaps.
    let gaps: Vec<usize> = offsets.windows(2).map(|w| w[1] - w[0]).collect();

    // Find the most common gap (= dominant stride).
    let mut gap_counts: HashMap<usize, usize> = HashMap::new();
    for &g in &gaps {
        if g >= MIN_STRIDE {
            *gap_counts.entry(g).or_default() += 1;
        }
    }

    let (&stride, &stride_hits) = gap_counts.iter().max_by_key(|(_, &c)| c)?;
    let consistency = stride_hits as f64 / gaps.len() as f64;
    if consistency < MIN_CONSISTENCY || stride_hits < 3 {
        return None;
    }

    let start = offsets[0];
    let end = (offsets[offsets.len() - 1] + 4).min(file_len);
    let conf = stride_confidence(offsets.len(), consistency, stride);

    let reason = format!(
        "pattern {:02x} {:02x} {:02x} {:02x} × {} occurrences at stride {} ({:.0}% consistent)",
        ng[0],
        ng[1],
        ng[2],
        ng[3],
        offsets.len(),
        stride,
        consistency * 100.0,
    );

    Some(Signal::new(
        Region::new(start, end - start),
        SignalKind::RepeatedPattern {
            pattern: ng.to_vec(),
            stride,
            occurrences: offsets.len(),
        },
        conf,
        reason,
    ))
}

fn stride_confidence(occurrences: usize, consistency: f64, stride: usize) -> f64 {
    // More occurrences and higher consistency → higher confidence.
    let occ_factor = ((occurrences.saturating_sub(3)) as f64 / 20.0).min(1.0);
    let base = 0.45 + 0.30 * consistency + 0.15 * occ_factor;
    // Slight boost for "round" strides (powers of two or multiples of 4).
    let round_boost = if stride.is_power_of_two() || stride.is_multiple_of(4) {
        0.05
    } else {
        0.0
    };
    (base + round_boost).min(0.90)
}

// ── Public API ────────────────────────────────────────────────────────────────

/// Run both the bigram profile and stride detection over `data`.
///
/// Returns all resulting signals sorted by offset.  The NgramProfile signal
/// (if emitted) always has `region.offset = 0` and covers the whole file.
pub fn scan_ngrams(data: &[u8]) -> Vec<Signal> {
    let mut signals = Vec::new();
    if let Some(profile) = bigram_profile(data) {
        signals.push(profile);
    }
    signals.extend(stride_patterns(data));
    signals
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::SignalKind;

    // ── Bigram profile ────────────────────────────────────────────────────────

    #[test]
    fn classifies_ascii_text_as_text() {
        // 512 bytes of ASCII text.
        let data: Vec<u8> = "the quick brown fox jumps over the lazy dog. "
            .bytes()
            .cycle()
            .take(512)
            .collect();
        let sigs = scan_ngrams(&data);
        let profile = sigs
            .iter()
            .find(|s| matches!(&s.kind, SignalKind::NgramProfile { .. }))
            .expect("expected NgramProfile signal");
        match &profile.kind {
            SignalKind::NgramProfile { data_type_hint, .. } => {
                assert_eq!(data_type_hint, "text");
            }
            _ => unreachable!(),
        }
    }

    #[test]
    fn classifies_null_heavy_data_as_sparse() {
        // 512 bytes: mostly nulls with scattered non-zero values.
        let mut data = vec![0u8; 512];
        for i in (0..512).step_by(16) {
            data[i] = 0x01;
        }
        let sigs = scan_ngrams(&data);
        let profile = sigs
            .iter()
            .find(|s| matches!(&s.kind, SignalKind::NgramProfile { .. }))
            .expect("expected NgramProfile signal");
        match &profile.kind {
            SignalKind::NgramProfile {
                data_type_hint,
                bigram_entropy,
                ..
            } => {
                assert_eq!(
                    data_type_hint, "sparse/structured",
                    "entropy={bigram_entropy}"
                );
            }
            _ => unreachable!(),
        }
    }

    #[test]
    fn no_profile_for_small_data() {
        let data = vec![0xffu8; 100];
        let sigs = scan_ngrams(&data);
        assert!(
            !sigs
                .iter()
                .any(|s| matches!(&s.kind, SignalKind::NgramProfile { .. })),
            "should not emit profile for < 256 bytes"
        );
    }

    #[test]
    fn top_bigrams_shows_dominant_pair() {
        // File of alternating 0x41 0x42 — bigram "41 42" should dominate.
        let data: Vec<u8> = std::iter::repeat([0x41u8, 0x42])
            .flatten()
            .take(512)
            .collect();
        let sigs = scan_ngrams(&data);
        let profile = sigs
            .iter()
            .find(|s| matches!(&s.kind, SignalKind::NgramProfile { .. }))
            .unwrap();
        match &profile.kind {
            SignalKind::NgramProfile { top_bigrams, .. } => {
                assert!(
                    top_bigrams[0].starts_with("41 42") || top_bigrams[0].starts_with("42 41"),
                    "expected 41 42 or 42 41 to dominate, got {:?}",
                    top_bigrams
                );
            }
            _ => unreachable!(),
        }
    }

    // ── Stride detection ──────────────────────────────────────────────────────

    #[test]
    fn detects_simple_stride() {
        // 4-byte pattern at stride 8 across 64 bytes → 8 occurrences.
        let marker = [0xde, 0xad, 0xbe, 0xef];
        let mut data = vec![0u8; 8 * 8]; // 64 bytes
        for i in 0..8 {
            data[i * 8..i * 8 + 4].copy_from_slice(&marker);
        }
        let sigs = scan_ngrams(&data);
        // The marker, plus every sliding offset into the 8-byte record, all repeat
        // at stride=8.  Verify the marker pattern specifically is among the results.
        let marker_sig = sigs.iter().find(|s| {
            matches!(&s.kind, SignalKind::RepeatedPattern { pattern, stride: 8, occurrences }
                if pattern.as_slice() == marker && *occurrences >= 4)
        });
        assert!(
            marker_sig.is_some(),
            "expected stride=8 signal for the marker pattern"
        );
    }

    #[test]
    fn boring_pattern_not_detected() {
        // All-zero 4-byte blocks at regular stride — should not produce a
        // stride signal because is_boring filters out same-byte patterns.
        let mut data = vec![0xffu8; 64];
        for i in 0..8 {
            data[i * 8..i * 8 + 4].copy_from_slice(&[0u8; 4]);
        }
        let sigs = scan_ngrams(&data);
        let zero_stride = sigs.iter().find(|s| {
            matches!(&s.kind, SignalKind::RepeatedPattern { pattern, .. } if pattern == &[0u8,0,0,0])
        });
        assert!(zero_stride.is_none(), "all-zero pattern should be filtered");
    }

    #[test]
    fn stride_requires_min_occurrences() {
        // Only 3 occurrences — below MIN_OCCURRENCES=4, should not fire.
        let marker = [0xca, 0xfe, 0xba, 0xbe];
        let mut data = vec![0u8; 8 * 4];
        for i in 0..3 {
            data[i * 8..i * 8 + 4].copy_from_slice(&marker);
        }
        let sigs = scan_ngrams(&data);
        let stride_sig = sigs
            .iter()
            .find(|s| matches!(&s.kind, SignalKind::RepeatedPattern { .. }));
        assert!(
            stride_sig.is_none(),
            "fewer than 4 occurrences should not emit"
        );
    }

    #[test]
    fn stride_confidence_increases_with_occurrences() {
        let c_few = stride_confidence(4, 0.90, 8);
        let c_many = stride_confidence(20, 0.90, 8);
        assert!(c_many > c_few);
    }

    #[test]
    fn stride_confidence_increases_with_consistency() {
        let c_low = stride_confidence(8, 0.60, 8);
        let c_high = stride_confidence(8, 1.00, 8);
        assert!(c_high > c_low);
    }
}
