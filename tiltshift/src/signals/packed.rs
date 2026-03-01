use crate::types::{Region, Signal, SignalKind};

/// Minimum data length to attempt packed-field detection.
const MIN_LEN: usize = 64;
/// Minimum marginal entropy for each nibble — excludes trivially constant data.
const MIN_NIBBLE_ENTROPY: f64 = 0.5;
/// Maximum marginal entropy — excludes random/encrypted data where H ≈ 4.0.
const MAX_NIBBLE_ENTROPY: f64 = 3.7;
/// Maximum |H_high − H_low| before the balance filter rejects the region.
/// The ASCII text discriminator: in ASCII H_high ≈ 2.0, H_low ≈ 3.9 → delta ≈ 1.9.
const MAX_ENTROPY_DELTA: f64 = 1.5;
/// Minimum H_joint / (H_high + H_low) to qualify as "nibbles are independent".
const MIN_INDEPENDENCE_RATIO: f64 = 0.85;
/// Fraction of bytes with both nibbles in 0..=9 required to declare BCD.
const BCD_THRESHOLD: f64 = 0.90;

/// Compute the Shannon entropy of a frequency table (counts, not probabilities).
///
/// Returns entropy in bits (log₂-based).  The caller must ensure `total > 0`.
fn entropy_of(hist: &[u64], total: u64) -> f64 {
    let n = total as f64;
    hist.iter()
        .filter(|&&c| c > 0)
        .map(|&c| {
            let p = c as f64 / n;
            -p * p.log2()
        })
        .sum()
}

/// Scan for packed nibble sub-fields.
///
/// Measures whether the high and low nibbles of each byte vary *independently*,
/// which is the hallmark of packed two-field encodings: BCD dates, 4-bit
/// type/subtype pairs, MPEG-2 flag bytes, TCP DSCP+ECN, etc.
///
/// Only a single signal is emitted (covering the whole file), and only when
/// the filtering criteria are satisfied.  Returns an empty `Vec` otherwise.
pub fn scan_packed(data: &[u8]) -> Vec<Signal> {
    if data.len() < MIN_LEN {
        return vec![];
    }

    let mut hist_high = [0u64; 16];
    let mut hist_low = [0u64; 16];
    let mut hist_joint = [0u64; 256];
    let mut bcd_count = 0usize;

    for &b in data {
        let hi = (b >> 4) as usize;
        let lo = (b & 0x0F) as usize;
        hist_high[hi] += 1;
        hist_low[lo] += 1;
        hist_joint[b as usize] += 1;
        if hi <= 9 && lo <= 9 {
            bcd_count += 1;
        }
    }

    let total = data.len() as u64;
    let h_high = entropy_of(&hist_high, total);
    let h_low = entropy_of(&hist_low, total);
    let h_joint = entropy_of(&hist_joint, total);

    // Filter 1: both nibbles must actually vary.
    if h_high < MIN_NIBBLE_ENTROPY || h_low < MIN_NIBBLE_ENTROPY {
        return vec![];
    }
    // Filter 2: exclude random / encrypted data.
    if h_high > MAX_NIBBLE_ENTROPY || h_low > MAX_NIBBLE_ENTROPY {
        return vec![];
    }
    // Filter 3: balance — both nibbles carry comparable information.
    // This is the key ASCII discriminator (ASCII: H_high ≈ 2.0, H_low ≈ 3.9).
    if (h_high - h_low).abs() >= MAX_ENTROPY_DELTA {
        return vec![];
    }

    let sum_marginals = h_high + h_low;
    // sum_marginals > 0 because both exceed MIN_NIBBLE_ENTROPY > 0.
    let independence_ratio = h_joint / sum_marginals;

    // Filter 4: nibbles must be mostly independent.
    if independence_ratio < MIN_INDEPENDENCE_RATIO {
        return vec![];
    }

    // Mutual information (clamped ≥ 0 for floating-point rounding).
    let mutual_information = (sum_marginals - h_joint).max(0.0);

    // ── Confidence ────────────────────────────────────────────────────────────
    let ind_boost = 0.20 * ((independence_ratio - MIN_INDEPENDENCE_RATIO) / 0.15).min(1.0);
    let bal_boost = 0.10 * (1.0 - (h_high - h_low).abs() / MAX_ENTROPY_DELTA).max(0.0);
    let mut confidence = (0.55 + ind_boost + bal_boost).min(0.88);

    // ── BCD special case ──────────────────────────────────────────────────────
    let bcd_ratio = bcd_count as f64 / data.len() as f64;
    let is_bcd = bcd_ratio >= BCD_THRESHOLD;
    if is_bcd {
        confidence = (confidence + 0.15).min(0.92);
    }

    // ── Hint string ───────────────────────────────────────────────────────────
    let hint = if is_bcd {
        format!(
            "BCD-encoded decimal data ({:.0}% of bytes)",
            bcd_ratio * 100.0
        )
    } else if (h_high - h_low).abs() < 0.3 {
        "two equal-cardinality nibble fields (H_hi≈H_lo)".to_string()
    } else if h_high > h_low {
        "high nibble = wide field, low nibble = narrow field".to_string()
    } else {
        "high nibble = narrow field, low nibble = wide field".to_string()
    };

    let reason = format!(
        "nibble independence ratio {independence_ratio:.3} \
         (H_hi={h_high:.2}, H_lo={h_low:.2}, MI={mutual_information:.3})"
    );

    vec![Signal::new(
        Region::new(0, data.len()),
        SignalKind::PackedField {
            high_nibble_entropy: h_high,
            low_nibble_entropy: h_low,
            mutual_information,
            independence_ratio,
            hint,
        },
        confidence,
        reason,
    )]
}

#[cfg(test)]
mod tests {
    use super::*;

    // ── BCD bytes ────────────────────────────────────────────────────────────

    #[test]
    fn bcd_data_emits_signal_with_bcd_hint() {
        // Construct all 100 BCD byte combinations: hi ∈ 0..=9, lo ∈ 0..=9.
        // Because every (hi, lo) pair appears exactly once, H_high = H_low = log2(10)
        // ≈ 3.32 bits and the joint entropy H_joint ≈ log2(100) ≈ 6.64 bits, giving
        // independence_ratio ≈ 1.0 — well above the 0.85 threshold.
        let mut base: Vec<u8> = Vec::with_capacity(100);
        for hi in 0u8..=9 {
            for lo in 0u8..=9 {
                base.push((hi << 4) | lo);
            }
        }
        // Repeat twice to get 200 bytes (well above MIN_LEN=64).
        let data: Vec<u8> = base.iter().cycle().take(200).cloned().collect();
        let sigs = scan_packed(&data);
        assert_eq!(sigs.len(), 1, "expected exactly one signal");
        let sig = &sigs[0];
        if let SignalKind::PackedField { hint, .. } = &sig.kind {
            assert!(hint.contains("BCD"), "hint should mention BCD: {hint}");
        } else {
            panic!("wrong signal kind");
        }
        assert!(sig.confidence >= 0.70, "confidence={}", sig.confidence);
    }

    // ── ASCII text → no signal ────────────────────────────────────────────────

    #[test]
    fn ascii_text_does_not_emit_signal() {
        // ASCII text: high nibbles cluster around 0x6, 0x7 → H_high ≈ 2.0
        // while low nibbles are broadly varied → H_low ≈ 3.9 → |delta| > 1.5
        let text = b"abcdefghijklmnopqrstuvwxyz ABCDEFGHIJKLMNOPQRSTUVWXYZ \
                     0123456789 the quick brown fox jumps over the lazy dog";
        // Pad to at least MIN_LEN by repeating.
        let data: Vec<u8> = text.iter().cycle().take(256).cloned().collect();
        let sigs = scan_packed(&data);
        assert!(
            sigs.is_empty(),
            "ASCII text should not trigger packed-field detector"
        );
    }

    // ── All-zero / constant data → no signal ──────────────────────────────────

    #[test]
    fn constant_data_does_not_emit_signal() {
        let data = vec![0x00u8; 128];
        assert!(scan_packed(&data).is_empty());
    }

    #[test]
    fn all_ff_does_not_emit_signal() {
        let data = vec![0xFFu8; 128];
        assert!(scan_packed(&data).is_empty());
    }

    // ── Short data → no signal ────────────────────────────────────────────────

    #[test]
    fn short_data_does_not_emit_signal() {
        // Build 32 bytes of otherwise valid packed-field data — below MIN_LEN.
        let pattern: Vec<u8> = (0u8..16).map(|i| (i << 4) | (15 - i)).collect();
        let data: Vec<u8> = pattern.iter().cycle().take(32).cloned().collect();
        assert!(scan_packed(&data).is_empty());
    }

    // ── Two independent sub-fields → high independence_ratio ─────────────────

    #[test]
    fn independent_nibble_fields_emit_signal_with_high_ratio() {
        // Use nibble values 0..=11 (12 distinct values) so H_high = H_low =
        // log2(12) ≈ 3.585 bits — below MAX_NIBBLE_ENTROPY=3.7.  Covering all
        // 12×12=144 combinations gives H_joint ≈ log2(144) ≈ 7.17 bits, so
        // independence_ratio = 7.17 / (3.585 + 3.585) ≈ 1.0.
        let mut base = Vec::with_capacity(144);
        for hi in 0u8..12 {
            for lo in 0u8..12 {
                base.push((hi << 4) | lo);
            }
        }
        // Repeat 4× → 576 bytes.
        let data: Vec<u8> = base.iter().cycle().take(576).cloned().collect();
        let sigs = scan_packed(&data);
        assert_eq!(sigs.len(), 1, "expected exactly one signal");
        if let SignalKind::PackedField {
            independence_ratio, ..
        } = &sigs[0].kind
        {
            assert!(*independence_ratio > 0.95, "ratio={independence_ratio}");
        } else {
            panic!("wrong kind");
        }
    }
}
