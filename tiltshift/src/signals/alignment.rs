use crate::types::{Region, Signal, SignalKind};

/// Minimum entropy spread (bits) to emit a signal.
const MIN_SPREAD: f64 = 0.5;

/// Minimum number of complete A-blocks required to analyze an alignment.
const MIN_BLOCKS: usize = 8;

/// Detect dominant byte alignment by measuring per-phase entropy variation.
///
/// For each candidate alignment A ∈ {2, 4, 8, 16}, builds A per-phase byte
/// histograms and computes Shannon entropy for each phase.  When one phase is
/// systematically more (or less) varied than the others, data respects that
/// alignment boundary.
///
/// Returns at most one signal: the alignment with the largest entropy spread.
pub fn scan_alignment(data: &[u8]) -> Vec<Signal> {
    let mut best: Option<(usize, f64, usize)> = None; // (alignment, spread, dominant_phase)

    for &a in &[2usize, 4, 8, 16] {
        let n_blocks = data.len() / a;
        if n_blocks < MIN_BLOCKS {
            continue;
        }

        // Build per-phase byte histograms.
        let mut hists = vec![[0u32; 256]; a];
        let usable = n_blocks * a;
        for i in 0..usable {
            hists[i % a][data[i] as usize] += 1;
        }

        // Compute Shannon entropy for each phase's histogram.
        let n = n_blocks as f64;
        let entropies: Vec<f64> = hists
            .iter()
            .map(|hist| {
                hist.iter()
                    .filter(|&&c| c > 0)
                    .map(|&c| {
                        let p = c as f64 / n;
                        -p * p.log2()
                    })
                    .sum()
            })
            .collect();

        let max_h = entropies.iter().cloned().fold(f64::NEG_INFINITY, f64::max);
        let min_h = entropies.iter().cloned().fold(f64::INFINITY, f64::min);
        let spread = max_h - min_h;

        if spread < MIN_SPREAD {
            continue;
        }

        // Keep the candidate with the strictly largest spread.
        if best.is_none_or(|(_, best_spread, _)| spread > best_spread) {
            let dominant_phase = entropies
                .iter()
                .enumerate()
                .max_by(|(_, x), (_, y)| x.partial_cmp(y).unwrap())
                .map(|(i, _)| i)
                .unwrap_or(0);
            best = Some((a, spread, dominant_phase));
        }
    }

    let (alignment, spread, dominant_phase) = match best {
        Some(b) => b,
        None => return vec![],
    };

    // Confidence: 0.55 at spread == MIN_SPREAD, up to 0.90 at spread >= 3.0.
    let t = ((spread - MIN_SPREAD) / (3.0 - MIN_SPREAD)).clamp(0.0, 1.0);
    let confidence = 0.55 + t * (0.90 - 0.55);

    let region = Region::new(0, data.len());
    let reason = format!(
        "entropy spread {spread:.2} bits across {alignment}-byte phases; phase {dominant_phase} most variable"
    );

    vec![Signal::new(
        region,
        SignalKind::AlignmentHint {
            alignment,
            entropy_spread: spread,
            dominant_phase,
        },
        confidence,
        reason,
    )]
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::SignalKind;

    fn u32le_array(values: impl Iterator<Item = u32>) -> Vec<u8> {
        values.flat_map(|v| v.to_le_bytes()).collect()
    }

    fn u16le_array(values: impl Iterator<Item = u16>) -> Vec<u8> {
        values.flat_map(|v| v.to_le_bytes()).collect()
    }

    #[test]
    fn detects_4byte_aligned_integers() {
        // 256 u32le values 0..256: low bytes vary, high bytes are zero.
        // Alignment-4 spread = 8; alignment-2 spread ≈ 5.5 — 4 wins.
        let data = u32le_array(0u32..256);
        let signals = scan_alignment(&data);
        assert_eq!(signals.len(), 1);
        let SignalKind::AlignmentHint { alignment, .. } = signals[0].kind else {
            panic!("wrong kind");
        };
        assert_eq!(alignment, 4);
    }

    #[test]
    fn detects_2byte_aligned_data() {
        // 256 u16le values 0..256: low bytes vary, high bytes are zero.
        // Alignment-2 spread = 8; alignment-4 spread = 7 — 2 wins.
        let data = u16le_array(0u16..256);
        let signals = scan_alignment(&data);
        assert_eq!(signals.len(), 1);
        let SignalKind::AlignmentHint { alignment, .. } = signals[0].kind else {
            panic!("wrong kind");
        };
        assert_eq!(alignment, 2);
    }

    #[test]
    fn no_signal_for_uniform_phases() {
        // All 4-byte blocks are [i, i, i, i]: every phase has the same distribution
        // → spread = 0 for every candidate alignment.
        let data: Vec<u8> = (0u8..=255).flat_map(|i| [i, i, i, i]).collect();
        let signals = scan_alignment(&data);
        assert!(signals.is_empty(), "expected no signal, got {signals:?}");
    }

    #[test]
    fn no_signal_for_short_data() {
        // 12 bytes: no alignment can form 8 complete blocks (need ≥ 16 for A=2).
        let data = vec![0u8; 12];
        let signals = scan_alignment(&data);
        assert!(
            signals.is_empty(),
            "expected no signal for short data, got {signals:?}"
        );
    }

    #[test]
    fn confidence_scales_with_spread() {
        // Clear 4-byte pattern: spread = 8 → high confidence.
        let clear = u32le_array(0u32..256);
        let sigs = scan_alignment(&clear);
        assert_eq!(sigs.len(), 1);
        assert!(
            sigs[0].confidence > 0.80,
            "expected high confidence, got {}",
            sigs[0].confidence
        );

        // All-zeros: no spread → no signal.
        assert!(scan_alignment(&vec![0u8; 256]).is_empty());
    }

    #[test]
    fn dominant_phase_reported_correctly() {
        // u32le array: phase 0 (low byte) is the most varied → dominant_phase = 0.
        let data = u32le_array(0u32..256);
        let signals = scan_alignment(&data);
        assert_eq!(signals.len(), 1);
        let SignalKind::AlignmentHint { dominant_phase, .. } = signals[0].kind else {
            panic!("wrong kind");
        };
        assert_eq!(
            dominant_phase, 0,
            "low byte (phase 0) should be most varied"
        );
    }
}
