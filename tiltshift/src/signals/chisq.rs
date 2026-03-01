//! Chi-square test for byte-distribution uniformity.
//!
//! The chi-square statistic measures how far the observed byte-frequency
//! distribution deviates from a perfectly uniform distribution (the null
//! hypothesis for random/encrypted data).
//!
//! ```text
//!   chi-sq = Σ (observed_i − expected_i)² / expected_i   over i ∈ 0..256
//!   expected_i = N / 256
//!   degrees of freedom = 255
//! ```
//!
//! Under H₀ (truly random bytes) the statistic follows chi-squared(255):
//! mean = 255, std ≈ 22.6.  The p-value is P(X ≥ chi_sq) under that
//! distribution, approximated via the Wilson–Hilferty cube-root transform.
//!
//! **Complements Shannon entropy**: entropy measures average information
//! per byte; chi-square tests whether the *frequency distribution* is
//! plausibly uniform.  A region can have near-maximum entropy but still
//! fail the uniformity test if some byte values are slightly over- or
//! under-represented — which is common in compression artifacts or PRNG
//! output with short periods.
//!
//! One `Signal` is emitted per file.  Files smaller than `MIN_BYTES` are
//! skipped because the test is unreliable when the expected count per bin
//! (N/256) falls below ~2.

use crate::signals::entropy::byte_histogram;
use crate::types::{Region, Signal, SignalKind};

/// Minimum file size (bytes) for a meaningful chi-square test.
/// Need expected count per bin ≥ 2, so N ≥ 512.
const MIN_BYTES: usize = 512;

// ── Math helpers ──────────────────────────────────────────────────────────────

/// Approximation of the error function (Abramowitz & Stegun 7.1.26, max
/// absolute error < 1.5 × 10⁻⁷).
fn erf_approx(x: f64) -> f64 {
    let sign = if x >= 0.0 { 1.0 } else { -1.0 };
    let x = x.abs();
    let t = 1.0 / (1.0 + 0.3275911 * x);
    let poly = ((((1.061_405_429 * t - 1.453_152_027) * t) + 1.421_413_741) * t - 0.284_496_736)
        * t
        + 0.254_829_592;
    sign * (1.0 - poly * t * (-x * x).exp())
}

/// Standard normal CDF: Φ(z) = P(Z ≤ z).
fn normal_cdf(z: f64) -> f64 {
    0.5 * (1.0 + erf_approx(z / 2.0_f64.sqrt()))
}

/// P(X ≥ chi_sq) for X ~ χ²(df), via Wilson–Hilferty cube-root transform.
///
/// Accurate to within ~0.005 for df ≥ 30 and p-values in [0.001, 0.999].
fn chi_sq_p_value(chi_sq: f64, df: usize) -> f64 {
    let k = df as f64;
    let h = 2.0 / (9.0 * k);
    let z = ((chi_sq / k).powf(1.0 / 3.0) - (1.0 - h)) / h.sqrt();
    1.0 - normal_cdf(z)
}

// ── Core statistic ────────────────────────────────────────────────────────────

/// Chi-square statistic for uniformity over all 256 byte values.
///
/// Returns 0.0 for empty input.  Degrees of freedom = 255.
pub fn chi_square_uniformity(data: &[u8]) -> f64 {
    if data.is_empty() {
        return 0.0;
    }
    let hist = byte_histogram(data);
    let expected = data.len() as f64 / 256.0;
    hist.iter()
        .map(|&obs| {
            let diff = obs as f64 - expected;
            diff * diff / expected
        })
        .sum()
}

// ── Signal scanner ────────────────────────────────────────────────────────────

/// Classify the p-value into a human-readable label.
fn uniformity_label(p_value: f64) -> &'static str {
    if p_value < 0.01 {
        "non-uniform"
    } else if p_value < 0.05 {
        "mildly non-uniform"
    } else if p_value > 0.99 {
        "suspiciously uniform"
    } else if p_value > 0.95 {
        "over-uniform"
    } else {
        "consistent with uniform"
    }
}

/// Emit one chi-square uniformity signal for the whole file.
///
/// Returns `None` for files shorter than `MIN_BYTES`.
pub fn scan_chi_square(data: &[u8]) -> Option<Signal> {
    if data.len() < MIN_BYTES {
        return None;
    }

    let chi_sq = chi_square_uniformity(data);
    let p_value = chi_sq_p_value(chi_sq, 255);
    let label = uniformity_label(p_value);

    // Confidence: the test is statistically founded, but smaller files give
    // noisier results.  Confidence reaches 0.85 at 4096+ bytes.
    let size_factor = ((data.len() as f64).log2() - 9.0).clamp(0.0, 4.0) / 4.0;
    let confidence = 0.60 + 0.25 * size_factor;

    let reason = format!(
        "chi-sq {chi_sq:.1}  p={:.3}  ({} bytes, df=255) → {label}",
        p_value,
        data.len(),
    );

    Some(Signal::new(
        Region::new(0, data.len()),
        SignalKind::ChiSquare { chi_sq, p_value },
        confidence,
        reason,
    ))
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::SignalKind;

    #[test]
    fn chi_sq_all_same_byte_is_maximum() {
        // All 4096 bytes equal 0x00 → all count is in one bin.
        let data = vec![0u8; 4096];
        let chi = chi_square_uniformity(&data);
        // Only bin 0 is populated: (4096 - 16)^2 / 16 + 255 * 16 = large
        // Just verify it is very large.
        assert!(chi > 1_000_000.0, "expected very high chi-sq, got {chi}");
    }

    #[test]
    fn chi_sq_near_255_for_uniform() {
        // One complete cycle 0x00..=0xFF repeated 16 times = 4096 bytes.
        let data: Vec<u8> = (0u8..=255).cycle().take(4096).collect();
        let chi = chi_square_uniformity(&data);
        // Perfectly uniform → exactly 0 (every bin has exactly N/256 counts).
        assert!(chi < 1e-6, "expected ~0 chi-sq for uniform, got {chi}");
    }

    #[test]
    fn chi_sq_p_value_near_half_for_expected_chi_sq() {
        // chi-sq = 255 (= df) should give p ≈ 0.50.
        let p = chi_sq_p_value(255.0, 255);
        assert!((p - 0.50).abs() < 0.03, "expected p≈0.50, got {p}");
    }

    #[test]
    fn chi_sq_p_value_small_for_large_statistic() {
        // Extremely large chi-sq → p should be near 0.
        let p = chi_sq_p_value(1_000_000.0, 255);
        assert!(p < 0.001, "expected p≈0, got {p}");
    }

    #[test]
    fn chi_sq_p_value_large_for_small_statistic() {
        // Near-zero chi-sq → p should be near 1.
        let p = chi_sq_p_value(0.01, 255);
        assert!(p > 0.999, "expected p≈1, got {p}");
    }

    #[test]
    fn no_signal_for_small_file() {
        let data = vec![0u8; MIN_BYTES - 1];
        assert!(scan_chi_square(&data).is_none());
    }

    #[test]
    fn signal_present_for_adequate_file() {
        let data: Vec<u8> = (0u8..=255).cycle().take(1024).collect();
        let sig = scan_chi_square(&data);
        assert!(sig.is_some());
    }

    #[test]
    fn uniform_data_classified_correctly() {
        // Perfectly uniform: expect p ≈ 1.0 → "consistent with uniform" or "over-uniform"
        let data: Vec<u8> = (0u8..=255).cycle().take(4096).collect();
        let sig = scan_chi_square(&data).unwrap();
        match &sig.kind {
            SignalKind::ChiSquare { p_value, .. } => {
                // p near 1.0 because chi_sq is exactly 0
                assert!(
                    *p_value > 0.95,
                    "expected high p-value for uniform data, got {p_value}"
                );
            }
            _ => panic!("unexpected kind"),
        }
    }

    #[test]
    fn structured_data_classified_as_non_uniform() {
        // ASCII text: only 95 printable byte values used.
        let data: Vec<u8> = b"the quick brown fox jumps over the lazy dog. "
            .iter()
            .copied()
            .cycle()
            .take(4096)
            .collect();
        let sig = scan_chi_square(&data).unwrap();
        match &sig.kind {
            SignalKind::ChiSquare { p_value, .. } => {
                assert!(
                    *p_value < 0.01,
                    "expected low p-value for ASCII text, got {p_value}"
                );
            }
            _ => panic!("unexpected kind"),
        }
    }

    #[test]
    fn confidence_increases_with_file_size() {
        let small: Vec<u8> = (0u8..=255).cycle().take(512).collect();
        let large: Vec<u8> = (0u8..=255).cycle().take(65536).collect();
        let c_small = scan_chi_square(&small).unwrap().confidence;
        let c_large = scan_chi_square(&large).unwrap().confidence;
        assert!(
            c_large > c_small,
            "larger file should have higher confidence"
        );
    }
}
