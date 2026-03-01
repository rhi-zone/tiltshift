//! Compression ratio probe.
//!
//! Deflate-compresses the file and measures `compressed_size / original_size`.
//! This is a more direct proxy for data randomness than Shannon entropy:
//!
//! - **entropy** measures average information per symbol in the byte
//!   distribution, but says nothing about *sequential* structure;
//! - **compression ratio** tests whether the *sequence* has exploitable
//!   patterns — repetition, locality, and context-dependence that deflate's
//!   LZ77 + Huffman stage can exploit.
//!
//! Practical consequence: compressed data (gzip, zstd, etc.) and encrypted
//! data both have near-maximum entropy, but only encrypted data has a ratio
//! near 1.0.  Compressed data will have ratio > 1.0 because deflate cannot
//! improve on already-compressed bytes while still adding the zlib header.
//!
//! One `Signal` is emitted per file.  Files shorter than `MIN_BYTES` are
//! skipped because overhead bytes dominate at tiny sizes.

use crate::types::{Region, Signal, SignalKind};
use flate2::{write::ZlibEncoder, Compression};
use std::io::Write;

/// Minimum file size (bytes) to run the probe.
const MIN_BYTES: usize = 256;

// ── Compression helper ────────────────────────────────────────────────────────

/// Deflate-compress `data` (zlib framing, level 6) and return the compressed
/// byte count.  Returns `data.len()` on error, giving a ratio of 1.0.
fn deflate_size(data: &[u8]) -> usize {
    let mut enc = ZlibEncoder::new(Vec::with_capacity(data.len()), Compression::default());
    if enc.write_all(data).is_err() {
        return data.len();
    }
    enc.finish().map(|v| v.len()).unwrap_or(data.len())
}

// ── Classification ────────────────────────────────────────────────────────────

fn compressibility_label(ratio: f64) -> &'static str {
    if ratio >= 0.99 {
        "incompressible"
    } else if ratio >= 0.90 {
        "nearly incompressible"
    } else if ratio >= 0.70 {
        "mildly compressible"
    } else if ratio >= 0.40 {
        "moderately compressible"
    } else {
        "highly compressible"
    }
}

// ── Signal scanner ────────────────────────────────────────────────────────────

/// Try to compress the whole file and emit a compression ratio signal.
///
/// Returns `None` for files shorter than `MIN_BYTES`.
pub fn scan_compress_probe(data: &[u8]) -> Option<Signal> {
    if data.len() < MIN_BYTES {
        return None;
    }

    let original_size = data.len();
    let compressed_size = deflate_size(data);
    let ratio = compressed_size as f64 / original_size as f64;
    let label = compressibility_label(ratio);

    // Confidence grows with file size — small files yield noisier estimates.
    let size_factor = ((original_size as f64).log2() - 8.0).clamp(0.0, 4.0) / 4.0;
    let confidence = 0.65 + 0.20 * size_factor;

    let reason =
        format!("deflate {compressed_size}/{original_size} bytes → ratio {ratio:.3} → {label}");

    Some(Signal::new(
        Region::new(0, original_size),
        SignalKind::CompressionProbe {
            original_size,
            compressed_size,
            ratio,
        },
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
    fn no_signal_for_tiny_file() {
        let data = vec![0u8; MIN_BYTES - 1];
        assert!(scan_compress_probe(&data).is_none());
    }

    #[test]
    fn signal_emitted_for_adequate_file() {
        let data = vec![0u8; 1024];
        assert!(scan_compress_probe(&data).is_some());
    }

    #[test]
    fn all_zeros_is_highly_compressible() {
        // Runs of zeros deflate to almost nothing.
        let data = vec![0u8; 65536];
        let sig = scan_compress_probe(&data).unwrap();
        let SignalKind::CompressionProbe { ratio, .. } = sig.kind else {
            panic!("unexpected kind")
        };
        assert!(
            ratio < 0.05,
            "expected very low ratio for zeros, got {ratio}"
        );
    }

    #[test]
    fn random_like_data_is_nearly_incompressible() {
        // Simple LCG produces pseudo-random bytes with no exploitable repetition.
        let mut x = 12345u64;
        let data: Vec<u8> = (0..65536)
            .map(|_| {
                x = x
                    .wrapping_mul(6_364_136_223_846_793_005)
                    .wrapping_add(1_442_695_040_888_963_407);
                (x >> 33) as u8
            })
            .collect();
        let sig = scan_compress_probe(&data).unwrap();
        let SignalKind::CompressionProbe { ratio, .. } = sig.kind else {
            panic!("unexpected kind")
        };
        assert!(
            ratio > 0.90,
            "expected high ratio for pseudo-random data, got {ratio}"
        );
    }

    #[test]
    fn ascii_text_is_compressible() {
        let chunk = b"the quick brown fox jumps over the lazy dog. ";
        let data: Vec<u8> = chunk.iter().copied().cycle().take(16384).collect();
        let sig = scan_compress_probe(&data).unwrap();
        let SignalKind::CompressionProbe { ratio, .. } = sig.kind else {
            panic!("unexpected kind")
        };
        assert!(
            ratio < 0.20,
            "expected low ratio for repeated text, got {ratio}"
        );
    }

    #[test]
    fn confidence_increases_with_file_size() {
        let small: Vec<u8> = (0u8..=255).cycle().take(256).collect();
        let large: Vec<u8> = (0u8..=255).cycle().take(65536).collect();
        let c_small = scan_compress_probe(&small).unwrap().confidence;
        let c_large = scan_compress_probe(&large).unwrap().confidence;
        assert!(
            c_large > c_small,
            "larger file should yield higher confidence"
        );
    }

    #[test]
    fn ratio_field_matches_sizes() {
        let data: Vec<u8> = (0u8..=255).cycle().take(4096).collect();
        let sig = scan_compress_probe(&data).unwrap();
        let SignalKind::CompressionProbe {
            original_size,
            compressed_size,
            ratio,
        } = sig.kind
        else {
            panic!("unexpected kind")
        };
        assert_eq!(original_size, 4096);
        let expected_ratio = compressed_size as f64 / original_size as f64;
        assert!((ratio - expected_ratio).abs() < 1e-9);
    }
}
