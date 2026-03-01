use crate::types::{EntropyClass, Region, Signal, SignalKind};

/// Byte frequency histogram over a slice.
pub fn byte_histogram(data: &[u8]) -> [u64; 256] {
    let mut hist = [0u64; 256];
    for &b in data {
        hist[b as usize] += 1;
    }
    hist
}

/// Shannon entropy in bits/byte (0.0–8.0).
pub fn shannon_entropy(data: &[u8]) -> f64 {
    if data.is_empty() {
        return 0.0;
    }
    let hist = byte_histogram(data);
    let len = data.len() as f64;
    hist.iter()
        .filter(|&&c| c > 0)
        .map(|&c| {
            let p = c as f64 / len;
            -p * p.log2()
        })
        .sum()
}

/// Sliding-window entropy map.  Returns one `Signal` per block.
///
/// DESIGN rationale: transitions between regions (changes in entropy) are more
/// informative than absolute entropy values.  Use a sliding window so region
/// boundaries are visible in the output.
pub fn entropy_map(data: &[u8], block_size: usize, stride: usize) -> Vec<Signal> {
    assert!(block_size > 0 && stride > 0);

    let mut signals = Vec::new();
    let mut offset = 0;

    while offset < data.len() {
        let end = (offset + block_size).min(data.len());
        let block = &data[offset..end];
        let e = shannon_entropy(block);
        let class = EntropyClass::from_entropy(e);
        let reason = format!(
            "Shannon entropy {:.2} bits/byte over {} bytes → {}",
            e,
            block.len(),
            class.label()
        );
        // Confidence: entropy blocks are always genuine observations; the
        // classification is what varies in reliability.  High-entropy blocks
        // are highly reliable (compressed data is not "maybe" compressed);
        // very-low-entropy blocks are equally reliable.  Mixed is weakest.
        let confidence = match class {
            EntropyClass::Structured | EntropyClass::HighlyRandom => 0.90,
            EntropyClass::Compressed => 0.80,
            EntropyClass::Mixed => 0.65,
        };
        signals.push(Signal::new(
            Region::new(offset, end - offset),
            SignalKind::EntropyBlock { entropy: e, class },
            confidence,
            reason,
        ));
        offset += stride;
    }

    signals
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn entropy_zero_for_uniform_bytes() {
        let data = vec![0u8; 256];
        assert_eq!(shannon_entropy(&data), 0.0);
    }

    #[test]
    fn entropy_max_for_all_values() {
        let data: Vec<u8> = (0u8..=255).collect();
        let e = shannon_entropy(&data);
        assert!((e - 8.0).abs() < 1e-10, "expected 8.0 got {e}");
    }

    #[test]
    fn entropy_map_covers_whole_file() {
        let data: Vec<u8> = (0u8..=255).cycle().take(1024).collect();
        let signals = entropy_map(&data, 256, 256);
        // 1024 / 256 = 4 non-overlapping blocks
        assert_eq!(signals.len(), 4);
        // all offsets covered
        let last = signals.last().unwrap();
        assert_eq!(last.region.end(), 1024);
    }

    #[test]
    fn entropy_map_handles_tail() {
        // data not a multiple of block_size
        let data = vec![0u8; 300];
        let signals = entropy_map(&data, 256, 256);
        assert_eq!(signals.len(), 2);
        assert_eq!(signals[1].region.len, 44);
    }
}
