use crate::corpus::{Corpus, FormatEntry};
use crate::types::{Region, Signal, SignalKind};

/// Scan `data` for every magic byte sequence in `corpus`.
///
/// Uses a first-byte index so the scan is O(n) in the common case rather than
/// O(n × patterns).
///
/// DESIGN rationale: detect at *any* offset (not just 0) — embedded formats
/// are as interesting as top-level ones.  Non-zero offset hits get slightly
/// lower confidence (0.95 vs 0.99) to reflect that surrounding structure
/// should confirm the hypothesis.
pub fn scan(data: &[u8], corpus: &Corpus) -> Vec<Signal> {
    // Build a first-byte index over parsed entries.  Skip entries whose magic
    // fails to parse (load_file already validated user entries, but be safe).
    let parsed: Vec<(Vec<u8>, &FormatEntry)> = corpus
        .formats
        .iter()
        .filter_map(|e| e.magic_bytes().ok().map(|b| (b, e)))
        .collect();

    let mut index: [Vec<usize>; 256] = std::array::from_fn(|_| Vec::new());
    for (i, (bytes, _)) in parsed.iter().enumerate() {
        if let Some(&first) = bytes.first() {
            index[first as usize].push(i);
        }
    }

    let mut signals = Vec::new();

    for offset in 0..data.len() {
        let first = data[offset] as usize;
        for &idx in &index[first] {
            let (ref magic, entry) = parsed[idx];
            // Short patterns (< 3 bytes) are too common in binary data to be
            // meaningful at non-zero offsets — only match them at file start.
            if offset > 0 && magic.len() < 3 {
                continue;
            }
            if data[offset..].starts_with(magic.as_slice()) {
                let hex = magic
                    .iter()
                    .map(|b| format!("{b:02x}"))
                    .collect::<Vec<_>>()
                    .join(" ");
                let confidence = if offset == 0 { 0.99 } else { 0.95 };
                let reason = format!(
                    "matches {} magic bytes [{}]{}",
                    entry.name,
                    hex,
                    if offset == 0 {
                        " at file start"
                    } else {
                        " at non-zero offset (embedded format)"
                    }
                );
                signals.push(Signal::new(
                    Region::new(offset, magic.len()),
                    SignalKind::MagicBytes {
                        format: entry.name.clone(),
                        hex,
                    },
                    confidence,
                    reason,
                ));
            }
        }
    }

    signals
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::corpus;

    fn corpus() -> Corpus {
        corpus::load()
    }

    #[test]
    fn detects_png_at_offset_zero() {
        let data = b"\x89PNG\r\n\x1a\n\x00\x00\x00\x0d";
        let sigs = scan(data, &corpus());
        let png = sigs
            .iter()
            .find(|s| matches!(&s.kind, SignalKind::MagicBytes { format, .. } if format == "PNG"));
        assert!(png.is_some(), "PNG not found");
        assert_eq!(png.unwrap().region.offset, 0);
        assert!((png.unwrap().confidence - 0.99).abs() < 1e-9);
    }

    #[test]
    fn detects_embedded_format() {
        let mut data = vec![0u8; 16];
        data.extend_from_slice(b"\x89PNG\r\n\x1a\n");
        let sigs = scan(&data, &corpus());
        let png = sigs
            .iter()
            .find(|s| matches!(&s.kind, SignalKind::MagicBytes { format, .. } if format == "PNG"));
        assert!(png.is_some(), "embedded PNG not found");
        assert_eq!(png.unwrap().region.offset, 16);
        assert!((png.unwrap().confidence - 0.95).abs() < 1e-9);
    }

    #[test]
    fn no_false_positive_on_empty() {
        assert!(scan(&[], &corpus()).is_empty());
    }

    #[test]
    fn no_false_positive_on_zeros() {
        assert!(scan(&[0u8; 64], &corpus()).is_empty());
    }

    #[test]
    fn zstandard_correct_magic() {
        // Magic is 28 b5 2f fd (little-endian of 0xFD2FB528), NOT fd 2f b5 28
        let data = b"\x28\xb5\x2f\xfd\x04\x00";
        let sigs = scan(data, &corpus());
        let zst = sigs.iter().find(|s| {
            matches!(&s.kind, SignalKind::MagicBytes { format, .. } if format.contains("Zstandard"))
        });
        assert!(zst.is_some(), "Zstandard not detected with correct magic");
    }
}
