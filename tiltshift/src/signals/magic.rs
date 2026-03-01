use crate::types::{Region, Signal, SignalKind};

/// Known magic byte sequences.  Each entry is `(human label, byte pattern)`.
///
/// DESIGN rationale: detect at *any* offset (not just 0) and correlate across
/// multiple files.  Matching at non-zero offsets reveals embedded formats,
/// which is more useful than header-only detection.
static MAGIC_TABLE: &[(&str, &[u8])] = &[
    ("PNG", b"\x89PNG\r\n\x1a\n"),
    ("JPEG", b"\xff\xd8\xff"),
    ("GIF87a", b"GIF87a"),
    ("GIF89a", b"GIF89a"),
    ("ZIP (local file header)", b"PK\x03\x04"),
    ("ZIP (end-of-central-directory)", b"PK\x05\x06"),
    ("ZIP (central directory)", b"PK\x01\x02"),
    ("ELF", b"\x7fELF"),
    ("PDF", b"%PDF"),
    ("BMP", b"BM"),
    ("RIFF", b"RIFF"),
    ("WEBP (inside RIFF)", b"WEBP"),
    ("PE/MZ", b"MZ"),
    ("GZIP", b"\x1f\x8b"),
    ("zlib (default compression)", b"\x78\x9c"),
    ("zlib (best compression)", b"\x78\xda"),
    ("zlib (no compression)", b"\x78\x01"),
    ("OGG", b"OggS"),
    ("7-Zip", b"7z\xbc\xaf\x27\x1c"),
    ("TAR (POSIX ustar)", b"ustar"),
    ("SQLite3", b"SQLite format 3\x00"),
    ("Zstandard", b"\xfd\x2f\xb5\x28"),
    ("LZ4 frame", b"\x04\x22\x4d\x18"),
    ("BZIP2", b"BZh"),
    ("XZ", b"\xfd7zXZ\x00"),
    ("WebAssembly", b"\x00asm"),
    ("Java class file", b"\xca\xfe\xba\xbe"),
    ("Mach-O 64-bit", b"\xcf\xfa\xed\xfe"),
    ("Mach-O 32-bit", b"\xce\xfa\xed\xfe"),
    ("FLAC", b"fLaC"),
    ("MP3 (ID3 tag)", b"ID3"),
    ("MIDI", b"MThd"),
    ("RAR v4", b"Rar!\x1a\x07\x00"),
    ("RAR v5", b"Rar!\x1a\x07\x01"),
    ("Lua bytecode", b"\x1bLua"),
    ("WAVE (fmt chunk)", b"fmt "),
];

/// Build a lookup index: first_byte → list of (label, pattern) pairs.
fn build_index() -> [Vec<(&'static str, &'static [u8])>; 256] {
    // Can't use array::from_fn with non-Copy Default in stable without unsafe;
    // use a manual approach.
    let mut index: [Vec<(&'static str, &'static [u8])>; 256] = std::array::from_fn(|_| Vec::new());
    for &(label, pattern) in MAGIC_TABLE {
        if let Some(&first) = pattern.first() {
            index[first as usize].push((label, pattern));
        }
    }
    index
}

/// Scan `data` for magic byte sequences at every offset.
///
/// Hits at offset 0 get confidence 0.99; hits at non-zero offsets get 0.95
/// (still very high — magic bytes are reliable signals).  The slightly lower
/// score reflects that embedded format detection warrants additional
/// confirmation from surrounding structure.
pub fn scan(data: &[u8]) -> Vec<Signal> {
    let index = build_index();
    let mut signals = Vec::new();

    for offset in 0..data.len() {
        let first = data[offset] as usize;
        for &(label, pattern) in &index[first] {
            if data[offset..].starts_with(pattern) {
                let hex = pattern
                    .iter()
                    .map(|b| format!("{b:02x}"))
                    .collect::<Vec<_>>()
                    .join(" ");
                let confidence = if offset == 0 { 0.99 } else { 0.95 };
                let reason = format!(
                    "matches {label} magic bytes [{hex}]{}",
                    if offset == 0 {
                        " at file start"
                    } else {
                        " at non-zero offset (embedded format)"
                    }
                );
                signals.push(Signal::new(
                    Region::new(offset, pattern.len()),
                    SignalKind::MagicBytes {
                        format: label.to_string(),
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

    #[test]
    fn detects_png_at_offset_zero() {
        let data = b"\x89PNG\r\n\x1a\n\x00\x00\x00\x0d";
        let sigs = scan(data);
        assert!(!sigs.is_empty());
        match &sigs[0].kind {
            SignalKind::MagicBytes { format, .. } => assert_eq!(format, "PNG"),
            _ => panic!("wrong kind"),
        }
        assert_eq!(sigs[0].region.offset, 0);
        assert!((sigs[0].confidence - 0.99).abs() < 1e-9);
    }

    #[test]
    fn detects_embedded_format() {
        let mut data = vec![0u8; 16];
        data.extend_from_slice(b"\x89PNG\r\n\x1a\n");
        let sigs = scan(&data);
        let png = sigs
            .iter()
            .find(|s| matches!(&s.kind, SignalKind::MagicBytes { format, .. } if format == "PNG"));
        assert!(png.is_some());
        let png = png.unwrap();
        assert_eq!(png.region.offset, 16);
        assert!((png.confidence - 0.95).abs() < 1e-9);
    }

    #[test]
    fn no_false_positive_on_empty() {
        assert!(scan(&[]).is_empty());
    }

    #[test]
    fn no_false_positive_on_zeros() {
        assert!(scan(&[0u8; 64]).is_empty());
    }
}
