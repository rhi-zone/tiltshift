//! Numeric value semantics scanner.
//!
//! Scans u32 LE/BE values across the file and flags those with structural
//! significance:
//!
//!  - **file-size**: value equals the file size — likely a stored total-size field.
//!  - **power-of-two**: value is a power of two ≥ 16 — common for buffer sizes,
//!    alignment values, chunk capacities.
//!  - **candidate-offset**: value falls within the file's address space, is
//!    4-byte aligned, and appears in the header region (first 512 bytes) —
//!    likely a stored offset/pointer into the file.
//!
//! The within-bounds scan is restricted to the header region because data
//! regions generate massive false-positive rates (any value < file_size
//! qualifies).  `probe` covers per-offset within-bounds annotation for
//! arbitrary positions the user selects interactively.

use crate::types::{Region, Signal, SignalKind};

/// Byte range from the start of the file scanned for candidate-offset values.
/// Covers virtually all real binary format headers while keeping noise low.
const HEADER_SCAN_LIMIT: usize = 512;

/// Minimum u32 value to flag as a power-of-two landmark (avoids 1/2/4/8,
/// which are too ubiquitous to be informative).
const POW2_MIN: u32 = 16;

/// Minimum u32 value to flag as a candidate offset (values below this are
/// structural constants, not realistic file offsets).
const OFFSET_MIN: usize = 256;

/// Scan `data` for u32 LE/BE values with structural significance.
///
/// `data` must be the full file contents so that `data.len()` equals the
/// file size (used for within-bounds and file-size checks).
pub fn scan_numeric_landmarks(data: &[u8]) -> Vec<Signal> {
    if data.len() < 4 {
        return Vec::new();
    }

    let file_size = data.len();
    let header_limit = HEADER_SCAN_LIMIT.min(file_size);
    let scan_end = data.len() - 3; // last valid 4-byte window start
    let mut signals = Vec::new();

    for offset in 0..scan_end {
        let arr: [u8; 4] = data[offset..offset + 4].try_into().unwrap();

        for &little_endian in &[true, false] {
            let v_u32 = if little_endian {
                u32::from_le_bytes(arr)
            } else {
                u32::from_be_bytes(arr)
            };
            let v = v_u32 as usize;

            let file_size_match = v == file_size;
            let power_of_two = v_u32 >= POW2_MIN && v_u32.is_power_of_two();
            let within_bounds =
                offset < header_limit && v > OFFSET_MIN && v < file_size && v.is_multiple_of(4);

            if !file_size_match && !power_of_two && !within_bounds {
                continue;
            }

            let conf = confidence(file_size_match, power_of_two, within_bounds);
            let endian = if little_endian { "le" } else { "be" };
            let mut flags = Vec::new();
            if file_size_match {
                flags.push("file-size");
            }
            if power_of_two {
                flags.push("power-of-two");
            }
            if within_bounds {
                flags.push("candidate-offset");
            }
            let reason = format!("u32{} {} (0x{:08x}): {}", endian, v, v, flags.join(", "));

            signals.push(Signal::new(
                Region::new(offset, 4),
                SignalKind::NumericValue {
                    little_endian,
                    value: v_u32,
                    file_size_match,
                    power_of_two,
                    within_bounds,
                },
                conf,
                reason,
            ));
        }
    }

    signals
}

fn confidence(file_size_match: bool, power_of_two: bool, within_bounds: bool) -> f64 {
    match (file_size_match, power_of_two, within_bounds) {
        (true, true, _) => 0.85,      // file size that is also a power of two
        (true, false, _) => 0.80,     // file size match
        (false, true, true) => 0.55,  // power-of-two value that is also a plausible offset
        (false, true, false) => 0.40, // power of two
        (false, false, true) => 0.35, // candidate offset only
        _ => 0.25,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::SignalKind;

    #[test]
    fn detects_file_size_match() {
        // 8-byte file; first 4 bytes = 8 (the file size) in u32le.
        let data = [0x08u8, 0x00, 0x00, 0x00, 0xde, 0xad, 0xbe, 0xef];
        let sigs = scan_numeric_landmarks(&data);
        let hit = sigs.iter().find(|s| {
            matches!(
                &s.kind,
                SignalKind::NumericValue {
                    file_size_match: true,
                    little_endian: true,
                    ..
                }
            )
        });
        assert!(hit.is_some(), "expected file-size-match signal");
    }

    #[test]
    fn detects_power_of_two() {
        // u32le = 256 (0x00000100) at offset 0.
        let data = [0x00u8, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00];
        let sigs = scan_numeric_landmarks(&data);
        let hit = sigs.iter().find(|s| {
            matches!(
                &s.kind,
                SignalKind::NumericValue {
                    power_of_two: true,
                    little_endian: true,
                    value: 256,
                    ..
                }
            )
        });
        assert!(hit.is_some(), "expected power-of-two signal for 256");
    }

    #[test]
    fn does_not_flag_small_powers_of_two() {
        // u32le = 4 — below POW2_MIN, should not emit.
        let mut data = vec![0u8; 8];
        data[0] = 0x04;
        let sigs = scan_numeric_landmarks(&data);
        let hit = sigs.iter().find(|s| {
            matches!(
                &s.kind,
                SignalKind::NumericValue {
                    value: 4,
                    little_endian: true,
                    ..
                }
            )
        });
        assert!(hit.is_none(), "should not flag value=4 as power-of-two");
    }

    #[test]
    fn detects_candidate_offset_in_header() {
        // Build a file where byte 0..4 is a u32le pointing to offset 512 (in-bounds, 4-aligned).
        // File must be >= 513 bytes to have offset 512 in bounds.
        let mut data = vec![0u8; 1024];
        // u32le = 512 at offset 0
        let ptr: u32 = 512;
        data[0..4].copy_from_slice(&ptr.to_le_bytes());
        let sigs = scan_numeric_landmarks(&data);
        let hit = sigs.iter().find(|s| {
            matches!(
                &s.kind,
                SignalKind::NumericValue {
                    within_bounds: true,
                    little_endian: true,
                    value: 512,
                    ..
                }
            )
        });
        assert!(hit.is_some(), "expected candidate-offset signal");
    }

    #[test]
    fn no_candidate_offset_outside_header_region() {
        // Same pointer value but placed at offset 600 (beyond HEADER_SCAN_LIMIT=512).
        let mut data = vec![0u8; 1024];
        let ptr: u32 = 512;
        data[600..604].copy_from_slice(&ptr.to_le_bytes());
        let sigs = scan_numeric_landmarks(&data);
        let hit = sigs.iter().find(|s| {
            matches!(
                &s.kind,
                SignalKind::NumericValue {
                    within_bounds: true,
                    value: 512,
                    ..
                }
            ) && s.region.offset == 600
        });
        assert!(
            hit.is_none(),
            "candidate-offset should not fire outside header region"
        );
    }

    #[test]
    fn detects_u32be_value() {
        // u32be = 256 (bytes: 00 00 01 00)
        let data = [0x00u8, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00];
        let sigs = scan_numeric_landmarks(&data);
        let hit = sigs.iter().find(|s| {
            matches!(
                &s.kind,
                SignalKind::NumericValue {
                    power_of_two: true,
                    little_endian: false,
                    value: 256,
                    ..
                }
            )
        });
        assert!(hit.is_some(), "expected u32be power-of-two signal");
    }

    #[test]
    fn empty_and_short_data_ok() {
        assert!(scan_numeric_landmarks(&[]).is_empty());
        assert!(scan_numeric_landmarks(&[0x01, 0x00, 0x00]).is_empty());
    }

    #[test]
    fn combined_flags_get_higher_confidence() {
        let c_both = confidence(true, true, false);
        let c_size = confidence(true, false, false);
        let c_pow2 = confidence(false, true, false);
        assert!(c_both > c_size);
        assert!(c_size > c_pow2);
    }
}
