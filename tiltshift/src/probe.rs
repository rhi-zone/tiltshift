//! Typed interpretations of raw bytes at a given offset.
//!
//! `probe(data, offset, len)` returns a `ProbeResult` containing every
//! typed reading of the selected bytes that is feasible given the available
//! length.

/// A single typed interpretation of a byte span.
#[derive(Debug, Clone)]
pub struct Interpretation {
    /// Short label, e.g. "u32le" or "ascii".
    pub label: &'static str,
    /// Width in bytes consumed by this interpretation (may be < the probed
    /// span if the span is longer than needed).
    pub width: usize,
    /// The formatted value.
    pub value: String,
    /// Optional note (e.g. "within file bounds → candidate offset").
    pub note: Option<String>,
}

/// All feasible typed interpretations of a byte span.
#[derive(Debug, Default)]
pub struct ProbeResult {
    pub offset: usize,
    pub bytes: Vec<u8>,
    pub interpretations: Vec<Interpretation>,
}

impl ProbeResult {
    /// Return only interpretations with the given `width`, in insertion order.
    ///
    /// Width `0` is a sentinel meaning "variable / non-numeric" and is used by
    /// string and hex interpretations.
    pub fn by_width(&self, width: usize) -> impl Iterator<Item = &Interpretation> {
        self.interpretations
            .iter()
            .filter(move |i| i.width == width)
    }
}

/// Probe `data` at `offset`, consuming up to `len` bytes.
///
/// `file_size` is used to annotate values that land within the file's bounds
/// (candidate offsets/lengths).
pub fn probe(data: &[u8], offset: usize, len: usize, file_size: usize) -> ProbeResult {
    let available = data.len().saturating_sub(offset);
    let len = len.min(available);
    let bytes = data[offset..offset + len].to_vec();

    let mut result = ProbeResult {
        offset,
        bytes: bytes.clone(),
        interpretations: Vec::new(),
    };

    macro_rules! push {
        ($label:expr, $width:expr, $value:expr, $note:expr) => {
            result.interpretations.push(Interpretation {
                label: $label,
                width: $width,
                value: $value,
                note: $note,
            });
        };
    }

    // ── 1-byte ──────────────────────────────────────────────────────────────
    if !bytes.is_empty() {
        let b = bytes[0];
        push!("u8", 1, format!("{b}  (0x{b:02x})"), None);
        push!("i8", 1, format!("{}", b as i8), None);
        push!("bits", 1, format!("{b:08b}"), None);
    }

    // ── 2-byte ──────────────────────────────────────────────────────────────
    if bytes.len() >= 2 {
        let arr2: [u8; 2] = bytes[..2].try_into().unwrap();
        let u_le = u16::from_le_bytes(arr2);
        let u_be = u16::from_be_bytes(arr2);
        push!(
            "u16le",
            2,
            format!("{u_le}  (0x{u_le:04x})"),
            within_bounds_note(u_le as usize, file_size)
        );
        push!(
            "u16be",
            2,
            format!("{u_be}  (0x{u_be:04x})"),
            within_bounds_note(u_be as usize, file_size)
        );
        push!("i16le", 2, format!("{}", i16::from_le_bytes(arr2)), None);
        push!("i16be", 2, format!("{}", i16::from_be_bytes(arr2)), None);
    }

    // ── 4-byte ──────────────────────────────────────────────────────────────
    if bytes.len() >= 4 {
        let arr4: [u8; 4] = bytes[..4].try_into().unwrap();
        let u_le = u32::from_le_bytes(arr4);
        let u_be = u32::from_be_bytes(arr4);
        let f_le = f32::from_le_bytes(arr4);
        let f_be = f32::from_be_bytes(arr4);

        push!(
            "u32le",
            4,
            format!("{u_le}  (0x{u_le:08x})"),
            u32_note(u_le, file_size)
        );
        push!(
            "u32be",
            4,
            format!("{u_be}  (0x{u_be:08x})"),
            u32_note(u_be, file_size)
        );
        push!("i32le", 4, format!("{}", i32::from_le_bytes(arr4)), None);
        push!("i32be", 4, format!("{}", i32::from_be_bytes(arr4)), None);

        let f_note_le = if f_le.is_finite() && f_le.abs() < 1e10 {
            None
        } else {
            Some("non-finite".to_string())
        };
        let f_note_be = if f_be.is_finite() && f_be.abs() < 1e10 {
            None
        } else {
            Some("non-finite".to_string())
        };
        push!("f32le", 4, format!("{f_le:.6}"), f_note_le);
        push!("f32be", 4, format!("{f_be:.6}"), f_note_be);

        // Unix timestamp (u32le and u32be): plausible range 2000-01-01 to 2100-01-01
        let ts_lo: u32 = 946_684_800;
        let ts_hi: u32 = 4_102_444_800_u64.min(u32::MAX as u64) as u32;
        if u_le >= ts_lo && u_le <= ts_hi {
            push!(
                "timestamp_le",
                4,
                format_unix_ts(u_le as u64),
                Some("plausible Unix timestamp".to_string())
            );
        }
        if u_be >= ts_lo && u_be <= ts_hi {
            push!(
                "timestamp_be",
                4,
                format_unix_ts(u_be as u64),
                Some("plausible Unix timestamp".to_string())
            );
        }
    }

    // ── 8-byte ──────────────────────────────────────────────────────────────
    if bytes.len() >= 8 {
        let arr8: [u8; 8] = bytes[..8].try_into().unwrap();
        let u_le = u64::from_le_bytes(arr8);
        let u_be = u64::from_be_bytes(arr8);
        let f_le = f64::from_le_bytes(arr8);
        let f_be = f64::from_be_bytes(arr8);

        push!(
            "u64le",
            8,
            format!("{u_le}  (0x{u_le:016x})"),
            within_bounds_note(u_le as usize, file_size)
        );
        push!(
            "u64be",
            8,
            format!("{u_be}  (0x{u_be:016x})"),
            within_bounds_note(u_be as usize, file_size)
        );
        push!("i64le", 8, format!("{}", i64::from_le_bytes(arr8)), None);
        push!("i64be", 8, format!("{}", i64::from_be_bytes(arr8)), None);

        let f_note_le = if f_le.is_finite() && f_le.abs() < 1e15 {
            None
        } else {
            Some("non-finite".to_string())
        };
        let f_note_be = if f_be.is_finite() && f_be.abs() < 1e15 {
            None
        } else {
            Some("non-finite".to_string())
        };
        push!("f64le", 8, format!("{f_le:.10}"), f_note_le);
        push!("f64be", 8, format!("{f_be:.10}"), f_note_be);
    }

    // ── String interpretations (use full available slice) ────────────────────
    if !bytes.is_empty() {
        // ASCII printable bytes
        let ascii_len = bytes
            .iter()
            .take_while(|&&b| b.is_ascii_graphic() || b == b' ')
            .count();
        // String interpretations use width = 0 (sentinel: variable / non-numeric).
        if ascii_len > 0 {
            let s = std::str::from_utf8(&bytes[..ascii_len])
                .unwrap_or("")
                .to_string();
            push!("ascii", 0, format!("{s:?}"), None);
        }

        // UTF-8 decode as much as possible
        let utf8_str = std::str::from_utf8(&bytes)
            .map(|s| s.to_string())
            .unwrap_or_else(|e| {
                std::str::from_utf8(&bytes[..e.valid_up_to()])
                    .unwrap_or("")
                    .to_string()
            });
        let utf8_len = utf8_str.len();
        if utf8_len > 0 && utf8_len != ascii_len {
            // Only show if it adds something over the ASCII reading
            push!("utf-8", 0, format!("{utf8_str:?}"), None);
        }

        // Hex dump of the full span (always shown)
        let hex = bytes
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect::<Vec<_>>()
            .join(" ");
        push!("hex", 0, hex, None);
    }

    result
}

// ── helpers ──────────────────────────────────────────────────────────────────

fn within_bounds_note(v: usize, file_size: usize) -> Option<String> {
    if v > 0 && v < file_size {
        Some("within file bounds → candidate offset/length".to_string())
    } else {
        None
    }
}

fn u32_note(v: u32, file_size: usize) -> Option<String> {
    let v = v as usize;
    let mut notes = Vec::new();
    if v > 0 && v < file_size {
        notes.push("within file bounds → candidate offset/length");
    }
    if v > 0 && (v & (v - 1)) == 0 {
        notes.push("power of two");
    }
    if notes.is_empty() {
        None
    } else {
        Some(notes.join(", "))
    }
}

fn format_unix_ts(secs: u64) -> String {
    let days = secs / 86400;
    let time = secs % 86400;
    let hh = time / 3600;
    let mm = (time % 3600) / 60;
    let ss = time % 60;
    let (year, month, day) = days_to_ymd(days as i64);
    format!("{year:04}-{month:02}-{day:02}T{hh:02}:{mm:02}:{ss:02}Z")
}

/// Convert days since Unix epoch (1970-01-01) to (year, month, day).
fn days_to_ymd(days: i64) -> (i64, u32, u32) {
    // Algorithm from https://howardhinnant.github.io/date_algorithms.html
    let z = days + 719468;
    let era = if z >= 0 { z } else { z - 146096 } / 146097;
    let doe = z - era * 146097;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = if m <= 2 { y + 1 } else { y };
    (y, m as u32, d as u32)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn probe_u32le() {
        // bytes: 01 00 00 00 → u32le = 1
        let data = [0x01u8, 0x00, 0x00, 0x00];
        let r = probe(&data, 0, 4, 1024);
        let u32le = r
            .interpretations
            .iter()
            .find(|i| i.label == "u32le")
            .unwrap();
        assert!(u32le.value.starts_with('1'));
    }

    #[test]
    fn probe_ascii() {
        let data = b"Hello\x00world";
        let r = probe(data, 0, 5, data.len());
        let ascii = r
            .interpretations
            .iter()
            .find(|i| i.label == "ascii")
            .unwrap();
        assert!(ascii.value.contains("Hello"));
    }

    #[test]
    fn timestamp_roundtrip() {
        // 2024-01-15T12:00:00Z = 1705316400
        let ts: u32 = 1_705_316_400;
        let s = format_unix_ts(ts as u64);
        assert!(s.starts_with("2024-01-15"));
    }

    #[test]
    fn days_to_ymd_epoch() {
        assert_eq!(days_to_ymd(0), (1970, 1, 1));
    }
}
