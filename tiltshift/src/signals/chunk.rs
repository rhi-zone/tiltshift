//! Chunk pattern detector.
//!
//! Scans for repeating (tag, length, data) sequences in the IFF / RIFF / PNG
//! family of container formats.  All three share the same structural idea but
//! differ in byte order and tag placement:
//!
//!   RIFF/WAV/AVI  — [tag:4][len:4 LE][data:len], padded to 2-byte boundary
//!   IFF/AIFF      — [tag:4][len:4 BE][data:len], padded to 2-byte boundary
//!   PNG           — [len:4 BE][tag:4][data:len], no padding
//!
//! A valid chunk tag is a FourCC: ≥3 ASCII letters (a–z, A–Z), with the
//! remaining byte being a letter, digit, or space.
//!
//! A *chunk run* is a consecutive sequence of valid-looking chunks.  Runs of
//! ≥ 2 chunks are emitted as signals.  Confidence scales with run length and
//! gets a boost when the first tag matches a known format.

use crate::types::{Region, Signal, SignalKind};

// ── FourCC validation ─────────────────────────────────────────────────────────

/// A valid chunk FourCC has ≥ 3 ASCII letters; remaining bytes are
/// letters, digits, or spaces.  This matches 'IHDR', 'fmt ', 'cue ', 'tEXt',
/// 'RIFF', 'FORM', etc.
fn is_valid_fourcc(tag: &[u8; 4]) -> bool {
    let alpha = tag.iter().filter(|&&b| b.is_ascii_alphabetic()).count();
    let all_ok = tag.iter().all(|&b| b.is_ascii_alphanumeric() || b == b' ');
    alpha >= 3 && all_ok
}

fn fourcc_str(tag: &[u8; 4]) -> String {
    // Space (0x20) is a valid FourCC byte (e.g. 'fmt ') but not ascii_graphic.
    tag.iter()
        .map(|&b| {
            if !b.is_ascii_control() {
                b as char
            } else {
                '.'
            }
        })
        .collect()
}

// ── Chain walking ─────────────────────────────────────────────────────────────

/// One validated chunk within a run.
#[derive(Debug)]
struct ChunkEntry {
    offset: usize,
    tag: [u8; 4],
    body_len: usize,
}

/// Try to walk a linear chain of chunks starting at `start`.
///
/// Returns all valid chunks found; stops at the first parse failure or
/// out-of-bounds condition.
fn try_walk_chain(
    data: &[u8],
    start: usize,
    tag_first: bool,
    little_endian: bool,
    two_byte_align: bool,
) -> Vec<ChunkEntry> {
    let mut chunks = Vec::new();
    let mut offset = start;
    let file_len = data.len();

    loop {
        if offset + 8 > file_len {
            break;
        }

        // Split the 8-byte header into (tag, length) based on layout.
        let (tag_arr, len_arr): ([u8; 4], [u8; 4]) = if tag_first {
            (
                data[offset..offset + 4].try_into().unwrap(),
                data[offset + 4..offset + 8].try_into().unwrap(),
            )
        } else {
            (
                data[offset + 4..offset + 8].try_into().unwrap(),
                data[offset..offset + 4].try_into().unwrap(),
            )
        };

        if !is_valid_fourcc(&tag_arr) {
            break;
        }

        let body_len = if little_endian {
            u32::from_le_bytes(len_arr) as usize
        } else {
            u32::from_be_bytes(len_arr) as usize
        };

        let chunk_end = offset + 8 + body_len;
        if chunk_end > file_len {
            break;
        }

        chunks.push(ChunkEntry {
            offset,
            tag: tag_arr,
            body_len,
        });

        // Advance to next chunk, respecting optional 2-byte alignment padding.
        let next = if two_byte_align && !body_len.is_multiple_of(2) {
            chunk_end + 1
        } else {
            chunk_end
        };
        // Avoid infinite loop if body_len = 0 and no alignment somehow stalls.
        if next <= offset {
            break;
        }
        offset = next;
    }

    chunks
}

// ── Format hint ───────────────────────────────────────────────────────────────

/// Known first-chunk tags that identify a format family.
fn format_hint(first_tag: &[u8; 4]) -> &'static str {
    match first_tag {
        // RIFF container tags
        b"RIFF" | b"RIFX" | b"LIST" | b"INFO" => "RIFF",
        // Common RIFF sub-chunk tags (WAV, AVI, etc.)
        b"fmt " | b"data" | b"cue " | b"JUNK" | b"bext" | b"fact" | b"wavl" | b"slnt" | b"idx1"
        | b"movi" | b"hdrl" | b"avih" | b"strl" | b"strh" | b"strf" => "RIFF",
        // IFF container
        b"FORM" => "IFF",
        // AIFF sub-chunks (FORM/AIFF container)
        b"COMM" | b"SSND" | b"MARK" | b"INST" | b"MIDI" | b"AESD" | b"APPL" => "AIFF",
        // PNG chunk types
        b"IHDR" | b"IDAT" | b"IEND" | b"tEXt" | b"iTXt" | b"gAMA" | b"pHYs" | b"tIME" | b"bKGD"
        | b"cHRM" | b"sRGB" | b"zTXt" | b"hIST" | b"sBIT" | b"sPLT" | b"tRNS" => "PNG",
        // MP4 / QuickTime atom tags
        b"ftyp" | b"moov" | b"mdat" | b"free" | b"skip" | b"udta" | b"trak" | b"mdia" | b"minf"
        | b"stbl" | b"mvhd" | b"tkhd" | b"mdhd" | b"hdlr" | b"vmhd" | b"smhd" | b"dinf"
        | b"stsd" | b"stts" | b"stsc" | b"stsz" | b"stco" => "MP4/QuickTime",
        _ => "generic",
    }
}

// ── Confidence ────────────────────────────────────────────────────────────────

fn confidence(chunk_count: usize, hint: &str) -> f64 {
    // Base scales from 0.50 at count=2 up to 0.88 at count=10+.
    let base = (0.50 + 0.05 * (chunk_count.saturating_sub(2)) as f64).min(0.88);
    // Boost for known format families.
    let boost = if hint != "generic" { 0.07 } else { 0.0 };
    (base + boost).min(0.92)
}

// ── Deduplication ─────────────────────────────────────────────────────────────

/// A candidate chain before it becomes a Signal.
struct Candidate {
    start: usize,
    end: usize,
    chunk_count: usize,
    tags: Vec<String>,
    tag_first: bool,
    little_endian: bool,
    two_byte_align: bool,
    hint: String,
}

/// Greedily select non-overlapping candidates, preferring those with more
/// chunks (longer structural evidence), then those that start earlier.
fn select_non_overlapping(mut candidates: Vec<Candidate>) -> Vec<Candidate> {
    // Sort: more chunks first, earlier start as tiebreak.
    candidates.sort_by(|a, b| {
        b.chunk_count
            .cmp(&a.chunk_count)
            .then(a.start.cmp(&b.start))
    });

    let mut selected: Vec<Candidate> = Vec::new();
    'outer: for cand in candidates {
        for sel in &selected {
            // Overlap check: [cand.start, cand.end) ∩ [sel.start, sel.end) ≠ ∅
            if cand.start < sel.end && cand.end > sel.start {
                continue 'outer;
            }
        }
        selected.push(cand);
    }

    // Re-sort by start offset for output.
    selected.sort_by_key(|c| c.start);
    selected
}

// ── Public API ────────────────────────────────────────────────────────────────

/// Scan `data` for repeating chunk sequences (RIFF / IFF / PNG style).
///
/// Returns one signal per non-overlapping run of ≥ 2 consecutive valid chunks.
pub fn scan_chunks(data: &[u8]) -> Vec<Signal> {
    if data.len() < 16 {
        // Need at least two 8-byte headers.
        return Vec::new();
    }

    // Configurations: (tag_first, little_endian, two_byte_align)
    // Covers RIFF/IFF (tag-first), PNG (length-first), aligned and non-aligned.
    const CONFIGS: &[(bool, bool, bool)] = &[
        (true, true, true),    // RIFF-style (LE, 2-byte aligned)
        (true, true, false),   // generic tag-first LE
        (true, false, true),   // IFF/AIFF-style (BE, 2-byte aligned)
        (true, false, false),  // generic tag-first BE
        (false, false, false), // PNG-style (length-first BE)
        (false, true, false),  // length-first LE (rare)
    ];

    let file_len = data.len();
    let mut all_candidates: Vec<Candidate> = Vec::new();

    for &(tag_first, little_endian, align) in CONFIGS {
        let mut skip_until = 0usize;

        for start in 0..file_len {
            if start < skip_until {
                continue;
            }
            // Quick pre-check: does this offset start a valid FourCC?
            let tag_offset = if tag_first { start } else { start + 4 };
            if tag_offset + 4 > file_len {
                break;
            }
            let tag_candidate: [u8; 4] = data[tag_offset..tag_offset + 4].try_into().unwrap();
            if !is_valid_fourcc(&tag_candidate) {
                continue;
            }

            let chain = try_walk_chain(data, start, tag_first, little_endian, align);
            if chain.len() < 2 {
                continue;
            }

            let last = chain.last().unwrap();
            let chain_end = last.offset
                + 8
                + last.body_len
                + if align && !last.body_len.is_multiple_of(2) {
                    1
                } else {
                    0
                };
            let chain_end = chain_end.min(file_len);

            let hint = format_hint(&chain[0].tag);
            let tags: Vec<String> = chain.iter().take(8).map(|e| fourcc_str(&e.tag)).collect();

            all_candidates.push(Candidate {
                start,
                end: chain_end,
                chunk_count: chain.len(),
                tags,
                tag_first,
                little_endian,
                two_byte_align: align,
                hint: hint.to_string(),
            });

            skip_until = chain_end;
        }
    }

    let selected = select_non_overlapping(all_candidates);

    selected
        .into_iter()
        .map(|c| {
            let conf = confidence(c.chunk_count, &c.hint);
            let endian_label = if c.little_endian { "le" } else { "be" };
            let layout_label = if c.tag_first { "tag+len" } else { "len+tag" };
            let align_label = if c.two_byte_align {
                ", 2-byte aligned"
            } else {
                ""
            };
            let reason = format!(
                "{} chunks ({} {}{}); tags: {}",
                c.chunk_count,
                layout_label,
                endian_label,
                align_label,
                c.tags.join(", ")
            );
            Signal::new(
                Region::new(c.start, c.end - c.start),
                SignalKind::ChunkSequence {
                    format_hint: c.hint,
                    tag_first: c.tag_first,
                    little_endian: c.little_endian,
                    chunk_count: c.chunk_count,
                    tags: c.tags,
                },
                conf,
                reason,
            )
        })
        .collect()
}

// ── Public helpers ────────────────────────────────────────────────────────────

/// Label for a ChunkSequence signal (e.g. "RIFF tag+len-le").
pub fn sequence_label(tag_first: bool, little_endian: bool) -> &'static str {
    match (tag_first, little_endian) {
        (true, true) => "tag+len-le",
        (true, false) => "tag+len-be",
        (false, true) => "len+tag-le",
        (false, false) => "len+tag-be",
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::SignalKind;

    fn make_riff_chunk(tag: &[u8; 4], body: &[u8]) -> Vec<u8> {
        let mut v = tag.to_vec();
        let len = body.len() as u32;
        v.extend_from_slice(&len.to_le_bytes());
        v.extend_from_slice(body);
        if !body.len().is_multiple_of(2) {
            v.push(0x00); // RIFF pad byte
        }
        v
    }

    fn make_png_chunk(tag: &[u8; 4], body: &[u8]) -> Vec<u8> {
        let len = body.len() as u32;
        let mut v = len.to_be_bytes().to_vec();
        v.extend_from_slice(tag);
        v.extend_from_slice(body);
        // PNG has a 4-byte CRC but we skip it for testing
        v
    }

    #[test]
    fn detects_riff_sequence() {
        let mut data = Vec::new();
        // RIFF container: RIFF chunk wrapping two sub-chunks
        data.extend(make_riff_chunk(b"fmt ", &[0u8; 16]));
        data.extend(make_riff_chunk(b"data", &[0u8; 8]));
        data.extend(make_riff_chunk(b"LIST", &[0u8; 4]));

        let sigs = scan_chunks(&data);
        assert!(!sigs.is_empty(), "expected at least one chunk sequence");
        let sig = &sigs[0];
        match &sig.kind {
            SignalKind::ChunkSequence {
                chunk_count,
                tag_first,
                little_endian,
                ..
            } => {
                assert!(*chunk_count >= 2);
                assert!(*tag_first);
                assert!(*little_endian);
            }
            _ => panic!("wrong signal kind"),
        }
    }

    #[test]
    fn detects_png_sequence() {
        let mut data = Vec::new();
        // PNG-style: length-first BE, no alignment
        data.extend(make_png_chunk(b"IHDR", &[0u8; 13]));
        data.extend(make_png_chunk(b"IDAT", &[0u8; 32]));
        data.extend(make_png_chunk(b"IEND", &[]));

        let sigs = scan_chunks(&data);
        assert!(!sigs.is_empty(), "expected PNG-style sequence");
        let sig = sigs.iter().find(|s| {
            matches!(
                &s.kind,
                SignalKind::ChunkSequence {
                    tag_first: false,
                    ..
                }
            )
        });
        assert!(sig.is_some(), "expected length-first (PNG) signal");
        if let Some(s) = sig {
            match &s.kind {
                SignalKind::ChunkSequence {
                    format_hint,
                    chunk_count,
                    tags,
                    ..
                } => {
                    assert_eq!(format_hint, "PNG");
                    assert!(*chunk_count >= 2);
                    assert!(tags.contains(&"IHDR".to_string()));
                }
                _ => unreachable!(),
            }
        }
    }

    #[test]
    fn rejects_single_chunk() {
        // Only one valid chunk — should not emit a signal.
        let data = make_riff_chunk(b"RIFF", &[0u8; 4]);
        let sigs = scan_chunks(&data);
        assert!(
            sigs.is_empty(),
            "single-chunk sequence should not be emitted"
        );
    }

    #[test]
    fn rejects_out_of_bounds_body() {
        // Tag looks valid but length claims more bytes than available.
        let mut data = b"RIFF".to_vec();
        data.extend_from_slice(&u32::MAX.to_le_bytes()); // impossible length
        data.extend_from_slice(b"WAVE");
        data.extend_from_slice(&4u32.to_le_bytes());
        data.extend_from_slice(&[0u8; 4]);
        let sigs = scan_chunks(&data);
        // The first "chunk" with u32::MAX body won't fit, so no valid chain.
        assert!(sigs.is_empty());
    }

    #[test]
    fn confidence_increases_with_count() {
        let c2 = confidence(2, "generic");
        let c5 = confidence(5, "generic");
        let c10 = confidence(10, "generic");
        assert!(c2 < c5);
        assert!(c5 < c10);
    }

    #[test]
    fn known_format_boost() {
        let generic = confidence(3, "generic");
        let known = confidence(3, "RIFF");
        assert!(known > generic);
    }

    #[test]
    fn iff_be_sequence_detected() {
        let mut data = Vec::new();
        // IFF-style: tag-first BE
        for tag in &[b"FORM", b"COMM", b"SSND"] {
            let mut chunk = tag.to_vec();
            let body = vec![0u8; 8];
            chunk.extend_from_slice(&(8u32).to_be_bytes());
            chunk.extend_from_slice(&body);
            data.extend(chunk);
        }
        let sigs = scan_chunks(&data);
        assert!(!sigs.is_empty());
        let be_sig = sigs.iter().find(|s| {
            matches!(
                &s.kind,
                SignalKind::ChunkSequence {
                    tag_first: true,
                    little_endian: false,
                    ..
                }
            )
        });
        assert!(be_sig.is_some(), "expected tag-first BE signal");
    }

    #[test]
    fn is_valid_fourcc_rejects_binary() {
        assert!(!is_valid_fourcc(&[0x00, 0x01, 0x02, 0x03]));
        assert!(!is_valid_fourcc(&[0xff, 0xfe, 0xfd, 0xfc]));
    }

    #[test]
    fn is_valid_fourcc_accepts_common_tags() {
        assert!(is_valid_fourcc(b"IHDR"));
        assert!(is_valid_fourcc(b"fmt "));
        assert!(is_valid_fourcc(b"RIFF"));
        assert!(is_valid_fourcc(b"tEXt"));
        assert!(is_valid_fourcc(b"cue "));
    }
}
