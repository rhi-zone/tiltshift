//! Hypothesis engine — converts raw signals into ranked, confidence-scored
//! interpretations of the file's structure.
//!
//! ## Passes
//!
//! 1. **Compound string tables** — 3+ adjacent null-terminated strings →
//!    a single "string table" hypothesis.
//!    1.5. **Cross-signal compounds** — pairs of reinforcing signals become a
//!    single higher-confidence hypothesis:
//!    - MagicBytes + ChunkSequence at the same header offset → confirmed format.
//!    - TlvSequence(type_width=1) + VarInt(leb128) in overlapping regions →
//!      protobuf-like encoding.
//!    - RepeatedPattern + AlignmentHint where stride is a multiple of the
//!      detected alignment → aligned struct array.
//! 2. **File-wide characterization** — chi-square, compression ratio, and ngram
//!    profile combine into a single characterization of the file's overall data
//!    character (structured, text, encrypted, …).
//! 3. **Direct single-signal hypotheses** — each structural signal that wasn't
//!    consumed by a compound pass gets its own hypothesis.
//!
//! The result is a [`PartialSchema`] whose hypotheses are sorted: file-wide
//! first, then by confidence descending.

use std::collections::HashSet;

use crate::types::{Hypothesis, PartialSchema, Region, Signal, SignalKind};

/// Convert a flat list of signals into a [`PartialSchema`] of ranked hypotheses.
pub fn build(signals: &[Signal], file_size: usize) -> PartialSchema {
    let mut schema = PartialSchema::new(file_size);

    if file_size == 0 {
        return schema;
    }

    // Pass 1 — compound string tables
    let (string_hyps, mut consumed) = compound_string_tables(signals);
    schema.hypotheses.extend(string_hyps);

    // Pass 1.5 — cross-signal compound hypotheses
    let (compound_hyps, more_consumed) = cross_signal_compounds(signals);
    schema.hypotheses.extend(compound_hyps);
    consumed.extend(more_consumed);

    // Pass 2 — file-wide statistical characterization
    if let Some(h) = file_wide_characterization(signals, file_size) {
        schema.hypotheses.push(h);
    }

    // Pass 3 — direct single-signal hypotheses for unconsumed, non-statistical signals
    for (i, sig) in signals.iter().enumerate() {
        if consumed.contains(&i) {
            continue;
        }
        if matches!(
            sig.kind,
            SignalKind::ChiSquare { .. }
                | SignalKind::CompressionProbe { .. }
                | SignalKind::NgramProfile { .. }
                | SignalKind::EntropyBlock { .. }
                | SignalKind::Padding { .. }
        ) {
            continue;
        }
        if let Some(h) = direct_hypothesis(sig) {
            schema.hypotheses.push(h);
        }
    }

    // Sort: file-wide hypothesis first, then by confidence descending.
    schema.hypotheses.sort_by(|a, b| {
        let a_fw = a.region.offset == 0 && a.region.len == file_size;
        let b_fw = b.region.offset == 0 && b.region.len == file_size;
        match (a_fw, b_fw) {
            (true, false) => std::cmp::Ordering::Less,
            (false, true) => std::cmp::Ordering::Greater,
            _ => b
                .confidence
                .partial_cmp(&a.confidence)
                .unwrap_or(std::cmp::Ordering::Equal),
        }
    });

    schema
}

// ── Direct conversion ────────────────────────────────────────────────────────

fn direct_hypothesis(sig: &Signal) -> Option<Hypothesis> {
    match &sig.kind {
        SignalKind::MagicBytes { format, .. } => Some(Hypothesis {
            region: sig.region.clone(),
            label: format!("Known format: {format}"),
            confidence: sig.confidence,
            signals: vec![sig.clone()],
            alternatives: vec![(
                "coincidental byte match".to_string(),
                (sig.confidence * 0.15).min(0.20),
            )],
        }),

        SignalKind::ChunkSequence {
            format_hint,
            chunk_count,
            ..
        } => Some(Hypothesis {
            region: sig.region.clone(),
            label: format!(
                "Chunk-structured container — {format_hint} family ({chunk_count} chunks)"
            ),
            confidence: sig.confidence,
            signals: vec![sig.clone()],
            alternatives: vec![("coincidental length patterns".to_string(), 0.15)],
        }),

        SignalKind::TlvSequence {
            type_width,
            len_width,
            little_endian,
            record_count,
            ..
        } => {
            let tw = format!("u{}", type_width * 8);
            let endian = if *len_width == 1 {
                String::new()
            } else if *little_endian {
                "le".to_string()
            } else {
                "be".to_string()
            };
            let lw = format!("u{}{}", len_width * 8, endian);
            Some(Hypothesis {
                region: sig.region.clone(),
                label: format!("TLV-encoded data stream — {tw}+{lw} ({record_count} records)"),
                confidence: sig.confidence,
                signals: vec![sig.clone()],
                alternatives: vec![("coincidental length matches".to_string(), 0.20)],
            })
        }

        SignalKind::LengthPrefixedBlob {
            prefix_width,
            little_endian,
            declared_len,
            printable_ratio,
        } => {
            let endian_label = if *prefix_width == 1 {
                String::new()
            } else if *little_endian {
                "le".to_string()
            } else {
                "be".to_string()
            };
            let type_label = format!("u{}{}", prefix_width * 8, endian_label);
            let content_hint = if *printable_ratio > 0.8 { "text" } else { "binary" };
            Some(Hypothesis {
                region: sig.region.clone(),
                label: format!(
                    "Length-prefixed {content_hint} blob ({type_label} prefix, {declared_len} bytes)"
                ),
                confidence: sig.confidence,
                signals: vec![sig.clone()],
                alternatives: vec![("coincidental value".to_string(), 0.25)],
            })
        }

        SignalKind::RepeatedPattern {
            stride, occurrences, ..
        } => Some(Hypothesis {
            region: sig.region.clone(),
            label: format!("Array of fixed-size records (stride={stride}, ×{occurrences})"),
            confidence: sig.confidence,
            signals: vec![sig.clone()],
            alternatives: vec![("coincidental repetition".to_string(), 0.20)],
        }),

        SignalKind::VarInt {
            encoding,
            count,
            avg_width,
            ..
        } => {
            let label = match encoding.as_str() {
                "leb128-unsigned" => format!(
                    "LEB128 variable-length integers ({} values, avg {:.1}B)",
                    count, avg_width
                ),
                "utf8-multibyte" => format!(
                    "UTF-8 multibyte text run ({} codepoints, avg {:.1}B)",
                    count, avg_width
                ),
                _ => format!("{encoding} variable-length encoding ({count} values)"),
            };
            let alt = match encoding.as_str() {
                "leb128-unsigned" => (
                    "raw binary data with high-bit bytes".to_string(),
                    0.25f64,
                ),
                "utf8-multibyte" => ("non-UTF-8 multibyte encoding".to_string(), 0.20f64),
                _ => ("coincidental pattern".to_string(), 0.20f64),
            };
            Some(Hypothesis {
                region: sig.region.clone(),
                label,
                confidence: sig.confidence,
                signals: vec![sig.clone()],
                alternatives: vec![alt],
            })
        }

        SignalKind::AlignmentHint {
            alignment,
            entropy_spread,
            ..
        } => Some(Hypothesis {
            region: sig.region.clone(),
            label: format!(
                "Data respects {alignment}-byte field alignment (entropy spread {entropy_spread:.2} bits)"
            ),
            confidence: sig.confidence,
            signals: vec![sig.clone()],
            alternatives: vec![(
                "coincidental byte-value distribution".to_string(),
                (1.0 - sig.confidence).max(0.05),
            )],
        }),

        SignalKind::NumericValue {
            little_endian,
            value,
            file_size_match,
            power_of_two,
            within_bounds,
        } => {
            let endian = if *little_endian { "le" } else { "be" };
            if *file_size_match {
                Some(Hypothesis {
                    region: sig.region.clone(),
                    label: format!("File size stored as u32{endian} = {value}"),
                    confidence: sig.confidence,
                    signals: vec![sig.clone()],
                    alternatives: vec![("coincidental value match".to_string(), 0.20)],
                })
            } else if *power_of_two {
                Some(Hypothesis {
                    region: sig.region.clone(),
                    label: format!(
                        "Power-of-two constant u32{endian} = {value} (alignment, count, or buffer size)"
                    ),
                    confidence: sig.confidence,
                    signals: vec![sig.clone()],
                    alternatives: vec![("arbitrary data value".to_string(), 0.35)],
                })
            } else if *within_bounds {
                Some(Hypothesis {
                    region: sig.region.clone(),
                    label: format!(
                        "Candidate offset/pointer u32{endian} = 0x{value:x} (in-bounds)"
                    ),
                    confidence: sig.confidence,
                    signals: vec![sig.clone()],
                    alternatives: vec![("unrelated numeric value".to_string(), 0.45)],
                })
            } else {
                None
            }
        }

        SignalKind::PackedField { hint, .. } => Some(Hypothesis {
            region: sig.region.clone(),
            label: format!("Packed nibble sub-fields — {hint}"),
            confidence: sig.confidence,
            signals: vec![sig.clone()],
            alternatives: vec![(
                "coincidental nibble independence".to_string(),
                0.25,
            )],
        }),

        SignalKind::OffsetGraph {
            pointer_width,
            little_endian,
            component_nodes,
            component_edges,
            ..
        } => {
            let endian = if *little_endian { "le" } else { "be" };
            let label = format!(
                "Offset graph — u{}{endian} — {component_nodes} nodes, {component_edges} edges",
                pointer_width * 8,
            );
            Some(Hypothesis {
                region: sig.region.clone(),
                label,
                confidence: sig.confidence,
                signals: vec![sig.clone()],
                alternatives: vec![(
                    "coincidental within-bounds values".to_string(),
                    (1.0_f64 - sig.confidence).max(0.05),
                )],
            })
        }

        // NullTerminatedString: fully handled by compound_string_tables.
        // Everything else (EntropyBlock, Padding, ChiSquare, CompressionProbe,
        // NgramProfile) is either too fine-grained or handled in pass 2.
        _ => None,
    }
}

// ── Compound: string tables ──────────────────────────────────────────────────

/// Group adjacent null-terminated strings into table hypotheses.
///
/// Strings separated by ≤ 4 bytes are considered part of the same run.
/// Runs with ≥ 3 strings become a "string table" hypothesis; smaller runs
/// produce individual string hypotheses.  Returns the hypotheses and the
/// set of signal indices consumed.
fn compound_string_tables(signals: &[Signal]) -> (Vec<Hypothesis>, HashSet<usize>) {
    let mut consumed = HashSet::new();
    let mut hypotheses = Vec::new();

    let str_sigs: Vec<(usize, &Signal)> = signals
        .iter()
        .enumerate()
        .filter(|(_, s)| matches!(s.kind, SignalKind::NullTerminatedString { .. }))
        .collect();

    if str_sigs.is_empty() {
        return (hypotheses, consumed);
    }

    // Group into contiguous runs (gap ≤ 4 bytes between consecutive strings).
    let mut groups: Vec<Vec<(usize, &Signal)>> = Vec::new();
    let mut current: Vec<(usize, &Signal)> = Vec::new();

    for &(idx, sig) in &str_sigs {
        if let Some(last) = current.last() {
            let gap = sig.region.offset.saturating_sub(last.1.region.end());
            if gap <= 4 {
                current.push((idx, sig));
                continue;
            }
        }
        if !current.is_empty() {
            groups.push(std::mem::take(&mut current));
        }
        current.push((idx, sig));
    }
    if !current.is_empty() {
        groups.push(current);
    }

    for group in &groups {
        let count = group.len();

        for (idx, _) in group {
            consumed.insert(*idx);
        }

        if count >= 3 {
            let first_sig = group.first().unwrap().1;
            let last_sig = group.last().unwrap().1;
            let span_len = last_sig.region.end() - first_sig.region.offset;
            let avg_conf = group.iter().map(|(_, s)| s.confidence).sum::<f64>() / count as f64;
            let table_conf = (avg_conf + 0.15).min(0.95);

            let samples: Vec<String> = group
                .iter()
                .take(4)
                .filter_map(|(_, s)| {
                    if let SignalKind::NullTerminatedString { content } = &s.kind {
                        Some(format!("{content:?}"))
                    } else {
                        None
                    }
                })
                .collect();
            let more = count.saturating_sub(4);
            let sample_str = samples.join(", ");
            let label = if more > 0 {
                format!("String table — {count} strings: {sample_str}, +{more} more")
            } else {
                format!("String table — {count} strings: {sample_str}")
            };

            hypotheses.push(Hypothesis {
                region: Region::new(first_sig.region.offset, span_len),
                label,
                confidence: table_conf,
                signals: group.iter().map(|(_, s)| (*s).clone()).collect(),
                alternatives: vec![(
                    "individual strings in binary structure".to_string(),
                    avg_conf,
                )],
            });
        } else {
            // Runs of 1–2 strings: emit as individual hypotheses.
            for (_, sig) in group {
                if let SignalKind::NullTerminatedString { content } = &sig.kind {
                    hypotheses.push(Hypothesis {
                        region: sig.region.clone(),
                        label: format!("Null-terminated string: {content:?}"),
                        confidence: sig.confidence,
                        signals: vec![(*sig).clone()],
                        alternatives: vec![(
                            "coincidental null byte after printable run".to_string(),
                            (1.0 - sig.confidence) * 0.5,
                        )],
                    });
                }
            }
        }
    }

    (hypotheses, consumed)
}

// ── Compound: cross-signal ────────────────────────────────────────────────────

/// Look for pairs of signals that reinforce each other and emit higher-confidence
/// compound hypotheses.  Signals consumed here are removed from pass 3.
///
/// Rules:
/// - **MagicBytes + ChunkSequence** at the same header offset → confirmed format.
/// - **TlvSequence(type_width=1) + VarInt(leb128)** in overlapping regions →
///   protobuf-like encoding.
/// - **RepeatedPattern + AlignmentHint** where stride is a multiple of the
///   detected alignment → aligned struct array.
fn cross_signal_compounds(signals: &[Signal]) -> (Vec<Hypothesis>, HashSet<usize>) {
    let mut consumed: HashSet<usize> = HashSet::new();
    let mut hypotheses: Vec<Hypothesis> = Vec::new();

    // Collect indices by kind.
    let magic_idxs: Vec<usize> = (0..signals.len())
        .filter(|&i| matches!(signals[i].kind, SignalKind::MagicBytes { .. }))
        .collect();
    let chunk_idxs: Vec<usize> = (0..signals.len())
        .filter(|&i| matches!(signals[i].kind, SignalKind::ChunkSequence { .. }))
        .collect();
    let tlv_idxs: Vec<usize> = (0..signals.len())
        .filter(|&i| matches!(signals[i].kind, SignalKind::TlvSequence { .. }))
        .collect();
    let varint_leb_idxs: Vec<usize> = (0..signals.len())
        .filter(|&i| {
            matches!(&signals[i].kind, SignalKind::VarInt { encoding, .. } if encoding == "leb128-unsigned")
        })
        .collect();
    let repeated_idxs: Vec<usize> = (0..signals.len())
        .filter(|&i| matches!(signals[i].kind, SignalKind::RepeatedPattern { .. }))
        .collect();
    let align_idxs: Vec<usize> = (0..signals.len())
        .filter(|&i| matches!(signals[i].kind, SignalKind::AlignmentHint { .. }))
        .collect();

    // ── Rule 1: MagicBytes + ChunkSequence → confirmed format ────────────────
    //
    // The chunk structure must start at or just after the magic bytes (≤ 16 B),
    // and the magic must be in the file header (offset < 64).
    for &mi in &magic_idxs {
        if consumed.contains(&mi) {
            continue;
        }
        let ms = &signals[mi];
        let SignalKind::MagicBytes { format, .. } = &ms.kind else {
            continue;
        };
        if ms.region.offset >= 64 {
            continue;
        }

        let best_ci = chunk_idxs
            .iter()
            .filter(|&&ci| {
                !consumed.contains(&ci) && {
                    let cs = &signals[ci];
                    cs.region.offset >= ms.region.offset
                        && cs.region.offset - ms.region.offset <= 16
                }
            })
            .max_by(|&&a, &&b| {
                signals[a]
                    .confidence
                    .partial_cmp(&signals[b].confidence)
                    .unwrap_or(std::cmp::Ordering::Equal)
            })
            .copied();

        if let Some(ci) = best_ci {
            let cs = &signals[ci];
            let SignalKind::ChunkSequence { chunk_count, .. } = &cs.kind else {
                continue;
            };
            let conf = (ms.confidence.max(cs.confidence) + 0.05).min(0.98);
            hypotheses.push(Hypothesis {
                region: region_union(&ms.region, &cs.region),
                label: format!(
                    "Confirmed {format} container — magic header + {chunk_count} chunks"
                ),
                confidence: conf,
                signals: vec![ms.clone(), cs.clone()],
                alternatives: vec![("partial or corrupt file".to_string(), 0.05)],
            });
            consumed.insert(mi);
            consumed.insert(ci);
        }
    }

    // ── Rule 2: TlvSequence(type_width=1) + VarInt(leb128) → protobuf-like ──
    //
    // Protobuf encodes field tags as LEB128 varints (low 3 bits = wire type,
    // upper bits = field number), so a 1-byte-tag TLV stream co-located with a
    // LEB128 run is a strong protobuf (or protobuf-compatible) indicator.
    for &ti in &tlv_idxs {
        if consumed.contains(&ti) {
            continue;
        }
        let ts = &signals[ti];
        let SignalKind::TlvSequence {
            type_width,
            record_count,
            ..
        } = &ts.kind
        else {
            continue;
        };
        if *type_width != 1 {
            continue;
        }

        let best_vi = varint_leb_idxs
            .iter()
            .filter(|&&vi| {
                !consumed.contains(&vi) && regions_overlap(&ts.region, &signals[vi].region)
            })
            .max_by(|&&a, &&b| {
                signals[a]
                    .confidence
                    .partial_cmp(&signals[b].confidence)
                    .unwrap_or(std::cmp::Ordering::Equal)
            })
            .copied();

        if let Some(vi) = best_vi {
            let vs = &signals[vi];
            let conf = (ts.confidence.max(vs.confidence) + 0.08).min(0.90);
            hypotheses.push(Hypothesis {
                region: region_union(&ts.region, &vs.region),
                label: format!(
                    "Protobuf-like encoding — TLV field tags + LEB128 values ({record_count} records)"
                ),
                confidence: conf,
                signals: vec![ts.clone(), vs.clone()],
                alternatives: vec![
                    (
                        "custom TLV with incidental LEB128 data".to_string(),
                        0.20,
                    ),
                    ("MessagePack or CBOR binary protocol".to_string(), 0.15),
                ],
            });
            consumed.insert(ti);
            consumed.insert(vi);
        }
    }

    // ── Rule 3: RepeatedPattern + AlignmentHint → aligned struct array ───────
    //
    // When a repeated stride is an even multiple of the detected field alignment,
    // the two signals corroborate each other: the data is almost certainly an
    // array of structs laid out at aligned boundaries.
    for &ri in &repeated_idxs {
        if consumed.contains(&ri) {
            continue;
        }
        let rs = &signals[ri];
        let SignalKind::RepeatedPattern {
            stride,
            occurrences,
            ..
        } = &rs.kind
        else {
            continue;
        };

        let best_ai = align_idxs
            .iter()
            .filter(|&&ai| {
                !consumed.contains(&ai) && {
                    if let SignalKind::AlignmentHint { alignment, .. } = &signals[ai].kind {
                        stride.is_multiple_of(*alignment)
                    } else {
                        false
                    }
                }
            })
            .max_by(|&&a, &&b| {
                signals[a]
                    .confidence
                    .partial_cmp(&signals[b].confidence)
                    .unwrap_or(std::cmp::Ordering::Equal)
            })
            .copied();

        if let Some(ai) = best_ai {
            let als = &signals[ai];
            let SignalKind::AlignmentHint { alignment, .. } = &als.kind else {
                continue;
            };
            let conf = (rs.confidence.max(als.confidence) + 0.07).min(0.92);
            hypotheses.push(Hypothesis {
                region: rs.region.clone(),
                label: format!(
                    "Struct array — {occurrences}× {stride}-byte records, {alignment}-byte aligned"
                ),
                confidence: conf,
                signals: vec![rs.clone(), als.clone()],
                alternatives: vec![(
                    "coincidental pattern at alignment boundary".to_string(),
                    0.15,
                )],
            });
            consumed.insert(ri);
            consumed.insert(ai);
        }
    }

    (hypotheses, consumed)
}

fn regions_overlap(a: &Region, b: &Region) -> bool {
    a.offset < b.end() && b.offset < a.end()
}

fn region_union(a: &Region, b: &Region) -> Region {
    let start = a.offset.min(b.offset);
    let end = a.end().max(b.end());
    Region::new(start, end - start)
}

// ── Compound: file-wide characterization ─────────────────────────────────────

/// Combine chi-square, compression ratio, and ngram profile into a single
/// file-wide characterization hypothesis.
fn file_wide_characterization(signals: &[Signal], file_size: usize) -> Option<Hypothesis> {
    let chi = signals.iter().find_map(|s| {
        if let SignalKind::ChiSquare { p_value, chi_sq } = &s.kind {
            Some((*p_value, *chi_sq, s.clone()))
        } else {
            None
        }
    });
    let compress = signals.iter().find_map(|s| {
        if let SignalKind::CompressionProbe { ratio, .. } = &s.kind {
            Some((*ratio, s.clone()))
        } else {
            None
        }
    });
    let ngram = signals.iter().find_map(|s| {
        if let SignalKind::NgramProfile {
            data_type_hint,
            bigram_entropy,
            ..
        } = &s.kind
        {
            Some((data_type_hint.clone(), *bigram_entropy, s.clone()))
        } else {
            None
        }
    });

    if chi.is_none() && compress.is_none() && ngram.is_none() {
        return None;
    }

    let p_value = chi.as_ref().map(|(p, _, _)| *p);
    let ratio = compress.as_ref().map(|(r, _)| *r);
    let ngram_hint = ngram.as_ref().map(|(h, _, _)| h.as_str());

    // Uniform distribution (high p) + incompressible → encrypted / pre-compressed.
    // Non-uniform (low p) + compressible → structured.
    // Text ngram hint + compressible + non-uniform → text.
    let is_uniform = p_value.is_some_and(|p| p > 0.30);
    let incompressible = ratio.is_some_and(|r| r >= 0.95);
    let is_text = ngram_hint == Some("text");
    let is_sparse = ngram_hint == Some("sparse/structured");

    let (label, confidence, alt_label, alt_conf): (&str, f64, &str, f64) =
        if is_uniform && incompressible {
            (
                "encrypted or pre-compressed data",
                0.85,
                "random/noise data",
                0.40,
            )
        } else if is_text && !is_uniform {
            (
                "text or source code",
                0.82,
                "structured binary with embedded strings",
                0.45,
            )
        } else if is_sparse && !is_uniform {
            (
                "structured binary data (sparse/header-dominated)",
                0.80,
                "text with binary padding",
                0.35,
            )
        } else if !is_uniform {
            (
                "structured binary data",
                0.75,
                "mixed binary/text format",
                0.40,
            )
        } else {
            (
                "mixed or segmented data",
                0.60,
                "multiple distinct region types",
                0.45,
            )
        };

    let mut contributing = Vec::new();
    if let Some((_, _, s)) = &chi {
        contributing.push(s.clone());
    }
    if let Some((_, s)) = &compress {
        contributing.push(s.clone());
    }
    if let Some((_, _, s)) = &ngram {
        contributing.push(s.clone());
    }

    Some(Hypothesis {
        region: Region::new(0, file_size),
        label: label.to_string(),
        confidence,
        signals: contributing,
        alternatives: vec![(alt_label.to_string(), alt_conf)],
    })
}

// ── Helpers ──────────────────────────────────────────────────────────────────

/// Short human-readable name for a signal kind, used in contributing-signals
/// summaries.
pub fn signal_kind_label(kind: &SignalKind) -> &'static str {
    match kind {
        SignalKind::MagicBytes { .. } => "magic bytes",
        SignalKind::ChiSquare { .. } => "chi-square test",
        SignalKind::CompressionProbe { .. } => "compression probe",
        SignalKind::NgramProfile { .. } => "ngram profile",
        SignalKind::AlignmentHint { .. } => "alignment hint",
        SignalKind::ChunkSequence { .. } => "chunk sequence",
        SignalKind::TlvSequence { .. } => "TLV sequence",
        SignalKind::LengthPrefixedBlob { .. } => "length-prefixed blob",
        SignalKind::RepeatedPattern { .. } => "repeated pattern",
        SignalKind::VarInt { .. } => "varint encoding",
        SignalKind::NullTerminatedString { .. } => "null-terminated string",
        SignalKind::EntropyBlock { .. } => "entropy block",
        SignalKind::Padding { .. } => "padding",
        SignalKind::PackedField { .. } => "packed nibble fields",
        SignalKind::NumericValue { .. } => "numeric value",
        SignalKind::OffsetGraph { .. } => "offset graph",
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::{Region, SignalKind};

    fn make_signal(offset: usize, kind: SignalKind, confidence: f64) -> Signal {
        Signal::new(Region::new(offset, 8), kind, confidence, "test")
    }

    #[test]
    fn empty_signals_yields_empty_schema() {
        let schema = build(&[], 1024);
        assert!(schema.hypotheses.is_empty());
    }

    #[test]
    fn magic_bytes_becomes_hypothesis() {
        let sig = make_signal(
            0,
            SignalKind::MagicBytes {
                format: "PNG".to_string(),
                hex: "89 50 4e 47".to_string(),
            },
            0.97,
        );
        let schema = build(&[sig], 1024);
        let h = schema
            .hypotheses
            .iter()
            .find(|h| h.label.contains("PNG"))
            .expect("PNG hypothesis not found");
        assert!(h.confidence > 0.90);
    }

    #[test]
    fn string_table_compounded_from_three_adjacent_strings() {
        let make_str = |offset: usize, content: &str| {
            Signal::new(
                Region::new(offset, content.len() + 1),
                SignalKind::NullTerminatedString {
                    content: content.to_string(),
                },
                0.70,
                "test",
            )
        };
        let sigs = vec![
            make_str(0, "hello"),
            make_str(6, "world"),
            make_str(12, "foobar"),
        ];
        let schema = build(&sigs, 256);
        let table = schema
            .hypotheses
            .iter()
            .find(|h| h.label.contains("String table"))
            .expect("string table hypothesis not found");
        assert_eq!(table.signals.len(), 3);
        assert!(table.confidence > 0.70);
    }

    #[test]
    fn two_strings_not_compounded_as_table() {
        let make_str = |offset: usize, content: &str| {
            Signal::new(
                Region::new(offset, content.len() + 1),
                SignalKind::NullTerminatedString {
                    content: content.to_string(),
                },
                0.70,
                "test",
            )
        };
        let sigs = vec![make_str(0, "hello"), make_str(6, "world")];
        let schema = build(&sigs, 256);
        assert!(!schema
            .hypotheses
            .iter()
            .any(|h| h.label.contains("String table")));
    }

    #[test]
    fn file_wide_characterization_from_statistical_signals() {
        let chi = Signal::new(
            Region::new(0, 1024),
            SignalKind::ChiSquare {
                chi_sq: 280.0,
                p_value: 0.001,
            },
            0.80,
            "non-uniform",
        );
        let compress = Signal::new(
            Region::new(0, 1024),
            SignalKind::CompressionProbe {
                original_size: 1024,
                compressed_size: 400,
                ratio: 0.39,
            },
            0.90,
            "compressible",
        );
        let schema = build(&[chi, compress], 1024);
        let fw = schema
            .hypotheses
            .iter()
            .find(|h| h.region.len == 1024)
            .expect("file-wide hypothesis not found");
        assert!(fw.label.contains("structured"), "label: {}", fw.label);
    }

    #[test]
    fn magic_plus_chunk_compounded_into_confirmed_format() {
        let magic = Signal::new(
            Region::new(0, 8),
            SignalKind::MagicBytes {
                format: "PNG".to_string(),
                hex: "89504e47".to_string(),
            },
            0.97,
            "test",
        );
        let chunk = Signal::new(
            Region::new(8, 512),
            SignalKind::ChunkSequence {
                format_hint: "PNG".to_string(),
                tag_first: false,
                little_endian: false,
                chunk_count: 4,
                tags: vec!["IHDR".to_string(), "IDAT".to_string(), "IEND".to_string()],
            },
            0.90,
            "test",
        );
        let schema = build(&[magic, chunk], 520);
        let compound = schema
            .hypotheses
            .iter()
            .find(|h| h.label.contains("Confirmed") && h.label.contains("PNG"))
            .expect("compound format hypothesis not found");
        assert!(compound.confidence >= 0.97, "conf={}", compound.confidence);
        assert_eq!(compound.signals.len(), 2);
        // Neither signal should appear again as a standalone hypothesis.
        assert!(!schema
            .hypotheses
            .iter()
            .any(|h| h.label.contains("Known format: PNG")));
    }

    #[test]
    fn tlv_plus_varint_compounded_into_protobuf_like() {
        let tlv = Signal::new(
            Region::new(0, 200),
            SignalKind::TlvSequence {
                type_width: 1,
                len_width: 1,
                little_endian: true,
                record_count: 12,
                type_samples: vec![1, 2, 3],
            },
            0.75,
            "test",
        );
        let varint = Signal::new(
            Region::new(0, 180),
            SignalKind::VarInt {
                encoding: "leb128-unsigned".to_string(),
                count: 8,
                bytes_consumed: 24,
                avg_width: 2.1,
            },
            0.70,
            "test",
        );
        let schema = build(&[tlv, varint], 200);
        let compound = schema
            .hypotheses
            .iter()
            .find(|h| h.label.contains("Protobuf-like"))
            .expect("protobuf-like hypothesis not found");
        assert!(compound.confidence > 0.75, "conf={}", compound.confidence);
        assert_eq!(compound.signals.len(), 2);
    }

    #[test]
    fn repeated_plus_alignment_compounded_into_struct_array() {
        let rep = Signal::new(
            Region::new(0, 256),
            SignalKind::RepeatedPattern {
                pattern: vec![0x00, 0x00, 0x00, 0x00],
                stride: 8,
                occurrences: 32,
            },
            0.78,
            "test",
        );
        let align = Signal::new(
            Region::new(0, 256),
            SignalKind::AlignmentHint {
                alignment: 4,
                entropy_spread: 1.2,
                dominant_phase: 0,
            },
            0.72,
            "test",
        );
        let schema = build(&[rep, align], 256);
        let compound = schema
            .hypotheses
            .iter()
            .find(|h| h.label.contains("Struct array"))
            .expect("struct array hypothesis not found");
        assert!(
            compound.label.contains("8-byte"),
            "label: {}",
            compound.label
        );
        assert!(
            compound.label.contains("4-byte"),
            "label: {}",
            compound.label
        );
        assert_eq!(compound.signals.len(), 2);
    }

    #[test]
    fn incompatible_stride_does_not_compound() {
        // stride=6 is not a multiple of alignment=4, so no compound.
        let rep = Signal::new(
            Region::new(0, 256),
            SignalKind::RepeatedPattern {
                pattern: vec![0xDE, 0xAD, 0xBE, 0xEF],
                stride: 6,
                occurrences: 20,
            },
            0.78,
            "test",
        );
        let align = Signal::new(
            Region::new(0, 256),
            SignalKind::AlignmentHint {
                alignment: 4,
                entropy_spread: 1.0,
                dominant_phase: 0,
            },
            0.72,
            "test",
        );
        let schema = build(&[rep, align], 256);
        assert!(
            !schema
                .hypotheses
                .iter()
                .any(|h| h.label.contains("Struct array")),
            "should not compound when stride is not a multiple of alignment"
        );
    }

    #[test]
    fn file_wide_hypothesis_sorted_first() {
        let chi = Signal::new(
            Region::new(0, 512),
            SignalKind::ChiSquare {
                chi_sq: 280.0,
                p_value: 0.001,
            },
            0.80,
            "test",
        );
        let magic = Signal::new(
            Region::new(0, 4),
            SignalKind::MagicBytes {
                format: "PNG".to_string(),
                hex: "89504e47".to_string(),
            },
            0.97,
            "test",
        );
        let schema = build(&[chi, magic], 512);
        assert!(schema.hypotheses.len() >= 2);
        let first = &schema.hypotheses[0];
        assert_eq!(first.region.len, 512, "file-wide should be first");
    }
}
