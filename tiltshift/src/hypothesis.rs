//! Hypothesis engine — converts raw signals into ranked, confidence-scored
//! interpretations of the file's structure.
//!
//! ## Passes
//!
//! 1. **Compound string tables** — 3+ adjacent null-terminated strings →
//!    a single "string table" hypothesis.
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
    let (string_hyps, consumed) = compound_string_tables(signals);
    schema.hypotheses.extend(string_hyps);

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
        SignalKind::NumericValue { .. } => "numeric value",
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
