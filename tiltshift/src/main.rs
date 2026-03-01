use clap::{Parser, Subcommand};
use std::path::PathBuf;
use tiltshift::{
    constraint, corpus, hypothesis,
    loader::MappedFile,
    probe, search, signals,
    signals::{chunk::sequence_label, length_prefix::body_preview, tlv::tlv_label},
    types::{EntropyClass, LayoutSpan, Signal, SignalKind},
};

#[derive(Parser)]
#[command(
    name = "tiltshift",
    about = "Iterative structure extraction from opaque binary data"
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Run all signal extractors and report findings.
    Analyze {
        file: PathBuf,
        /// Entropy block size in bytes (default: 256).
        #[arg(long, default_value_t = 256)]
        block_size: usize,
        /// Output JSON instead of human-readable text.
        #[arg(long)]
        json: bool,
        /// Maximum recursion depth for sub-region analysis (0 = none, default: 1).
        #[arg(long, default_value_t = 1)]
        depth: usize,
    },

    /// Show typed interpretations of bytes at an offset.
    ///
    /// OFFSET may be decimal or hex (0x…). LEN defaults to 8.
    Probe {
        file: PathBuf,
        /// Byte offset to inspect (decimal or 0x hex).
        offset: String,
        /// Number of bytes to read (default: 8).
        #[arg(default_value_t = 8)]
        len: usize,
    },

    /// Manage the magic byte corpus.
    Magic {
        #[command(subcommand)]
        action: MagicAction,
    },

    /// Search a file for all occurrences of a byte pattern.
    ///
    /// PATTERN is a hex string: space-separated pairs or compact.
    /// Examples:
    ///   tiltshift scan data.bin "de ad be ef"
    ///   tiltshift scan data.bin deadbeef
    Scan {
        file: PathBuf,
        /// Hex bytes to search for (e.g. "89 50 4e 47" or "89504e47").
        pattern: String,
        /// Extra bytes of hex context to display after each hit.
        #[arg(long, default_value_t = 8)]
        context: usize,
        /// Output JSON instead of human-readable text.
        #[arg(long)]
        json: bool,
    },

    /// Copy a file to <file>.unk with all known magic bytes zeroed out.
    ///
    /// Produces an opaque blob useful for testing signal extractors against
    /// files whose format has been deliberately obscured.
    Obfuscate {
        file: PathBuf,
        /// Overwrite the output file if it already exists.
        #[arg(long)]
        force: bool,
    },

    /// Show ranked interpretations of a specific byte range.
    ///
    /// OFFSET and LEN may be decimal or hex (0x…).
    /// Examples:
    ///   tiltshift region data.bin 0x40 64
    ///   tiltshift region data.bin 128 256
    Region {
        file: PathBuf,
        /// Byte offset to start analysis (decimal or 0x hex).
        offset: String,
        /// Number of bytes to analyze (decimal or 0x hex).
        len: String,
        /// Entropy block size in bytes (default: 256).
        #[arg(long, default_value_t = 256)]
        block_size: usize,
        /// Output JSON instead of human-readable text.
        #[arg(long)]
        json: bool,
    },

    /// Recursively analyze a specific byte range of a file.
    ///
    /// Runs signal extraction and hypothesis building on the specified range, then
    /// recurses into any identified sub-structures up to --depth levels.
    ///
    /// OFFSET and LEN may be decimal or hex (0x…).
    /// Examples:
    ///   tiltshift descend data.bin 0x40 256
    ///   tiltshift descend data.bin 0x40 256 --depth 2
    Descend {
        file: PathBuf,
        /// Byte offset to start analysis (decimal or 0x hex).
        offset: String,
        /// Number of bytes to analyze (decimal or 0x hex).
        len: String,
        /// Entropy block size in bytes (default: 256).
        #[arg(long, default_value_t = 256)]
        block_size: usize,
        /// Maximum recursion depth (default: 1, 0 = no sub-region analysis).
        #[arg(long, default_value_t = 1)]
        depth: usize,
    },

    /// Compare the structure of two binary files.
    ///
    /// Bytes that are identical at the same offset in both files are structural
    /// (fixed headers, magic bytes, format tags). Bytes that differ are data fields.
    /// Examples:
    ///   tiltshift diff a.bin b.bin
    ///   tiltshift diff a.bin b.bin --min-structural 8
    Diff {
        file_a: PathBuf,
        file_b: PathBuf,
        /// Minimum run of identical bytes to annotate as structural (default: 4).
        #[arg(long, default_value_t = 4)]
        min_structural: usize,
        /// Entropy block size in bytes (default: 256).
        #[arg(long, default_value_t = 256)]
        block_size: usize,
        /// Output JSON instead of human-readable text.
        #[arg(long)]
        json: bool,
    },
}

#[derive(Subcommand)]
enum MagicAction {
    /// Register a new magic byte signature in your user corpus.
    ///
    /// MAGIC is a hex string: space-separated pairs or compact.
    /// Examples:
    ///   tiltshift magic add "My Format" "4d 59 46 4d"
    ///   tiltshift magic add "My Format" "4d59464d"
    Add {
        /// Human-readable format name.
        name: String,
        /// Hex bytes (e.g. "89 50 4e 47" or "89504e47").
        magic: String,
    },

    /// List all known magic byte signatures (built-in + user).
    List {
        /// Filter by name (case-insensitive substring match).
        #[arg(long, short)]
        filter: Option<String>,
    },
}

fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();
    match cli.command {
        Command::Analyze {
            file,
            block_size,
            json,
            depth,
        } => cmd_analyze(&file, block_size, json, depth),
        Command::Probe { file, offset, len } => cmd_probe(&file, &offset, len),
        Command::Magic { action } => match action {
            MagicAction::Add { name, magic } => cmd_magic_add(&name, &magic),
            MagicAction::List { filter } => cmd_magic_list(filter.as_deref()),
        },
        Command::Scan {
            file,
            pattern,
            context,
            json,
        } => cmd_scan(&file, &pattern, context, json),
        Command::Obfuscate { file, force } => cmd_obfuscate(&file, force),
        Command::Region {
            file,
            offset,
            len,
            block_size,
            json,
        } => cmd_region(&file, &offset, &len, block_size, json),
        Command::Descend {
            file,
            offset,
            len,
            block_size,
            depth,
        } => cmd_descend(&file, &offset, &len, block_size, depth),
        Command::Diff {
            file_a,
            file_b,
            min_structural,
            block_size,
            json,
        } => cmd_diff(&file_a, &file_b, min_structural, block_size, json),
    }
}

/// Minimum sub-region size in bytes worth descending into.
const MIN_DESCENT_SIZE: usize = 32;

fn cmd_analyze(path: &PathBuf, block_size: usize, json: bool, depth: usize) -> anyhow::Result<()> {
    let mapped = MappedFile::open(path)?;
    let data = mapped.bytes();
    let file_name = path.display();
    let file_size = data.len();

    let corpus = corpus::load();
    let all_signals = signals::extract_all(data, block_size, &corpus);

    if json {
        println!("{}", serde_json::to_string_pretty(&all_signals)?);
        return Ok(());
    }

    let bar = "═".repeat(60);
    println!("{bar}");
    println!("  tiltshift  {file_name}  ({file_size} bytes)");
    println!("{bar}");

    // ── Hypotheses ───────────────────────────────────────────────────────────
    let schema = hypothesis::build(&all_signals, file_size);
    const HYP_CAP: usize = 20;
    if !schema.hypotheses.is_empty() {
        println!("\nHYPOTHESES");
        println!("{}", "─".repeat(60));
        for hyp in schema.hypotheses.iter().take(HYP_CAP) {
            let region_str = if hyp.region.offset == 0 && hyp.region.len == file_size {
                "[file]    ".to_string()
            } else {
                format!("{:10}", hyp.region)
            };
            println!(
                "  {}  {}  (confidence {:.0}%)",
                region_str,
                hyp.label,
                hyp.confidence * 100.0
            );
            // Reasoning — always shown
            if !hyp.reasoning.is_empty() {
                println!("              why: {}", hyp.reasoning);
            }
            // Contributing signals summary (only when multiple signals compound)
            if hyp.signals.len() > 1 {
                let desc = hyp
                    .signals
                    .iter()
                    .map(|s| hypothesis::signal_kind_label(&s.kind))
                    .collect::<Vec<_>>()
                    .join(", ");
                println!("              via: {desc}");
            }
            // Top alternative
            if let Some((alt_label, alt_conf)) = hyp.alternatives.first() {
                println!("              alt: {alt_label} ({:.0}%)", alt_conf * 100.0);
            }
        }
        if schema.hypotheses.len() > HYP_CAP {
            println!(
                "  … {} more (use --json for full list)",
                schema.hypotheses.len() - HYP_CAP
            );
        }
    }

    // LAYOUT — linear view of which byte ranges are explained vs. unknown.
    let layout = schema.layout();
    let known_count = layout
        .iter()
        .filter(|s| matches!(s, LayoutSpan::Known(_)))
        .count();
    if known_count > 0 {
        let unknown_count = layout.len() - known_count;
        println!("\nLAYOUT  ({file_size} bytes, {known_count} known, {unknown_count} unknown)");
        println!("{}", "─".repeat(60));

        // Derive pointer/offset constraints to annotate unknown spans.
        let constraints = constraint::propagate(&all_signals);

        for span in &layout {
            match span {
                LayoutSpan::Known(hyp) => {
                    let start = hyp.region.offset;
                    let end = hyp.region.end().saturating_sub(1);
                    println!(
                        "  0x{start:06x}–0x{end:06x}  KNOWN    {} ({:.0}%)",
                        hyp.label,
                        hyp.confidence * 100.0
                    );
                    if depth > 0 && hyp.region.len >= MIN_DESCENT_SIZE {
                        let sub_data = hyp.region.slice(data);
                        println!(
                            "      ↳ sub-region 0x{start:06x}+{} (inside: {})",
                            hyp.region.len, hyp.label
                        );
                        print_region_analysis(sub_data, start, block_size, depth - 1, "        ");
                    }
                }
                LayoutSpan::Unknown(region) => {
                    let start = region.offset;
                    let end = region.end().saturating_sub(1);
                    println!("  0x{start:06x}–0x{end:06x}  UNKNOWN  {} B", region.len);
                    for c in constraint::for_region(&constraints, region) {
                        println!("                             ← {}", c.note);
                    }
                }
            }
        }
    }

    let magic: Vec<_> = all_signals
        .iter()
        .filter(|s| matches!(&s.kind, SignalKind::MagicBytes { .. }))
        .collect();

    if !magic.is_empty() {
        println!("\nMAGIC BYTES");
        println!("{}", "─".repeat(60));
        for sig in &magic {
            let SignalKind::MagicBytes { format, hex } = &sig.kind else {
                unreachable!()
            };
            println!(
                "  {:8}  {}  [{}]  (confidence {:.0}%)",
                sig.region.to_string(),
                format,
                hex,
                sig.confidence * 100.0
            );
            println!("            → {}", sig.reason);
        }
    }

    let strings: Vec<_> = all_signals
        .iter()
        .filter(|s| matches!(&s.kind, SignalKind::NullTerminatedString { .. }))
        .collect();

    if !strings.is_empty() {
        println!("\nSTRINGS  (null-terminated)");
        println!("{}", "─".repeat(60));
        for sig in &strings {
            let SignalKind::NullTerminatedString { content } = &sig.kind else {
                unreachable!()
            };
            println!(
                "  {:8}  {:?}  (confidence {:.0}%)",
                sig.region.to_string(),
                content,
                sig.confidence * 100.0
            );
        }
    }

    let len_prefixed: Vec<_> = all_signals
        .iter()
        .filter(|s| matches!(&s.kind, SignalKind::LengthPrefixedBlob { .. }))
        .collect();

    if !len_prefixed.is_empty() {
        println!("\nLENGTH-PREFIXED BLOBS");
        println!("{}", "─".repeat(60));
        for sig in &len_prefixed {
            let SignalKind::LengthPrefixedBlob {
                prefix_width,
                little_endian,
                declared_len,
                ..
            } = &sig.kind
            else {
                unreachable!()
            };
            let endian_label = if *prefix_width == 1 {
                String::new()
            } else if *little_endian {
                "le".to_string()
            } else {
                "be".to_string()
            };
            let type_label = format!("u{}{}", prefix_width * 8, endian_label);
            let preview = body_preview(
                data,
                sig.region.offset,
                *prefix_width as usize,
                *declared_len,
            );
            println!(
                "  {:8}  {} len={}  {}  (confidence {:.0}%)",
                sig.region.to_string(),
                type_label,
                declared_len,
                preview,
                sig.confidence * 100.0
            );
        }
    }

    let chunk_seqs: Vec<_> = all_signals
        .iter()
        .filter(|s| matches!(&s.kind, SignalKind::ChunkSequence { .. }))
        .collect();

    if !chunk_seqs.is_empty() {
        println!("\nCHUNK SEQUENCES");
        println!("{}", "─".repeat(60));
        for sig in &chunk_seqs {
            let SignalKind::ChunkSequence {
                format_hint,
                tag_first,
                little_endian,
                chunk_count,
                tags,
            } = &sig.kind
            else {
                unreachable!()
            };
            let layout = sequence_label(*tag_first, *little_endian);
            let tag_list = tags.join(", ");
            let more = if tags.len() < *chunk_count {
                format!(", +{} more", chunk_count - tags.len())
            } else {
                String::new()
            };
            println!(
                "  {:8}  {} {} ({} chunks)  [{}{}]  (confidence {:.0}%)",
                sig.region.to_string(),
                format_hint,
                layout,
                chunk_count,
                tag_list,
                more,
                sig.confidence * 100.0
            );
        }
    }

    let numeric_vals: Vec<_> = all_signals
        .iter()
        .filter(|s| matches!(&s.kind, SignalKind::NumericValue { .. }))
        .collect();

    if !numeric_vals.is_empty() {
        // Partition by primary flag for display; show most-specific first.
        let size_hits: Vec<_> = numeric_vals
            .iter()
            .filter(|s| {
                matches!(
                    &s.kind,
                    SignalKind::NumericValue {
                        file_size_match: true,
                        ..
                    }
                )
            })
            .collect();
        let pow2_hits: Vec<_> = numeric_vals
            .iter()
            .filter(|s| {
                matches!(
                    &s.kind,
                    SignalKind::NumericValue {
                        file_size_match: false,
                        power_of_two: true,
                        ..
                    }
                )
            })
            .collect();
        let offset_hits: Vec<_> = numeric_vals
            .iter()
            .filter(|s| {
                matches!(
                    &s.kind,
                    SignalKind::NumericValue {
                        file_size_match: false,
                        power_of_two: false,
                        within_bounds: true,
                        ..
                    }
                )
            })
            .collect();

        println!("\nNUMERIC VALUE LANDMARKS");
        println!("{}", "─".repeat(60));

        for sig in &size_hits {
            print_numeric_sig(sig);
        }
        for sig in &pow2_hits {
            print_numeric_sig(sig);
        }
        const OFFSET_DISPLAY_CAP: usize = 12;
        for sig in offset_hits.iter().take(OFFSET_DISPLAY_CAP) {
            print_numeric_sig(sig);
        }
        if offset_hits.len() > OFFSET_DISPLAY_CAP {
            println!(
                "  … {} more candidate-offset values (use --json for full list)",
                offset_hits.len() - OFFSET_DISPLAY_CAP
            );
        }
    }

    // ── Ngram profile (one per file) ────────────────────────────────────────
    if let Some(profile) = all_signals
        .iter()
        .find(|s| matches!(&s.kind, SignalKind::NgramProfile { .. }))
    {
        let SignalKind::NgramProfile {
            bigram_entropy,
            top_bigrams,
            data_type_hint,
        } = &profile.kind
        else {
            unreachable!()
        };
        println!("\nNGRAM PROFILE");
        println!("{}", "─".repeat(60));
        println!("  bigram entropy  {bigram_entropy:.2} bits   hint: {data_type_hint}");
        println!("  top bigrams     {}", top_bigrams.join("  "));
    }

    // ── Alignment hint (one per file) ───────────────────────────────────────
    if let Some(align_sig) = all_signals
        .iter()
        .find(|s| matches!(&s.kind, SignalKind::AlignmentHint { .. }))
    {
        let SignalKind::AlignmentHint {
            alignment,
            entropy_spread,
            dominant_phase,
        } = &align_sig.kind
        else {
            unreachable!()
        };
        println!("\nALIGNMENT HINT");
        println!("{}", "─".repeat(60));
        println!(
            "  {alignment}-byte alignment  spread {entropy_spread:.2} bits  phase {dominant_phase} most variable  (confidence {:.0}%)",
            align_sig.confidence * 100.0
        );
        println!("  → {}", align_sig.reason);
    }

    // ── Repeating stride patterns ────────────────────────────────────────────
    let stride_sigs: Vec<_> = all_signals
        .iter()
        .filter(|s| matches!(&s.kind, SignalKind::RepeatedPattern { .. }))
        .collect();

    if !stride_sigs.is_empty() {
        println!("\nREPEATING PATTERNS  (stride)");
        println!("{}", "─".repeat(60));
        const STRIDE_DISPLAY_CAP: usize = 8;
        for sig in stride_sigs.iter().take(STRIDE_DISPLAY_CAP) {
            let SignalKind::RepeatedPattern {
                pattern,
                stride,
                occurrences,
            } = &sig.kind
            else {
                unreachable!()
            };
            let hex: String = pattern
                .iter()
                .map(|b| format!("{b:02x}"))
                .collect::<Vec<_>>()
                .join(" ");
            println!(
                "  {:8}  stride={:<4}  ×{:<3}  [{}]  (confidence {:.0}%)",
                sig.region.to_string(),
                stride,
                occurrences,
                hex,
                sig.confidence * 100.0
            );
        }
        if stride_sigs.len() > STRIDE_DISPLAY_CAP {
            println!(
                "  … {} more (use --json for full list)",
                stride_sigs.len() - STRIDE_DISPLAY_CAP
            );
        }
    }

    let tlv_seqs: Vec<_> = all_signals
        .iter()
        .filter(|s| matches!(&s.kind, SignalKind::TlvSequence { .. }))
        .collect();

    if !tlv_seqs.is_empty() {
        println!("\nTLV SEQUENCES");
        println!("{}", "─".repeat(60));
        const TLV_DISPLAY_CAP: usize = 12;
        for sig in tlv_seqs.iter().take(TLV_DISPLAY_CAP) {
            let SignalKind::TlvSequence {
                type_width,
                len_width,
                little_endian,
                record_count,
                type_samples,
            } = &sig.kind
            else {
                unreachable!()
            };
            let label = tlv_label(*type_width, *len_width, *little_endian);
            let tw = *type_width;
            let type_fmt: String = type_samples
                .iter()
                .map(|&t| {
                    if tw == 1 {
                        format!("{t:02x}")
                    } else {
                        format!("{t:04x}")
                    }
                })
                .collect::<Vec<_>>()
                .join(", ");
            let more = if type_samples.len() < *record_count {
                format!(", +{} more", record_count - type_samples.len())
            } else {
                String::new()
            };
            println!(
                "  {:8}  {} ×{}  types: [{}{} ]  (confidence {:.0}%)",
                sig.region.to_string(),
                label,
                record_count,
                type_fmt,
                more,
                sig.confidence * 100.0
            );
        }
        if tlv_seqs.len() > TLV_DISPLAY_CAP {
            println!(
                "  … {} more (use --json for full list)",
                tlv_seqs.len() - TLV_DISPLAY_CAP
            );
        }
    }

    let padding_runs: Vec<_> = all_signals
        .iter()
        .filter(|s| matches!(&s.kind, SignalKind::Padding { .. }))
        .collect();

    if !padding_runs.is_empty() {
        println!("\nPADDING RUNS");
        println!("{}", "─".repeat(60));
        const PADDING_DISPLAY_CAP: usize = 16;
        for sig in padding_runs.iter().take(PADDING_DISPLAY_CAP) {
            let SignalKind::Padding {
                byte_value,
                run_len,
            } = &sig.kind
            else {
                unreachable!()
            };
            let label = if *byte_value == 0x00 {
                "zero-fill"
            } else {
                "0xFF-fill"
            };
            println!(
                "  {:8}  {} ×{}  (confidence {:.0}%)",
                sig.region.to_string(),
                label,
                run_len,
                sig.confidence * 100.0
            );
        }
        if padding_runs.len() > PADDING_DISPLAY_CAP {
            println!(
                "  … {} more (use --json for full list)",
                padding_runs.len() - PADDING_DISPLAY_CAP
            );
        }
    }

    // ── Chi-square uniformity (one per file) ────────────────────────────────
    if let Some(chisq_sig) = all_signals
        .iter()
        .find(|s| matches!(&s.kind, SignalKind::ChiSquare { .. }))
    {
        let SignalKind::ChiSquare { chi_sq, p_value } = &chisq_sig.kind else {
            unreachable!()
        };
        let label = if *p_value < 0.01 {
            "non-uniform"
        } else if *p_value < 0.05 {
            "mildly non-uniform"
        } else if *p_value > 0.99 {
            "suspiciously uniform"
        } else if *p_value > 0.95 {
            "over-uniform"
        } else {
            "consistent with uniform"
        };
        println!("\nCHI-SQUARE UNIFORMITY");
        println!("{}", "─".repeat(60));
        println!(
            "  chi-sq {chi_sq:.1}  p={p_value:.3}  → {label}  (confidence {:.0}%)",
            chisq_sig.confidence * 100.0
        );
        println!("  → {}", chisq_sig.reason);
    }

    // ── Variable-length integers ─────────────────────────────────────────────
    let varint_sigs: Vec<_> = all_signals
        .iter()
        .filter(|s| matches!(&s.kind, SignalKind::VarInt { .. }))
        .collect();

    if !varint_sigs.is_empty() {
        println!("\nVARIABLE-LENGTH INTEGERS");
        println!("{}", "─".repeat(60));
        const VARINT_DISPLAY_CAP: usize = 12;
        for sig in varint_sigs.iter().take(VARINT_DISPLAY_CAP) {
            let SignalKind::VarInt {
                encoding,
                count,
                avg_width,
                ..
            } = &sig.kind
            else {
                unreachable!()
            };
            println!(
                "  {:8}  {} ×{}  avg {:.1} bytes  (confidence {:.0}%)",
                sig.region.to_string(),
                encoding,
                count,
                avg_width,
                sig.confidence * 100.0
            );
            println!("            → {}", sig.reason);
        }
        if varint_sigs.len() > VARINT_DISPLAY_CAP {
            println!(
                "  … {} more (use --json for full list)",
                varint_sigs.len() - VARINT_DISPLAY_CAP
            );
        }
    }

    // ── Packed nibble sub-fields (one per file) ──────────────────────────────
    if let Some(packed_sig) = all_signals
        .iter()
        .find(|s| matches!(&s.kind, SignalKind::PackedField { .. }))
    {
        let SignalKind::PackedField {
            high_nibble_entropy,
            low_nibble_entropy,
            mutual_information,
            independence_ratio,
            hint,
        } = &packed_sig.kind
        else {
            unreachable!()
        };
        println!("\nPACKED NIBBLE FIELDS");
        println!("{}", "─".repeat(60));
        println!(
            "  H_hi={high_nibble_entropy:.2}  H_lo={low_nibble_entropy:.2}  \
             MI={mutual_information:.3}  ind={independence_ratio:.3}  \
             (confidence {:.0}%)",
            packed_sig.confidence * 100.0
        );
        println!("  → {hint}");
    }

    // ── Offset graph (one per width/endian pair) ─────────────────────────────
    let offset_graph_sigs: Vec<_> = all_signals
        .iter()
        .filter(|s| matches!(&s.kind, SignalKind::OffsetGraph { .. }))
        .collect();

    if !offset_graph_sigs.is_empty() {
        println!("\nOFFSET GRAPH");
        println!("{}", "─".repeat(60));
        for sig in &offset_graph_sigs {
            let SignalKind::OffsetGraph {
                pointer_width,
                little_endian,
                component_nodes,
                component_edges,
                pointer_density,
                sample_edges,
                candidate_count: _,
            } = &sig.kind
            else {
                unreachable!()
            };
            let endian = if *little_endian { "le" } else { "be" };
            println!(
                "  u{}{}  {} nodes  {} edges  density {:.1}%  (confidence {:.0}%)",
                pointer_width * 8,
                endian,
                component_nodes,
                component_edges,
                pointer_density * 100.0,
                sig.confidence * 100.0,
            );
            const EDGE_DISPLAY_CAP: usize = 8;
            for &(src, dst) in sample_edges.iter().take(EDGE_DISPLAY_CAP) {
                println!("    0x{src:06x} → 0x{dst:06x}");
            }
            if *component_edges > EDGE_DISPLAY_CAP {
                println!(
                    "    … {} more edges (use --json for full list)",
                    component_edges - EDGE_DISPLAY_CAP
                );
            }
        }
    }

    // ── Compression ratio probe (one per file) ───────────────────────────────
    if let Some(compress_sig) = all_signals
        .iter()
        .find(|s| matches!(&s.kind, SignalKind::CompressionProbe { .. }))
    {
        let SignalKind::CompressionProbe {
            original_size,
            compressed_size,
            ratio,
        } = &compress_sig.kind
        else {
            unreachable!()
        };
        let label = if *ratio >= 0.99 {
            "incompressible"
        } else if *ratio >= 0.90 {
            "nearly incompressible"
        } else if *ratio >= 0.70 {
            "mildly compressible"
        } else if *ratio >= 0.40 {
            "moderately compressible"
        } else {
            "highly compressible"
        };
        println!("\nCOMPRESSION PROBE");
        println!("{}", "─".repeat(60));
        println!(
            "  {compressed_size}/{original_size} bytes  ratio {ratio:.3}  → {label}  (confidence {:.0}%)",
            compress_sig.confidence * 100.0
        );
    }

    let entropy_blocks: Vec<_> = all_signals
        .iter()
        .filter(|s| matches!(&s.kind, SignalKind::EntropyBlock { .. }))
        .collect();

    if !entropy_blocks.is_empty() {
        println!("\nENTROPY MAP  ({block_size}-byte blocks)");
        println!("{}", "─".repeat(60));
        for sig in &entropy_blocks {
            let SignalKind::EntropyBlock { entropy, class } = &sig.kind else {
                unreachable!()
            };
            let bar = entropy_bar(*entropy);
            println!(
                "  {:8}  {bar}  {:.2}  {}",
                sig.region.to_string(),
                entropy,
                class.label()
            );
        }
    }

    println!("\nSUMMARY");
    println!("{}", "─".repeat(60));
    println!("  {} magic byte match(es)", magic.len());
    println!("  {} null-terminated string(s)", strings.len());
    println!("  {} length-prefixed blob(s)", len_prefixed.len());
    println!("  {} chunk sequence(s)", chunk_seqs.len());
    println!("  {} numeric landmark(s)", numeric_vals.len());
    let alignment_hint = all_signals
        .iter()
        .filter(|s| matches!(&s.kind, SignalKind::AlignmentHint { .. }))
        .count();
    println!("  {} alignment hint(s)", alignment_hint);
    let chisq_count = all_signals
        .iter()
        .filter(|s| matches!(&s.kind, SignalKind::ChiSquare { .. }))
        .count();
    println!("  {} chi-square test(s)", chisq_count);
    let compress_count = all_signals
        .iter()
        .filter(|s| matches!(&s.kind, SignalKind::CompressionProbe { .. }))
        .count();
    println!("  {} compression probe(s)", compress_count);
    println!("  {} variable-length integer run(s)", varint_sigs.len());
    let packed_count = all_signals
        .iter()
        .filter(|s| matches!(&s.kind, SignalKind::PackedField { .. }))
        .count();
    println!("  {} packed nibble field signal(s)", packed_count);
    println!("  {} offset graph signal(s)", offset_graph_sigs.len());
    println!("  {} repeating stride pattern(s)", stride_sigs.len());
    println!("  {} TLV sequence(s)", tlv_seqs.len());
    println!("  {} padding run(s)", padding_runs.len());
    println!("  {} entropy block(s)", entropy_blocks.len());

    let high_entropy_bytes: usize = entropy_blocks
        .iter()
        .filter(|s| {
            matches!(&s.kind, SignalKind::EntropyBlock { class, .. }
                if *class == EntropyClass::HighlyRandom || *class == EntropyClass::Compressed)
        })
        .map(|s| s.region.len)
        .sum();
    let pct = if file_size > 0 {
        high_entropy_bytes * 100 / file_size
    } else {
        0
    };
    println!("  ~{pct}% of file is compressed/high-entropy");
    println!();
    Ok(())
}

/// Print structural analysis (HYPOTHESES + LAYOUT) for a sub-slice, indented.
///
/// `base_offset` is the absolute file offset of `data[0]`; all displayed
/// offsets are translated to absolute coordinates.  `depth` is the remaining
/// recursion budget — 0 means print this level but do not descend further.
/// `indent` is prepended to every output line.
fn print_region_analysis(
    data: &[u8],
    base_offset: usize,
    block_size: usize,
    depth: usize,
    indent: &str,
) {
    if data.len() < MIN_DESCENT_SIZE {
        return;
    }
    let corpus = corpus::load();
    let signals = signals::extract_all(data, block_size, &corpus);
    let schema = hypothesis::build(&signals, data.len());

    if schema.hypotheses.is_empty() {
        return;
    }

    // ── HYPOTHESES ───────────────────────────────────────────────────────────
    const HYP_CAP: usize = 10;
    let total = schema.hypotheses.len();
    if total > HYP_CAP {
        println!("{indent}HYPOTHESES  ({HYP_CAP} of {total} shown)");
    } else {
        println!("{indent}HYPOTHESES");
    }
    for hyp in schema.hypotheses.iter().take(HYP_CAP) {
        let region_str = if hyp.region.offset == 0 && hyp.region.len == data.len() {
            "[sub-region]".to_string()
        } else {
            let abs = base_offset + hyp.region.offset;
            format!("0x{abs:06x}+{}", hyp.region.len)
        };
        println!(
            "{indent}  {region_str:<14}  {}  ({:.0}%)",
            hyp.label,
            hyp.confidence * 100.0
        );
        if !hyp.reasoning.is_empty() {
            println!("{indent}    why: {}", hyp.reasoning);
        }
    }

    // ── LAYOUT ───────────────────────────────────────────────────────────────
    let layout = schema.layout();
    let known_count = layout
        .iter()
        .filter(|s| matches!(s, LayoutSpan::Known(_)))
        .count();
    if known_count == 0 {
        return;
    }
    let unknown_count = layout.len() - known_count;
    println!(
        "{indent}LAYOUT  ({} bytes, {known_count} known, {unknown_count} unknown)",
        data.len()
    );

    let constraints = constraint::propagate(&signals);
    let next_indent = format!("{indent}    ");
    for span in &layout {
        match span {
            LayoutSpan::Known(hyp) => {
                let abs_start = base_offset + hyp.region.offset;
                let abs_end = abs_start + hyp.region.len.saturating_sub(1);
                println!(
                    "{indent}  0x{abs_start:06x}–0x{abs_end:06x}  KNOWN    {} ({:.0}%)",
                    hyp.label,
                    hyp.confidence * 100.0
                );
                if depth > 0 && hyp.region.len >= MIN_DESCENT_SIZE {
                    let sub_data = hyp.region.slice(data);
                    let sub_base = base_offset + hyp.region.offset;
                    println!(
                        "{next_indent}↳ sub-region 0x{sub_base:06x}+{} (inside: {})",
                        hyp.region.len, hyp.label
                    );
                    print_region_analysis(
                        sub_data,
                        sub_base,
                        block_size,
                        depth - 1,
                        &format!("{next_indent}  "),
                    );
                }
            }
            LayoutSpan::Unknown(region) => {
                let abs_start = base_offset + region.offset;
                let abs_end = abs_start + region.len.saturating_sub(1);
                println!(
                    "{indent}  0x{abs_start:06x}–0x{abs_end:06x}  UNKNOWN  {} B",
                    region.len
                );
                for c in constraint::for_region(&constraints, region) {
                    println!("{indent}                             ← {}", c.note);
                }
            }
        }
    }
}

fn cmd_descend(
    path: &PathBuf,
    offset_str: &str,
    len_str: &str,
    block_size: usize,
    depth: usize,
) -> anyhow::Result<()> {
    let mapped = MappedFile::open(path)?;
    let data = mapped.bytes();
    let file_size = data.len();

    let base = parse_offset(offset_str)
        .ok_or_else(|| anyhow::anyhow!("invalid offset: {offset_str:?}"))?;
    let requested_len =
        parse_offset(len_str).ok_or_else(|| anyhow::anyhow!("invalid length: {len_str:?}"))?;

    if base >= file_size {
        anyhow::bail!("offset 0x{base:x} is beyond end of file ({file_size} bytes)");
    }
    if requested_len == 0 {
        anyhow::bail!("length must be greater than zero");
    }
    let len = requested_len.min(file_size - base);

    let file_name = path.display();
    let bar = "═".repeat(60);
    println!("{bar}");
    println!("  tiltshift descend  {file_name}  0x{base:06x}+{len}  ({len} bytes)");
    println!("{bar}");

    let slice = &data[base..base + len];
    print_region_analysis(slice, base, block_size, depth, "");
    println!();
    Ok(())
}

fn cmd_probe(path: &PathBuf, offset_str: &str, len: usize) -> anyhow::Result<()> {
    let mapped = MappedFile::open(path)?;
    let data = mapped.bytes();
    let file_size = data.len();

    let offset = parse_offset(offset_str)
        .ok_or_else(|| anyhow::anyhow!("invalid offset: {offset_str:?}"))?;

    if offset >= file_size {
        anyhow::bail!("offset 0x{offset:x} is beyond end of file ({file_size} bytes)");
    }

    let result = probe::probe(data, offset, len, file_size);

    let hex_bytes: String = result
        .bytes
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect::<Vec<_>>()
        .join(" ");

    let bar = "═".repeat(60);
    println!("{bar}");
    println!(
        "  probe  {}  @0x{:x}  ({} byte{})",
        path.display(),
        offset,
        result.bytes.len(),
        if result.bytes.len() == 1 { "" } else { "s" }
    );
    println!("{bar}");
    println!("  bytes  {hex_bytes}");
    println!("{}", "─".repeat(60));

    // Group by width for display
    for width in [1usize, 2, 4, 8] {
        let group: Vec<_> = result.by_width(width).collect();
        if group.is_empty() {
            continue;
        }
        for interp in group {
            let note = interp
                .note
                .as_deref()
                .map(|n| format!("  ← {n}"))
                .unwrap_or_default();
            println!("  {:<14}  {}{}", interp.label, interp.value, note);
        }
        println!("{}", "─".repeat(60));
    }

    // String / hex interpretations (width = 0 sentinel)
    let text_group: Vec<_> = result.by_width(0).collect();
    if !text_group.is_empty() {
        for interp in text_group {
            let note = interp
                .note
                .as_deref()
                .map(|n| format!("  ← {n}"))
                .unwrap_or_default();
            println!("  {:<14}  {}{}", interp.label, interp.value, note);
        }
        println!("{}", "─".repeat(60));
    }
    println!();
    Ok(())
}

fn cmd_scan(path: &PathBuf, pattern_str: &str, context: usize, json: bool) -> anyhow::Result<()> {
    let pattern =
        corpus::parse_hex(pattern_str).map_err(|e| anyhow::anyhow!("invalid pattern: {e}"))?;

    let mapped = MappedFile::open(path)?;
    let data = mapped.bytes();

    let hits = search::find_all(data, &pattern);

    if json {
        let records: Vec<_> = hits
            .iter()
            .map(|&offset| {
                let ctx_end = (offset + pattern.len() + context).min(data.len());
                let ctx_bytes = &data[offset..ctx_end];
                let hex: String = ctx_bytes
                    .iter()
                    .map(|b| format!("{b:02x}"))
                    .collect::<Vec<_>>()
                    .join(" ");
                serde_json::json!({ "offset": offset, "hex": hex })
            })
            .collect();
        println!("{}", serde_json::to_string_pretty(&records)?);
        return Ok(());
    }

    let pat_hex: String = pattern
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect::<Vec<_>>()
        .join(" ");

    let bar = "═".repeat(60);
    println!("{bar}");
    println!(
        "  scan  {}  pattern=[{}]  ({} byte{})",
        path.display(),
        pat_hex,
        pattern.len(),
        if pattern.len() == 1 { "" } else { "s" }
    );
    println!("{bar}");

    if hits.is_empty() {
        println!("  (no matches)");
    } else {
        for &offset in &hits {
            let ctx_start = offset + pattern.len();
            let ctx_end = ctx_start.saturating_add(context).min(data.len());
            let ctx_hex: String = if ctx_start < data.len() && context > 0 {
                let bytes = &data[ctx_start..ctx_end];
                format!(
                    "  +{}",
                    bytes
                        .iter()
                        .map(|b| format!("{b:02x}"))
                        .collect::<Vec<_>>()
                        .join(" ")
                )
            } else {
                String::new()
            };
            println!("  0x{offset:08x}  [{pat_hex}]{ctx_hex}");
        }
    }

    println!();
    println!("  {} hit(s)", hits.len());
    println!();
    Ok(())
}

/// Parse a decimal or 0x-prefixed hex string into a usize offset.
fn parse_offset(s: &str) -> Option<usize> {
    let s = s.trim();
    if let Some(hex) = s.strip_prefix("0x").or_else(|| s.strip_prefix("0X")) {
        usize::from_str_radix(hex, 16).ok()
    } else {
        s.parse::<usize>().ok()
    }
}

fn cmd_obfuscate(path: &PathBuf, force: bool) -> anyhow::Result<()> {
    let mapped = MappedFile::open(path)?;
    let data = mapped.bytes();

    // Build output path: append .unk suffix
    let out_path = {
        let mut s = path.as_os_str().to_owned();
        s.push(".unk");
        PathBuf::from(s)
    };

    if out_path.exists() && !force {
        anyhow::bail!(
            "output file already exists: {}  (use --force to overwrite)",
            out_path.display()
        );
    }

    let corpus = corpus::load();
    let mut buf = data.to_vec();
    let mut zeroed: Vec<(usize, String, usize)> = Vec::new(); // (offset, name, magic_len)

    for entry in &corpus.formats {
        let Ok(magic) = entry.magic_bytes() else {
            continue;
        };
        if magic.is_empty() {
            continue;
        }
        let hits = search::find_all(data, &magic);
        for offset in hits {
            // Zero the magic bytes in the output buffer
            for b in buf[offset..offset + magic.len()].iter_mut() {
                *b = 0x00;
            }
            zeroed.push((offset, entry.name.clone(), magic.len()));
        }
    }

    std::fs::write(&out_path, &buf)?;

    let bar = "═".repeat(60);
    println!("{bar}");
    println!(
        "  tiltshift obfuscate  {}  ({} bytes)",
        path.display(),
        data.len()
    );
    println!("{bar}");

    if zeroed.is_empty() {
        println!("  no known magic bytes found — file is already opaque");
    } else {
        println!("  zeroed {} magic region(s):", zeroed.len());
        for (offset, name, len) in &zeroed {
            println!("  0x{offset:08x}  {name}  ({len} bytes)");
        }
    }

    println!();
    println!("  output: {}", out_path.display());
    println!();
    Ok(())
}

fn cmd_region(
    path: &PathBuf,
    offset_str: &str,
    len_str: &str,
    block_size: usize,
    json: bool,
) -> anyhow::Result<()> {
    let mapped = MappedFile::open(path)?;
    let data = mapped.bytes();
    let file_size = data.len();

    let base = parse_offset(offset_str)
        .ok_or_else(|| anyhow::anyhow!("invalid offset: {offset_str:?}"))?;
    let requested_len =
        parse_offset(len_str).ok_or_else(|| anyhow::anyhow!("invalid length: {len_str:?}"))?;

    if base >= file_size {
        anyhow::bail!("offset 0x{base:x} is beyond end of file ({file_size} bytes)");
    }
    if requested_len == 0 {
        anyhow::bail!("length must be greater than zero");
    }
    let len = requested_len.min(file_size - base);

    let slice = &data[base..base + len];
    let corpus = corpus::load();
    let all_signals = signals::extract_all(slice, block_size, &corpus);
    let schema = hypothesis::build(&all_signals, slice.len());

    if json {
        let output = serde_json::json!({
            "file": path.display().to_string(),
            "offset": base,
            "len": len,
            "hypotheses": schema.hypotheses,
            "signals": all_signals,
        });
        println!("{}", serde_json::to_string_pretty(&output)?);
        return Ok(());
    }

    let file_name = path.display();
    let bar = "═".repeat(60);
    println!("{bar}");
    println!("  tiltshift region  {file_name}  0x{base:06x}+{len}  ({len} bytes)");
    println!("{bar}");

    if schema.hypotheses.is_empty() {
        println!("\n  (no hypotheses — region may be too small or featureless)");
    } else {
        println!("\nHYPOTHESES");
        println!("{}", "─".repeat(60));
        const HYP_CAP: usize = 10;
        for hyp in schema.hypotheses.iter().take(HYP_CAP) {
            // Display file-absolute offsets.
            let region_str = if hyp.region.offset == 0 && hyp.region.len == len {
                "[region]  ".to_string()
            } else {
                let abs = base + hyp.region.offset;
                format!("0x{abs:06x}+{}", hyp.region.len)
            };
            println!(
                "  {}  {}  (confidence {:.0}%)",
                region_str,
                hyp.label,
                hyp.confidence * 100.0
            );
            if !hyp.reasoning.is_empty() {
                println!("              why: {}", hyp.reasoning);
            }
            if hyp.signals.len() > 1 {
                let desc = hyp
                    .signals
                    .iter()
                    .map(|s| hypothesis::signal_kind_label(&s.kind))
                    .collect::<Vec<_>>()
                    .join(", ");
                println!("              via: {desc}");
            }
            if let Some((alt_label, alt_conf)) = hyp.alternatives.first() {
                println!("              alt: {alt_label} ({:.0}%)", alt_conf * 100.0);
            }
        }
        if schema.hypotheses.len() > HYP_CAP {
            println!(
                "  … {} more (use --json for full list)",
                schema.hypotheses.len() - HYP_CAP
            );
        }
    }

    // Brief signal summary.
    if !all_signals.is_empty() {
        println!("\nSIGNALS  ({} total)", all_signals.len());
        println!("{}", "─".repeat(60));
        let mut kind_counts: std::collections::HashMap<&str, usize> =
            std::collections::HashMap::new();
        for sig in &all_signals {
            *kind_counts
                .entry(hypothesis::signal_kind_label(&sig.kind))
                .or_default() += 1;
        }
        let mut counts: Vec<_> = kind_counts.into_iter().collect();
        counts.sort_by(|a, b| b.1.cmp(&a.1).then(a.0.cmp(b.0)));
        for (label, count) in &counts {
            println!("  {count:3}  {label}");
        }
    }

    println!();
    Ok(())
}

// ── diff helpers ─────────────────────────────────────────────────────────────

#[derive(Clone, Copy, PartialEq, Eq)]
enum RunKind {
    Structural,
    Data,
}

struct DiffRun {
    offset: usize,
    len: usize,
    kind: RunKind,
}

/// Sweep `a` and `b` byte-by-byte, emitting runs where bytes match (structural)
/// or differ (data).
fn compute_diff_runs(a: &[u8], b: &[u8]) -> Vec<DiffRun> {
    let n = a.len().min(b.len());
    if n == 0 {
        return vec![];
    }
    let mut runs = Vec::new();
    let mut i = 0;
    while i < n {
        let is_match = a[i] == b[i];
        let start = i;
        while i < n && (a[i] == b[i]) == is_match {
            i += 1;
        }
        runs.push(DiffRun {
            offset: start,
            len: i - start,
            kind: if is_match {
                RunKind::Structural
            } else {
                RunKind::Data
            },
        });
    }
    runs
}

/// Partition signals into: shared (same variant + offset in both files), a-only, b-only.
fn partition_signals(
    signals_a: &[Signal],
    signals_b: &[Signal],
) -> (Vec<Signal>, Vec<Signal>, Vec<Signal>) {
    let mut shared = Vec::new();
    let mut a_only = Vec::new();
    for sig_a in signals_a {
        if signals_b.iter().any(|sig_b| {
            std::mem::discriminant(&sig_a.kind) == std::mem::discriminant(&sig_b.kind)
                && sig_a.region.offset == sig_b.region.offset
        }) {
            shared.push(sig_a.clone());
        } else {
            a_only.push(sig_a.clone());
        }
    }
    let b_only: Vec<Signal> = signals_b
        .iter()
        .filter(|sig_b| {
            !signals_a.iter().any(|sig_a| {
                std::mem::discriminant(&sig_a.kind) == std::mem::discriminant(&sig_b.kind)
                    && sig_a.region.offset == sig_b.region.offset
            })
        })
        .cloned()
        .collect();
    (shared, a_only, b_only)
}

/// Compact one-line description of a signal for use in diff reports.
fn format_signal_summary(sig: &Signal) -> String {
    let label = hypothesis::signal_kind_label(&sig.kind);
    let region = format!("0x{:06x}+{}", sig.region.offset, sig.region.len);
    let detail: String = match &sig.kind {
        SignalKind::MagicBytes { format, .. } => format!("\"{format}\""),
        SignalKind::NullTerminatedString { content } => {
            let s = if content.len() > 24 {
                &content[..24]
            } else {
                content.as_str()
            };
            format!("{s:?}")
        }
        SignalKind::ChunkSequence {
            format_hint,
            chunk_count,
            ..
        } => format!("{format_hint}  {chunk_count} chunks"),
        SignalKind::LengthPrefixedBlob {
            prefix_width,
            declared_len,
            little_endian,
            ..
        } => {
            let endian = if *little_endian { "le" } else { "be" };
            format!("u{}{endian}  declared_len={declared_len}", prefix_width * 8)
        }
        SignalKind::RepeatedPattern {
            stride,
            occurrences,
            ..
        } => format!("stride={stride}  ×{occurrences}"),
        SignalKind::TlvSequence {
            type_width,
            len_width,
            record_count,
            ..
        } => format!(
            "T{}L{}  {record_count} records",
            type_width * 8,
            len_width * 8
        ),
        SignalKind::AlignmentHint { alignment, .. } => format!("align={alignment}"),
        SignalKind::VarInt {
            encoding, count, ..
        } => format!("{encoding}  ×{count}"),
        SignalKind::OffsetGraph {
            pointer_width,
            component_nodes,
            ..
        } => format!("u{}  {component_nodes} nodes", pointer_width * 8),
        SignalKind::NumericValue { value, .. } => format!("0x{value:08x}"),
        _ => String::new(),
    };
    let conf = (sig.confidence * 100.0) as u32;
    if detail.is_empty() {
        format!("  {label:<22}  {region}   conf={conf}%")
    } else {
        format!("  {label:<22}  {region}   {detail}  conf={conf}%")
    }
}

fn cmd_diff(
    path_a: &PathBuf,
    path_b: &PathBuf,
    min_structural: usize,
    block_size: usize,
    json: bool,
) -> anyhow::Result<()> {
    let mapped_a = MappedFile::open(path_a)?;
    let mapped_b = MappedFile::open(path_b)?;
    let data_a = mapped_a.bytes();
    let data_b = mapped_b.bytes();
    let common_len = data_a.len().min(data_b.len());
    if common_len == 0 {
        anyhow::bail!("one or both files are empty");
    }

    let runs = compute_diff_runs(&data_a[..common_len], &data_b[..common_len]);
    let structural_bytes: usize = runs
        .iter()
        .filter(|r| r.kind == RunKind::Structural)
        .map(|r| r.len)
        .sum();
    let data_bytes = common_len - structural_bytes;

    let corpus = corpus::load();
    let signals_a = signals::extract_all(data_a, block_size, &corpus);
    let signals_b = signals::extract_all(data_b, block_size, &corpus);
    let (shared_signals, a_only_signals, b_only_signals) =
        partition_signals(&signals_a, &signals_b);
    let schema = hypothesis::build(&shared_signals, common_len);

    if json {
        let output = serde_json::json!({
            "file_a": { "path": path_a.display().to_string(), "size": data_a.len() },
            "file_b": { "path": path_b.display().to_string(), "size": data_b.len() },
            "common_length": common_len,
            "structural_bytes": structural_bytes,
            "data_bytes": data_bytes,
            "runs": runs.iter().map(|r| serde_json::json!({
                "offset": r.offset,
                "len": r.len,
                "kind": if r.kind == RunKind::Structural { "structural" } else { "data" },
            })).collect::<Vec<_>>(),
            "shared_signals": shared_signals,
            "file_a_only_signals": a_only_signals,
            "file_b_only_signals": b_only_signals,
            "hypotheses": schema.hypotheses,
        });
        println!("{}", serde_json::to_string_pretty(&output)?);
        return Ok(());
    }

    let bar = "═".repeat(60);
    println!("{bar}");
    println!(
        "  tiltshift diff  {}  vs  {}",
        path_a.display(),
        path_b.display()
    );
    println!("{bar}");
    println!();
    println!("  file_a:  {} bytes  ({})", data_a.len(), path_a.display());
    println!("  file_b:  {} bytes  ({})", data_b.len(), path_b.display());
    if data_a.len() != data_b.len() {
        let diff = data_a.len().abs_diff(data_b.len());
        let larger = if data_a.len() > data_b.len() {
            "a"
        } else {
            "b"
        };
        println!(
            "  note: file_{larger} is {diff} bytes longer; only the first {common_len} bytes compared"
        );
    }
    let pct_structural = structural_bytes as f64 / common_len as f64 * 100.0;
    let pct_data = data_bytes as f64 / common_len as f64 * 100.0;
    println!();
    println!("  structural:  {structural_bytes} of {common_len} bytes  ({pct_structural:.1}%)  identical");
    println!("  data:        {data_bytes} of {common_len} bytes  ({pct_data:.1}%)  vary");

    // Byte map
    println!("\nBYTE MAP  ({} runs)", runs.len());
    println!("{}", "─".repeat(60));
    const RUN_CAP: usize = 60;
    for run in runs.iter().take(RUN_CAP) {
        let label = match run.kind {
            RunKind::Structural => "STRUCT",
            RunKind::Data => "DATA  ",
        };
        // Annotate structural runs ≥ min_structural with the signal kinds they contain.
        let annotation = if run.kind == RunKind::Structural && run.len >= min_structural {
            let mut seen = std::collections::HashSet::new();
            let kinds: Vec<&str> = shared_signals
                .iter()
                .filter(|s| s.region.offset >= run.offset && s.region.offset < run.offset + run.len)
                .map(|s| hypothesis::signal_kind_label(&s.kind))
                .filter(|&lbl| seen.insert(lbl))
                .collect();
            if kinds.is_empty() {
                String::new()
            } else {
                format!("  → {}", kinds.join(", "))
            }
        } else {
            String::new()
        };
        println!(
            "  [{label}] 0x{:06x}+{:5}{}",
            run.offset, run.len, annotation
        );
    }
    if runs.len() > RUN_CAP {
        println!(
            "  … {} more runs (use --json for full list)",
            runs.len() - RUN_CAP
        );
    }

    // Shared signals
    if !shared_signals.is_empty() {
        println!(
            "\nSHARED SIGNALS  ({} structural markers confirmed in both files)",
            shared_signals.len()
        );
        println!("{}", "─".repeat(60));
        const SIG_CAP: usize = 20;
        for sig in shared_signals.iter().take(SIG_CAP) {
            println!("{}", format_signal_summary(sig));
        }
        if shared_signals.len() > SIG_CAP {
            println!(
                "  … {} more (use --json for full list)",
                shared_signals.len() - SIG_CAP
            );
        }
    }

    // Hypotheses from shared signals
    if !schema.hypotheses.is_empty() {
        println!("\nHYPOTHESES  (structural interpretation)");
        println!("{}", "─".repeat(60));
        const HYP_CAP: usize = 10;
        for hyp in schema.hypotheses.iter().take(HYP_CAP) {
            let region_str = if hyp.region.len == common_len {
                "[file]    ".to_string()
            } else {
                format!("0x{:06x}+{}", hyp.region.offset, hyp.region.len)
            };
            println!(
                "  {}  {}  (confidence {:.0}%)",
                region_str,
                hyp.label,
                hyp.confidence * 100.0
            );
            if !hyp.reasoning.is_empty() {
                println!("              why: {}", hyp.reasoning);
            }
            if hyp.signals.len() > 1 {
                let desc = hyp
                    .signals
                    .iter()
                    .map(|s| hypothesis::signal_kind_label(&s.kind))
                    .collect::<Vec<_>>()
                    .join(", ");
                println!("              via: {desc}");
            }
            if let Some((alt_label, alt_conf)) = hyp.alternatives.first() {
                println!("              alt: {alt_label} ({:.0}%)", alt_conf * 100.0);
            }
        }
        if schema.hypotheses.len() > HYP_CAP {
            println!(
                "  … {} more (use --json for full list)",
                schema.hypotheses.len() - HYP_CAP
            );
        }
    }

    // Divergent signals
    const DIV_CAP: usize = 10;
    if !a_only_signals.is_empty() {
        println!(
            "\nFILE_A ONLY SIGNALS  ({} — likely data-dependent)",
            a_only_signals.len()
        );
        println!("{}", "─".repeat(60));
        for sig in a_only_signals.iter().take(DIV_CAP) {
            println!("{}", format_signal_summary(sig));
        }
        if a_only_signals.len() > DIV_CAP {
            println!(
                "  … {} more (use --json for full list)",
                a_only_signals.len() - DIV_CAP
            );
        }
    }
    if !b_only_signals.is_empty() {
        println!(
            "\nFILE_B ONLY SIGNALS  ({} — likely data-dependent)",
            b_only_signals.len()
        );
        println!("{}", "─".repeat(60));
        for sig in b_only_signals.iter().take(DIV_CAP) {
            println!("{}", format_signal_summary(sig));
        }
        if b_only_signals.len() > DIV_CAP {
            println!(
                "  … {} more (use --json for full list)",
                b_only_signals.len() - DIV_CAP
            );
        }
    }

    println!();
    Ok(())
}

fn cmd_magic_add(name: &str, magic: &str) -> anyhow::Result<()> {
    let path = corpus::add_entry(name, magic)?;
    // echo what was stored
    let normalized = corpus::parse_hex(magic)
        .map(|b| {
            b.iter()
                .map(|x| format!("{x:02x}"))
                .collect::<Vec<_>>()
                .join(" ")
        })
        .unwrap_or_else(|_| magic.to_string());
    println!("Added: {name:?}  [{normalized}]");
    println!("  → {}", path.display());
    Ok(())
}

fn cmd_magic_list(filter: Option<&str>) -> anyhow::Result<()> {
    let corpus = corpus::load();
    let filter_lc = filter.map(|f| f.to_lowercase());

    let bar = "═".repeat(60);
    println!("{bar}");
    println!(
        "  tiltshift magic corpus  ({} entries)",
        corpus.formats.len()
    );
    println!("{bar}");

    for entry in &corpus.formats {
        if let Some(ref f) = filter_lc {
            if !entry.name.to_lowercase().contains(f.as_str()) {
                continue;
            }
        }
        let bytes = entry.magic_bytes().unwrap_or_default();
        let hex = bytes
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect::<Vec<_>>()
            .join(" ");
        if let Some(ref mime) = entry.mime {
            println!("  {:40}  [{}]  ({})", entry.name, hex, mime);
        } else {
            println!("  {:40}  [{}]", entry.name, hex);
        }
    }
    println!();
    Ok(())
}

fn print_numeric_sig(sig: &tiltshift::types::Signal) {
    let SignalKind::NumericValue {
        little_endian,
        value,
        file_size_match,
        power_of_two,
        within_bounds,
    } = &sig.kind
    else {
        unreachable!()
    };
    let endian = if *little_endian { "le" } else { "be" };
    let mut flags = Vec::new();
    if *file_size_match {
        flags.push("file-size");
    }
    if *power_of_two {
        flags.push("power-of-two");
    }
    if *within_bounds {
        flags.push("candidate-offset");
    }
    println!(
        "  {:8}  u32{}  {:10}  (0x{:08x})  ← {}  (confidence {:.0}%)",
        sig.region.to_string(),
        endian,
        value,
        value,
        flags.join(", "),
        sig.confidence * 100.0
    );
}

/// 8-cell block bar representing entropy 0.0–8.0.
fn entropy_bar(entropy: f64) -> String {
    const BLOCKS: &[char] = &[' ', '▏', '▎', '▍', '▌', '▋', '▊', '▉', '█'];
    let cells = 8usize;
    let filled = (entropy / 8.0 * cells as f64).min(cells as f64);
    let full_cells = filled as usize;
    let frac = filled - full_cells as f64;
    let frac_char = BLOCKS[(frac * 8.0) as usize];
    let mut s = String::new();
    for _ in 0..full_cells {
        s.push('█');
    }
    if full_cells < cells {
        s.push(frac_char);
        for _ in (full_cells + 1)..cells {
            s.push(' ');
        }
    }
    s
}
