use clap::{Parser, Subcommand};
use hdbscan::{Hdbscan, HdbscanHyperParams};
use rayon::prelude::*;
use std::path::PathBuf;
use tiltshift::{
    cluster, constraint, corpus, hypothesis,
    loader::MappedFile,
    opcodes, probe, search, session, signals,
    signals::{chunk::sequence_label, tlv::tlv_label},
    types::{EntropyClass, Hypothesis, LayoutSpan, Region, Signal, SignalKind},
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
        /// Only display signals and hypotheses at or above this confidence (0.0–1.0).
        #[arg(long, default_value_t = 0.0)]
        min_confidence: f64,
        /// Show signal reasoning for all signal types and all alternative hypotheses.
        #[arg(long)]
        verbose: bool,
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

    /// Copy files to <stem>.unk with all known magic bytes zeroed out.
    ///
    /// The original file extension is stripped so "photo.png" becomes
    /// "photo.unk", not "photo.png.unk" (which would leak the format).
    /// Accepts multiple files and glob patterns (e.g. "*.png" "dir/**/*.bin").
    /// Each input produces a separate <stem>.unk file alongside the original.
    /// Produces opaque blobs useful for testing signal extractors against
    /// files whose format has been deliberately obscured.
    Obfuscate {
        /// Files or glob patterns to obfuscate.
        files: Vec<String>,
        /// Overwrite output files if they already exist.
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
        /// Only display signals and hypotheses at or above this confidence (0.0–1.0).
        #[arg(long, default_value_t = 0.0)]
        min_confidence: f64,
        /// Show signal reasoning for all signal types and all alternative hypotheses.
        #[arg(long)]
        verbose: bool,
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
        /// Only display signals and hypotheses at or above this confidence (0.0–1.0).
        #[arg(long, default_value_t = 0.0)]
        min_confidence: f64,
        /// Show signal reasoning for all signal types and all alternative hypotheses.
        #[arg(long)]
        verbose: bool,
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

    /// Build a corpus model from multiple files, or save one as a named format.
    ///
    /// Examples:
    ///   tiltshift corpus build sample1.bin sample2.bin sample3.bin
    ///   tiltshift corpus build --threshold 0.8 *.bin
    ///   tiltshift corpus add png ref1.png ref2.png ref3.png
    Corpus {
        #[command(subcommand)]
        action: CorpusAction,
    },

    /// Check a file against a structural model built from reference samples.
    ///
    /// Builds a consensus model from the reference files, then reports signals in
    /// the target that diverge: unexpected signals not in the model, and expected
    /// signals that are absent from the target.
    /// Examples:
    ///   tiltshift anomaly suspect.bin ref1.bin ref2.bin ref3.bin
    ///   tiltshift anomaly --threshold 0.8 suspect.bin ref1.bin ref2.bin
    Anomaly {
        /// The file to check for anomalies.
        target: PathBuf,
        /// Two or more reference files defining the expected format.
        refs: Vec<PathBuf>,
        /// Min fraction of refs a signal must appear in to count as expected (default: 1.0).
        #[arg(long, default_value_t = 1.0)]
        threshold: f64,
        /// Entropy block size in bytes (default: 256).
        #[arg(long, default_value_t = 256)]
        block_size: usize,
        /// Output JSON instead of human-readable text.
        #[arg(long)]
        json: bool,
        /// Only show anomalous signals at or above this confidence (0.0–1.0).
        #[arg(long, default_value_t = 0.0)]
        min_confidence: f64,
    },

    /// Decode instructions from a byte offset using a named opcode grammar.
    ///
    /// OFFSET may be decimal or hex (0x…).  FORMAT is the name of an installed
    /// grammar (see `tiltshift opcodes list`).  Displays decoded mnemonics and
    /// operand bytes; unknown opcodes are shown as UNKNOWN and consume 1 byte.
    ///
    /// Examples:
    ///   tiltshift decode bytecode.bin 0x10 my-vm
    ///   tiltshift decode bytecode.bin 256 my-vm --count 64
    Decode {
        file: PathBuf,
        /// Byte offset to start decoding (decimal or 0x hex).
        offset: String,
        /// Grammar name (from `tiltshift opcodes list`).
        format: String,
        /// Maximum number of instructions to decode (default: 64).
        #[arg(long, default_value_t = 64)]
        count: usize,
    },

    /// Manage opcode grammar files.
    ///
    /// Grammar files map opcode bytes to mnemonics and operand widths.
    /// They are written by hand after identifying a bytecode format and
    /// enable the `tiltshift decode` command to display named instructions.
    Opcodes {
        #[command(subcommand)]
        action: OpcodesAction,
    },

    /// Tag a byte range with a human-readable label, persisted in <file>.tiltshift.toml.
    ///
    /// Annotations survive re-analysis and are shown as ANNOTATED spans in the LAYOUT
    /// section of `tiltshift analyze`. Running `annotate` on an already-annotated region
    /// (same offset+len) replaces the existing label.
    ///
    /// OFFSET and LEN may be decimal or hex (0x…).
    /// Examples:
    ///   tiltshift annotate data.bin 0 4 "File header"
    ///   tiltshift annotate data.bin 0x40 64 "Resource table"
    Annotate {
        file: PathBuf,
        /// Byte offset to annotate (decimal or 0x hex).
        offset: String,
        /// Number of bytes to annotate (decimal or 0x hex).
        len: String,
        /// Human-readable label for this region.
        label: String,
    },

    /// Group files into clusters based on signal similarity (unsupervised HDBSCAN).
    ///
    /// Extracts a 10-dimensional feature vector from each file's signals and runs
    /// HDBSCAN to discover natural groupings without specifying the number of classes.
    /// Files that don't fit any cluster are reported as noise.
    ///
    /// Examples:
    ///   tiltshift cluster *.unk
    ///   tiltshift cluster --min-cluster-size 3 ~/corpus/*.unk
    Cluster {
        /// Files to cluster.
        files: Vec<PathBuf>,
        /// Minimum number of files required to form a cluster (default: 5).
        #[arg(long, default_value_t = 5)]
        min_cluster_size: usize,
        /// Entropy block size in bytes for signal extraction (default: 256).
        #[arg(long, default_value_t = 256)]
        block_size: usize,
        /// Show feature vector for each file.
        #[arg(long)]
        features: bool,
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

#[derive(Subcommand)]
enum CorpusAction {
    /// Extract a structural model from N binary files of the same format.
    ///
    /// Finds signals present across all (or most) files at the same offset.
    /// Useful for reverse-engineering unknown binary formats from multiple samples.
    /// Examples:
    ///   tiltshift corpus build sample1.bin sample2.bin sample3.bin
    ///   tiltshift corpus build --threshold 0.8 *.bin
    Build {
        /// Two or more files to analyse.
        files: Vec<PathBuf>,
        /// Min fraction of files a signal must appear in (0.0–1.0, default: 1.0).
        #[arg(long, default_value_t = 1.0)]
        threshold: f64,
        /// Entropy block size in bytes (default: 256).
        #[arg(long, default_value_t = 256)]
        block_size: usize,
        /// Output JSON instead of human-readable text.
        #[arg(long)]
        json: bool,
        /// Only display signals and hypotheses at or above this confidence (0.0–1.0).
        #[arg(long, default_value_t = 0.0)]
        min_confidence: f64,
    },
    /// Build a corpus model from reference files and save it as a named format.
    ///
    /// The model is stored at ~/.config/tiltshift/formats/<format>.toml and can
    /// be inspected with `corpus list`. Examples:
    ///   tiltshift corpus add png ref1.png ref2.png ref3.png
    ///   tiltshift corpus add wav --threshold 0.8 sample1.wav sample2.wav
    Add {
        /// Short name for this format (e.g. "png", "wav", "elf").
        format: String,
        /// Two or more representative files.
        files: Vec<PathBuf>,
        /// Min fraction of files a signal must appear in (0.0–1.0, default: 1.0).
        #[arg(long, default_value_t = 1.0)]
        threshold: f64,
        /// Entropy block size in bytes (default: 256).
        #[arg(long, default_value_t = 256)]
        block_size: usize,
        /// Only include signals at or above this confidence (0.0–1.0, default: 0.0).
        #[arg(long, default_value_t = 0.0)]
        min_confidence: f64,
    },
    /// List saved format models.
    ///
    /// Shows all named formats stored at ~/.config/tiltshift/formats/.
    List,
}

#[derive(Subcommand)]
enum OpcodesAction {
    /// Install an opcode grammar file from a TOML path.
    ///
    /// The file must contain `name`, optional `description`, and `[[opcodes]]`
    /// entries with `byte`, `mnemonic`, and `operand_bytes` fields.
    /// It is validated and copied to ~/.config/tiltshift/opcodes/<name>.toml.
    ///
    /// Example:
    ///   tiltshift opcodes add my-vm /path/to/my-vm.toml
    Add {
        /// Short name to install the grammar under (e.g. "my-vm").
        name: String,
        /// Path to the TOML grammar file.
        file: PathBuf,
    },

    /// List installed opcode grammars.
    ///
    /// Shows all grammars stored at ~/.config/tiltshift/opcodes/.
    List,
}

fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();
    match cli.command {
        Command::Analyze {
            file,
            block_size,
            json,
            depth,
            min_confidence,
            verbose,
        } => cmd_analyze(&file, block_size, json, depth, min_confidence, verbose),
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
        Command::Obfuscate { files, force } => cmd_obfuscate_multi(&files, force),
        Command::Region {
            file,
            offset,
            len,
            block_size,
            json,
            min_confidence,
            verbose,
        } => cmd_region(
            &file,
            &offset,
            &len,
            block_size,
            json,
            min_confidence,
            verbose,
        ),
        Command::Descend {
            file,
            offset,
            len,
            block_size,
            depth,
            min_confidence,
            verbose,
        } => cmd_descend(
            &file,
            &offset,
            &len,
            block_size,
            depth,
            min_confidence,
            verbose,
        ),
        Command::Diff {
            file_a,
            file_b,
            min_structural,
            block_size,
            json,
        } => cmd_diff(&file_a, &file_b, min_structural, block_size, json),
        Command::Corpus { action } => match action {
            CorpusAction::Build {
                files,
                threshold,
                block_size,
                json,
                min_confidence,
            } => cmd_corpus(&files, threshold, block_size, json, min_confidence),
            CorpusAction::Add {
                format,
                files,
                threshold,
                block_size,
                min_confidence,
            } => cmd_corpus_add(&format, &files, threshold, block_size, min_confidence),
            CorpusAction::List => cmd_corpus_list(),
        },
        Command::Anomaly {
            target,
            refs,
            threshold,
            block_size,
            json,
            min_confidence,
        } => cmd_anomaly(&target, &refs, threshold, block_size, json, min_confidence),
        Command::Annotate {
            file,
            offset,
            len,
            label,
        } => cmd_annotate(&file, &offset, &len, &label),
        Command::Decode {
            file,
            offset,
            format,
            count,
        } => cmd_decode(&file, &offset, &format, count),
        Command::Opcodes { action } => match action {
            OpcodesAction::Add { name, file } => cmd_opcodes_add(&name, &file),
            OpcodesAction::List => cmd_opcodes_list(),
        },
        Command::Cluster {
            files,
            min_cluster_size,
            block_size,
            features,
        } => cmd_cluster(&files, min_cluster_size, block_size, features),
    }
}

/// Minimum sub-region size in bytes worth descending into.
const MIN_DESCENT_SIZE: usize = 32;

fn cmd_analyze(
    path: &PathBuf,
    block_size: usize,
    json: bool,
    depth: usize,
    min_confidence: f64,
    verbose: bool,
) -> anyhow::Result<()> {
    let mapped = MappedFile::open(path)?;
    let data = mapped.bytes();
    let file_name = path.display();
    let file_size = data.len();

    // Load session state; create fresh if absent or file changed size.
    let mut state = session::load(path)
        .filter(|s| s.file_size == file_size)
        .unwrap_or_else(|| session::SessionState::new(file_size));

    let corpus = corpus::load();
    let all_signals = if state.signals.is_empty() {
        let sigs = signals::extract_all(data, block_size, &corpus);
        state.signals.clone_from(&sigs);
        if let Err(e) = session::save(path, &state) {
            eprintln!("warning: could not save session state: {e}");
        }
        sigs
    } else {
        state.signals.clone()
    };

    if json {
        println!("{}", serde_json::to_string_pretty(&all_signals)?);
        return Ok(());
    }

    let bar = "═".repeat(60);
    println!("{bar}");
    println!("  tiltshift  {file_name}  ({file_size} bytes)");
    if !state.annotations.is_empty() {
        println!(
            "  {} user annotation(s)  (sidecar: {}.tiltshift.toml)",
            state.annotations.len(),
            file_name
        );
    }
    println!("{bar}");

    // ── Hypotheses ───────────────────────────────────────────────────────────
    let mut schema = hypothesis::build(&all_signals, file_size);

    // Inject user annotations as top-priority hypotheses.
    for ann in &state.annotations {
        schema.hypotheses.push(Hypothesis {
            region: Region::new(ann.offset, ann.len),
            label: ann.label.clone(),
            confidence: 1.0,
            reasoning: String::new(),
            signals: vec![],
            alternatives: vec![],
            annotated: true,
        });
    }

    const HYP_CAP: usize = 20;
    let filtered_hyps: Vec<_> = schema
        .hypotheses
        .iter()
        .filter(|h| h.confidence >= min_confidence)
        .collect();
    if !filtered_hyps.is_empty() {
        println!("\nHYPOTHESES");
        println!("{}", "─".repeat(60));
        for hyp in filtered_hyps.iter().take(HYP_CAP) {
            let region_str = if hyp.region.offset == 0 && hyp.region.len == file_size {
                "[file]    ".to_string()
            } else {
                format!("{:10}", hyp.region)
            };
            let tag = if hyp.annotated { "  [user]" } else { "" };
            println!(
                "  {}  {}{}  (confidence {:.0}%)",
                region_str,
                hyp.label,
                tag,
                hyp.confidence * 100.0
            );
            // Reasoning — shown for auto-detected hypotheses only
            if !hyp.annotated && !hyp.reasoning.is_empty() {
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
            // Alternatives: all when verbose, first otherwise
            if verbose {
                for (alt_label, alt_conf) in &hyp.alternatives {
                    println!("              alt: {alt_label} ({:.0}%)", alt_conf * 100.0);
                }
            } else if let Some((alt_label, alt_conf)) = hyp.alternatives.first() {
                println!("              alt: {alt_label} ({:.0}%)", alt_conf * 100.0);
            }
        }
        if filtered_hyps.len() > HYP_CAP {
            println!(
                "  … {} more (use --json for full list)",
                filtered_hyps.len() - HYP_CAP
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
                    let kind = if hyp.annotated {
                        "ANNOTATED"
                    } else {
                        "KNOWN    "
                    };
                    println!(
                        "  0x{start:06x}–0x{end:06x}  {kind}  {} ({:.0}%)",
                        hyp.label,
                        hyp.confidence * 100.0
                    );
                    if depth > 0 && hyp.region.len >= MIN_DESCENT_SIZE && !hyp.annotated {
                        let sub_data = hyp.region.slice(data);
                        println!(
                            "      ↳ sub-region 0x{start:06x}+{} (inside: {})",
                            hyp.region.len, hyp.label
                        );
                        print_region_analysis(
                            sub_data,
                            start,
                            block_size,
                            depth - 1,
                            "        ",
                            min_confidence,
                            verbose,
                        );
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
        .filter(|s| {
            matches!(&s.kind, SignalKind::MagicBytes { .. }) && s.confidence >= min_confidence
        })
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
        .filter(|s| {
            matches!(&s.kind, SignalKind::NullTerminatedString { .. })
                && s.confidence >= min_confidence
        })
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
            if verbose && !sig.reason.is_empty() {
                println!("            → {}", sig.reason);
            }
        }
    }

    let len_prefixed: Vec<_> = all_signals
        .iter()
        .filter(|s| {
            matches!(&s.kind, SignalKind::LengthPrefixedBlob { .. })
                && s.confidence >= min_confidence
        })
        .collect();

    if !len_prefixed.is_empty() {
        println!("\nLENGTH-PREFIXED BLOB SEQUENCES");
        println!("{}", "─".repeat(60));
        for sig in &len_prefixed {
            let SignalKind::LengthPrefixedBlob {
                prefix_width,
                little_endian,
                blob_count,
                inter_blob_gap,
                printable_ratio,
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
            let gap_tag = if *inter_blob_gap == 0 {
                String::new()
            } else {
                format!("  gap={inter_blob_gap}B")
            };
            println!(
                "  {:8}  {} ×{}{} avg {:.0}% printable  (confidence {:.0}%)",
                sig.region.to_string(),
                type_label,
                blob_count,
                gap_tag,
                printable_ratio * 100.0,
                sig.confidence * 100.0
            );
            if verbose && !sig.reason.is_empty() {
                println!("            → {}", sig.reason);
            }
        }
    }

    let chunk_seqs: Vec<_> = all_signals
        .iter()
        .filter(|s| {
            matches!(&s.kind, SignalKind::ChunkSequence { .. }) && s.confidence >= min_confidence
        })
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
            if verbose && !sig.reason.is_empty() {
                println!("            → {}", sig.reason);
            }
        }
    }

    let numeric_vals: Vec<_> = all_signals
        .iter()
        .filter(|s| {
            matches!(&s.kind, SignalKind::NumericValue { .. }) && s.confidence >= min_confidence
        })
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
            print_numeric_sig(sig, verbose);
        }
        for sig in &pow2_hits {
            print_numeric_sig(sig, verbose);
        }
        const OFFSET_DISPLAY_CAP: usize = 12;
        for sig in offset_hits.iter().take(OFFSET_DISPLAY_CAP) {
            print_numeric_sig(sig, verbose);
        }
        if offset_hits.len() > OFFSET_DISPLAY_CAP {
            println!(
                "  … {} more candidate-offset values (use --json for full list)",
                offset_hits.len() - OFFSET_DISPLAY_CAP
            );
        }
    }

    // ── Ngram profile (one per file) ────────────────────────────────────────
    if let Some(profile) = all_signals.iter().find(|s| {
        matches!(&s.kind, SignalKind::NgramProfile { .. }) && s.confidence >= min_confidence
    }) {
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
        if verbose && !profile.reason.is_empty() {
            println!("  → {}", profile.reason);
        }
    }

    // ── Alignment hint (one per file) ───────────────────────────────────────
    if let Some(align_sig) = all_signals.iter().find(|s| {
        matches!(&s.kind, SignalKind::AlignmentHint { .. }) && s.confidence >= min_confidence
    }) {
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
        .filter(|s| {
            matches!(&s.kind, SignalKind::RepeatedPattern { .. }) && s.confidence >= min_confidence
        })
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
            if verbose && !sig.reason.is_empty() {
                println!("            → {}", sig.reason);
            }
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
        .filter(|s| {
            matches!(&s.kind, SignalKind::TlvSequence { .. }) && s.confidence >= min_confidence
        })
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
            if verbose && !sig.reason.is_empty() {
                println!("            → {}", sig.reason);
            }
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
        .filter(|s| matches!(&s.kind, SignalKind::Padding { .. }) && s.confidence >= min_confidence)
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
            if verbose && !sig.reason.is_empty() {
                println!("            → {}", sig.reason);
            }
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
        .find(|s| matches!(&s.kind, SignalKind::ChiSquare { .. }) && s.confidence >= min_confidence)
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
        .filter(|s| matches!(&s.kind, SignalKind::VarInt { .. }) && s.confidence >= min_confidence)
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
    if let Some(packed_sig) = all_signals.iter().find(|s| {
        matches!(&s.kind, SignalKind::PackedField { .. }) && s.confidence >= min_confidence
    }) {
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
        if verbose && !packed_sig.reason.is_empty() {
            println!("  → {}", packed_sig.reason);
        }
    }

    // ── Offset graph (one per width/endian pair) ─────────────────────────────
    let offset_graph_sigs: Vec<_> = all_signals
        .iter()
        .filter(|s| {
            matches!(&s.kind, SignalKind::OffsetGraph { .. }) && s.confidence >= min_confidence
        })
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
            if verbose && !sig.reason.is_empty() {
                println!("    → {}", sig.reason);
            }
        }
    }

    // ── Bytecode stream signals ───────────────────────────────────────────────
    let bytecode_sigs: Vec<_> = all_signals
        .iter()
        .filter(|s| {
            matches!(&s.kind, SignalKind::BytecodeStream { .. }) && s.confidence >= min_confidence
        })
        .collect();

    if !bytecode_sigs.is_empty() {
        println!("\nBYTECODE STREAMS");
        println!("{}", "─".repeat(60));
        for sig in &bytecode_sigs {
            let SignalKind::BytecodeStream {
                entry_point,
                decode_coverage,
                jump_validity,
                instruction_count,
                fixed_width,
                opcode_widths,
            } = &sig.kind
            else {
                unreachable!()
            };
            let fw_tag = fixed_width
                .map(|w| format!("  fixed-W={w}"))
                .unwrap_or_default();
            let jv_tag = jump_validity
                .map(|j| format!("  jump-valid={:.0}%", j * 100.0))
                .unwrap_or_default();
            println!(
                "  {:8}  {} instr  cov={:.0}%{fw_tag}{jv_tag}  (confidence {:.0}%)",
                sig.region.to_string(),
                instruction_count,
                decode_coverage * 100.0,
                sig.confidence * 100.0
            );
            if !opcode_widths.is_empty() {
                let pairs: String = opcode_widths
                    .iter()
                    .take(8)
                    .map(|(op, w)| format!("{op:02x}+{w}"))
                    .collect::<Vec<_>>()
                    .join("  ");
                let more = if opcode_widths.len() > 8 {
                    format!("  …+{}", opcode_widths.len() - 8)
                } else {
                    String::new()
                };
                println!("            opcodes: {pairs}{more}");
            }
            if verbose {
                println!("            entry: 0x{entry_point:06x}");
                println!("            → {}", sig.reason);
            }
        }
    }

    // ── Compression ratio probe (one per file) ───────────────────────────────
    if let Some(compress_sig) = all_signals.iter().find(|s| {
        matches!(&s.kind, SignalKind::CompressionProbe { .. }) && s.confidence >= min_confidence
    }) {
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
    println!("  {} bytecode stream(s)", bytecode_sigs.len());
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
    min_confidence: f64,
    verbose: bool,
) {
    if data.len() < MIN_DESCENT_SIZE {
        return;
    }
    let corpus = corpus::load();
    let signals = signals::extract_all(data, block_size, &corpus);
    let schema = hypothesis::build(&signals, data.len());

    let filtered_hyps: Vec<_> = schema
        .hypotheses
        .iter()
        .filter(|h| h.confidence >= min_confidence)
        .collect();
    if filtered_hyps.is_empty() {
        return;
    }

    // ── HYPOTHESES ───────────────────────────────────────────────────────────
    const HYP_CAP: usize = 10;
    let total = filtered_hyps.len();
    if total > HYP_CAP {
        println!("{indent}HYPOTHESES  ({HYP_CAP} of {total} shown)");
    } else {
        println!("{indent}HYPOTHESES");
    }
    for hyp in filtered_hyps.iter().take(HYP_CAP) {
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
        if verbose {
            for (alt_label, alt_conf) in &hyp.alternatives {
                println!("{indent}    alt: {alt_label} ({:.0}%)", alt_conf * 100.0);
            }
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
                        min_confidence,
                        verbose,
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
    min_confidence: f64,
    verbose: bool,
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
    print_region_analysis(slice, base, block_size, depth, "", min_confidence, verbose);
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

fn cmd_obfuscate_multi(patterns: &[String], force: bool) -> anyhow::Result<()> {
    if patterns.is_empty() {
        anyhow::bail!("no files specified");
    }

    // Expand each argument: glob patterns (containing *, ?, [) are expanded;
    // plain paths are used as-is and will error if missing when opened.
    let mut paths: Vec<PathBuf> = Vec::new();
    for pat in patterns {
        let is_glob = pat.contains(['*', '?', '[']);
        if is_glob {
            let matches: Vec<_> = glob::glob(pat)
                .map_err(|e| anyhow::anyhow!("invalid glob {pat:?}: {e}"))?
                .collect();
            if matches.is_empty() {
                eprintln!("tiltshift: warning: glob {pat:?} matched no files");
                continue;
            }
            for result in matches {
                let p = result.map_err(|e| anyhow::anyhow!("glob error: {e}"))?;
                if p.is_file() {
                    paths.push(p);
                }
            }
        } else {
            paths.push(PathBuf::from(pat));
        }
    }

    if paths.is_empty() {
        anyhow::bail!("no files matched");
    }

    let corpus = corpus::load();

    let errors: usize = paths
        .par_iter()
        .map(|path| match obfuscate_one(path, &corpus, force) {
            Ok(()) => 0,
            Err(e) => {
                eprintln!("tiltshift: {}: {e}", path.display());
                1
            }
        })
        .sum();

    if errors > 0 {
        anyhow::bail!("{errors} file(s) failed");
    }
    Ok(())
}

fn obfuscate_one(path: &PathBuf, corpus: &corpus::Corpus, force: bool) -> anyhow::Result<()> {
    let mapped = MappedFile::open(path)?;
    let data = mapped.bytes();

    // Strip the original extension so "photo.png" → "photo.unk", not
    // "photo.png.unk" (which leaks the format through the filename).
    let out_path = path.with_extension("unk");

    if out_path.exists() && !force {
        anyhow::bail!(
            "output already exists: {}  (use --force to overwrite)",
            out_path.display()
        );
    }

    let mut buf = data.to_vec();
    let mut zeroed: Vec<(usize, String, usize)> = Vec::new();

    // Minimum magic length to zero at non-zero offsets.  Short sequences
    // (BMP "BM", MP3 sync "\xff\xfb", …) appear by chance inside compressed
    // or binary data; only trust them at offset 0 where they're unambiguous
    // file headers.
    const MIN_INTERIOR_MAGIC_LEN: usize = 4;

    // Collect valid patterns paired with their corpus entry index so we can
    // resolve names and lengths after the Aho-Corasick pass.
    let mut patterns: Vec<Vec<u8>> = Vec::new();
    let mut pattern_meta: Vec<(String, usize)> = Vec::new(); // (name, magic_len)

    for entry in &corpus.formats {
        let Ok(magic) = entry.magic_bytes() else {
            continue;
        };
        if magic.is_empty() {
            continue;
        }
        let len = magic.len();
        patterns.push(magic);
        pattern_meta.push((entry.name.clone(), len));
    }

    if !patterns.is_empty() {
        // Single O(n + patterns + matches) pass over the file.
        let ac = aho_corasick::AhoCorasick::new(&patterns)
            .map_err(|e| anyhow::anyhow!("aho-corasick build error: {e}"))?;

        for mat in ac.find_iter(data) {
            let offset = mat.start();
            let (name, magic_len) = &pattern_meta[mat.pattern().as_usize()];
            if offset > 0 && *magic_len < MIN_INTERIOR_MAGIC_LEN {
                continue; // too short to be reliable away from offset 0
            }
            for b in buf[offset..offset + magic_len].iter_mut() {
                *b = 0x00;
            }
            zeroed.push((offset, name.clone(), *magic_len));
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
    min_confidence: f64,
    verbose: bool,
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

    let filtered_hyps: Vec<_> = schema
        .hypotheses
        .iter()
        .filter(|h| h.confidence >= min_confidence)
        .collect();
    if filtered_hyps.is_empty() {
        println!("\n  (no hypotheses — region may be too small or featureless)");
    } else {
        println!("\nHYPOTHESES");
        println!("{}", "─".repeat(60));
        const HYP_CAP: usize = 10;
        for hyp in filtered_hyps.iter().take(HYP_CAP) {
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
            if verbose {
                for (alt_label, alt_conf) in &hyp.alternatives {
                    println!("              alt: {alt_label} ({:.0}%)", alt_conf * 100.0);
                }
            } else if let Some((alt_label, alt_conf)) = hyp.alternatives.first() {
                println!("              alt: {alt_label} ({:.0}%)", alt_conf * 100.0);
            }
        }
        if filtered_hyps.len() > HYP_CAP {
            println!(
                "  … {} more (use --json for full list)",
                filtered_hyps.len() - HYP_CAP
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
            blob_count,
            inter_blob_gap,
            little_endian,
            ..
        } => {
            let endian = if *little_endian { "le" } else { "be" };
            let gap = if *inter_blob_gap > 0 {
                format!("  gap={inter_blob_gap}B")
            } else {
                String::new()
            };
            format!("u{}{endian}  ×{blob_count} blobs{gap}", prefix_width * 8)
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

struct FileEntry {
    path: PathBuf,
    size: usize,
    signals: Vec<Signal>,
}

fn load_file_entry(
    path: &PathBuf,
    block_size: usize,
    mc: &tiltshift::corpus::Corpus,
) -> anyhow::Result<Option<FileEntry>> {
    let mapped = MappedFile::open(path)?;
    let data = mapped.bytes();
    let file_size = data.len();
    if file_size == 0 {
        eprintln!("warning: skipping empty file: {}", path.display());
        return Ok(None);
    }

    let mut state = session::load(path)
        .filter(|s| s.file_size == file_size)
        .unwrap_or_else(|| session::SessionState::new(file_size));

    let sigs = if state.signals.is_empty() {
        let extracted = signals::extract_all(data, block_size, mc);
        state.signals.clone_from(&extracted);
        if let Err(e) = session::save(path, &state) {
            eprintln!("warning: could not save session state: {e}");
        }
        extracted
    } else {
        state.signals.clone()
    };

    Ok(Some(FileEntry {
        path: path.clone(),
        size: file_size,
        signals: sigs,
    }))
}

/// Build consensus key set and representative signals from a slice of file entries.
///
/// Returns `(consensus_keys, consensus_signals)` where `consensus_keys` is the set of
/// `(kind_label, offset)` pairs present in at least `ceil(threshold * entries.len())`
/// files, and `consensus_signals` is the highest-confidence representative for each key,
/// sorted by offset.
fn build_consensus(
    entries: &[FileEntry],
    threshold: f64,
) -> (std::collections::HashSet<(String, usize)>, Vec<Signal>) {
    use std::collections::HashMap;

    let n = entries.len();
    let min_count = (threshold * n as f64).ceil() as usize;

    // Per-file signal index: (kind_label, offset) → highest-confidence signal.
    let mut per_file: Vec<HashMap<(String, usize), Signal>> = Vec::with_capacity(n);
    for entry in entries {
        let mut index: HashMap<(String, usize), Signal> = HashMap::new();
        for sig in &entry.signals {
            let key = (
                hypothesis::signal_kind_label(&sig.kind).to_string(),
                sig.region.offset,
            );
            let keep = index
                .get(&key)
                .is_none_or(|prev| sig.confidence > prev.confidence);
            if keep {
                index.insert(key, sig.clone());
            }
        }
        per_file.push(index);
    }

    // Count how many files contain each key.
    let mut key_counts: HashMap<(String, usize), usize> = HashMap::new();
    for index in &per_file {
        for key in index.keys() {
            *key_counts.entry(key.clone()).or_insert(0) += 1;
        }
    }

    // Consensus: keys present in >= min_count files.
    let consensus_keys: std::collections::HashSet<(String, usize)> = key_counts
        .iter()
        .filter(|(_, &cnt)| cnt >= min_count)
        .map(|(k, _)| k.clone())
        .collect();

    // Take highest-confidence representative per consensus key.
    let mut best: HashMap<(String, usize), Signal> = HashMap::new();
    for index in &per_file {
        for (key, sig) in index {
            if consensus_keys.contains(key) {
                let keep = best
                    .get(key)
                    .is_none_or(|prev| sig.confidence > prev.confidence);
                if keep {
                    best.insert(key.clone(), sig.clone());
                }
            }
        }
    }
    let mut consensus_signals: Vec<Signal> = best.into_values().collect();
    consensus_signals.sort_by(|a, b| {
        a.region
            .offset
            .cmp(&b.region.offset)
            .then(b.confidence.partial_cmp(&a.confidence).unwrap())
    });

    (consensus_keys, consensus_signals)
}

fn cmd_corpus_add(
    format_name: &str,
    paths: &[PathBuf],
    threshold: f64,
    block_size: usize,
    min_confidence: f64,
) -> anyhow::Result<()> {
    if paths.len() < 2 {
        anyhow::bail!("corpus add requires at least 2 files");
    }

    let mc = corpus::load();

    let mut entries: Vec<FileEntry> = Vec::new();
    for path in paths {
        if let Some(entry) = load_file_entry(path, block_size, &mc)? {
            entries.push(entry);
        }
    }

    if entries.len() < 2 {
        anyhow::bail!("corpus add requires at least 2 non-empty files");
    }

    let n = entries.len();
    let min_count = ((threshold * n as f64).ceil() as usize).max(1);
    let (_consensus_keys, consensus_signals) = build_consensus(&entries, threshold);

    let filtered: Vec<_> = consensus_signals
        .into_iter()
        .filter(|s| s.confidence >= min_confidence)
        .collect();

    let path = corpus::save_format(format_name, &filtered)?;

    let threshold_pct = (threshold * 100.0) as u32;
    println!(
        "Saved {} consensus signal(s) for format {:?}",
        filtered.len(),
        format_name
    );
    println!(
        "  Files: {}  Threshold: {threshold_pct}% ({min_count}/{n})",
        n
    );
    println!("  Model: {}", path.display());

    Ok(())
}

fn cmd_corpus_list() -> anyhow::Result<()> {
    let dir = match corpus::formats_dir() {
        Some(d) => d,
        None => anyhow::bail!("cannot determine config dir (no HOME or XDG_CONFIG_HOME)"),
    };

    let entries = match std::fs::read_dir(&dir) {
        Ok(e) => e,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            println!("No saved format models ({})", dir.display());
            return Ok(());
        }
        Err(e) => return Err(e.into()),
    };

    let mut models: Vec<(String, usize)> = Vec::new();
    for entry in entries.flatten() {
        let path = entry.path();
        if path.extension().and_then(|e| e.to_str()) != Some("toml") {
            continue;
        }
        if let Ok(text) = std::fs::read_to_string(&path) {
            if let Ok(model) = toml::from_str::<corpus::FormatModel>(&text) {
                models.push((model.name, model.signals.len()));
            }
        }
    }

    if models.is_empty() {
        println!("No saved format models ({})", dir.display());
        return Ok(());
    }

    models.sort_by(|a, b| a.0.cmp(&b.0));
    println!("Saved format models  ({})", dir.display());
    println!("{}", "─".repeat(60));
    for (name, n_signals) in &models {
        println!("  {name:<20}  {n_signals} signal(s)");
    }

    Ok(())
}

fn cmd_corpus(
    paths: &[PathBuf],
    threshold: f64,
    block_size: usize,
    json: bool,
    min_confidence: f64,
) -> anyhow::Result<()> {
    if paths.len() < 2 {
        anyhow::bail!("corpus requires at least 2 files");
    }

    let mc = corpus::load();

    let mut entries: Vec<FileEntry> = Vec::new();
    for path in paths {
        if let Some(entry) = load_file_entry(path, block_size, &mc)? {
            entries.push(entry);
        }
    }

    if entries.len() < 2 {
        anyhow::bail!("corpus requires at least 2 non-empty files");
    }

    let n = entries.len();
    let common_size = entries.iter().map(|e| e.size).min().unwrap_or(0);
    let min_count = ((threshold * n as f64).ceil() as usize).max(1);

    let (consensus_keys, consensus_signals) = build_consensus(&entries, threshold);
    let schema = hypothesis::build(&consensus_signals, common_size);

    // Per-file divergences: signals NOT in the consensus key set.
    let per_file_divergences: Vec<(String, Vec<Signal>)> = entries
        .iter()
        .map(|entry| {
            use std::collections::HashMap;
            let mut index: HashMap<(String, usize), Signal> = HashMap::new();
            for sig in &entry.signals {
                let key = (
                    hypothesis::signal_kind_label(&sig.kind).to_string(),
                    sig.region.offset,
                );
                if !consensus_keys.contains(&key) {
                    let keep = index
                        .get(&key)
                        .is_none_or(|prev| sig.confidence > prev.confidence);
                    if keep {
                        index.insert(key, sig.clone());
                    }
                }
            }
            let mut divs: Vec<Signal> = index.into_values().collect();
            divs.sort_by(|a, b| {
                a.region
                    .offset
                    .cmp(&b.region.offset)
                    .then(b.confidence.partial_cmp(&a.confidence).unwrap())
            });
            (entry.path.display().to_string(), divs)
        })
        .collect();

    if json {
        let output = serde_json::json!({
            "files": entries.iter().map(|e| serde_json::json!({
                "path": e.path.display().to_string(),
                "size": e.size,
            })).collect::<Vec<_>>(),
            "threshold": threshold,
            "min_count": min_count,
            "common_prefix_length": common_size,
            "consensus_signals": consensus_signals,
            "hypotheses": schema.hypotheses,
            "per_file_divergences": per_file_divergences.iter().map(|(path, divs)| {
                (path.clone(), divs.clone())
            }).collect::<std::collections::HashMap<_, _>>(),
        });
        println!("{}", serde_json::to_string_pretty(&output)?);
        return Ok(());
    }

    // ── Text output ──────────────────────────────────────────────────────────
    let bar = "═".repeat(60);
    println!("{bar}");
    println!("  tiltshift corpus  —  {} files", n);
    println!("{bar}");
    println!();
    let shortest = common_size;
    for entry in &entries {
        if entry.size == shortest {
            println!("  {}   {} bytes", entry.path.display(), entry.size);
        } else {
            let diff = entry.size - shortest;
            println!(
                "  {}   {} bytes   ({diff} bytes longer than shortest)",
                entry.path.display(),
                entry.size
            );
        }
    }
    println!();
    let threshold_pct = (threshold * 100.0) as u32;
    println!("  Consensus threshold:  {threshold_pct}%  (signals in {min_count}/{n} files)");
    println!("  Consensus signals:    {}", consensus_signals.len());
    println!("  Common prefix length: {common_size} bytes");

    // Hypotheses
    const HYP_CAP: usize = 20;
    let filtered_hyps: Vec<_> = schema
        .hypotheses
        .iter()
        .filter(|h| h.confidence >= min_confidence)
        .collect();
    if !filtered_hyps.is_empty() {
        println!("\nCONSENSUS HYPOTHESES");
        println!("{}", "─".repeat(60));
        for hyp in filtered_hyps.iter().take(HYP_CAP) {
            let region_str = if hyp.region.offset == 0 && hyp.region.len == common_size {
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
        if filtered_hyps.len() > HYP_CAP {
            println!(
                "  … {} more (use --json for full list)",
                filtered_hyps.len() - HYP_CAP
            );
        }
    }

    // Layout
    const LAYOUT_CAP: usize = 10;
    let layout = schema.layout();
    let known_count = layout
        .iter()
        .filter(|s| matches!(s, LayoutSpan::Known(_)))
        .count();
    if known_count > 0 {
        let unknown_count = layout.len() - known_count;
        println!(
            "\nCONSENSUS LAYOUT  ({common_size} bytes, {known_count} known, {unknown_count} unknown)"
        );
        println!("{}", "─".repeat(60));
        for (shown, span) in layout.iter().enumerate() {
            if shown >= LAYOUT_CAP {
                println!("  … more spans (use --json for full list)");
                break;
            }
            match span {
                LayoutSpan::Known(hyp) => {
                    let start = hyp.region.offset;
                    let end = hyp.region.end().saturating_sub(1);
                    println!(
                        "  0x{start:06x}–0x{end:06x}  KNOWN    {} ({:.0}%)",
                        hyp.label,
                        hyp.confidence * 100.0
                    );
                }
                LayoutSpan::Unknown(region) => {
                    let start = region.offset;
                    let end = region.end().saturating_sub(1);
                    println!("  0x{start:06x}–0x{end:06x}  UNKNOWN  {} B", region.len);
                }
            }
        }
    }

    // Per-file divergences
    const DIV_CAP: usize = 10;
    println!("\nPER-FILE DIVERGENCES");
    println!("{}", "─".repeat(60));
    for (path_str, divs) in &per_file_divergences {
        let shown_divs: Vec<_> = divs
            .iter()
            .filter(|s| s.confidence >= min_confidence)
            .collect();
        println!("  {path_str}:  {} unique signal(s)", shown_divs.len());
        for sig in shown_divs.iter().take(DIV_CAP) {
            println!(
                "    {}  (not in consensus)",
                format_signal_summary(sig).trim_start()
            );
        }
        if shown_divs.len() > DIV_CAP {
            println!(
                "    … {} more (use --json for full list)",
                shown_divs.len() - DIV_CAP
            );
        }
    }
    println!();
    Ok(())
}

fn cmd_anomaly(
    target: &PathBuf,
    refs: &[PathBuf],
    threshold: f64,
    block_size: usize,
    json: bool,
    min_confidence: f64,
) -> anyhow::Result<()> {
    if refs.len() < 2 {
        anyhow::bail!("anomaly requires at least 2 reference files");
    }

    let mc = corpus::load();

    // Load target.
    let target_entry = load_file_entry(target, block_size, &mc)?
        .ok_or_else(|| anyhow::anyhow!("target file is empty"))?;

    // Load reference files.
    let mut ref_entries: Vec<FileEntry> = Vec::new();
    for path in refs {
        if let Some(entry) = load_file_entry(path, block_size, &mc)? {
            ref_entries.push(entry);
        }
    }
    if ref_entries.len() < 2 {
        anyhow::bail!("anomaly requires at least 2 non-empty reference files");
    }

    let n_refs = ref_entries.len();
    let (consensus_keys, consensus_signals) = build_consensus(&ref_entries, threshold);

    // Build target signal index: (kind_label, offset) → highest-confidence signal.
    let target_index: std::collections::HashMap<(String, usize), Signal> = {
        use std::collections::HashMap;
        let mut index: HashMap<(String, usize), Signal> = HashMap::new();
        for sig in &target_entry.signals {
            let key = (
                hypothesis::signal_kind_label(&sig.kind).to_string(),
                sig.region.offset,
            );
            let keep = index
                .get(&key)
                .is_none_or(|prev| sig.confidence > prev.confidence);
            if keep {
                index.insert(key, sig.clone());
            }
        }
        index
    };

    // Unexpected: in target but not in consensus model.
    let mut unexpected: Vec<Signal> = target_index
        .iter()
        .filter(|(key, _)| !consensus_keys.contains(*key))
        .map(|(_, sig)| sig.clone())
        .collect();
    unexpected.sort_by(|a, b| {
        a.region
            .offset
            .cmp(&b.region.offset)
            .then(b.confidence.partial_cmp(&a.confidence).unwrap())
    });

    // Missing: in all refs (count == n_refs) but absent from target.
    // Build per-ref key counts for "all refs" determination.
    let all_ref_keys: std::collections::HashSet<(String, usize)> = {
        use std::collections::HashMap;
        let mut counts: HashMap<(String, usize), usize> = HashMap::new();
        for entry in &ref_entries {
            let mut seen: std::collections::HashSet<(String, usize)> =
                std::collections::HashSet::new();
            for sig in &entry.signals {
                let key = (
                    hypothesis::signal_kind_label(&sig.kind).to_string(),
                    sig.region.offset,
                );
                if seen.insert(key.clone()) {
                    *counts.entry(key).or_insert(0) += 1;
                }
            }
        }
        counts
            .into_iter()
            .filter(|(_, cnt)| *cnt == n_refs)
            .map(|(k, _)| k)
            .collect()
    };

    // Missing signals: universal in refs, absent from target; use consensus representative.
    let consensus_map: std::collections::HashMap<(String, usize), &Signal> = consensus_signals
        .iter()
        .map(|sig| {
            let key = (
                hypothesis::signal_kind_label(&sig.kind).to_string(),
                sig.region.offset,
            );
            (key, sig)
        })
        .collect();

    let mut missing: Vec<Signal> = all_ref_keys
        .iter()
        .filter(|key| !target_index.contains_key(*key))
        .filter_map(|key| consensus_map.get(key).copied().cloned())
        .collect();
    missing.sort_by(|a, b| {
        a.region
            .offset
            .cmp(&b.region.offset)
            .then(b.confidence.partial_cmp(&a.confidence).unwrap())
    });

    // Apply confidence filter after sorting (preserves sort order).
    unexpected.retain(|s| s.confidence >= min_confidence);
    missing.retain(|s| s.confidence >= min_confidence);

    let anomaly_score = unexpected.len() + missing.len();
    let anomaly_class = match anomaly_score {
        0 => "clean",
        1..=3 => "low",
        4..=9 => "medium",
        _ => "high",
    };

    if json {
        let output = serde_json::json!({
            "target": {
                "path": target_entry.path.display().to_string(),
                "size": target_entry.size,
            },
            "refs": ref_entries.iter().map(|e| serde_json::json!({
                "path": e.path.display().to_string(),
                "size": e.size,
            })).collect::<Vec<_>>(),
            "threshold": threshold,
            "consensus_signals": consensus_signals.len(),
            "anomaly_score": anomaly_score,
            "anomaly_class": anomaly_class,
            "unexpected": &unexpected,
            "missing": &missing,
        });
        println!("{}", serde_json::to_string_pretty(&output)?);
        return Ok(());
    }

    // ── Text output ──────────────────────────────────────────────────────────
    let bar = "═".repeat(60);
    println!("{bar}");
    println!("  tiltshift anomaly  —  {}", target_entry.path.display());
    println!("{bar}");
    println!();
    println!(
        "  Target:  {}   {} bytes",
        target_entry.path.display(),
        target_entry.size
    );
    let threshold_pct = (threshold * 100.0) as u32;
    println!(
        "  Model:   {} reference file(s), threshold {threshold_pct}%, {} consensus signal(s)",
        n_refs,
        consensus_signals.len(),
    );
    println!();
    println!("  Anomaly score:  {anomaly_score}  ({anomaly_class})");

    const UNEXPECTED_CAP: usize = 20;
    println!(
        "\nUNEXPECTED SIGNALS  ({} — in target, not in model)",
        unexpected.len()
    );
    println!("{}", "─".repeat(60));
    if unexpected.is_empty() {
        println!("  (none)");
    } else {
        for sig in unexpected.iter().take(UNEXPECTED_CAP) {
            println!("{}", format_signal_summary(sig));
        }
        if unexpected.len() > UNEXPECTED_CAP {
            println!(
                "  … {} more (use --json for full list)",
                unexpected.len() - UNEXPECTED_CAP
            );
        }
    }

    const MISSING_CAP: usize = 10;
    println!(
        "\nMISSING SIGNALS  ({} — in all {} ref(s), absent from target)",
        missing.len(),
        n_refs,
    );
    println!("{}", "─".repeat(60));
    if missing.is_empty() {
        println!("  (none)");
    } else {
        for sig in missing.iter().take(MISSING_CAP) {
            println!("{}  (expected from model)", format_signal_summary(sig));
        }
        if missing.len() > MISSING_CAP {
            println!(
                "  … {} more (use --json for full list)",
                missing.len() - MISSING_CAP
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

fn print_numeric_sig(sig: &tiltshift::types::Signal, verbose: bool) {
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
    if verbose && !sig.reason.is_empty() {
        println!("            → {}", sig.reason);
    }
}

fn cmd_annotate(
    path: &PathBuf,
    offset_str: &str,
    len_str: &str,
    label: &str,
) -> anyhow::Result<()> {
    let mapped = MappedFile::open(path)?;
    let file_size = mapped.bytes().len();

    let offset = parse_offset(offset_str)
        .ok_or_else(|| anyhow::anyhow!("invalid offset: {offset_str:?}"))?;
    let len =
        parse_offset(len_str).ok_or_else(|| anyhow::anyhow!("invalid length: {len_str:?}"))?;

    if len == 0 {
        anyhow::bail!("annotation length must be greater than zero");
    }
    if offset + len > file_size {
        anyhow::bail!(
            "annotation range 0x{offset:x}+{len} extends past end of file ({file_size} bytes)"
        );
    }

    let mut state = session::load(path)
        .filter(|s| s.file_size == file_size)
        .unwrap_or_else(|| session::SessionState::new(file_size));

    // Replace existing annotation for the same region, or add new.
    state
        .annotations
        .retain(|a| !(a.offset == offset && a.len == len));
    state.annotations.push(session::Annotation {
        offset,
        len,
        label: label.to_string(),
    });

    session::save(path, &state)?;

    let sidecar = session::sidecar_path(path);
    println!("annotated  0x{offset:06x}+{len}  \"{label}\"");
    println!("  saved → {}", sidecar.display());
    Ok(())
}

// ── decode ────────────────────────────────────────────────────────────────────

fn cmd_decode(
    path: &PathBuf,
    offset_str: &str,
    format_name: &str,
    count: usize,
) -> anyhow::Result<()> {
    let offset = parse_offset(offset_str)
        .ok_or_else(|| anyhow::anyhow!("invalid offset: {offset_str:?}"))?;

    let grammar = opcodes::load_grammar(format_name)?;
    let table = grammar.table();

    let mapped = MappedFile::open(path)?;
    let data = mapped.bytes();

    if offset >= data.len() {
        anyhow::bail!(
            "offset 0x{offset:x} is past end of file ({} bytes)",
            data.len()
        );
    }

    let bar = "═".repeat(60);
    println!("{bar}");
    println!(
        "  decode  {}  offset 0x{offset:x}  grammar: {}",
        path.display(),
        grammar.name
    );
    if !grammar.description.is_empty() {
        println!("  {}", grammar.description);
    }
    println!("{bar}");
    println!();

    let mut pos = offset;
    let mut decoded = 0usize;

    while pos < data.len() && decoded < count {
        let opcode_byte = data[pos];

        match table[opcode_byte as usize] {
            Some(entry) => {
                let end = (pos + 1 + entry.operand_bytes as usize).min(data.len());
                let operand_data = &data[pos + 1..end];

                // Format operand bytes as hex.
                let hex_bytes: String = std::iter::once(opcode_byte)
                    .chain(operand_data.iter().copied())
                    .map(|b| format!("{b:02x}"))
                    .collect::<Vec<_>>()
                    .join(" ");

                // Interpret operand as little-endian integer for display.
                let operand_str = match operand_data.len() {
                    0 => String::new(),
                    1 => format!("0x{:02x}", operand_data[0]),
                    2 => format!(
                        "0x{:04x}",
                        u16::from_le_bytes([operand_data[0], operand_data[1]])
                    ),
                    3 => format!(
                        "0x{:06x}",
                        u32::from_le_bytes([operand_data[0], operand_data[1], operand_data[2], 0])
                    ),
                    _ => format!(
                        "0x{:08x}",
                        u32::from_le_bytes([
                            operand_data[0],
                            operand_data[1],
                            operand_data[2],
                            operand_data[3]
                        ])
                    ),
                };

                println!(
                    "  0x{pos:06x}  {hex_bytes:<20}  {:<12}  {operand_str}",
                    entry.mnemonic
                );

                pos += 1 + entry.operand_bytes as usize;
            }
            None => {
                println!(
                    "  0x{pos:06x}  {:02x}                     UNKNOWN",
                    opcode_byte
                );
                pos += 1; // advance one byte and continue
            }
        }
        decoded += 1;
    }

    println!();
    println!("  {decoded} instruction(s) decoded");
    if pos < data.len() && decoded == count {
        println!("  (use --count to see more)");
    }
    Ok(())
}

// ── opcodes ───────────────────────────────────────────────────────────────────

fn cmd_opcodes_add(name: &str, src: &std::path::Path) -> anyhow::Result<()> {
    let dest = opcodes::install_grammar(name, src)?;
    println!("installed grammar {name:?} → {}", dest.display());
    // Load it back to show a summary.
    let grammar = opcodes::load_grammar(name)?;
    println!("  {} opcode(s) defined", grammar.entries.len());
    if !grammar.description.is_empty() {
        println!("  {}", grammar.description);
    }
    Ok(())
}

fn cmd_opcodes_list() -> anyhow::Result<()> {
    let grammars = opcodes::list_grammars()?;
    if grammars.is_empty() {
        println!("No opcode grammars installed.");
        println!();
        println!("Install one with:");
        println!("  tiltshift opcodes add <name> <grammar.toml>");
        return Ok(());
    }
    let bar = "═".repeat(60);
    println!("{bar}");
    println!("  Installed opcode grammars");
    println!("{bar}");
    for g in &grammars {
        let desc = if g.description.is_empty() {
            String::new()
        } else {
            format!("  — {}", g.description)
        };
        println!("  {:<20}  {} opcode(s){desc}", g.name, g.entries.len());
    }
    println!();
    println!(
        "  stored at: {}",
        opcodes::grammar_dir()
            .map(|d| d.display().to_string())
            .unwrap_or_else(|| "(unknown)".to_string())
    );
    Ok(())
}

// ── cluster ───────────────────────────────────────────────────────────────────

fn cmd_cluster(
    paths: &[PathBuf],
    min_cluster_size: usize,
    block_size: usize,
    show_features: bool,
) -> anyhow::Result<()> {
    if paths.is_empty() {
        anyhow::bail!("no files provided");
    }
    if paths.len() < 2 {
        anyhow::bail!("need at least 2 files to cluster");
    }

    let corpus = corpus::load();

    // Extract feature vector for each file, using a lightweight feature cache.
    // We deliberately avoid loading the full signal session cache here — for
    // large uncompressed files it can be hundreds of MB, causing OOM when many
    // files are processed together.
    let entries: Vec<(PathBuf, Vec<f32>)> = paths
        .iter()
        .map(|path| {
            let mapped = MappedFile::open(path)?;
            let data = mapped.bytes();
            let file_size = data.len() as u64;

            // Fast path: feature cache hit.
            if let Some(feat) = cluster::load_feature_cache(path, file_size) {
                return Ok((path.clone(), feat));
            }

            // Slow path: extract signals, compute features, persist lightweight cache.
            // Cap the sample to the first 4 MB so large files (e.g. 180 MB bundles)
            // don't spend minutes in compress.rs / bytecode.rs — the feature vector
            // is a summary statistic and a prefix sample is accurate enough.
            const CLUSTER_SAMPLE_BYTES: usize = 4 * 1024 * 1024;
            let sample = if data.len() > CLUSTER_SAMPLE_BYTES {
                &data[..CLUSTER_SAMPLE_BYTES]
            } else {
                data
            };
            let sigs = signals::extract_all(sample, block_size, &corpus);
            let feat = cluster::extract_features(&sigs);
            cluster::save_feature_cache(path, file_size, &feat);

            Ok((path.clone(), feat))
        })
        .collect::<anyhow::Result<_>>()?;

    let feature_matrix: Vec<Vec<f32>> = entries.iter().map(|(_, f)| f.clone()).collect();

    // HDBSCAN panics if n < min_cluster_size in the parallel implementation.
    if feature_matrix.len() < min_cluster_size {
        anyhow::bail!(
            "need at least {} files to cluster (got {}); try --min-cluster-size {}",
            min_cluster_size,
            feature_matrix.len(),
            feature_matrix.len() / 2 + 1,
        );
    }

    let hp = HdbscanHyperParams::builder()
        .min_cluster_size(min_cluster_size)
        .build();
    let labels = Hdbscan::new(&feature_matrix, hp)
        .cluster_par()
        .map_err(|e| anyhow::anyhow!("HDBSCAN failed: {e:?}"))?;

    // Group files by cluster label.
    let mut clusters: std::collections::BTreeMap<i32, Vec<&PathBuf>> =
        std::collections::BTreeMap::new();
    for (i, label) in labels.iter().enumerate() {
        clusters.entry(*label).or_default().push(&entries[i].0);
    }

    let bar = "═".repeat(60);
    println!("{bar}");
    println!("  tiltshift cluster  ({} files)", paths.len());
    println!("{bar}");

    // Noise first, then numbered clusters.
    if let Some(noise) = clusters.get(&-1) {
        println!();
        println!("  NOISE  ({} file(s) — no cluster)", noise.len());
        for p in noise {
            println!("    {}", p.display());
        }
    }

    let cluster_labels: Vec<i32> = clusters.keys().filter(|&&k| k >= 0).copied().collect();
    for label in &cluster_labels {
        let members = &clusters[label];

        // Compute mean feature vector for the cluster.
        let dim = cluster::FEATURE_NAMES.len();
        let mut mean = vec![0.0f32; dim];
        for p in members.iter() {
            let feat = entries.iter().find(|(pp, _)| pp == *p).map(|(_, f)| f);
            if let Some(f) = feat {
                for (d, v) in f.iter().enumerate() {
                    mean[d] += v;
                }
            }
        }
        for v in &mut mean {
            *v /= members.len() as f32;
        }

        println!();
        println!(
            "  CLUSTER {}  ({} file(s)) — {}",
            label,
            members.len(),
            cluster::describe_cluster(&mean)
        );
        for p in members {
            println!("    {}", p.display());
            if show_features {
                let feat = entries.iter().find(|(pp, _)| pp == *p).map(|(_, f)| f);
                if let Some(f) = feat {
                    let fstr: Vec<String> = cluster::FEATURE_NAMES
                        .iter()
                        .zip(f.iter())
                        .map(|(name, v)| format!("{name}={v:.2}"))
                        .collect();
                    println!("      [{}]", fstr.join("  "));
                }
            }
        }
    }

    println!();
    println!(
        "  {} cluster(s), {} noise",
        cluster_labels.len(),
        clusters.get(&-1).map_or(0, |v| v.len())
    );

    Ok(())
}

// ── entropy bar ──────────────────────────────────────────────────────────────

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
