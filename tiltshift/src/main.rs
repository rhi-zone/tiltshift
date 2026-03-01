use clap::{Parser, Subcommand};
use std::path::PathBuf;
use tiltshift::{
    corpus,
    loader::MappedFile,
    probe, signals,
    signals::{chunk::sequence_label, length_prefix::body_preview},
    types::{EntropyClass, SignalKind},
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
        } => cmd_analyze(&file, block_size, json),
        Command::Probe { file, offset, len } => cmd_probe(&file, &offset, len),
        Command::Magic { action } => match action {
            MagicAction::Add { name, magic } => cmd_magic_add(&name, &magic),
            MagicAction::List { filter } => cmd_magic_list(filter.as_deref()),
        },
    }
}

fn cmd_analyze(path: &PathBuf, block_size: usize, json: bool) -> anyhow::Result<()> {
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
    println!("  {} repeating stride pattern(s)", stride_sigs.len());
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

/// Parse a decimal or 0x-prefixed hex string into a usize offset.
fn parse_offset(s: &str) -> Option<usize> {
    let s = s.trim();
    if let Some(hex) = s.strip_prefix("0x").or_else(|| s.strip_prefix("0X")) {
        usize::from_str_radix(hex, 16).ok()
    } else {
        s.parse::<usize>().ok()
    }
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
