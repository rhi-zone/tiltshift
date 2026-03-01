use clap::{Parser, Subcommand};
use std::path::PathBuf;
use tiltshift::{
    loader::MappedFile,
    signals,
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
}

fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();
    match cli.command {
        Command::Analyze {
            file,
            block_size,
            json,
        } => cmd_analyze(&file, block_size, json),
    }
}

fn cmd_analyze(path: &PathBuf, block_size: usize, json: bool) -> anyhow::Result<()> {
    let mapped = MappedFile::open(path)?;
    let data = mapped.bytes();
    let file_name = path.display();
    let file_size = data.len();

    let all_signals = signals::extract_all(data, block_size);

    if json {
        println!("{}", serde_json::to_string_pretty(&all_signals)?);
        return Ok(());
    }

    // ── Header ───────────────────────────────────────────────────────────────
    let bar = "═".repeat(60);
    println!("{bar}");
    println!("  tiltshift  {file_name}  ({file_size} bytes)");
    println!("{bar}");

    // ── Magic bytes ──────────────────────────────────────────────────────────
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

    // ── Strings ──────────────────────────────────────────────────────────────
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

    // ── Entropy map ──────────────────────────────────────────────────────────
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

    // ── Summary ──────────────────────────────────────────────────────────────
    println!("\nSUMMARY");
    println!("{}", "─".repeat(60));
    println!("  {} magic byte match(es)", magic.len());
    println!("  {} null-terminated string(s)", strings.len());
    println!("  {} entropy block(s)", entropy_blocks.len());

    let high_entropy = entropy_blocks.iter().filter(|s| {
        matches!(&s.kind, SignalKind::EntropyBlock { class, .. }
            if *class == EntropyClass::HighlyRandom || *class == EntropyClass::Compressed)
    });
    let high_entropy_bytes: usize = high_entropy.map(|s| s.region.len).sum();
    let pct = if file_size > 0 {
        high_entropy_bytes * 100 / file_size
    } else {
        0
    };
    println!("  ~{pct}% of file is compressed/high-entropy");

    println!();
    Ok(())
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
