//! Bytecode stream signal — format-agnostic, self-consistency-based detection.
//!
//! ## Laws (never violate)
//!
//! 1. **No format knowledge.** Zero hardcoded names (x86, JVM, WASM, etc.).
//! 2. **Self-consistency is the only oracle:** decode_coverage + jump_target_validity.
//! 3. **LEB128 defers to VarInt signal** — noted as a hint, not reimplemented here.
//! 4. **Grammar files are outputs** of human verification, never read here.
//!
//! ## Algorithm
//!
//! **Phase 1 — fixed-width scan O(n)**
//! For W in {1, 2, 3, 4, 8}: partition bytes at entry_point into opcode
//! positions (every W bytes) and operand positions.  Score =
//! H(operand_bytes) − H(opcode_bytes).  If the best score > 0.5 bits, that W
//! is a candidate fixed width.  The score is retained as `entropy_sep_norm`
//! (capped at 4 bits → 0.0–1.0) and contributes to confidence directly.
//!
//! **Phase 2 — variable-width bootstrap**
//! Walk from entry_point treating each byte as an opcode.  For unknown opcodes
//! try operand widths 0–4 and take the one that lets the subsequent decode run
//! longest (greedy).  Repeat until coverage delta < 0.01.
//!
//! **Phase 3 — jump target validation**
//! Collect 1–4 byte little-endian operand values within region bounds; count
//! those that land on an instruction boundary.
//!
//! **Frequency analysis**
//! After Phase 2, build a frequency histogram of opcode bytes at instruction
//! boundaries.  Two metrics are derived:
//!
//! - `distinct_opcodes` — number of unique opcode bytes seen (display only).
//! - `top5_dominance` — fraction of all instructions using the 5 most common
//!   opcodes.  Real instruction sets are heavily skewed (common instructions
//!   like load/push/return dominate); greedy-decoded random data spreads
//!   uniformly across many opcodes.  A cyclic stream decoded with greedy
//!   width=4 produces ~102 equally-frequent opcodes → top-5 dominance ≈ 5%.
//!   A 3-opcode synthetic stream → top-5 dominance = 100%.  This term cannot
//!   be gamed by the greedy bootstrap the way `distinct/256` can.

use crate::types::{Region, Signal, SignalKind};

/// Minimum instructions required to emit a signal.
const MIN_INSTRUCTIONS: usize = 16;
/// Minimum decode coverage to emit a signal at all.
const MIN_COVERAGE: f64 = 0.60;
/// Minimum confidence at entry_point=0 (unanchored).
const MIN_CONF_UNANCHORED: f64 = 0.60;
/// Minimum confidence when entry_point is provided externally.
const MIN_CONF_ANCHORED: f64 = 0.45;
/// Minimum data length (bytes) before running the detector.
const MIN_DATA_LEN: usize = 32;
/// Minimum entropy separation (bits) between opcode and operand positions
/// to declare a fixed-width winner.
const FIXED_WIDTH_THRESHOLD: f64 = 0.5;
/// Minimum fraction of all decoded instructions that must use the top-5 most
/// common opcodes.  Real instruction sets are always skewed (a handful of
/// common instructions dominate); random or periodic data decoded with the
/// greedy bootstrap spreads instructions across many opcodes → top-5 ≤ 5–16%.
/// This gate is the primary defence against false positives.
const MIN_TOP5_DOMINANCE: f64 = 0.20;

// ── Shannon entropy helper ────────────────────────────────────────────────────

fn shannon_entropy(freq: &[u32]) -> f64 {
    let total: u32 = freq.iter().sum();
    if total == 0 {
        return 0.0;
    }
    let total_f = total as f64;
    freq.iter()
        .filter(|&&c| c > 0)
        .map(|&c| {
            let p = c as f64 / total_f;
            -p * p.log2()
        })
        .sum()
}

// ── Phase 1: fixed-width scan ─────────────────────────────────────────────────

/// For each candidate width W, compute H(operands) − H(opcodes).
/// Returns the best (width, score) pair, or None if no candidate clears the
/// threshold.
fn best_fixed_width(data: &[u8], entry: usize) -> Option<(usize, f64)> {
    let candidates = [1usize, 2, 3, 4, 8];
    let mut best: Option<(usize, f64)> = None;

    for &w in &candidates {
        if data.len() < entry + w * 4 {
            continue;
        }
        let mut opcode_freq = vec![0u32; 256];
        let mut operand_freq = vec![0u32; 256];

        let mut pos = entry;
        while pos + w <= data.len() {
            opcode_freq[data[pos] as usize] += 1;
            for &b in &data[pos + 1..pos + w] {
                operand_freq[b as usize] += 1;
            }
            pos += w;
        }

        let h_op = shannon_entropy(&opcode_freq);
        let h_operand = if w == 1 {
            // No operand bytes — use 0 so we only emit on separation evidence.
            0.0
        } else {
            shannon_entropy(&operand_freq)
        };
        let score = h_operand - h_op;

        if score > FIXED_WIDTH_THRESHOLD && best.is_none_or(|(_, best_score)| score > best_score) {
            best = Some((w, score));
        }
    }

    best
}

// ── Phase 2: variable-width bootstrap ────────────────────────────────────────

/// Try decoding from `entry` using the known `grammar` (opcode → operand_bytes).
/// For unknown opcodes, try widths 0–4 greedily (take the one that extends the
/// run furthest).
///
/// Returns `(instruction_boundaries, opcode_widths_discovered)`.
fn variable_width_decode(
    data: &[u8],
    entry: usize,
    grammar: &[Option<u8>; 256],
) -> (Vec<usize>, Vec<(u8, u8)>) {
    let mut boundaries: Vec<usize> = Vec::new();
    let mut discovered: Vec<(u8, u8)> = Vec::new();
    let mut pos = entry;

    while pos < data.len() {
        boundaries.push(pos);
        let opcode = data[pos];
        let operand_bytes: u8 = if let Some(w) = grammar[opcode as usize] {
            w
        } else {
            // Greedy: try each width and pick the one that lets us go furthest.
            let best_w = (0u8..=4).max_by_key(|&k| {
                let next = pos + 1 + k as usize;
                if next > data.len() {
                    return 0usize;
                }
                // Look ahead: how many consecutive already-known instructions
                // can we decode from `next`?
                let mut lookahead = next;
                let mut count = 0usize;
                while lookahead < data.len() && count < 8 {
                    let op2 = data[lookahead];
                    if let Some(w2) = grammar[op2 as usize] {
                        lookahead += 1 + w2 as usize;
                        count += 1;
                    } else {
                        break;
                    }
                }
                count
            });
            let best_w = best_w.unwrap_or(0);
            discovered.push((opcode, best_w));
            best_w
        };

        let next = pos + 1 + operand_bytes as usize;
        if next > data.len() {
            break;
        }
        pos = next;
    }

    (boundaries, discovered)
}

// ── Phase 3: jump target validation ──────────────────────────────────────────

/// For each decoded instruction with ≥ 1 operand bytes, interpret the operand
/// as a little-endian offset (1–4 bytes).  Count how many candidate targets
/// are within data bounds AND land on a known instruction boundary.
fn jump_validity(data: &[u8], boundaries: &[usize], grammar: &[Option<u8>; 256]) -> Option<f64> {
    let boundary_set: std::collections::HashSet<usize> = boundaries.iter().copied().collect();

    let mut total = 0usize;
    let mut hits = 0usize;

    for &pos in boundaries {
        if pos >= data.len() {
            continue;
        }
        let opcode = data[pos];
        let operand_bytes = match grammar[opcode as usize] {
            Some(w) if w >= 1 => w,
            _ => continue,
        };
        let end = pos + 1 + operand_bytes as usize;
        if end > data.len() {
            continue;
        }

        // Read up to 4 operand bytes as little-endian u32.
        let n = (operand_bytes as usize).min(4);
        let mut val = 0u32;
        for k in 0..n {
            val |= (data[pos + 1 + k] as u32) << (k * 8);
        }
        let target = val as usize;
        if target < data.len() {
            total += 1;
            if boundary_set.contains(&target) {
                hits += 1;
            }
        }
    }

    if total == 0 {
        None
    } else {
        Some(hits as f64 / total as f64)
    }
}

// ── Main scanner ─────────────────────────────────────────────────────────────

/// Scan `data` for bytecode-like instruction streams.
///
/// `entry_point` is the byte offset (relative to `data`) to start decoding.
/// Pass 0 for unanchored detection (higher emit threshold applies).
pub fn scan_bytecode(data: &[u8], entry_point: usize) -> Vec<Signal> {
    if data.len() < MIN_DATA_LEN || entry_point >= data.len() {
        return vec![];
    }

    let anchored = entry_point > 0;
    let min_conf = if anchored {
        MIN_CONF_ANCHORED
    } else {
        MIN_CONF_UNANCHORED
    };

    // ── Phase 1: fixed-width candidate ───────────────────────────────────────
    let fixed_result = best_fixed_width(data, entry_point);
    let fixed_width = fixed_result.map(|(w, _)| w);
    // Normalise the separation score to [0.0, 1.0]; 4 bits is already strong.
    let entropy_sep_norm = fixed_result
        .map(|(_, score)| (score / 4.0).min(1.0))
        .unwrap_or(0.0);

    // Build initial grammar from fixed-width discovery.
    let mut grammar = [None::<u8>; 256];
    if let Some(w) = fixed_width {
        // Every opcode is assumed to have (w-1) operand bytes.
        let operand_bytes = (w as u8).saturating_sub(1);
        for op in 0u8..=255 {
            grammar[op as usize] = Some(operand_bytes);
        }
    }

    // ── Phase 2: variable-width bootstrap (up to 3 passes) ───────────────────
    let mut all_boundaries: Vec<usize> = Vec::new();
    let mut all_opcode_widths: Vec<(u8, u8)> = Vec::new();

    let mut prev_coverage = 0.0f64;
    for _pass in 0..3 {
        let (boundaries, discovered) = variable_width_decode(data, entry_point, &grammar);

        // Merge discovered widths into grammar (first-seen wins).
        for (op, w) in &discovered {
            if grammar[*op as usize].is_none() {
                grammar[*op as usize] = Some(*w);
                all_opcode_widths.push((*op, *w));
            }
        }

        all_boundaries = boundaries;

        let covered_bytes: usize = all_boundaries
            .iter()
            .map(|&pos| {
                let op = data[pos];
                1 + grammar[op as usize].unwrap_or(0) as usize
            })
            .sum();

        let coverage = covered_bytes as f64 / data.len() as f64;
        if coverage - prev_coverage < 0.01 {
            break;
        }
        prev_coverage = coverage;
    }

    // ── Compute final metrics ─────────────────────────────────────────────────
    let instruction_count = all_boundaries.len();
    if instruction_count < MIN_INSTRUCTIONS {
        return vec![];
    }

    // Recalculate decode_coverage properly (no overflows).
    let covered_bytes: usize = all_boundaries
        .iter()
        .map(|&pos| {
            if pos >= data.len() {
                return 0;
            }
            let op = data[pos];
            let w = 1 + grammar[op as usize].unwrap_or(0) as usize;
            if pos + w > data.len() {
                0
            } else {
                w
            }
        })
        .sum();
    let decode_coverage = covered_bytes as f64 / data.len() as f64;

    if decode_coverage < MIN_COVERAGE {
        return vec![];
    }

    // ── Phase 3: jump target validation ──────────────────────────────────────
    let jump_val = jump_validity(data, &all_boundaries, &grammar);

    // ── Frequency analysis: top-5 opcode dominance ───────────────────────────
    // Build a frequency histogram of opcode bytes at instruction boundaries,
    // then compute what fraction of all instructions use the top-5 opcodes.
    let mut opcode_freq = [0u32; 256];
    for &pos in &all_boundaries {
        if pos < data.len() {
            opcode_freq[data[pos] as usize] += 1;
        }
    }
    let total_instructions = instruction_count as u32;
    let mut freq_sorted: Vec<u32> = opcode_freq.iter().copied().filter(|&f| f > 0).collect();
    freq_sorted.sort_unstable_by(|a, b| b.cmp(a));
    let distinct_opcodes = freq_sorted.len();
    let top5_count: u32 = freq_sorted.iter().take(5).sum();
    let top5_dominance = if total_instructions > 0 {
        top5_count as f64 / total_instructions as f64
    } else {
        0.0
    };

    // Hard gate: random and periodic data decoded with greedy width=4 bootstrap
    // spread instructions across many opcodes → top-5 ≤ ~16%.  Real instruction
    // sets always exceed 20% because a small number of common instructions
    // (load, push, return, branch, …) dominate any real program.
    if top5_dominance < MIN_TOP5_DOMINANCE {
        return vec![];
    }

    // ── Confidence ───────────────────────────────────────────────────────────
    // Weights: coverage 0.55, jump_validity 0.15, entropy_sep 0.15,
    //          top5_dominance 0.15.
    // Greedy-decoded random data: top-5 opcodes ≈ 5% → dominance ≈ 0.05,
    // sep = 0, coverage ≈ 1.0 → conf ≈ 0.55 + 0.008 = 0.558 < threshold 0.60.
    let confidence = decode_coverage * 0.55
        + jump_val.unwrap_or(0.0) * 0.15
        + entropy_sep_norm * 0.15
        + top5_dominance * 0.15;

    if confidence < min_conf {
        return vec![];
    }

    // ── Build opcode_widths summary (up to 16, sorted) ───────────────────────
    all_opcode_widths.sort_by_key(|(op, _)| *op);
    all_opcode_widths.dedup_by_key(|(op, _)| *op);
    all_opcode_widths.truncate(16);

    // If we used a fixed-width grammar from phase 1, populate opcode_widths
    // with a representative sample of observed opcodes.
    let opcode_widths: Vec<(u8, u8)> =
        if let (true, Some(w)) = (all_opcode_widths.is_empty(), fixed_width) {
            let operand_bytes = (w as u8).saturating_sub(1);
            // Collect unique opcodes seen at stride positions.
            let mut seen: Vec<u8> = Vec::new();
            let mut pos = entry_point;
            while pos + w <= data.len() && seen.len() < 16 {
                let op = data[pos];
                if !seen.contains(&op) {
                    seen.push(op);
                }
                pos += w;
            }
            seen.iter().map(|&op| (op, operand_bytes)).collect()
        } else {
            all_opcode_widths
        };

    let reason = {
        let fw_part = fixed_width
            .map(|w| format!("fixed-width W={w}; "))
            .unwrap_or_default();
        let jv_part = jump_val
            .map(|j| format!("jump validity {:.0}%; ", j * 100.0))
            .unwrap_or_else(|| "no jump targets; ".to_string());
        format!(
            "{fw_part}{instruction_count} instructions decoded from offset {entry_point}; \
             coverage {:.0}%; {jv_part}\
             {distinct_opcodes} distinct opcodes (top-5 dominance {:.0}%); \
             entropy sep {:.2} bits; confidence {:.0}%",
            decode_coverage * 100.0,
            top5_dominance * 100.0,
            entropy_sep_norm * 4.0,
            confidence * 100.0
        )
    };

    vec![Signal::new(
        Region::new(entry_point, data.len() - entry_point),
        SignalKind::BytecodeStream {
            entry_point,
            decode_coverage,
            jump_validity: jump_val,
            instruction_count,
            fixed_width,
            opcode_widths,
        },
        confidence,
        reason,
    )]
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    /// Build a synthetic W=2 stream: opcode byte drawn from a small set (0x10,
    /// 0x20, 0x30), followed by one operand byte (0x00–0xFF).
    fn make_fixed2_stream(len_instructions: usize) -> Vec<u8> {
        let opcodes = [0x10u8, 0x20, 0x30];
        let mut data = Vec::with_capacity(len_instructions * 2);
        for i in 0..len_instructions {
            data.push(opcodes[i % 3]);
            data.push((i * 7 % 256) as u8);
        }
        data
    }

    #[test]
    fn fixed_width_2_detected() {
        let data = make_fixed2_stream(40); // 40 instructions × 2 bytes = 80 bytes
        let sigs = scan_bytecode(&data, 0);
        assert!(
            !sigs.is_empty(),
            "expected BytecodeStream signal for W=2 data"
        );
        let SignalKind::BytecodeStream {
            fixed_width,
            instruction_count,
            decode_coverage,
            ..
        } = &sigs[0].kind
        else {
            panic!("wrong kind")
        };
        // Phase 1 should discover W=2 (opcodes cluster, operands spread).
        assert_eq!(*fixed_width, Some(2), "fixed_width should be Some(2)");
        assert!(*instruction_count >= 16, "too few instructions");
        assert!(*decode_coverage >= 0.60, "coverage too low");
    }

    /// LCG pseudo-random sequence — approximates independently sampled bytes.
    fn make_pseudorandom(n: usize) -> Vec<u8> {
        let mut x: u64 = 0x123456789ABCDE;
        (0..n)
            .map(|_| {
                x = x
                    .wrapping_mul(6_364_136_223_846_793_005)
                    .wrapping_add(1_442_695_040_888_963_407);
                (x >> 33) as u8
            })
            .collect()
    }

    #[test]
    fn pseudorandom_data_does_not_emit() {
        // LCG bytes spread instructions across many opcodes → top-5 dominance
        // well below MIN_TOP5_DOMINANCE (0.20) → hard gate rejects it.
        let data = make_pseudorandom(512);
        let sigs = scan_bytecode(&data, 0);
        assert!(
            sigs.is_empty(),
            "pseudo-random data should not emit (conf={:.3})",
            sigs.first().map_or(0.0, |s| s.confidence)
        );
    }

    #[test]
    fn cyclic_data_does_not_emit() {
        // 0x00–0xFF repeated: periodic structure may win a fixed-width slot, but
        // the instruction distribution is still spread → top-5 dominance low.
        let data: Vec<u8> = (0u8..=255).cycle().take(512).collect();
        let sigs = scan_bytecode(&data, 0);
        assert!(
            sigs.is_empty(),
            "cyclic 0-255 stream should not emit (conf={:.3})",
            sigs.first().map_or(0.0, |s| s.confidence)
        );
    }

    #[test]
    fn fixed_width_2_has_high_concentration() {
        // Only 3 distinct opcodes used → concentration ≈ 0.99; should lift confidence.
        let data = make_fixed2_stream(40);
        let sigs = scan_bytecode(&data, 0);
        assert!(!sigs.is_empty());
        // With 3 opcodes and varied operands, confidence should be well above threshold.
        assert!(
            sigs[0].confidence >= 0.70,
            "confidence should be ≥ 0.70 with high concentration, got {:.3}",
            sigs[0].confidence
        );
    }

    #[test]
    fn too_short_returns_empty() {
        let data = vec![0x10u8; 10];
        let sigs = scan_bytecode(&data, 0);
        assert!(sigs.is_empty(), "should not emit on too-short data");
    }

    #[test]
    fn variable_width_simple_vm() {
        // Construct a 3-opcode VM:
        //   0x01 — PUSH u8    (1 operand)
        //   0x02 — ADD        (0 operands)
        //   0x03 — JMP u16    (2 operands)
        let mut data: Vec<u8> = Vec::new();
        for i in 0..20 {
            match i % 3 {
                0 => {
                    data.push(0x01);
                    data.push((i * 13 % 256) as u8);
                }
                1 => {
                    data.push(0x02);
                }
                _ => {
                    data.push(0x03);
                    data.push((i * 5 % 256) as u8);
                    data.push((i * 3 % 256) as u8);
                }
            }
        }
        let sigs = scan_bytecode(&data, 0);
        // Variable-width VM with 20 instructions: may or may not exceed threshold
        // depending on coverage — just check it doesn't panic and emits at most 1 signal.
        assert!(sigs.len() <= 1);
        if !sigs.is_empty() {
            assert!(matches!(sigs[0].kind, SignalKind::BytecodeStream { .. }));
        }
    }
}
