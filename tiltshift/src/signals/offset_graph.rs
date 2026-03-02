use std::collections::HashMap;

use crate::types::{Region, Signal, SignalKind};

/// Minimum file size to attempt offset-graph detection.
const MIN_FILE_SIZE: usize = 16;

/// Skip u16 scans for files larger than this — almost every u16 value is
/// within bounds for large files, making the scan uninformative.
const U16_MAX_FILE_SIZE: usize = 32_768;

// ── Union-Find ───────────────────────────────────────────────────────────────

struct UnionFind {
    parent: HashMap<usize, usize>,
}

impl UnionFind {
    fn new() -> Self {
        Self {
            parent: HashMap::new(),
        }
    }

    fn find(&mut self, x: usize) -> usize {
        // Ensure x is registered.
        self.parent.entry(x).or_insert(x);

        // Walk to root.
        let mut root = x;
        loop {
            let p = *self.parent.get(&root).unwrap();
            if p == root {
                break;
            }
            root = p;
        }

        // Path compression.
        let mut curr = x;
        loop {
            let p = *self.parent.get(&curr).unwrap();
            if p == root {
                break;
            }
            self.parent.insert(curr, root);
            curr = p;
        }

        root
    }

    fn union(&mut self, a: usize, b: usize) {
        let ra = self.find(a);
        let rb = self.find(b);
        if ra != rb {
            self.parent.insert(ra, rb);
        }
    }
}

// ── Helpers ──────────────────────────────────────────────────────────────────

fn read_uint(data: &[u8], pos: usize, width: usize, little_endian: bool) -> Option<usize> {
    if pos + width > data.len() {
        return None;
    }
    let s = &data[pos..pos + width];
    let v: u64 = match (width, little_endian) {
        (2, true) => u16::from_le_bytes([s[0], s[1]]) as u64,
        (2, false) => u16::from_be_bytes([s[0], s[1]]) as u64,
        (4, true) => u32::from_le_bytes([s[0], s[1], s[2], s[3]]) as u64,
        (4, false) => u32::from_be_bytes([s[0], s[1], s[2], s[3]]) as u64,
        (8, true) => u64::from_le_bytes([s[0], s[1], s[2], s[3], s[4], s[5], s[6], s[7]]),
        (8, false) => u64::from_be_bytes([s[0], s[1], s[2], s[3], s[4], s[5], s[6], s[7]]),
        _ => return None,
    };
    usize::try_from(v).ok()
}

// ── Per-width scan ────────────────────────────────────────────────────────────

fn scan_width(data: &[u8], width: usize, little_endian: bool) -> Option<Signal> {
    let file_size = data.len();

    if width == 2 && file_size > U16_MAX_FILE_SIZE {
        return None;
    }

    let min_threshold: usize = match width {
        2 => 5,
        4 => 4,
        8 => 2,
        _ => return None,
    };

    let total_positions = file_size / width;
    if total_positions == 0 {
        return None;
    }

    // Bail out early if density exceeds 50%.  High density means the file
    // is large enough that many arbitrary values happen to land within
    // bounds — the signal would be noise and we'd penalise it anyway.
    // Checking mid-scan avoids ever building the expensive union-find for
    // the noisy case.
    let max_candidates = total_positions / 2;

    let mut uf = UnionFind::new();
    let mut edges: Vec<(usize, usize)> = Vec::new();
    let mut candidate_count = 0usize;

    for i in 0..total_positions {
        let pos = i * width;
        let Some(value) = read_uint(data, pos, width, little_endian) else {
            continue;
        };
        // value must point past itself, be within file bounds, and not be
        // a self-loop.
        if value >= width && value < file_size && value != pos {
            candidate_count += 1;
            if candidate_count > max_candidates {
                // density > 50% — bail before building the full UF structure.
                return None;
            }
            uf.union(pos, value);
            edges.push((pos, value));
        }
    }

    if candidate_count == 0 {
        return None;
    }

    // Collect every node that appears in at least one edge.
    let mut all_nodes: Vec<usize> = edges.iter().flat_map(|&(src, dst)| [src, dst]).collect();
    all_nodes.sort_unstable();
    all_nodes.dedup();

    // Build a stable node → root map (also finalises all path compression).
    let node_to_root: HashMap<usize, usize> = all_nodes.iter().map(|&n| (n, uf.find(n))).collect();

    // Count nodes per component root.
    let mut component_node_counts: HashMap<usize, usize> = HashMap::new();
    for &root in node_to_root.values() {
        *component_node_counts.entry(root).or_insert(0) += 1;
    }

    let (&best_root, &component_nodes) = component_node_counts
        .iter()
        .max_by_key(|(_, &count)| count)?;

    if component_nodes < min_threshold {
        return None;
    }

    let component_edges = edges
        .iter()
        .filter(|&&(src, _)| node_to_root.get(&src) == Some(&best_root))
        .count();

    let sample_edges: Vec<(usize, usize)> = edges
        .iter()
        .filter(|&&(src, _)| node_to_root.get(&src) == Some(&best_root))
        .take(8)
        .copied()
        .collect();

    let density = candidate_count as f64 / total_positions as f64;
    let size_boost = 0.20 * ((component_nodes - min_threshold) as f64 / 10.0).min(1.0);
    let confidence = (0.50 + size_boost).clamp(0.0, 0.85);

    let endian_str = if little_endian { "le" } else { "be" };
    let reason = format!(
        "u{}{}: {} nodes in largest component ({} candidates, density {:.1}%)",
        width * 8,
        endian_str,
        component_nodes,
        candidate_count,
        density * 100.0,
    );

    Some(Signal::new(
        Region::new(0, file_size),
        SignalKind::OffsetGraph {
            pointer_width: width as u8,
            little_endian,
            candidate_count,
            component_nodes,
            component_edges,
            pointer_density: density,
            sample_edges,
        },
        confidence,
        reason,
    ))
}

// ── Public entry point ────────────────────────────────────────────────────────

/// Scan for pointer/offset graphs: detect u16/u32/u64 values (LE and BE) that
/// form a directed graph of within-bounds offsets large enough to be
/// non-coincidental.
///
/// At most one signal is emitted per `(width, endian)` pair.
pub fn scan_offset_graph(data: &[u8]) -> Vec<Signal> {
    if data.len() < MIN_FILE_SIZE {
        return vec![];
    }

    let mut signals = Vec::new();
    for &width in &[2usize, 4, 8] {
        for &le in &[true, false] {
            if let Some(sig) = scan_width(data, width, le) {
                signals.push(sig);
            }
        }
    }
    signals
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    // ── Helpers ──────────────────────────────────────────────────────────────

    fn le32(v: u32) -> [u8; 4] {
        v.to_le_bytes()
    }

    fn le64(v: u64) -> [u8; 8] {
        v.to_le_bytes()
    }

    // ── Test 1: synthetic u32le offset chain ─────────────────────────────────

    /// A header with a chain of 4 u32le pointers each referencing the next
    /// pointer position forms a connected component: {0, 16, 32, 48, 64}.
    /// component_nodes = 5 ≥ 4 (u32 threshold) → signal emitted.
    #[test]
    fn synthetic_u32le_offset_chain_emits_signal() {
        // File layout (256 bytes):
        //   pos 0  : u32le = 16
        //   pos 16 : u32le = 32
        //   pos 32 : u32le = 48
        //   pos 48 : u32le = 64
        //   rest   : zeros (u32le = 0, which is < width=4, no edge)
        let mut data = vec![0u8; 256];
        data[0..4].copy_from_slice(&le32(16));
        data[16..20].copy_from_slice(&le32(32));
        data[32..36].copy_from_slice(&le32(48));
        data[48..52].copy_from_slice(&le32(64));

        let sigs = scan_offset_graph(&data);
        let og = sigs
            .iter()
            .find(|s| {
                matches!(
                    &s.kind,
                    SignalKind::OffsetGraph {
                        pointer_width: 4,
                        little_endian: true,
                        ..
                    }
                )
            })
            .expect("expected u32le offset-graph signal");

        let SignalKind::OffsetGraph {
            component_nodes, ..
        } = &og.kind
        else {
            unreachable!()
        };
        assert!(
            *component_nodes >= 4,
            "component_nodes={component_nodes}, expected ≥ 4"
        );
    }

    // ── Test 2: no within-bounds candidates → no signal ──────────────────────

    /// When all u32 values exceed file_size, no candidates exist → no signal.
    #[test]
    fn no_within_bounds_values_no_signal() {
        // 64 bytes, all 0xFF → u32le = 0xFFFFFFFF >> 64, not within bounds.
        let data = vec![0xFFu8; 64];
        let sigs = scan_offset_graph(&data);
        assert!(
            !sigs.iter().any(|s| matches!(
                &s.kind,
                SignalKind::OffsetGraph {
                    pointer_width: 4,
                    ..
                }
            )),
            "expected no u32 offset-graph signal for out-of-bounds data"
        );
    }

    // ── Test 3: short file → no signal ───────────────────────────────────────

    #[test]
    fn short_file_no_signal() {
        let data = vec![0x10u8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00];
        assert!(
            scan_offset_graph(&data).is_empty(),
            "file below MIN_FILE_SIZE should produce no signals"
        );
    }

    // ── Test 4: u16 scan skipped for large files ──────────────────────────────

    /// A file slightly above 32 KiB with valid u16 pointer chains must NOT
    /// emit a u16 signal (scan skipped entirely for selectivity).
    #[test]
    fn u16_scan_skipped_for_large_file() {
        // Construct a u16 chain in the first few bytes, then pad to 33 000.
        // chain: 0→2, 2→4, 4→6, 6→8, 8→10  (6 nodes ≥ 5 threshold)
        let file_size = 33_000usize;
        let mut data = vec![0u8; file_size];
        // Write u16le values that form a chain at aligned positions.
        data[0..2].copy_from_slice(&(2u16).to_le_bytes());
        data[2..4].copy_from_slice(&(4u16).to_le_bytes());
        data[4..6].copy_from_slice(&(6u16).to_le_bytes());
        data[6..8].copy_from_slice(&(8u16).to_le_bytes());
        data[8..10].copy_from_slice(&(10u16).to_le_bytes());

        let sigs = scan_offset_graph(&data);
        assert!(
            !sigs.iter().any(|s| matches!(
                &s.kind,
                SignalKind::OffsetGraph {
                    pointer_width: 2,
                    ..
                }
            )),
            "u16 scan should be skipped for file_size > 32768"
        );
    }

    // ── Test 5: u64le offset table → signal ──────────────────────────────────

    /// A short chain of 2 u64le pointers reaches the min threshold of 2 nodes
    /// (node 0 → 8 → 16 = 3 distinct nodes ≥ 2).
    #[test]
    fn u64le_offset_table_emits_signal() {
        // File layout (256 bytes):
        //   pos 0  : u64le = 16
        //   pos 16 : u64le = 32
        //   rest   : zeros (u64le = 0, not >= width=8)
        let mut data = vec![0u8; 256];
        data[0..8].copy_from_slice(&le64(16));
        data[16..24].copy_from_slice(&le64(32));

        let sigs = scan_offset_graph(&data);
        let og = sigs
            .iter()
            .find(|s| {
                matches!(
                    &s.kind,
                    SignalKind::OffsetGraph {
                        pointer_width: 8,
                        little_endian: true,
                        ..
                    }
                )
            })
            .expect("expected u64le offset-graph signal");

        let SignalKind::OffsetGraph {
            component_nodes, ..
        } = &og.kind
        else {
            unreachable!()
        };
        assert!(*component_nodes >= 2, "component_nodes={component_nodes}");
    }

    // ── Test 6: high-density data → no signal emitted ────────────────────────

    /// When nearly all positions are within-bounds candidates (density > 50%),
    /// the scan bails out early and emits no signal — the data is noise.
    #[test]
    fn high_density_emits_no_signal() {
        // Build a file where all u32le values are within bounds.
        // Each position i points to (i*4 + 4) % file_size.
        // With 64 positions in a 256-byte file, density > 50%.
        let file_size = 256usize;
        let mut data = vec![0u8; file_size];
        for i in 0..(file_size / 4) {
            let pos = i * 4;
            let target = (pos + 4) % file_size;
            if target != pos && target >= 4 {
                data[pos..pos + 4].copy_from_slice(&(target as u32).to_le_bytes());
            }
        }

        let sigs = scan_offset_graph(&data);
        assert!(
            !sigs.iter().any(|s| matches!(
                &s.kind,
                SignalKind::OffsetGraph {
                    pointer_width: 4,
                    little_endian: true,
                    ..
                }
            )),
            "expected no u32le signal for high-density data"
        );
    }
}
