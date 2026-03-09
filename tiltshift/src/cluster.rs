//! Feature extraction and HDBSCAN clustering over collections of files.
//!
//! Each file is reduced to a fixed 10-dimensional feature vector derived
//! from its extracted signals.  All dimensions are normalised to [0, 1] so
//! Euclidean distance treats them equally.
//!
//! Dimensions (in order):
//!   0  compression_ratio     — CompressionProbe.ratio
//!   1  bigram_entropy_norm   — NgramProfile.bigram_entropy / 16.0
//!   2  uniformity            — ChiSquare.p_value
//!   3  has_chunk_sequence    — 1 if any ChunkSequence signal present
//!   4  bytecode_coverage     — BytecodeStream.decode_coverage (else 0)
//!   5  stride_log_norm       — log2(max_stride+1) / 20   (else 0)
//!   6  tlv_log_norm          — log2(max_records+1) / 14  (else 0)
//!   7  has_varint            — 1 if any leb128-unsigned VarInt present
//!   8  graph_log_norm        — log2(max_component_nodes+1) / 12  (else 0)
//!   9  alignment_norm        — AlignmentHint.alignment / 16  (else 0)

use crate::types::{Signal, SignalKind};
use serde::{Deserialize, Serialize};
use std::path::Path;

pub const FEATURE_NAMES: &[&str] = &[
    "compression_ratio",
    "bigram_entropy",
    "uniformity",
    "chunk_sequence",
    "bytecode_coverage",
    "stride",
    "tlv_records",
    "varint",
    "offset_graph",
    "alignment",
];

/// Lightweight per-file cache storing just the feature vector + file size.
///
/// Stored as `<file>.tiltshift.features.toml` alongside the input.
/// Avoids loading the (potentially hundreds-of-MB) full signal session cache
/// when all we need is the 10-dimensional cluster input.
#[derive(Serialize, Deserialize)]
pub struct FeatureCache {
    pub file_size: u64,
    pub features: Vec<f32>,
}

/// Load a feature cache for `path`, returning `None` if absent or stale.
pub fn load_feature_cache(path: &Path, file_size: u64) -> Option<Vec<f32>> {
    let cache_path = cache_path(path);
    let text = std::fs::read_to_string(&cache_path).ok()?;
    let fc: FeatureCache = toml::from_str(&text).ok()?;
    if fc.file_size != file_size {
        return None;
    }
    Some(fc.features)
}

/// Save a feature vector to the lightweight cache file.
pub fn save_feature_cache(path: &Path, file_size: u64, features: &[f32]) {
    let fc = FeatureCache {
        file_size,
        features: features.to_vec(),
    };
    if let Ok(text) = toml::to_string(&fc) {
        let _ = std::fs::write(cache_path(path), text);
    }
}

fn cache_path(path: &Path) -> std::path::PathBuf {
    let mut p = path.as_os_str().to_owned();
    p.push(".tiltshift.features.toml");
    std::path::PathBuf::from(p)
}

/// Reduce a file's signals to a fixed-length feature vector.
pub fn extract_features(signals: &[Signal]) -> Vec<f32> {
    let mut compression_ratio = 0.5_f32; // unknown → mid
    let mut bigram_entropy_norm = 0.5_f32;
    let mut uniformity = 0.0_f32;
    let mut has_chunk_sequence = 0.0_f32;
    let mut bytecode_coverage = 0.0_f32;
    let mut max_stride: u64 = 0;
    let mut max_tlv_records: usize = 0;
    let mut has_varint = 0.0_f32;
    let mut max_graph_nodes: usize = 0;
    let mut alignment_norm = 0.0_f32;

    for sig in signals {
        match &sig.kind {
            SignalKind::CompressionProbe { ratio, .. } => {
                compression_ratio = *ratio as f32;
            }
            SignalKind::NgramProfile { bigram_entropy, .. } => {
                bigram_entropy_norm = (*bigram_entropy / 16.0) as f32;
            }
            SignalKind::ChiSquare { p_value, .. } => {
                uniformity = *p_value as f32;
            }
            SignalKind::ChunkSequence { .. } => {
                has_chunk_sequence = 1.0;
            }
            SignalKind::BytecodeStream {
                decode_coverage, ..
            } => {
                bytecode_coverage = bytecode_coverage.max(*decode_coverage as f32);
            }
            SignalKind::RepeatedPattern { stride, .. } => {
                max_stride = max_stride.max(*stride as u64);
            }
            SignalKind::TlvSequence { record_count, .. } => {
                max_tlv_records = max_tlv_records.max(*record_count);
            }
            SignalKind::VarInt { encoding, .. } if encoding == "leb128-unsigned" => {
                has_varint = 1.0;
            }
            SignalKind::OffsetGraph {
                component_nodes, ..
            } => {
                max_graph_nodes = max_graph_nodes.max(*component_nodes);
            }
            SignalKind::AlignmentHint { alignment, .. } => {
                alignment_norm = (*alignment as f32 / 16.0).min(1.0);
            }
            _ => {}
        }
    }

    let stride_log_norm = if max_stride > 0 {
        ((max_stride as f32 + 1.0).log2() / 20.0).min(1.0)
    } else {
        0.0
    };
    let tlv_log_norm = if max_tlv_records > 0 {
        ((max_tlv_records as f32 + 1.0).log2() / 14.0).min(1.0)
    } else {
        0.0
    };
    let graph_log_norm = if max_graph_nodes > 0 {
        ((max_graph_nodes as f32 + 1.0).log2() / 12.0).min(1.0)
    } else {
        0.0
    };

    vec![
        compression_ratio,
        bigram_entropy_norm,
        uniformity,
        has_chunk_sequence,
        bytecode_coverage,
        stride_log_norm,
        tlv_log_norm,
        has_varint,
        graph_log_norm,
        alignment_norm,
    ]
}

/// Describe the dominant features of a cluster from its mean feature vector.
/// Returns a short human-readable string like "compressed · chunk-structured".
pub fn describe_cluster(mean: &[f32]) -> String {
    let mut tags: Vec<&str> = Vec::new();

    // Compression class — most fundamental split.
    if mean[0] >= 0.92 {
        tags.push("compressed stream");
    } else if mean[0] >= 0.70 {
        tags.push("moderately compressible");
    } else {
        tags.push("structured/compressible");
    }

    if mean[3] >= 0.5 {
        tags.push("chunk-structured");
    }
    if mean[4] >= 0.5 {
        tags.push("bytecode");
    }
    if mean[5] >= 0.1 {
        tags.push("regular stride");
    }
    if mean[6] >= 0.1 {
        tags.push("TLV");
    }
    if mean[7] >= 0.5 {
        tags.push("varint");
    }
    if mean[8] >= 0.1 {
        tags.push("pointer graph");
    }

    tags.join(" · ")
}
