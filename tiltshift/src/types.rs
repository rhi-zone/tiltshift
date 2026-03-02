use serde::{Deserialize, Serialize};

/// A contiguous span of bytes within a file.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Region {
    pub offset: usize,
    pub len: usize,
}

impl Region {
    pub fn new(offset: usize, len: usize) -> Self {
        Self { offset, len }
    }

    pub fn end(&self) -> usize {
        self.offset + self.len
    }

    pub fn slice<'a>(&self, data: &'a [u8]) -> &'a [u8] {
        &data[self.offset..self.offset + self.len]
    }
}

impl std::fmt::Display for Region {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "0x{:06x}+{}", self.offset, self.len)
    }
}

/// Coarse classification of a region's entropy.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum EntropyClass {
    /// < 3.0 bits/byte — highly structured (headers, sparse data, padding)
    Structured,
    /// 3.0–6.0 bits/byte — mixed (text, moderate structure)
    Mixed,
    /// 6.0–7.5 bits/byte — dense data (compressed, packed integers)
    Compressed,
    /// > 7.5 bits/byte — likely encrypted or truly random
    HighlyRandom,
}

impl EntropyClass {
    pub fn from_entropy(e: f64) -> Self {
        if e < 3.0 {
            Self::Structured
        } else if e < 6.0 {
            Self::Mixed
        } else if e < 7.5 {
            Self::Compressed
        } else {
            Self::HighlyRandom
        }
    }

    pub fn label(&self) -> &'static str {
        match self {
            Self::Structured => "structured",
            Self::Mixed => "mixed",
            Self::Compressed => "compressed/packed",
            Self::HighlyRandom => "random/encrypted",
        }
    }
}

/// A raw observation extracted from the binary data.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Signal {
    pub region: Region,
    pub kind: SignalKind,
    /// 0.0–1.0 confidence that this observation is genuine.
    pub confidence: f64,
    /// Human-readable explanation of why this signal was emitted.
    pub reason: String,
}

impl Signal {
    pub fn new(
        region: Region,
        kind: SignalKind,
        confidence: f64,
        reason: impl Into<String>,
    ) -> Self {
        Self {
            region,
            kind,
            confidence,
            reason: reason.into(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type")]
pub enum SignalKind {
    MagicBytes {
        format: String,
        hex: String,
    },
    NullTerminatedString {
        content: String,
    },
    EntropyBlock {
        entropy: f64,
        class: EntropyClass,
    },
    Padding {
        byte_value: u8,
        run_len: usize,
    },
    /// A repeating (tag, length, data) sequence in the IFF/RIFF/PNG family.
    ChunkSequence {
        /// Detected format family: "RIFF", "IFF", "PNG", "MP4/QuickTime", or "generic".
        format_hint: String,
        /// true = [tag][len][data] (RIFF/IFF), false = [len][tag][data] (PNG).
        tag_first: bool,
        /// Byte order of the length field.
        little_endian: bool,
        /// Number of consecutive valid chunks in the run.
        chunk_count: usize,
        /// FourCC tags of the first up to 8 chunks.
        tags: Vec<String>,
    },
    /// A consecutive run of length-prefixed blobs (u8 / u16 / u32, LE or BE)
    /// where each blob's end is immediately followed by the next blob's prefix.
    ///
    /// A single occurrence is coincidence-level evidence; requiring ≥ 2
    /// consecutive blobs that chain exactly means the format is being observed,
    /// not guessed.
    LengthPrefixedBlob {
        /// Width of the prefix field in bytes: 1, 2, or 4.
        prefix_width: u8,
        /// Byte order of the prefix (ignored / always true for width=1).
        little_endian: bool,
        /// Number of consecutive blobs in the chain (always ≥ 2).
        blob_count: usize,
        /// Average fraction of body bytes that are printable ASCII (0.0–1.0).
        printable_ratio: f64,
    },
    /// Bigram frequency profile for the whole file, used to classify data type.
    NgramProfile {
        /// Shannon entropy of the bigram distribution (0–16 bits).
        bigram_entropy: f64,
        /// The five most frequent bigrams, e.g. `["00 00 (12.3%)", …]`.
        top_bigrams: Vec<String>,
        /// Coarse data-type classification: "text", "sparse/structured",
        /// "compressed/random", or "mixed".
        data_type_hint: String,
    },
    /// A 4-byte pattern that recurs at a consistent stride through the file,
    /// suggesting an array of fixed-size records.
    RepeatedPattern {
        /// The repeating byte sequence.
        pattern: Vec<u8>,
        /// Gap in bytes between consecutive occurrences (= record size candidate).
        stride: usize,
        /// Total number of times the pattern was found.
        occurrences: usize,
    },
    /// A consecutive run of Type-Length-Value records with consistent field widths.
    TlvSequence {
        /// Width of the type field in bytes: 1 or 2.
        type_width: u8,
        /// Width of the length field in bytes: 1, 2, or 4.
        len_width: u8,
        /// Byte order used for multi-byte fields (irrelevant when both widths are 1).
        little_endian: bool,
        /// Number of consecutive valid records in the run.
        record_count: usize,
        /// Type codes of the first up to 8 records.
        type_samples: Vec<u32>,
    },
    /// Chi-square test for byte-distribution uniformity over the whole file.
    ///
    /// The statistic follows χ²(255) under the null hypothesis that every byte
    /// value is equally likely (i.e. the data is random/encrypted).
    ChiSquare {
        /// Raw chi-square statistic (df = 255; expected ~255 for uniform data).
        chi_sq: f64,
        /// Approximate P(X ≥ chi_sq) under χ²(255).  Low ≈ non-uniform;
        /// high ≈ suspiciously uniform.
        p_value: f64,
    },
    /// Compression ratio probe: result of trying to deflate-compress the whole file.
    ///
    /// A ratio near or above 1.0 indicates incompressible data (random, encrypted,
    /// or already-compressed).  A low ratio indicates sequential structure that
    /// deflate's LZ77 + Huffman stage can exploit (repetition, locality).
    ///
    /// Complements chi-square (frequency uniformity) and Shannon entropy (symbol
    /// distribution), both of which are blind to sequential patterns.
    CompressionProbe {
        /// Original byte count.
        original_size: usize,
        /// Byte count after zlib/deflate compression (level 6).
        compressed_size: usize,
        /// `compressed_size / original_size` — lower means more compressible.
        ratio: f64,
    },
    /// Structural regularity at a specific byte alignment boundary.
    ///
    /// Detected by comparing per-phase Shannon entropy across the file: when one
    /// phase offset is consistently more (or less) varied than the others, the
    /// data respects that alignment.
    AlignmentHint {
        /// Dominant alignment in bytes: 2, 4, 8, or 16.
        alignment: usize,
        /// max(H(phase)) - min(H(phase)) in bits — how non-uniform the entropy profile is.
        entropy_spread: f64,
        /// Phase offset (0..alignment) with the highest per-phase entropy.
        dominant_phase: usize,
    },
    /// A run of variable-length encoded integers in a recognized VarInt scheme.
    ///
    /// Detected encodings:
    /// - `"leb128-unsigned"` — unsigned Little-Endian Base-128 (WebAssembly, protobuf,
    ///   DWARF, DEX).  Only emitted when ≥ 5 consecutive values are multi-byte.
    /// - `"utf8-multibyte"` — consecutive non-ASCII UTF-8 characters with no ASCII
    ///   bytes between them (CJK blocks, emoji runs, non-Latin script fields).
    VarInt {
        /// Encoding scheme: `"leb128-unsigned"` or `"utf8-multibyte"`.
        encoding: String,
        /// Number of consecutive successfully decoded values.
        count: usize,
        /// Total bytes consumed by the run.
        bytes_consumed: usize,
        /// Average bytes per encoded value (always > 1.0 for both encodings).
        avg_width: f64,
    },
    /// Nibble-level packed sub-fields detected via independence of high/low nibbles.
    ///
    /// Binary formats routinely pack two independent sub-fields into each byte at
    /// the nibble boundary (bits 7–4 / bits 3–0): BCD-encoded dates, 4-bit
    /// type + 4-bit subtype, MPEG-2 flag bytes, TCP DSCP+ECN, etc.
    PackedField {
        /// Shannon entropy of the high nibble (bits 7–4), 0–4 bits.
        high_nibble_entropy: f64,
        /// Shannon entropy of the low nibble (bits 3–0), 0–4 bits.
        low_nibble_entropy: f64,
        /// Estimated mutual information between nibbles (0 = independent).
        mutual_information: f64,
        /// H_joint / (H_high + H_low) — 1.0 = fully independent nibbles.
        independence_ratio: f64,
        /// Human-readable interpretation hint.
        hint: String,
    },
    /// A directed graph of candidate pointer/offset relationships found across the file.
    ///
    /// Emitted when multiple within-bounds pointer values form a connected component
    /// large enough to suggest intentional pointer structure rather than coincidence.
    OffsetGraph {
        /// Width of pointer fields in bytes: 2 (u16), 4 (u32), or 8 (u64).
        pointer_width: u8,
        /// Whether LE byte order was used to read pointer values.
        little_endian: bool,
        /// Total candidate pointer count (within-bounds values at aligned positions).
        candidate_count: usize,
        /// Nodes (distinct offsets) in the largest connected component.
        component_nodes: usize,
        /// Directed edges in the largest connected component.
        component_edges: usize,
        /// Fraction of scanned positions whose value was within bounds.
        pointer_density: f64,
        /// Up to 8 representative (source, target) offset pairs from the component.
        sample_edges: Vec<(usize, usize)>,
    },
    /// A u32 value with structural significance (power-of-two, file-size match,
    /// or a plausible in-bounds offset found in the header region).
    NumericValue {
        /// Byte order used to read this value.
        little_endian: bool,
        /// The raw u32 value.
        value: u32,
        /// Value equals the file's total byte count.
        file_size_match: bool,
        /// Value is a power of two ≥ 16.
        power_of_two: bool,
        /// Value is a plausible file offset (in-bounds, 4-byte aligned, header region).
        within_bounds: bool,
    },
}

/// A ranked interpretation built from one or more signals.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Hypothesis {
    pub region: Region,
    pub label: String,
    /// 0.0–1.0 aggregate confidence.
    pub confidence: f64,
    /// One or two sentences explaining the specific observations that led to
    /// this conclusion — *why* confidence is what it is, not just *what* was found.
    pub reasoning: String,
    pub signals: Vec<Signal>,
    /// Alternatives considered and why they ranked lower.
    pub alternatives: Vec<(String, f64)>,
    /// True when this hypothesis was added by the user via `tiltshift annotate`
    /// rather than derived automatically from signals.
    #[serde(default)]
    pub annotated: bool,
}

impl Hypothesis {
    pub fn from_signal(signal: Signal, label: impl Into<String>) -> Self {
        Self {
            region: signal.region.clone(),
            confidence: signal.confidence,
            label: label.into(),
            reasoning: String::new(),
            signals: vec![signal],
            alternatives: vec![],
            annotated: false,
        }
    }
}

/// A single entry in the linear layout view of a file.
pub enum LayoutSpan<'a> {
    /// A region covered by a known hypothesis.
    Known(&'a Hypothesis),
    /// A region not covered by any local hypothesis.
    Unknown(Region),
}

/// The current state of understanding of the file — some regions explained, others not.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct PartialSchema {
    pub file_size: usize,
    pub hypotheses: Vec<Hypothesis>,
}

impl PartialSchema {
    pub fn new(file_size: usize) -> Self {
        Self {
            file_size,
            hypotheses: vec![],
        }
    }

    /// Regions not covered by any hypothesis, in offset order.
    pub fn unexplained(&self) -> Vec<Region> {
        let mut covered: Vec<(usize, usize)> = self
            .hypotheses
            .iter()
            .map(|h| (h.region.offset, h.region.end()))
            .collect();
        covered.sort_unstable();
        covered.dedup();

        let mut gaps = Vec::new();
        let mut pos = 0usize;
        for (start, end) in &covered {
            if pos < *start {
                gaps.push(Region::new(pos, start - pos));
            }
            pos = pos.max(*end);
        }
        if pos < self.file_size {
            gaps.push(Region::new(pos, self.file_size - pos));
        }
        gaps
    }

    /// Linear layout of the file as a sequence of known and unknown spans.
    ///
    /// File-wide hypotheses (those covering the entire file) are excluded — they
    /// would collapse all unknown spans and make the layout useless.  Among
    /// remaining hypotheses, earlier offsets take precedence; ties are broken by
    /// confidence (higher wins).  Gaps between known spans become `Unknown`.
    pub fn layout(&self) -> Vec<LayoutSpan<'_>> {
        // Collect local (non-file-wide) hypotheses sorted by (offset asc, confidence desc).
        let mut local: Vec<&Hypothesis> = self
            .hypotheses
            .iter()
            .filter(|h| h.region.len < self.file_size)
            .collect();
        local.sort_by(|a, b| {
            a.region.offset.cmp(&b.region.offset).then_with(|| {
                b.confidence
                    .partial_cmp(&a.confidence)
                    .unwrap_or(std::cmp::Ordering::Equal)
            })
        });

        let mut spans: Vec<LayoutSpan<'_>> = Vec::new();
        let mut cursor: usize = 0;

        for hyp in local {
            if hyp.region.offset < cursor {
                // Overlaps with an already-placed span — skip.
                continue;
            }
            // Fill any gap before this hypothesis.
            if hyp.region.offset > cursor {
                spans.push(LayoutSpan::Unknown(Region::new(
                    cursor,
                    hyp.region.offset - cursor,
                )));
            }
            cursor = hyp.region.end();
            spans.push(LayoutSpan::Known(hyp));
        }

        // Trailing unknown.
        if cursor < self.file_size {
            spans.push(LayoutSpan::Unknown(Region::new(
                cursor,
                self.file_size - cursor,
            )));
        }

        spans
    }
}
