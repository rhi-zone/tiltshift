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
    /// A length prefix (u8 / u16 / u32, LE or BE) whose declared byte count
    /// lands within the file and is followed by plausible body data.
    LengthPrefixedBlob {
        /// Width of the prefix field in bytes: 1, 2, or 4.
        prefix_width: u8,
        /// Byte order of the prefix (ignored / always true for width=1).
        little_endian: bool,
        /// Value stored in the prefix — the declared body length.
        declared_len: usize,
        /// Fraction of body bytes that are printable ASCII (0.0–1.0).
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
    pub signals: Vec<Signal>,
    /// Alternatives considered and why they ranked lower.
    pub alternatives: Vec<(String, f64)>,
}

impl Hypothesis {
    pub fn from_signal(signal: Signal, label: impl Into<String>) -> Self {
        Self {
            region: signal.region.clone(),
            confidence: signal.confidence,
            label: label.into(),
            signals: vec![signal],
            alternatives: vec![],
        }
    }
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
}
