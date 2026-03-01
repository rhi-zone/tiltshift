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
