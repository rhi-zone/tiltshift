# Signal Reference

tiltshift runs 13 signal extractors simultaneously when you call `analyze`. Each signal carries a region (offset + length), confidence (0.0–1.0), and a human-readable reason.

## Statistical signals

### EntropyBlock

Sliding-window Shannon entropy over the file in configurable blocks (default: 256 bytes).

Entropy ranges from 0 (fully predictable) to 8 bits/byte (fully random). The transitions between blocks are more informative than absolute values: a jump from 2.1 to 7.9 bits typically marks a boundary between structured data and a compressed or encrypted payload.

Classes: `structured` (< 2.5), `mixed` (2.5–5.5), `compressed` (5.5–7.5), `highly-random` (> 7.5).

### NgramProfile

Bigram (byte-pair) frequency table over the entire file. Produces a data-type hint based on the distribution shape:

- `text` — ASCII range bigrams dominate
- `binary` — mixed distribution
- `compressed/encrypted` — near-uniform bigram distribution
- `structured binary` — clustered, low-entropy bigrams

Also reports the top bigrams and the bigram entropy.

### RepeatedPattern

Detects byte sequences that appear at fixed stride intervals. A pattern appearing every 16 bytes across a region strongly suggests an array of 16-byte structs. Reports the pattern bytes, stride, and occurrence count.

### ChiSquare

Chi-square test for byte uniformity against a flat distribution (df=255). Uses the Wilson–Hilferty approximation for the p-value.

- `p < 0.01` — non-uniform (structured data, text, etc.)
- `p > 0.99` — suspiciously uniform (possible encrypted/compressed data)
- `0.01 < p < 0.99` — consistent with uniform (random-looking)

One result per file; requires at least 512 bytes.

### CompressionProbe

Compresses the entire file with zlib at level 6 and reports the ratio (compressed/original).

- `≥ 0.99` — incompressible (likely encrypted or already compressed)
- `0.90–0.99` — nearly incompressible
- `0.70–0.90` — mildly compressible
- `0.40–0.70` — moderately compressible
- `< 0.40` — highly compressible (structured or redundant data)

A more honest proxy for randomness than entropy alone. One result per file; requires at least 256 bytes.

## Structural signals

### MagicBytes

Matches against a corpus of 100+ known magic byte signatures. Detects embedded formats at any offset, not just the start of the file. The corpus is extensible via `tiltshift magic add`.

Examples: PNG (`89 50 4e 47`), PDF (`25 50 44 46`), ZIP (`50 4b 03 04`), ELF (`7f 45 4c 46`).

### NullTerminatedString

Null-terminated ASCII runs of 4 or more printable bytes. Useful as structural anchors — strings often appear at predictable positions in headers, string tables, or metadata sections.

### LengthPrefixedBlob

A numeric prefix (u8, u16le, u16be, u32le, or u32be) followed by exactly that many bytes of plausible content. Confidence is higher when the body is printable ASCII or low-entropy data.

### ChunkSequence

Repeating tag+length+data structures: IFF/RIFF-style (`tag_first=true`) and PNG-style (`tag_first=false`). Detects sequences of ≥ 3 chunks and reports the format hint (IFF, RIFF, or PNG-style), layout, chunk count, and a sample of observed tag names.

### TlvSequence

Type-Length-Value records in various width configurations: `u8+u8`, `u8+u16le/be`, `u8+u32le/be`, `u16+u16le/be`. Reports the record count, type distribution, and bytes covered. Deduplicates by byte coverage (not record count) to avoid reporting equivalent matches at different widths.

### AlignmentHint

Measures entropy variance across byte-offset phases (mod 2, mod 4, mod 8, mod 16) to detect dominant alignment. One result per file. Reports the dominant alignment, entropy spread, and which phase offset shows the most variation (a proxy for where structure boundaries tend to fall).

## Numeric signals

### NumericValue

Scans all u32 values (both LE and BE) in the first 512 bytes of the file and flags values with semantic meaning:

- **file-size** — value equals the file size (or file size minus offset)
- **power-of-two** — value is a power of two ≥ 16 (block size, capacity, alignment)
- **candidate-offset** — value is within file bounds (may be a pointer or offset field)

### Padding

Runs of 4 or more consecutive `0x00` or `0xFF` bytes. Common at section boundaries, alignment gaps, and reserved header fields.

## Bit-level signals

### VarInt

Two encodings:

- **leb128-unsigned** — 5 or more consecutive valid LEB128 multi-byte values (high bit set as continuation marker). Confidence 0.55–0.80.
- **utf8-multibyte** — 5 or more consecutive valid non-ASCII UTF-8 codepoints. Confidence 0.70–0.88.

Reports the encoding type, value count, bytes consumed, and average byte width per value.

## Confidence scores

All signals carry a confidence value from 0.0 to 1.0. Signals with low confidence are included — weak signals are meant to accumulate. A "maybe length field" plus "consistent following region" plus "ngram match in following region" can compound into a confident hypothesis in the hypothesis engine (upcoming).

Use `--json` to get the full signal list with confidence values for programmatic use.
