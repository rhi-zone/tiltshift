# tiltshift — Design

## Core thesis

Binary format reverse engineering is an iterative process of uncovering pre-existing structure — not constructing a model, but gaining visibility into something that was always there and is fixed. Each analysis pass reveals partial structure; that partial structure constrains and informs the next pass. You stop when you're satisfied, not when the tool signals completion.

The structure always existed. You're just progressively less wrong about it.

## Problem space

Most RE tools are built for humans with significant domain expertise. They provide visual interfaces (hex editors, pattern highlighters) that leverage human visual pattern recognition. Agents can't use any of that.

For agents — and for humans without deep RE experience — the implicit knowledge needs to be made explicit:
- What signals indicate structure vs noise?
- What does a length-prefixed field *look like*?
- What makes a sequence of bytes "suspicious"?
- How do you know where to look next?

tiltshift encodes this expertise as queryable heuristics. The output is always annotated with *why* — not just "this might be a length field" but "this 4-byte value (=1024) is within plausible range for a file of this size and is followed by exactly 1024 bytes before the next apparent boundary."

## Scope

tiltshift operates at the **structural** layer, not the **semantic** layer:

| In scope | Out of scope |
|----------|--------------|
| Field boundaries | What the data means |
| Encoding detection | Application logic |
| Chunk structure | Disassembly / decompilation |
| Anomaly detection | Steganography solving (needs decoded pixel data) |
| Embedded format detection | Cryptographic analysis |

Steganography *detection* is a natural byproduct (anomalous byte distributions, regions that don't fit structural models) but solving stego payloads requires decoding the container format first — that's a different layer.

Disassembly / decompilation is explicitly out of scope — that's a well-solved problem with mature tools (Ghidra, Binary Ninja, IDA).

## Known vs unknown formats

tiltshift is agnostic of whether the input format is known. It runs its signal analysis regardless. This means:

- **Unknown format**: build structural understanding from scratch
- **Known format corpus**: feed known formats (PNG, ZIP, ELF, BMP, WAV) to validate signals and build a reference fragment library
- **Known format, anomalous file**: diff against corpus model to isolate deviations
- **Two unknown files**: multi-file correlation to separate structural fields from data fields

Known formats are the training data and validation set. Running tiltshift on PNG tells you tiltshift is finding the right signals; those results become reference models for detecting PNG fragments in unknown data.

## The iterative loop

```
signals(region) → hypotheses → partial_parse → new_constraints → signals(subregion) → ...
```

Each confirmed structural element becomes a constraint that narrows the remaining unknowns:

```
[KNOWN: header 0x00–0x3F] [UNKNOWN: 0x40–0x7F] [KNOWN: chunk @ 0x80]
```

The unknown region's *size* is now known (64 bytes), its neighboring context is known, and if multiple files are available, that region can be diffed in isolation.

Recursion: once a chunk boundary is confirmed, the chunk interior is a fresh analysis target whose context (type tag, position, size) feeds back into the signal extraction as additional constraints. A confirmed PNG IDAT chunk gets analyzed differently than an anonymous 2KB blob.

## Signal taxonomy

### Statistical signals
- **Byte frequency histogram** — shape indicates data type: uniform=encrypted/compressed, bimodal with ASCII range=text, clustered low=packed integers
- **Bigrams / ngrams** — frequency tables discriminate data types better than entropy alone; repeated ngrams at fixed stride indicate struct fields; cross-region similarity indicates same encoding
- **Shannon entropy** — useful for coarse classification (high=compressed/encrypted, low=structured) but weak as a standalone signal; sliding window entropy reveals *transitions* between regions, which are more informative than absolute values
- **Chi-square test** — more precise than entropy for "is this actually random/encrypted?"
- **Compression ratio** — try compressing a region; the result is a more honest proxy for randomness than entropy

### Structural signals
- **Magic bytes** — match against known corpus; detect at non-zero offsets; correlate across multiple files (same bytes at same offset in multiple samples = likely magic)
- **Chunk patterns** — tag (4-byte ASCII) + length + data, repeating; IFF/RIFF/PNG-style is extremely common; TLV (type-length-value) in various widths
- **Length-prefixed fields** — u8/u16/u32 followed by exactly that many plausible bytes; especially strong when followed by printable ASCII or low-entropy data
- **Null-terminated strings** — scan automatically; use as structural anchors
- **Alignment** — most formats align fields to 2, 4, or 8 bytes; map alignment regularity to find struct boundaries
- **Repetition** — repeating structural patterns at fixed stride indicate arrays of structs; find candidate record/array boundaries without prior hypotheses

### Numeric value semantics
- High bits all zero → small count, version, enum, or flags (not a dense integer)
- Power of two → block size, capacity, or alignment value
- Value matches file size, or `file_size - current_offset` → size or remaining-bytes field
- Value within file bounds → candidate pointer/offset
- Run of 0x00 or 0xFF → padding
- Value near 0 → version, small count, or enum

### Pointer / offset graph
- Automatically identify values that look like file offsets (value is within bounds, target region is non-empty)
- Render as a graph: "offset 0x10 contains value 0x400; offset 0x400 contains a likely string"
- Pointer chasing is how you navigate complex formats; detecting what *looks like* a pointer should be automatic

### Bit-level signals
- Variable-length integer encodings (LEB128, UTF-8 continuation bytes: high bit pattern)
- Packed fields: top nibble and bottom nibble with independent value distributions
- Flag bytes: individual bits that vary independently

### Multi-file signals
- **Delta analysis**: two versions of same format → diff structurally; fields that vary=data, fields that are identical=structural
- **Cross-file magic correlation**: bytes at same offset across multiple files → likely magic
- **Distribution similarity**: two disjoint regions with near-identical ngram distributions → same encoding, possibly same sub-format

## Output quality

The differentiator is feedback richness. Most binary parsing libraries return success/failure. tiltshift returns:

- What was found and where
- Confidence score with contributing signals
- Why that interpretation was reached ("value=1024 is plausible for this file size; followed by 1024 bytes before next apparent boundary; 3 signals compound to 0.87 confidence")
- What alternatives were considered and why they ranked lower
- What remains unexplained and what the next productive analysis targets are

Weak signals should accumulate properly — a "maybe length field" + "following region consistent with that length" + "ngram match in following region" should compound into a confident hypothesis, not stay as three separate weak guesses.

## Primitive API (sketch)

```
probe(offset, n) → typed interpretations (u32le, u32be, f32, ascii, ...)
scan(pattern) → all matching offsets with context
entropy_map(block_size) → entropy per block, sliding window variant
try_parse(offset, schema) → partial match result with per-field confidence
string_table(offset, len) → null-terminated / length-prefixed string extraction
pointer_graph() → all candidate offset values with their targets
repeat_detect() → candidate array/struct boundaries with stride
what_could_this_be(offset, len) → ranked interpretations with reasoning
diff(file_a, file_b) → structural delta, not byte delta
```

## Bytecode grammar discovery

### Goal

Given a region of bytes that may be an instruction stream, produce:

1. A **detection verdict**: is this bytecode? How confident?
2. A **candidate grammar**: opcode → operand-width mapping for as many opcodes as the data supports
3. A **coverage score**: what fraction of the region decodes consistently under the discovered grammar

The discovered grammar is the *output*, not the input. tiltshift must derive WASM, Python .pyc, JVM bytecode, x86, and unknown custom VMs from first principles — without being told what format to expect. If it cannot, the tool has failed.

### Laws

1. **No format knowledge in the signal.** The discovery algorithm contains zero special cases for any named bytecode format. Named format files (`data/opcodes/<format>.toml`) are *outputs* of verified discovery, not inputs to the signal. The signal never reads them.

2. **Self-consistency is the only oracle.** Two metrics, both format-agnostic:
   - **Decode coverage**: starting from a candidate entry point, what fraction of bytes decode as valid instructions before hitting a byte the current grammar cannot explain?
   - **Jump target validity**: what fraction of decoded branch-operand values land exactly on instruction boundaries? A wrong grammar produces targets that land mid-instruction.
   Both metrics require only the data and the candidate grammar — no external reference.

3. **Entry points come from context, not the algorithm.** The discovery signal receives a candidate entry point from the hypothesis engine (typically from a preceding MagicBytes signal — ELF `.text` offset, WASM code section, `.pyc` bytecode start). The signal also tries offset 0 and any user-annotated boundaries. It does not scan every offset for entry points.

4. **LEB128 operands defer to VarInt.** When the VarInt signal fires in the same region, BytecodeStream notes it as an encoding hint (operands may be LEB128-encoded) and adjusts operand-width estimation accordingly. It does not re-implement LEB128 decoding.

5. **Grammar files are persistence, not truth.** `data/opcodes/<format>.toml` serialises a human-verified grammar so it can be reused for display and validation. It does not make the discovery algorithm aware of the format — discovery must work from scratch every time.

### Why this is tractable

A bytecode stream has a property random data does not: **structural recurrence**. The same opcode bytes appear at positions that are consistent with a fixed decode rule. Random data does not produce a grammar whose application to the stream yields high decode coverage and high jump validity simultaneously.

The probability that random data produces decode-coverage > 0.90 AND jump-validity > 0.80 under any consistent grammar is vanishingly small. This is the basis for confidence scoring.

### Algorithm

**Phase 1 — Fixed-width scan (O(n))**

Try instruction sizes W ∈ {1, 2, 3, 4, 8}. For each W, measure:
- Entropy of bytes at positions 0, W, 2W, 3W … ("opcode positions") — should be lower (fewer distinct opcodes than data values)
- Entropy of bytes at other positions ("operand positions") — should be higher

Score = `H(operand_positions) - H(opcode_positions)`. High score means strong opcode/operand separation. Emit `fixed_width = W` signal if score exceeds threshold.

This handles: JVM-style (1-byte opcodes, variable padding detected separately), Python .pyc 3.6+ (2-byte wordcode), simple custom VMs with uniform instruction size, RISC architectures (4-byte instructions).

**Phase 2 — Variable-width bootstrap (O(n × max_width) per iteration)**

For formats where phase 1 finds no single dominant width:

1. Start with an empty grammar table W(v) = unknown for all opcode bytes v.
2. From the entry point, greedily decode: at each position, read one byte as opcode O. If W(O) is known, advance by (1 + W(O)) bytes. If unknown, try each width k ∈ {0, 1, 2, 3, 4} and score the resulting decode continuation (how many more instructions decode before failure).
3. Assign W(O) = the k that produced the longest continuation. Update the grammar.
4. Repeat from step 2 with the updated grammar until coverage stops improving (typically 2–3 passes).

Convergence criterion: decode coverage increases by < 1% between passes.

**Phase 3 — Jump target validation**

After phase 1 or 2, scan decoded operand values for values that fall within the decoded region. Count how many land on instruction boundaries vs mid-instruction. This ratio is `jump_validity`. High jump validity strongly confirms the grammar; low jump validity with high coverage suggests operand values are data, not addresses (valid for many formats).

### Signal representation

```rust
SignalKind::BytecodeStream {
    /// Offset where decoding began.
    entry_point: usize,
    /// Fraction of region bytes decoded before grammar failure. 1.0 = full decode.
    decode_coverage: f64,
    /// Fraction of decoded operand values that land on instruction boundaries.
    /// None if no operand values fell within the region.
    jump_validity: Option<f64>,
    /// Number of instructions successfully decoded.
    instruction_count: usize,
    /// If a single instruction width explains the whole region, its value in bytes.
    fixed_width: Option<usize>,
    /// Discovered (opcode_byte, operand_bytes) pairs. Empty before phase 2.
    opcode_widths: Vec<(u8, u8)>,
}
```

Confidence formula:
- Base: `decode_coverage × 0.70`
- Jump bonus: `jump_validity × 0.20` (if present)
- Fixed-width bonus: `+0.05` if `fixed_width.is_some()` (stronger evidence — single explanation)
- Minimum to emit: confidence ≥ 0.45 AND decode_coverage ≥ 0.60 AND instruction_count ≥ 16

### Grammar file format (`data/opcodes/<format>.toml`)

Written by the user after inspecting a discovery. Never read by the discovery signal.

```toml
name = "cpython-3.12"
description = "CPython 3.12 bytecode (2-byte wordcode)"

[[opcodes]]
byte = 0x64
mnemonic = "LOAD_CONST"
operand_bytes = 1   # index into co_consts

[[opcodes]]
byte = 0x7C
mnemonic = "LOAD_FAST"
operand_bytes = 1   # local variable index
```

Used only by `tiltshift decode <file> <offset> <format>` — a display/annotation command, not an analysis path.

### CLI additions

- `tiltshift decode <file> <offset> <format>` — decode and print instructions from `offset` using a named grammar file; shows opcode mnemonic + operand bytes
- `tiltshift opcodes add <format> <file>` — register a grammar file in `data/opcodes/<format>.toml`
- `tiltshift opcodes list` — list known grammar files with name and opcode count

## Relation to rhi ecosystem

- **paraphase** needs to understand source formats before planning conversion routes — tiltshift provides that understanding
- **reincarnate** lifts legacy software; understanding the binary formats that software reads/writes is half the job
- **rescribe** handles document formats; tiltshift handles the unknown/undocumented ones upstream
- **normalize** does structural views of source code; tiltshift does structural views of binary data — same pattern, different domain
