# analyze

Run all signal extractors on a file and report findings.

## Usage

```
tiltshift analyze <file> [--depth <N>] [--block-size <N>] [--json]
```

## Arguments

| Argument | Description |
|---|---|
| `<file>` | Path to the binary file to analyze |

## Options

| Option | Default | Description |
|---|---|---|
| `--depth <N>` | `1` | Maximum recursion depth for sub-region analysis (0 = none) |
| `--block-size <N>` | `256` | Entropy block size in bytes |
| `--min-confidence <F>` | `0.0` | Only show signals and hypotheses at or above this confidence (0.0–1.0) |
| `--verbose` | off | Show signal reasoning for all signal types and all alternative hypotheses |
| `--json` | off | Output JSON instead of human-readable text |

## Output sections

The human-readable output is structured in layers, from synthesized conclusions down to raw signals.

### HYPOTHESES

Ranked interpretations derived from signals, with confidence scores and reasoning:

```
HYPOTHESES
────────────────────────────────────────────────────────────
  [file]        text or source code  (confidence 82%)
                why: χ² p=0.000 → non-uniform; compression ratio 0.20 → highly compressible
                via: chi-square test, compression probe, ngram profile
                alt: structured binary with embedded strings (45%)
  0x000000+4    Known format: ELF  (confidence 95%)
                why: Bytes 7f 45 4c 46 at offset 0x0 match the ELF file signature.
                alt: coincidental byte match (14%)
```

- **`[file]`** — file-wide hypotheses covering the entire input (statistical character, encryption, compression)
- **`0xOFFSET+LEN`** — local hypotheses covering a specific byte range
- **`why:`** — the specific observations driving the conclusion (actual values, not just signal names)
- **`via:`** — contributing signals when multiple reinforce each other
- **`alt:`** — the most plausible alternative and its confidence

Capped at 20; use `--json` for the full list.

### LAYOUT

A linear map of the file showing which byte ranges are explained (KNOWN) and which are not yet accounted for (UNKNOWN):

```
LAYOUT  (4096 bytes, 3 known, 2 unknown)
────────────────────────────────────────────────────────────
  0x000000–0x000003  KNOWN    Known format: ELF (95%)
  0x000004–0x00003f  UNKNOWN  60 B
                               ← pointer target: u32le field at 0x18 = 0x4
  0x000040–0x0003ff  KNOWN    Offset graph — u32le — 8 nodes, 12 edges (72%)
  0x000400–0x0007ff  UNKNOWN  1024 B
  0x000800–0x000fff  KNOWN    Chunk-structured container — generic (3 chunks) (78%)
```

**KNOWN** spans are byte ranges covered by a hypothesis. Overlapping hypotheses are resolved in favour of the higher-confidence one at the earlier offset. File-wide hypotheses (statistical characterisation of the entire file) are excluded from the layout — they would cover everything and make the map useless.

**UNKNOWN** spans are gaps the current analysis cannot yet explain. Beneath each unknown span, **constraint annotations** show what the surrounding structure implies about it:

```
  0x000004–0x00003f  UNKNOWN  60 B
                               ← pointer target: u32le field at 0x18 = 0x4
                               ← pointer target: u32le edge from 0x1c
```

Constraints are derived from:

- **`NumericValue` (candidate offset)** — an in-bounds u32 field in the header region whose value is 4-byte aligned and points into an unknown span. The `←` line shows the source field offset and the stored value.
- **`OffsetGraph` edges** — destinations in the largest connected component of the pointer graph that land in an unknown span. The `←` line shows the source pointer address.

These annotations do not change the analysis — they are hints about where to look next, and what command (e.g. `tiltshift region`) to run on an unknown span with additional context.

### Sub-region descent

When `--depth` is 1 or greater (the default), each KNOWN span that is at least
32 bytes is automatically re-analyzed as a sub-region. The nested output appears
indented beneath the KNOWN line:

```
  0x000048–0x0003e7  KNOWN    Chunk-structured container — RIFF (5 chunks) (88%)
      ↳ sub-region 0x000048+960 (inside: Chunk-structured container — RIFF (5 chunks))
        HYPOTHESES
          [sub-region]    structured binary data  (75%)
          0x000048+256    Array of fixed-size records (stride=32, ×8)  (82%)
        LAYOUT  (960 bytes, 1 known, 1 unknown)
          0x000048–0x000147  KNOWN    Array of fixed-size records (stride=32, ×8) (82%)
          0x000148–0x0003e7  UNKNOWN  672 B
```

- **`[sub-region]`** — a file-wide hypothesis for the sub-slice (covers the entire sub-region)
- All offsets are file-absolute throughout the nested output
- Sub-regions with no hypotheses or smaller than 32 bytes are skipped silently

Use `--depth 0` to disable descent and restore the flat layout view.
Use `--depth 2` (or higher) to recurse further. For targeted exploration of a
known region, [`tiltshift descend`](/cli/descend) offers the same behaviour as
a standalone command.

### Signal sections

One section per signal type that produced results, listed after the layout:

- **MAGIC BYTES** — corpus matches with format name and hex signature
- **STRINGS** — null-terminated ASCII runs ≥ 4 bytes
- **LENGTH-PREFIXED BLOBS** — u8/u16/u32 prefix + matching body
- **CHUNK SEQUENCES** — IFF/RIFF/PNG-style tag+length+data runs
- **NUMERIC VALUE LANDMARKS** — file-size matches, powers of two, candidate offsets
- **NGRAM PROFILE** — bigram entropy and data-type hint
- **ALIGNMENT HINT** — dominant struct alignment (2/4/8/16 bytes)
- **REPEATING PATTERNS** — fixed-stride repeated byte sequences
- **TLV SEQUENCES** — type-length-value records in various widths
- **PADDING RUNS** — consecutive 0x00 or 0xFF bytes
- **CHI-SQUARE UNIFORMITY** — byte distribution test
- **VARIABLE-LENGTH INTEGERS** — LEB128 and UTF-8 multibyte runs
- **COMPRESSION PROBE** — zlib ratio
- **ENTROPY MAP** — per-block Shannon entropy with a visual bar
- **OFFSET GRAPH** — pointer/relocation tables detected via in-bounds integer clustering
- **PACKED FIELD** — bytes with independently-varying nibbles (BCD, 4-bit sub-fields)
- **BYTECODE STREAM** — format-agnostic bytecode detection via decode self-consistency

Followed by a **SUMMARY** count for each signal type.

## Examples

Basic analysis (recurses one level into sub-regions by default):

```bash
tiltshift analyze firmware.bin
```

Flat layout with no sub-region descent:

```bash
tiltshift analyze firmware.bin --depth 0
```

Two levels of recursive descent:

```bash
tiltshift analyze firmware.bin --depth 2
```

Larger entropy blocks for a coarser map:

```bash
tiltshift analyze firmware.bin --block-size 1024
```

JSON output for programmatic consumption:

```bash
tiltshift analyze firmware.bin --json | jq '.[] | select(.kind.MagicBytes)'
```

## JSON schema

The `--json` output is an array of signal objects. Each object has:

```json
{
  "region": { "offset": 0, "len": 4 },
  "confidence": 0.95,
  "reason": "matched PNG magic bytes at offset 0",
  "kind": {
    "MagicBytes": {
      "format": "PNG",
      "hex": "89 50 4e 47"
    }
  }
}
```

The `kind` field is a tagged enum — the key is the signal type and the value contains type-specific fields. See the [Signal Reference](/signals) for all signal types.
