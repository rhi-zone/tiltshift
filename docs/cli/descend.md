# descend

Recursively analyze a specific byte range of a file, descending into any
identified sub-structures.

## Usage

```
tiltshift descend <file> <offset> <len> [--depth <N>] [--block-size <N>]
```

## Arguments

| Argument | Description |
|---|---|
| `<file>` | Path to the binary file to inspect |
| `<offset>` | Start of the region (decimal or `0x` hex) |
| `<len>` | Number of bytes to analyze (decimal or `0x` hex) |

## Options

| Option | Default | Description |
|---|---|---|
| `--depth <N>` | `1` | Maximum recursion depth (0 = no sub-region descent) |
| `--block-size <N>` | `256` | Entropy block size in bytes |

## Description

`descend` runs signal extraction and hypothesis building on the specified byte
range, then recurses into any KNOWN sub-spans — running a fresh analysis on
each — up to `--depth` levels deep.

It is the manual counterpart to the automatic descent built into
[`analyze --depth`](/cli/analyze#layout). Use it when you already know the
offset and length of a region of interest and want to explore its internal
structure without running a full file analysis.

All displayed offsets are **file-absolute** — the base offset is added to
every sub-region position throughout the output.

### Comparison with `region`

| | `region` | `descend` |
|---|---|---|
| Runs signal extraction on the sub-slice | yes | yes |
| Shows HYPOTHESES | yes | yes |
| Shows LAYOUT of sub-region | no | yes |
| Recurses into sub-sub-regions | no | yes (up to `--depth`) |
| Shows detailed per-signal sections | no | no |
| JSON output | yes | no |

Use `region` when you want a quick ranked list of interpretations.
Use `descend` when you want to explore the internal structure of a known blob —
chunk body, length-prefixed payload, embedded container, etc.

## Output

The output shows HYPOTHESES and LAYOUT for the requested range, then for each
KNOWN span that is at least 32 bytes, an indented sub-analysis:

```
════════════════════════════════════════════════════════════
  tiltshift descend  firmware.bin  0x000040+1024  (1024 bytes)
════════════════════════════════════════════════════════════
HYPOTHESES
  [sub-region]    RIFF container  (95%)
    why: Bytes 52 49 46 46 at offset 0x40 match the RIFF signature …
  0x000048+960    Chunk-structured container — RIFF (5 chunks)  (88%)
    why: 5 consecutive RIFF-layout chunks starting 8 bytes after the header …

LAYOUT  (1024 bytes, 2 known, 1 unknown)
  0x000040–0x000047  KNOWN    RIFF container (95%)
  0x000048–0x0003e7  KNOWN    Chunk-structured container — RIFF (5 chunks) (88%)
      ↳ sub-region 0x000048+960 (inside: Chunk-structured container — RIFF (5 chunks))
        HYPOTHESES
          [sub-region]    structured binary data  (75%)
          0x000048+256    Array of fixed-size records (stride=32, ×8)  (82%)
        LAYOUT  (960 bytes, 1 known, 1 unknown)
          0x000048–0x000147  KNOWN    Array of fixed-size records (stride=32, ×8) (82%)
          0x000148–0x0003e7  UNKNOWN  672 B
  0x0003e8–0x00043f  UNKNOWN  88 B
```

Each `↳` line introduces a sub-region. HYPOTHESES and LAYOUT within it use
the same format as the top level, indented by two spaces per depth level.

Sub-regions smaller than 32 bytes are skipped (too small to yield useful
signals). If a sub-region produces no hypotheses, it is also skipped.

## Examples

Descend one level into a chunk body at offset 0x48:

```bash
tiltshift descend firmware.bin 0x48 960
```

Descend two levels deep:

```bash
tiltshift descend firmware.bin 0x48 960 --depth 2
```

Show only the top-level analysis without recursing:

```bash
tiltshift descend firmware.bin 0x48 960 --depth 0
```

Using decimal arguments:

```bash
tiltshift descend firmware.bin 72 960
```
