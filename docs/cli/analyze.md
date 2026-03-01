# analyze

Run all signal extractors on a file and report findings.

## Usage

```
tiltshift analyze <file> [--block-size <N>] [--json]
```

## Arguments

| Argument | Description |
|---|---|
| `<file>` | Path to the binary file to analyze |

## Options

| Option | Default | Description |
|---|---|---|
| `--block-size <N>` | `256` | Entropy block size in bytes |
| `--json` | off | Output JSON instead of human-readable text |

## Output sections

The human-readable output includes a section for each signal type that produced results:

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

Followed by a **SUMMARY** count for each signal type.

## Examples

Basic analysis:

```bash
tiltshift analyze firmware.bin
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
