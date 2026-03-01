# region

Show ranked interpretations of a specific byte range within a file.

## Usage

```
tiltshift region <file> <offset> <len> [--block-size <N>] [--json]
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
| `--block-size <N>` | `256` | Entropy block size in bytes |
| `--json` | off | Output JSON instead of human-readable text |

## Description

`region` runs the full signal extraction and hypothesis engine on a sub-slice
of a file and reports ranked hypotheses about what that byte range could be.
All displayed offsets are file-absolute (i.e. the base offset is added to
every slice-relative position).

This is useful for drilling into a specific area after `analyze` has given you
a layout — for example, examining an UNKNOWN span to see whether it looks like
a struct array, a string table, or something else entirely.

## Output sections

- **HYPOTHESES** — ranked interpretations of the region, highest-confidence first, with reasoning and alternatives
- **SIGNALS** — count of each signal type found within the region

## Examples

Analyze 256 bytes starting at offset 0x400:

```bash
tiltshift region firmware.bin 0x400 256
```

Using decimal arguments:

```bash
tiltshift region firmware.bin 1024 512
```

JSON output for programmatic use:

```bash
tiltshift region firmware.bin 0x80 64 --json
```

## JSON schema

The `--json` output wraps hypotheses and signals alongside the region coordinates:

```json
{
  "file": "firmware.bin",
  "offset": 128,
  "len": 64,
  "hypotheses": [ ... ],
  "signals": [ ... ]
}
```

`offset` and `len` are in bytes. Hypothesis and signal `region` fields within
the output are **slice-relative** (offset 0 = start of the requested region).
Add the top-level `offset` to convert to file-absolute positions.

The `hypotheses` array contains the same structure as produced by `analyze`.
The `signals` array contains the same tagged-enum signal objects. See the
[Signal Reference](/signals) for all signal types.
