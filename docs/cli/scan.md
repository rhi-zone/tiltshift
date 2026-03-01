# scan

Search a file for all occurrences of a byte pattern.

## Usage

```
tiltshift scan <file> <pattern> [--context <N>] [--json]
```

## Arguments

| Argument | Description |
|---|---|
| `<file>` | Path to the binary file to search |
| `<pattern>` | Hex bytes to search for |

## Options

| Option | Default | Description |
|---|---|---|
| `--context <N>` | `8` | Extra bytes of hex context to display after each hit |
| `--json` | off | Output JSON instead of human-readable text |

## Pattern format

Patterns are hex strings, either space-separated or compact:

```bash
tiltshift scan data.bin "89 50 4e 47"   # space-separated
tiltshift scan data.bin 89504e47        # compact
```

Both forms produce identical results.

## Examples

Find all PNG magic byte sequences:

```bash
tiltshift scan archive.bin "89 50 4e 47"
```

Find all occurrences of a 2-byte sequence with extra context:

```bash
tiltshift scan data.bin "ff d8" --context 16
```

JSON output:

```bash
tiltshift scan data.bin deadbeef --json
```

## Example output

```
════════════════════════════════════════════════════════════
  scan  archive.bin  pattern=[89 50 4e 47]  (4 bytes)
════════════════════════════════════════════════════════════
  0x00000000  [89 50 4e 47]  +0d 0a 1a 0a 00 00 00 0d
  0x00041820  [89 50 4e 47]  +0d 0a 1a 0a 00 00 00 0d

  2 hit(s)
```

## JSON schema

```json
[
  { "offset": 0, "hex": "89 50 4e 47 0d 0a 1a 0a 00 00 00 0d" },
  { "offset": 268320, "hex": "89 50 4e 47 0d 0a 1a 0a 00 00 00 0d" }
]
```

The `hex` field includes both the matched pattern bytes and the requested context bytes.
