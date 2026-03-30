# corpus

Build a structural consensus model from multiple files of the same format, or save one as a named format.

`corpus` has three subcommands: `build` (one-shot consensus), `add` (save a named format model), and `list` (inspect saved formats).

## corpus build

Extract a structural model from two or more binary files and print the consensus.

Finds signals present at the same offset across all (or a configurable fraction of) files. Files that diverge from the consensus are reported separately. Useful for reverse-engineering unknown binary formats when you have multiple samples.

### Usage

```
tiltshift corpus build [OPTIONS] <FILES>...
```

### Arguments

| Argument | Description |
|----------|-------------|
| `<FILES>...` | Two or more binary files to analyse |

### Options

| Option | Default | Description |
|--------|---------|-------------|
| `--threshold <F>` | `1.0` | Minimum fraction of files a signal must appear in (0.0–1.0). Use `0.8` to allow one file in five to be missing a signal. |
| `--block-size <N>` | `256` | Entropy block size in bytes |
| `--min-confidence <F>` | `0.0` | Only show signals and hypotheses at or above this confidence (0.0–1.0) |
| `--json` | off | Output JSON instead of human-readable text |

### Examples

```sh
tiltshift corpus build sample1.bin sample2.bin sample3.bin
```

```sh
tiltshift corpus build --threshold 0.8 *.bin
```

```sh
tiltshift corpus build --json a.bin b.bin | jq .hypotheses
```

## corpus add

Build a consensus model from reference files and save it as a named format.

The model is stored at `~/.config/tiltshift/formats/<format>.toml` and can be inspected with `corpus list`. Use `tiltshift anomaly` to check new files against a saved model.

### Usage

```
tiltshift corpus add [OPTIONS] <FORMAT> <FILES>...
```

### Arguments

| Argument | Description |
|----------|-------------|
| `<FORMAT>` | Short name for this format (e.g. `png`, `wav`, `elf`) |
| `<FILES>...` | Two or more representative files |

### Options

| Option | Default | Description |
|--------|---------|-------------|
| `--threshold <F>` | `1.0` | Minimum fraction of files a signal must appear in (0.0–1.0) |
| `--block-size <N>` | `256` | Entropy block size in bytes |
| `--min-confidence <F>` | `0.0` | Only include signals at or above this confidence (0.0–1.0) |

### Examples

```sh
tiltshift corpus add png ref1.png ref2.png ref3.png
```

```sh
tiltshift corpus add wav --threshold 0.8 sample1.wav sample2.wav
```

## corpus list

List all saved format models.

Shows all named formats stored at `~/.config/tiltshift/formats/`.

### Usage

```
tiltshift corpus list
```

## Output (text)

```
════════════════════════════════════════════════════════════
  tiltshift corpus  —  3 files
════════════════════════════════════════════════════════════

  file_a.bin   1234 bytes
  file_b.bin   1234 bytes
  file_c.bin   1236 bytes   (2 bytes longer than shortest)

  Consensus threshold:  100%  (signals in 3/3 files)
  Consensus signals:    7
  Common prefix length: 1234 bytes

CONSENSUS HYPOTHESES
──────────────────────────────────────────────────────────
  [file]      PNG image  (confidence 95%)
              why: Magic bytes 89 50 4E 47 + chunk sequence from offset 8

CONSENSUS LAYOUT
──────────────────────────────────────────────────────────
  0x000000–0x000007  KNOWN    PNG magic (100%)
  0x000008–0x00002b  KNOWN    Chunk structure (85%)
  0x00002c–0x0004d1  UNKNOWN  1190 B

PER-FILE DIVERGENCES
──────────────────────────────────────────────────────────
  file_a.bin:  2 unique signal(s)
    EntropyBlock  0x000200+256   conf=72%  (not in consensus)
  file_b.bin:  0 unique signal(s)
  file_c.bin:  1 unique signal(s)
    ...
```

## Output (JSON)

```json
{
  "files": [
    { "path": "file_a.bin", "size": 1234 },
    ...
  ],
  "threshold": 1.0,
  "min_count": 3,
  "common_prefix_length": 1234,
  "consensus_signals": [...],
  "hypotheses": [...],
  "per_file_divergences": {
    "file_a.bin": [...],
    ...
  }
}
```

## Signal caching

`corpus` reuses session caches (`.tiltshift.toml` sidecars) from previous `analyze` runs. If a file has already been analysed, extraction is skipped and the cached signals are used. This makes repeated `corpus` runs over large file sets fast.

## See also

- [`analyze`](./analyze) — single-file analysis
- [`anomaly`](./anomaly) — check a file against a saved model
- [`diff`](./diff) — structural delta between two files
- [`annotate`](./annotate) — tag known regions in a file
