# anomaly

Check a file against a structural model built from reference samples.

`tiltshift anomaly` builds a consensus signal model from two or more reference files, then compares the target file against that model. It reports:

- **Unexpected signals** — signals found in the target that are not in the reference model.
- **Missing signals** — signals present in every reference file that are absent from the target.

Useful for detecting structural outliers, modified files, or files that don't conform to a known format.

## Usage

```
tiltshift anomaly [OPTIONS] <TARGET> <REFS>...
```

## Arguments

| Argument | Description |
|----------|-------------|
| `<TARGET>` | The file to check for anomalies |
| `<REFS>...` | Two or more reference files defining the expected format |

## Options

| Option | Default | Description |
|--------|---------|-------------|
| `--threshold <F>` | `1.0` | Minimum fraction of refs a signal must appear in to be counted as expected (0.0–1.0) |
| `--block-size <N>` | `256` | Entropy block size in bytes |
| `--json` | off | Output JSON instead of human-readable text |

## Examples

### Basic usage

```sh
tiltshift anomaly suspect.bin ref1.bin ref2.bin ref3.bin
```

### Relax the threshold (signal must appear in 80% of refs)

```sh
tiltshift anomaly --threshold 0.8 suspect.bin ref1.bin ref2.bin ref3.bin ref4.bin
```

### Confirm a file is clean (zero anomalies)

```sh
tiltshift anomaly ref1.bin ref1.bin ref2.bin ref3.bin
```

### JSON output (for scripting)

```sh
tiltshift anomaly --json suspect.bin ref1.bin ref2.bin | jq .anomaly_class
```

## Output (text)

```
════════════════════════════════════════════════════════════
  tiltshift anomaly  —  suspect.bin
════════════════════════════════════════════════════════════

  Target:  suspect.bin   14832 bytes
  Model:   3 reference file(s), threshold 100%, 12 consensus signal(s)

  Anomaly score:  4  (medium)

UNEXPECTED SIGNALS  (3 — in target, not in model)
──────────────────────────────────────────────────────────
  MagicBytes            0x000200+4     "gzip"  conf=90%
  EntropyBlock          0x000200+256           conf=72%
  LengthPrefixedBlob    0x00040a+2     u16le  declared_len=1024  conf=65%

MISSING SIGNALS  (1 — in all 3 ref(s), absent from target)
──────────────────────────────────────────────────────────
  ChunkSequence         0x000008+...   RIFF  6 chunks  conf=88%  (expected from model)
```

### Anomaly classes

| Score | Class |
|-------|-------|
| 0 | `clean` |
| 1–3 | `low` |
| 4–9 | `medium` |
| ≥10 | `high` |

## Output (JSON)

```json
{
  "target": { "path": "suspect.bin", "size": 14832 },
  "refs": [
    { "path": "ref1.bin", "size": 14800 },
    { "path": "ref2.bin", "size": 14820 }
  ],
  "threshold": 1.0,
  "consensus_signals": 12,
  "anomaly_score": 4,
  "anomaly_class": "medium",
  "unexpected": [...],
  "missing": [...]
}
```

## Signal caching

`anomaly` reuses session caches (`.tiltshift.toml` sidecars) from previous `analyze` or `corpus` runs. If a file has already been analysed, extraction is skipped and the cached signals are used.

## See also

- [`corpus`](./corpus) — build and inspect the full consensus model
- [`analyze`](./analyze) — single-file signal analysis
- [`diff`](./diff) — byte-level structural delta between two files
