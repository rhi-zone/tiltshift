# diff

Compare the structure of two binary files.

Bytes that are **identical at the same offset** in both files are **structural** — fixed headers, magic bytes, format tags, and framing that belongs to the format rather than the payload. Bytes that **differ** between files are **data fields** — the varying content that the format carries.

```
tiltshift diff <file_a> <file_b> [OPTIONS]
```

## Options

| Flag | Default | Description |
|---|---|---|
| `--min-structural <N>` | `4` | Minimum run of identical bytes to annotate in the byte map |
| `--block-size <N>` | `256` | Entropy block size in bytes |
| `--json` | — | Emit JSON instead of human-readable output |

## Output

### Header

Shows both file sizes and, if they differ, a note that only the common prefix is compared.

```
════════════════════════════════════════════════════════════
  tiltshift diff  a.bin  vs  b.bin
════════════════════════════════════════════════════════════

  file_a:  1234 bytes  (a.bin)
  file_b:  1234 bytes  (b.bin)

  structural:  800 of 1234 bytes  (64.8%)  identical
  data:        434 of 1234 bytes  (35.2%)  vary
```

### BYTE MAP

A run-length view of the structural delta. Each line is a contiguous run of identical or differing bytes. Structural runs that meet `--min-structural` are annotated with the signal kinds found within them.

```
BYTE MAP  (8 runs)
────────────────────────────────────────────────────────────
  [STRUCT] 0x000000+    8  → magic bytes
  [DATA  ] 0x000008+    4
  [STRUCT] 0x00000c+   20  → null-terminated string
  [DATA  ] 0x000020+  256
  ...
```

### SHARED SIGNALS

Signal extractors run on both files independently. A signal is **shared** when the same signal variant appears at the same byte offset in both files — confirming that the pattern belongs to the format rather than the specific file's payload.

```
SHARED SIGNALS  (3 structural markers confirmed in both files)
────────────────────────────────────────────────────────────
  magic bytes           0x000000+8   "PNG"  conf=99%
  chunk sequence        0x000000+1234   PNG  4 chunks  conf=88%
  alignment hint        0x000000+1234   align=4  conf=70%
```

### HYPOTHESES

Hypotheses are built from the shared signals only, reflecting what is **structurally confirmed** across both files.

### FILE_A / FILE_B ONLY SIGNALS

Signals that appear in only one file are data-dependent — they reflect the specific payload of that file, not the shared format.

## JSON output

```
tiltshift diff a.bin b.bin --json
```

The JSON output includes all runs, all signals (shared / file_a_only / file_b_only), and hypotheses:

```json
{
  "file_a": { "path": "a.bin", "size": 1234 },
  "file_b": { "path": "b.bin", "size": 1234 },
  "common_length": 1234,
  "structural_bytes": 800,
  "data_bytes": 434,
  "runs": [
    { "offset": 0, "len": 8, "kind": "structural" },
    { "offset": 8, "len": 4, "kind": "data" },
    ...
  ],
  "shared_signals": [ ... ],
  "file_a_only_signals": [ ... ],
  "file_b_only_signals": [ ... ],
  "hypotheses": [ ... ]
}
```

## Use cases

**Identify the fixed header of an unknown format.** Collect two or more sample files of the same format and run `diff`. The structural runs at the start of the file reveal the header layout; the data runs reveal where the payload begins.

**Validate a format hypothesis.** If you believe bytes 0–15 are a fixed magic header, `diff` lets you confirm that those bytes are truly invariant across samples.

**Find format variants.** Files from different format versions may share most structural fields but differ in a version byte or flag region. The byte map exposes exactly where the divergence is.

## Examples

```sh
# Compare two PNG files — reveals shared PNG header and chunk framing
tiltshift diff image1.png image2.png

# Use a larger min-structural threshold to suppress short coincidental matches
tiltshift diff a.bin b.bin --min-structural 16

# Full signal and hypothesis data as JSON for scripting
tiltshift diff a.bin b.bin --json | jq '.hypotheses[].label'
```
