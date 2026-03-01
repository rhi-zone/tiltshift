# annotate

Tag a byte range with a human-readable label, persisted in a sidecar file
alongside the input.

## Usage

```
tiltshift annotate <file> <offset> <len> <label>
```

## Arguments

| Argument | Description |
|---|---|
| `<file>` | Path to the binary file to annotate |
| `<offset>` | Start of the region (decimal or `0x` hex) |
| `<len>` | Number of bytes to annotate (decimal or `0x` hex) |
| `<label>` | Human-readable name for this region |

## Description

`annotate` writes a region label to `<file>.tiltshift.toml` — a TOML
sidecar stored in the same directory as the input file. The label survives
re-analysis: the next time you run `tiltshift analyze`, the annotated region
appears as an `ANNOTATED` span in the LAYOUT section and a `[user]` entry in
the HYPOTHESES section.

If an annotation already exists for the **same offset and length**, it is
replaced. Annotations at different positions are accumulated independently.

### The sidecar file

The sidecar (`<file>.tiltshift.toml`) also caches the signal extraction
results produced by `analyze`. Both pieces of state live in the same file:

```toml
file_size = 4096

[[annotations]]
offset = 0
len = 4
label = "Magic header"

[[annotations]]
offset = 8
len = 56
label = "File header struct"

[[signals]]
# ... cached signals (written by analyze, not edited manually)
```

You can edit the sidecar by hand to rename or add annotations — any valid
TOML that matches the schema is accepted on the next `analyze` run.

### Signal cache invalidation

The cached signals are reused as long as the file's byte count matches the
value stored in `file_size`. If the file grows or shrinks, signals are
discarded and re-extracted on the next `analyze` run.

::: warning
If a file is replaced with a different file of the **same size**, the cached
signals will be stale. Delete the sidecar to force re-extraction.
:::

## Output

```
annotated  0x000000+4  "Magic header"
  saved → /path/to/data.bin.tiltshift.toml
```

## Effect on `analyze`

After annotating, `tiltshift analyze` reflects the annotation:

```
════════════════════════════════════════════════════════════
  tiltshift  data.bin  (4096 bytes)
  2 user annotation(s)  (sidecar: data.bin.tiltshift.toml)
════════════════════════════════════════════════════════════

HYPOTHESES
────────────────────────────────────────────────────────────
  0x000000+4   Magic header  [user]  (confidence 100%)
  0x000008+56  File header struct  [user]  (confidence 100%)
  …

LAYOUT  (4096 bytes, 3 known, 1 unknown)
────────────────────────────────────────────────────────────
  0x000000–0x000003  ANNOTATED  Magic header (100%)
  0x000004–0x000007  UNKNOWN  4 B
  0x000008–0x00003f  ANNOTATED  File header struct (100%)
  0x000040–0x000fff  KNOWN    … (auto-detected)
```

Annotated spans are not recursed into by [`analyze --depth`](/cli/analyze#layout)
— they represent regions the analyst has already identified, so automatic
descent would add noise rather than insight.

## Examples

Tag the first four bytes as a magic header:

```bash
tiltshift annotate firmware.bin 0 4 "Magic header"
```

Tag a known struct at a hex offset:

```bash
tiltshift annotate firmware.bin 0x40 64 "Resource table"
```

Replace an existing annotation:

```bash
tiltshift annotate firmware.bin 0x40 64 "Corrected: index table"
```

Then verify in the layout:

```bash
tiltshift analyze firmware.bin
```
