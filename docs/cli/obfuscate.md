# obfuscate

Copy a file to `<file>.unk` with all known magic bytes zeroed out.

## Usage

```
tiltshift obfuscate <file> [--force]
```

## Arguments

| Argument | Description |
|---|---|
| `<file>` | Path to the binary file to obfuscate |

## Options

| Option | Description |
|---|---|
| `--force` | Overwrite the output file if it already exists |

## Description

Scans the input file for all magic byte sequences in the corpus (built-in + user-defined), zeros them out in a copy, and writes the copy to `<file>.unk`.

The original file is not modified.

This is useful for testing signal extractors against files whose format has been deliberately obscured — the obfuscated file retains all structural properties (alignment, entropy regions, chunk boundaries, length-prefixed fields) except the format's identifying magic bytes.

## Example

```bash
tiltshift obfuscate sample.png
```

Output:

```
════════════════════════════════════════════════════════════
  tiltshift obfuscate  sample.png  (41820 bytes)
════════════════════════════════════════════════════════════
  zeroed 3 magic region(s):
  0x00000000  PNG  (8 bytes)
  0x0000000c  zlib  (2 bytes)
  0x0001a2f4  zlib  (2 bytes)

  output: sample.png.unk
```

## Use case

The `obfuscate` command is primarily a development and testing tool. Run `analyze` on the `.unk` file to verify that structural signals survive magic byte removal:

```bash
tiltshift obfuscate firmware.bin
tiltshift analyze firmware.bin.unk
```

If the signal extractors are working well, the structural signals (chunk sequences, length-prefixed blobs, entropy map) should be largely unaffected by zeroing the magic bytes.
