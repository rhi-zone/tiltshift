# probe

Show typed interpretations of bytes at a specific offset.

## Usage

```
tiltshift probe <file> <offset> [<len>]
```

## Arguments

| Argument | Default | Description |
|---|---|---|
| `<file>` | — | Path to the binary file |
| `<offset>` | — | Byte offset (decimal or `0x`-prefixed hex) |
| `<len>` | `8` | Number of bytes to read |

## Output

For the specified byte range, probe reports all plausible typed interpretations grouped by width:

- **u8 / i8** — single byte as unsigned and signed integer
- **u16le / u16be / i16le / i16be** — 16-bit integers, both endians
- **u32le / u32be / i32le / i32be / f32le / f32be** — 32-bit integers and floats
- **u64le / u64be / i64le / i64be / f64le / f64be** — 64-bit integers and floats
- **ascii** / **hex** — string views of the byte range

Interpretations include notes when the value is semantically interesting (e.g., matches file size, is within file bounds as an offset, is a power of two).

## Examples

Inspect the first 8 bytes of a file:

```bash
tiltshift probe unknown.bin 0
```

Read 16 bytes starting at offset 0x40 (decimal or hex both work):

```bash
tiltshift probe unknown.bin 0x40 16
tiltshift probe unknown.bin 64 16
```

## Example output

```
════════════════════════════════════════════════════════════
  probe  unknown.bin  @0x0  (8 bytes)
════════════════════════════════════════════════════════════
  bytes  89 50 4e 47 0d 0a 1a 0a
────────────────────────────────────────────────────────────
  u8              137
  i8              -119
────────────────────────────────────────────────────────────
  u16le           20617
  u16be           35152
  ...
────────────────────────────────────────────────────────────
  ascii           ".PNG...."
  hex             89504e470d0a1a0a
────────────────────────────────────────────────────────────
```
