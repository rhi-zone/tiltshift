# magic

Manage the magic byte corpus.

## Subcommands

### magic add

Register a new magic byte signature in your user corpus.

```
tiltshift magic add <name> <magic>
```

| Argument | Description |
|---|---|
| `<name>` | Human-readable format name |
| `<magic>` | Hex bytes (space-separated or compact) |

The signature is stored in `~/.config/tiltshift/magic.toml` and is immediately available to `analyze`, `scan`, and `obfuscate`.

**Examples:**

```bash
tiltshift magic add "My Format" "4d 59 46 4d"
tiltshift magic add "My Format" 4d59464d
```

### magic list

List all known magic byte signatures (built-in + user-defined).

```
tiltshift magic list [--filter <text>]
```

| Option | Description |
|---|---|
| `--filter <text>`, `-f <text>` | Case-insensitive substring filter on format name |

**Examples:**

```bash
tiltshift magic list
tiltshift magic list --filter png
tiltshift magic list -f zip
```

## Built-in corpus

The built-in corpus covers 100+ common formats including:

- Image formats: PNG, JPEG, GIF, BMP, TIFF, WebP, AVIF, HEIC, ICO, PSD
- Archive formats: ZIP, gzip, bzip2, xz, zstd, 7-Zip, RAR, tar
- Document formats: PDF, DOCX/XLSX/PPTX (ZIP-based), ODF
- Executable formats: ELF, PE/MZ, Mach-O, WASM
- Media formats: MP3, MP4, WAV, FLAC, OGG, AVI, MKV
- Database/data: SQLite, Parquet, Arrow, HDF5, LLVM bitcode
- Font formats: TTF/OTF, WOFF, WOFF2
- Certificate/key formats: PEM, DER, PKCS12

Use `magic list` to see the complete corpus with hex signatures and MIME types.
