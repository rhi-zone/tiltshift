# tiltshift — TODO

## Foundation

- [ ] Cargo workspace + `tiltshift-core` crate
- [ ] VitePress docs config (`docs/.vitepress/config.ts`, `docs/index.md`)
- [ ] Core data types: `Region`, `Signal`, `Hypothesis`, `PartialSchema`
- [ ] File loading with mmap for large inputs

## Signal extraction

- [ ] Byte frequency histogram
- [ ] Bigram / trigram frequency tables
- [ ] Shannon entropy (sliding window, not just point-in-time)
- [ ] Chi-square test for uniformity
- [ ] Compression ratio probe (try zlib/zstd on a region, measure result)
- [ ] Magic byte scanner (corpus of known magics: PNG, ZIP, ELF, PDF, BMP, WAV, ...)
- [ ] Null-terminated string scanner
- [ ] Length-prefixed blob detector (u8/u16/u32 × 3 endiannesses)
- [ ] Chunk pattern detector (tag + length + data, repeating — IFF/RIFF/PNG style)
- [ ] TLV detector (type-length-value, various widths)
- [ ] Alignment map (regularity at 2/4/8-byte boundaries)
- [ ] Repetition / stride detector (find arrays of structs)
- [ ] Numeric value semantics (high bits zero, power of two, matches file size, within-bounds pointer)
- [ ] Padding detector (runs of 0x00 or 0xFF)
- [ ] Pointer / offset graph builder
- [ ] Variable-length integer encoding detector (LEB128, UTF-8 continuation)
- [ ] Packed field detector (nibble-level independent variation)

## Hypothesis engine

- [ ] Signal → hypothesis conversion with confidence scoring
- [ ] Signal compounding: weak signals accumulate into stronger hypotheses
- [ ] `what_could_this_be(offset, len)` — ranked interpretations with reasoning
- [ ] Explanation generation: every hypothesis explains its contributing signals

## Iterative refinement

- [ ] Partial schema representation (some regions explained, others unknown)
- [ ] Constraint propagation: confirmed structure narrows remaining unknowns
- [ ] Recursive descent into confirmed sub-regions (chunk interior = fresh analysis target with context)
- [ ] Session state: persist partial results across invocations

## Multi-file analysis

- [ ] Structural delta (`diff(file_a, file_b)`) — field-level, not byte-level
- [ ] Cross-file magic correlation (same bytes at same offset across samples)
- [ ] Corpus model builder (feed N known-format files, extract structural model)
- [ ] Anomaly detection mode (file vs corpus model → what doesn't fit)

## Known format library

- [ ] PNG (chunk structure, IHDR/IDAT/IEND, zlib payload)
- [ ] ZIP (local file headers, central directory, EOCD)
- [ ] ELF (file header, program/section headers, symbol tables)
- [ ] BMP (file header, DIB header, pixel data)
- [ ] WAV (RIFF container, fmt/data chunks)
- [ ] PE (DOS header, PE header, section table)
- [ ] JPEG (SOI/EOI markers, segment structure)
- [ ] More formats as corpus grows

## CLI / output

- [ ] `tiltshift probe <file> <offset> [len]` — typed interpretations at offset
- [ ] `tiltshift scan <file> <pattern>` — find all occurrences
- [ ] `tiltshift analyze <file>` — full iterative analysis, structured output
- [ ] `tiltshift diff <file_a> <file_b>` — structural delta
- [ ] `tiltshift corpus add <format> <files...>` — add to known format library
- [ ] JSON output mode for agent consumption
- [ ] Confidence thresholds / verbosity flags

## Stretch

- [ ] REPL / interactive session for iterative exploration
- [ ] normalize integration (structural view of tiltshift's own output)
- [ ] paraphase integration (tiltshift output as format understanding input)
