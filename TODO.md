# tiltshift — TODO

## Next up (priority order)

1. ~~**Length-prefixed blob detector** — u8/u16/u32 × LE/BE~~  ✓ done (`391da57`)
2. ~~**Chunk pattern detector** — IFF/RIFF/PNG style~~  ✓ done (`e220de7`)
3. ~~**Numeric value semantics** — scan all u32le/be values~~  ✓ done (`d88f92e`)
4. ~~**Ngram frequency tables** — bigram/trigram tables~~  ✓ done (`cbcb64e`)
5. ~~**`tiltshift scan <file> <pattern>`** — find all occurrences of a byte pattern in a file~~  ✓ done (`c26ff1b`)

## Foundation

<!-- Core types flow directly from the iterative loop model: signals(region) → hypotheses → partial_parse → new_constraints (DESIGN.md § The iterative loop) -->

- [x] Cargo workspace + `tiltshift` crate (single crate with lib + bin targets)
- [x] VitePress docs config (`docs/.vitepress/config.ts`, `docs/index.md`)  ✓ done (`e30a9d1`)
- [x] Core data types: `Region`, `Signal`, `Hypothesis`, `PartialSchema`
- [x] File loading with mmap for large inputs

## Signal extraction

<!-- Full taxonomy in DESIGN.md § Signal taxonomy — statistical, structural, numeric, pointer/offset, bit-level, multi-file -->

- [x] Byte frequency histogram — shape indicates data type (DESIGN: Statistical signals)
- [x] Bigram / trigram frequency tables — discriminate types better than entropy alone; repeated ngrams at fixed stride → struct fields (DESIGN: Statistical signals)
- [x] Shannon entropy (sliding window, not just point-in-time) — transitions between regions > absolute values (DESIGN: Statistical signals)
- [x] Chi-square test for uniformity (DESIGN: Statistical signals)  ✓ done (`617a3c8`)
- [x] Compression ratio probe (try zlib/zstd on a region, measure result) — more honest proxy for randomness than entropy (DESIGN: Statistical signals)  ✓ done
- [x] Magic byte scanner — 102-entry corpus in data/magic.toml, extensible via `magic add`; detects at non-zero offsets (DESIGN: Structural signals)
- [x] Null-terminated string scanner — use as structural anchors (DESIGN: Structural signals)
- [x] Length-prefixed blob detector (u8/u16/u32 × LE/BE) — especially strong when followed by printable ASCII (DESIGN: Structural signals)
- [x] Chunk pattern detector (tag + length + data, repeating — IFF/RIFF/PNG style) (DESIGN: Structural signals)
- [x] TLV detector (type-length-value, various widths) (DESIGN: Structural signals)
- [x] Alignment map (regularity at 2/4/8-byte boundaries) — find struct boundaries (DESIGN: Structural signals)
- [x] Repetition / stride detector (find arrays of structs) (DESIGN: Structural signals)  ✓ done (covered by `ngram.rs` stride_patterns → `RepeatedPattern`)
- [x] Numeric value semantics (power of two, matches file size, within-bounds pointer in header region) (DESIGN: Numeric value semantics)
- [x] Padding detector (runs of 0x00 or 0xFF) (DESIGN: Numeric value semantics)
- [x] Pointer / offset graph builder — render as graph; pointer chasing should be automatic (DESIGN: Pointer / offset graph)  ✓ done
- [x] Variable-length integer encoding detector (LEB128, UTF-8 continuation) (DESIGN: Bit-level signals)  ✓ done
- [x] Packed field detector (nibble-level independent variation) (DESIGN: Bit-level signals)  ✓ done (`d4d1108`)
- [x] **Bytecode stream detector** — `signals/bytecode.rs`; phases 1–3; `BytecodeStream` signal kind; frequency analysis (top-5 dominance gate)  ✓ done (`edcd709`, `060fb95`)

## Bytecode grammar discovery

<!-- Full design in DESIGN.md § Bytecode grammar discovery.
     Laws: no format knowledge in signal; self-consistency oracle only;
     grammar files are outputs not inputs. Must derive WASM/pyc/JVM/x86
     from first principles or the tool has failed. -->

- [x] **Phase 1 — fixed-width scan** — entropy separation H(operands)−H(opcodes) > 0.5 bits; W∈{1,2,3,4,8}  ✓ done
- [x] **Phase 2 — variable-width bootstrap** — greedy lookahead, ≤3 passes, coverage-delta < 0.01 exit  ✓ done
- [x] **Phase 3 — jump target validation** — branch operands landing on instruction boundaries  ✓ done
- [x] **`BytecodeStream` signal kind** — entry_point, decode_coverage, jump_validity, instruction_count, fixed_width, opcode_widths  ✓ done
- [x] **Frequency analysis** — top-5 opcode dominance hard gate (≥ 0.20); entropy_sep_norm in confidence  ✓ done
- [x] **`tiltshift decode <file> <offset> <format>`** — display command only; reads `~/.config/tiltshift/opcodes/<format>.toml`; never feeds back into discovery  ✓ done
- [x] **`tiltshift opcodes add/list`** — install and list grammar files; validates TOML, copies to config dir  ✓ done

## Hypothesis engine

<!-- Differentiator is feedback richness: what was found, confidence + contributing signals, why, alternatives considered, what remains (DESIGN.md § Output quality) -->

- [x] Signal → hypothesis conversion with confidence scoring  ✓ done (`hypothesis.rs`)
- [x] Signal compounding: weak signals accumulate into stronger hypotheses — MagicBytes+ChunkSequence → confirmed format; TLV+LEB128 → protobuf-like; RepeatedPattern+AlignmentHint → aligned struct array  ✓ done (`f4245b2`)
- [x] `what_could_this_be(offset, len)` — ranked interpretations with reasoning (DESIGN: Primitive API)  ✓ done (`tiltshift region <file> <offset> <len>`)
- [x] Explanation generation: every hypothesis explains its contributing signals and alternatives considered (DESIGN: Output quality)  ✓ done (`6564112`)

## Iterative refinement

<!-- Core loop: signals(region) → hypotheses → partial_parse → new_constraints → signals(subregion) → ... (DESIGN.md § The iterative loop) -->

- [x] Partial schema representation (some regions explained, others unknown) — e.g. `[KNOWN: 0x00–0x3F] [UNKNOWN: 0x40–0x7F] [KNOWN: chunk @ 0x80]`  ✓ done (`5355191`)
- [x] Constraint propagation: confirmed structure narrows remaining unknowns — unknown region's size/context/neighbors become known  ✓ done (`83df6ca`)
- [x] Recursive descent into confirmed sub-regions — chunk interior = fresh analysis target whose type tag, position, size feed back as constraints (DESIGN: The iterative loop)  ✓ done (`analyze --depth N`, `tiltshift descend`)
- [x] Session state: persist partial results across invocations  ✓ done (`43db419`, `tiltshift annotate`, `<file>.tiltshift.toml` sidecar)

## Multi-file analysis

<!-- Two unknown files: correlate to separate structural fields from data fields. Known formats: validate signals, build reference library. (DESIGN.md § Known vs unknown formats, § Multi-file signals) -->

- [x] Structural delta (`diff(file_a, file_b)`) — field-level, not byte-level; fields that vary=data, identical=structural (DESIGN: Multi-file signals)  ✓ done (`tiltshift diff`)
- [x] Cross-file magic correlation (same bytes at same offset across samples) (DESIGN: Multi-file signals)  ✓ done (covered by `tiltshift corpus`)
- [x] Corpus model builder (feed N known-format files, extract structural model) — known formats are the training data and validation set (DESIGN: Known vs unknown formats)  ✓ done (`tiltshift corpus`)
- [x] Anomaly detection mode (file vs corpus model → what doesn't fit) — steganography detection is a natural byproduct (DESIGN: Scope)  ✓ done (`tiltshift anomaly`)

## Signal tuning backlog (from corpus validation, 608 files)

Real-world validation on 608 obfuscated corpus files revealed the following remaining issues after `fix(signals)` commit (369da66):

### Fixed in 369da66
- 2-byte magic false positives at non-zero offsets (ff f3, 78 9c, 4d 5a etc.)
- LEB128 false positives in compressed data (> 40% high bytes → skip)
- TLV false positives in compressed data (same gate)
- RepeatedPattern deduplication by stride (adjacent phase offsets → keep best)

### Remaining issues (descending priority)
- **Short null-terminated strings in large uncompressed images**: 4-7 byte accidental runs are common in uncompressed pixel data (PNG with no-compression IDAT). Expected ~21000 false positives in a 21MB uncompressed image. Possible fixes: raise MIN_STRING_BYTES from 4 to 8, or add local-context entropy check (skip if surrounding byte entropy too high).
- **3-byte magic patterns at non-zero offsets in large files**: "FWS" (SWF), "MP+" (Musepack), "ID3", "JPEG XR" each get multiple hits in 21MB uncompressed image. Each 3-byte pattern has ~1.3 expected false hits per 21MB; seeing more (~5-10) suggests the null-byte distribution in images boosts some patterns. Consider lowering confidence for 3-byte hits at non-zero offsets (0.95 → 0.75) so they sort below stronger signals.
- **Offset graph with very few edges (2 nodes, 1 edge) at 50% confidence**: too weak to be useful. Minimum edge count should probably be 3+, or confidence for 1-edge graphs should be ≤ 0.40.
- **NumericValue power-of-two signals in sub-region LAYOUT**: generates many low-confidence signals in recursive descent. Already at 40% confidence, but still appears in top-20 for small files with many power-of-two pixel values.

- **GIF false positive → "Protobuf-like"**: pat.unk and shy.unk are GIF89a files. After stripping the 6-byte magic, GIF's sub-block structure (1-byte size + data, repeat until 0x00) looks exactly like u8+u8 TLV. LZW-compressed pixel data has ~38% high bytes — just under the 40% suppression gate — so LEB128 detection runs on it and the Protobuf compound fires. GIF has distinctive features that could be detected: `0x21`/`0x2C`/`0x3B` block markers, 3×N-byte RGB palette immediately after screen descriptor, "NETSCAPE2.0" string in animated GIFs, LZW min-code-size byte before each image. The LZW high-byte fraction gate could be tuned to 35% to suppress on GIF.

### Positive findings (working well)
- PNG detection via "IHDR" null-terminated string at offset 0x0c (stripped magic → still identified)
- WebP detection via "VP8X" / "ALPH" chunk tags (ChunkSequence works without RIFF magic)
- MP3 detection via "mLAME" encoder tag string
- BytecodeStream detecting shader bytecode (assets.unk: W=8, 353 instrs, 100% coverage, 64-77% jump validity)
- PNG IDAT chunk stride detection (stride=16396 = 16384+12, ×86 occurrences for shewasahewasa.unk)

## Known format library

<!-- Running tiltshift on known formats validates signals; results become reference models for detecting fragments in unknown data. (DESIGN.md § Known vs unknown formats) -->

- [ ] PNG (chunk structure, IHDR/IDAT/IEND, zlib payload)
- [ ] ZIP (local file headers, central directory, EOCD)
- [ ] ELF (file header, program/section headers, symbol tables)
- [ ] BMP (file header, DIB header, pixel data)
- [ ] WAV (RIFF container, fmt/data chunks)
- [ ] PE (DOS header, PE header, section table)
- [ ] JPEG (SOI/EOI markers, segment structure)
- [ ] More formats as corpus grows

## CLI / output

<!-- Commands map to the Primitive API sketch in DESIGN.md § Primitive API; JSON mode enables agent consumption (DESIGN.md § Problem space) -->

- [x] `tiltshift probe <file> <offset> [len]` — typed interpretations at offset (DESIGN: Primitive API `probe`)
- [x] `tiltshift scan <file> <pattern>` — find all occurrences (DESIGN: Primitive API `scan`)
- [x] `tiltshift analyze <file>` — runs all signals, outputs magic/strings/entropy map
- [x] `tiltshift region <file> <offset> <len>` — ranked interpretations of a sub-range  ✓ done (`802b694`, docs `b9588a6`)
- [x] `tiltshift diff <file_a> <file_b>` — structural delta (DESIGN: Primitive API `diff`)  ✓ done
- [x] `tiltshift corpus add <format> <files...>` — add to known format library  ✓ done (`corpus build` / `corpus add` / `corpus list`)
- [x] JSON output mode for agent consumption (`--json` flag on `analyze`)
- [x] Confidence thresholds / verbosity flags  ✓ done (`9ed3ecb`, `--min-confidence`, `--verbose`)

## Performance

- [x] `offset_graph` early-exit on density > 50% (mid-scan bail-out avoids building union-find for noisy data)  ✓ done
- [x] `length_prefix` O(n²) body scanning fixed: body quality now sampled (max 512 bytes), body capped at 4 KB/64 KB, printable ≥ 50% required for u16/u32  ✓ done
- [x] `session::save` serialized signals before checking writability — now opens file first to fail fast on read-only paths  ✓ done
- Net result: 1.5 MB ELF analysis 90 s → ~2 s (release build)

## Stretch

- [x] `tiltshift obfuscate <file>` — copy file to `<filename>.unk` then zero out known magic bytes to produce an opaque blob for analysis testing  ✓ done
- [x] **`length_prefix` stride extension** — histogram over inter-blob gaps finds consistent non-zero gaps; `inter_blob_gap: usize` field added to `LengthPrefixedBlob` (0 = exact, N = N-byte gap); ≥3 blobs required for stride>0  ✓ done (`69b026a`)
- [ ] V8 compressed pointer cluster — u32 values with low bit=1 (tagged pointers), narrow upper-32 range (shared cage base); emit `CompressedPointerCluster` signal (future extension of offset graph)
- [ ] Integration test on real .pyc file — verify BytecodeStream emits (W=2 expected for CPython 3.6+); need a sample .pyc or generate one with `python3 -c "import py_compile; py_compile.compile('x.py')"` and strip the 16-byte header first
- [ ] REPL / interactive session for iterative exploration
- [ ] normalize integration (structural view of tiltshift's own output) — same pattern, different domain (DESIGN: Relation to rhi ecosystem)
- [ ] paraphase integration (tiltshift output as format understanding input) — paraphase needs format understanding before planning conversion routes (DESIGN: Relation to rhi ecosystem)
