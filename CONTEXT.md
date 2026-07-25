# Ubiquitous Language

Domain vocabulary for tiltshift. Use these terms precisely in code, docs, and conversations.

## Signal
_Avoid:_ finding, detection, match, result

A detected structural pattern with a confidence score, a region, and reasoning. A Signal is a typed observation — not just "something was found" but a specific `SignalKind` (magic bytes, entropy block, length-prefixed field, etc.) with associated evidence. Signals are inputs to the hypothesis engine, not conclusions.

## SignalKind
_Avoid:_ signal type, category

The discriminating variant of a Signal. Key variants (all distinct, not aliases):
- **MagicBytes** — known format signature matched at a specific offset
- **EntropyBlock** — a region with characteristically high or low Shannon entropy
- **ChunkSequence** — IFF/RIFF-style repeating tag+length+data with fixed-width tags
- **TlvSequence** — type-length-value sequences (variable tag/length widths)
- **LengthPrefixedBlob** — a single u8/u16/u32 length prefix followed by exactly that many bytes

ChunkSequence, TlvSequence, and LengthPrefixedBlob are three distinct variants — do not treat them as aliases.

## Region
_Avoid:_ range, span, area, section

A contiguous byte range with semantic meaning: an offset and a length. The fundamental unit of location in tiltshift. Signals, constraints, and hypotheses all reference regions.

## Hypothesis
_Avoid:_ conclusion, interpretation, result, finding

A proposed structural interpretation synthesized from one or more signals. Hypotheses are provisional — they feed back into constraint-driven analysis to narrow subsequent unknowns. A hypothesis is not a confirmed parse; it is a candidate that the engine may refine or discard.

## Constraint
_Avoid:_ rule, requirement, known region

A boundary established by prior analysis that narrows the search space for subsequent unknown regions. Two distinct sources:
- **Inferred**: derived from signals and hypotheses (e.g., "bytes 0–3 are a magic header")
- **User-provided**: explicit annotations supplied by the analyst

Do not conflate them — inferred constraints are provisional, user-provided constraints are authoritative.

## Annotation
_Avoid:_ label, tag, note

A user-authored structural claim about a specific region. Distinct from a signal (which is automatically detected) and a hypothesis (which is synthesized). Annotations surface as hypotheses with `user_provided: true` in the engine.

## Probe
_Avoid:_ read, parse, check

A targeted byte interpretation at a specific offset with a specific type (u32le, u32be, f32, ascii, etc.). A probe asks "if I interpret these bytes as X, does the result make sense?" and returns a `ProbeResult` with an `Interpretation`.

## EntropyBlock
_Avoid:_ compressed region, random region, entropy region

A region classified by its Shannon entropy profile. Transitions between entropy blocks are more informative than absolute entropy values — a sharp drop from high to low entropy often signals a header boundary. Not synonymous with "compressed" (high entropy) or "plaintext" (low entropy).

## NgramProfile
_Avoid:_ entropy, frequency analysis

A bigram (byte-pair) frequency distribution used to classify data type: text, binary, compressed, or executable. Distinct from entropy analysis — NgramProfile is a classifier that uses byte-pair frequencies, not information-theoretic entropy. Used in the file-wide characterization pass.

## BytecodeStream
_Avoid:_ executable, binary, code section

A region detected as bytecode via decode coverage and jump-target validity — not by matching a known format. By law, `BytecodeStream` signals store no format names: the detection is format-agnostic. Naming a specific VM in the signal is a violation.

## Corpus
_Avoid:_ database, library, format model

The bundled reference library of known formats (PNG, ZIP, ELF, etc.) used for magic byte matching and validation. Distinct from **FormatModel** — the corpus ships with tiltshift, a FormatModel is user-built.

## FormatModel
_Avoid:_ corpus, schema, format definition

A user-built structural model stored in `~/.config/` describing the expected layout of a specific format. Not part of the bundled corpus. The analyst builds FormatModels incrementally as they understand a new format.

## PartialSchema / LayoutSpan
_Avoid:_ schema, layout, structure

A partial, in-progress structural description of a region. LayoutSpans are the named sub-regions within a PartialSchema. Both are provisional — they represent current understanding, not a complete parse.

---

## The Feedback Loop

The core engine iterates: **signals → hypotheses → constraints → new signals**.

1. Extractors produce **Signals** from raw bytes
2. The hypothesis engine synthesizes **Hypotheses** from signals
3. Confirmed hypotheses become **Constraints** that narrow unknown regions
4. Constraints guide new probes and extraction passes on remaining unknowns

This is a cycle, not a pipeline. A constraint established in pass N enables signals in pass N+1 that were not visible before.
