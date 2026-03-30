# Introduction

tiltshift is a binary analysis tool that progressively uncovers the structure of unknown or opaque binary formats through signal analysis.

## Core thesis

Binary format reverse engineering is an iterative process of uncovering pre-existing structure — not constructing a model, but gaining visibility into something that was always there and is fixed. Each analysis pass reveals partial structure; that partial structure constrains and informs the next pass. You stop when you're satisfied, not when the tool signals completion.

The structure always existed. You're just progressively less wrong about it.

## What tiltshift does

tiltshift operates at the **structural** layer, not the semantic layer:

| In scope | Out of scope |
|---|---|
| Field boundaries | What the data means |
| Encoding detection | Application logic |
| Chunk structure | Disassembly / decompilation |
| Anomaly detection | Cryptographic analysis |
| Embedded format detection | Steganography solving |

It runs 16 signal extractors simultaneously and reports what it finds, with confidence scores and reasoning. Useful for unknown formats, validating known ones, detecting anomalies, and building format corpora.

## Installation

```bash
cargo install --path tiltshift
```

Or build from source:

```bash
git clone https://github.com/rhi-zone/tiltshift
cd tiltshift
cargo build --release
```

## Quick start

Run all signal extractors on a file:

```bash
tiltshift analyze mystery.bin
```

Inspect bytes at a specific offset:

```bash
tiltshift probe mystery.bin 0x40
```

Search for a byte pattern:

```bash
tiltshift scan mystery.bin "89 50 4e 47"
```

## The iterative loop

```
signals(region) → hypotheses → partial_parse → new_constraints → signals(subregion) → ...
```

Each confirmed structural element becomes a constraint that narrows the remaining unknowns:

```
[KNOWN: header 0x00–0x3F] [UNKNOWN: 0x40–0x7F] [KNOWN: chunk @ 0x80]
```

The unknown region's *size* is now known (64 bytes), its neighboring context is known, and if multiple files are available, that region can be diffed in isolation. Once a chunk boundary is confirmed, its interior becomes a fresh analysis target whose context (type tag, position, size) feeds back into signal extraction as additional constraints.

## Relation to the rhi ecosystem

- **paraphase** needs to understand source formats before planning conversion routes — tiltshift provides that understanding
- **reincarnate** lifts legacy software; understanding the binary formats that software reads/writes is half the job
- **rescribe** handles document formats; tiltshift handles the unknown/undocumented ones upstream
- **normalize** does structural views of source code; tiltshift does structural views of binary data — same pattern, different domain
