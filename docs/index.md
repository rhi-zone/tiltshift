---
layout: home

hero:
  name: "tiltshift"
  text: "Binary structure extraction"
  tagline: "Progressively uncover the structure of unknown binary formats through signal analysis — chunk boundaries, length-prefixed fields, magic bytes, encoding patterns, and statistical anomalies."
  actions:
    - theme: brand
      text: Get Started
      link: /introduction
    - theme: alt
      text: Signal Reference
      link: /signals

features:
  - title: Signal Analysis
    details: 16 signal extractors covering statistical, structural, numeric, bit-level, pointer, and bytecode patterns. Each signal is annotated with confidence and reason.
  - title: Iterative Refinement
    details: Each confirmed structure becomes a constraint that narrows remaining unknowns. Analyze → hypothesize → refine → repeat.
  - title: Agent-Friendly Output
    details: JSON output mode for all commands. Designed to make implicit reverse engineering expertise queryable by agents and tooling.
  - title: Extensible Corpus
    details: 100+ built-in magic byte signatures. Add your own with `tiltshift magic add`. Corpus is shared across all commands.
---

## Quick Links

- [Introduction](/introduction) — what tiltshift is and how to use it
- [Signal Reference](/signals) — all signal types and what they mean
- [CLI Reference](/cli/analyze) — command documentation
