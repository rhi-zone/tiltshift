# tiltshift

Iterative structure extraction from opaque binary data.

tiltshift progressively uncovers the structure of binary formats through signal analysis — finding chunk boundaries, length-prefixed fields, magic bytes, encoding patterns, and statistical anomalies. each pass informs the next, converging on a structural model of whatever you feed it.

useful for reverse engineering unknown formats, validating known ones, detecting anomalies, and building format corpora.

## Status

Active development. Signal extraction layer is functional (13 extractors). Hypothesis engine is next.

## Links

- [Documentation](https://docs.rhi.zone/tiltshift/)
- [rhi ecosystem](https://rhi.zone/)
