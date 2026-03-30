# cluster

Group files into clusters based on structural signal similarity using unsupervised HDBSCAN.

`tiltshift cluster` extracts a feature vector from each file's signals and runs HDBSCAN (Hierarchical Density-Based Spatial Clustering of Applications with Noise) to discover natural groupings — without specifying the number of classes in advance. Files that don't fit any cluster are reported as noise.

Useful when you have a directory of unknown files and want to identify how many distinct formats are present before diving into per-format analysis.

## Usage

```
tiltshift cluster [OPTIONS] <FILES>...
```

## Arguments

| Argument | Description |
|----------|-------------|
| `<FILES>...` | Files to cluster (supports globs, e.g. `*.unk`) |

## Options

| Option | Default | Description |
|--------|---------|-------------|
| `--min-cluster-size <N>` | `5` | Minimum number of files required to form a cluster. Lower values allow smaller clusters; raise to suppress noise. |
| `--block-size <N>` | `256` | Entropy block size in bytes for signal extraction |
| `--features` | off | Also show the raw 10-dimensional feature vector for each file |

## Examples

Cluster all unknown files in the current directory:

```bash
tiltshift cluster *.unk
```

Allow smaller clusters (useful when you have fewer samples per format):

```bash
tiltshift cluster --min-cluster-size 3 ~/corpus/*.unk
```

Show feature vectors alongside cluster assignments:

```bash
tiltshift cluster --features firmware/*.bin
```

## How it works

Each file is characterised by a 10-dimensional feature vector derived from its signals:

- Entropy (mean and variance across blocks)
- Compression ratio
- Chi-square p-value
- Ngram distribution class
- Presence and density of: magic bytes, strings, length-prefixed blobs, chunk sequences, TLV records

HDBSCAN then finds dense regions in this feature space. Files near the same region are grouped into a cluster; sparse outliers are labelled as noise (`-1`).

## Output

```
════════════════════════════════════════════════════════════
  tiltshift cluster  —  24 files
════════════════════════════════════════════════════════════

  Cluster 0  (8 files)
    file_a.unk
    file_b.unk
    file_c.unk
    ...

  Cluster 1  (6 files)
    file_x.unk
    file_y.unk
    ...

  Noise  (10 files — did not fit any cluster)
    file_p.unk
    file_q.unk
    ...
```

Each cluster represents a probable distinct file format or structural family. Investigate each cluster with `tiltshift corpus build` to find consensus signals, then `tiltshift analyze` on individual members.

## Workflow

A typical workflow for an unknown corpus:

```bash
# 1. Cluster to find how many format families exist
tiltshift cluster *.unk

# 2. For each cluster, build a consensus model
tiltshift corpus build cluster0-files/*.unk
tiltshift corpus build cluster1-files/*.unk

# 3. Analyze outliers individually
tiltshift analyze noise-file.unk
```

## See also

- [`corpus`](./corpus) — build a consensus model from a group of same-format files
- [`anomaly`](./anomaly) — check a file against a reference model
- [`analyze`](./analyze) — single-file signal analysis
