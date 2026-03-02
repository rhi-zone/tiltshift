//! Session state — persistent cache of signals and user annotations for a file.
//!
//! The sidecar file `<file>.tiltshift.toml` is written alongside the input file
//! after the first `analyze` run and updated by `annotate`. Signals are cached so
//! repeated analysis skips expensive re-extraction; annotations survive across runs.
//!
//! The cache is invalidated whenever the file size changes. A changed file with
//! the same size would reuse stale signals — note this as a known limitation.

use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::types::Signal;

/// A manually-assigned label for a byte range, added via `tiltshift annotate`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Annotation {
    pub offset: usize,
    pub len: usize,
    pub label: String,
}

/// The full persistent state associated with a single input file.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SessionState {
    /// Byte count of the file when this state was last written.
    ///
    /// Used to detect file changes; if `file_size` no longer matches the
    /// current file, cached signals are discarded and re-extracted.
    pub file_size: usize,
    /// Cached output of `signals::extract_all`. Empty until the first `analyze`.
    #[serde(default)]
    pub signals: Vec<Signal>,
    /// User-provided region labels added via `tiltshift annotate`.
    #[serde(default)]
    pub annotations: Vec<Annotation>,
}

impl SessionState {
    pub fn new(file_size: usize) -> Self {
        Self {
            file_size,
            signals: vec![],
            annotations: vec![],
        }
    }
}

/// Path of the sidecar TOML file for `file`.
///
/// `data.bin` → `data.bin.tiltshift.toml` (in the same directory).
pub fn sidecar_path(file: &Path) -> PathBuf {
    let name = file
        .file_name()
        .map(|n| format!("{}.tiltshift.toml", n.to_string_lossy()))
        .unwrap_or_else(|| "_.tiltshift.toml".to_string());
    file.with_file_name(name)
}

/// Load session state from `<file>.tiltshift.toml`.
///
/// Returns `None` if the sidecar does not exist or cannot be parsed.
pub fn load(file: &Path) -> Option<SessionState> {
    let path = sidecar_path(file);
    let text = std::fs::read_to_string(&path).ok()?;
    toml::from_str(&text).ok()
}

/// Persist `state` to `<file>.tiltshift.toml`.
///
/// Opens the destination file *before* serializing so that read-only paths
/// fail fast without paying the cost of TOML serialization (which can be
/// expensive when the state contains many signals).
pub fn save(file: &Path, state: &SessionState) -> anyhow::Result<()> {
    let path = sidecar_path(file);
    use std::io::Write;
    let mut dest = std::fs::OpenOptions::new()
        .create(true)
        .write(true)
        .truncate(true)
        .open(&path)?;
    let text = toml::to_string_pretty(state)?;
    dest.write_all(text.as_bytes())?;
    Ok(())
}
