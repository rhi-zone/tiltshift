use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};

use crate::types::Signal;

/// A single format entry: a name, a magic byte pattern, and an optional MIME type.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FormatEntry {
    pub name: String,
    /// Hex bytes, space-separated (e.g. `"89 50 4e 47"`).
    pub magic: String,
    pub mime: Option<String>,
}

impl FormatEntry {
    /// Parse the `magic` hex string into raw bytes.
    pub fn magic_bytes(&self) -> Result<Vec<u8>, String> {
        parse_hex(&self.magic)
    }
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Corpus {
    #[serde(rename = "format", default)]
    pub formats: Vec<FormatEntry>,
}

impl Corpus {
    fn merge(&mut self, other: Corpus) {
        self.formats.extend(other.formats);
    }
}

/// Parse a hex string (space-separated or compact) into bytes.
///
/// Accepts `"89 50 4e 47"` and `"89504e47"` interchangeably.
pub fn parse_hex(s: &str) -> Result<Vec<u8>, String> {
    let compact: String = s.chars().filter(|c| !c.is_whitespace()).collect();
    if compact.is_empty() {
        return Err("empty hex string".into());
    }
    if !compact.len().is_multiple_of(2) {
        return Err(format!("odd number of hex digits in {s:?}"));
    }
    compact
        .as_bytes()
        .chunks(2)
        .map(|chunk| {
            let pair = std::str::from_utf8(chunk).map_err(|e| e.to_string())?;
            u8::from_str_radix(pair, 16).map_err(|e| format!("{pair}: {e}"))
        })
        .collect()
}

const BUILTIN: &str = include_str!("../../data/magic.toml");

/// Load the merged corpus: built-ins + user global + project local.
///
/// Errors in user/project files are logged and skipped; built-in always loads.
pub fn load() -> Corpus {
    let mut corpus: Corpus = toml::from_str(BUILTIN)
        .expect("built-in magic.toml is always valid; this is a compile-time invariant");

    for path in user_corpus_paths() {
        match load_file(&path) {
            Ok(extra) => corpus.merge(extra),
            Err(e) if is_not_found(&e) => {}
            Err(e) => eprintln!("tiltshift: skipping corpus file {}: {e}", path.display()),
        }
    }

    corpus
}

fn is_not_found(e: &anyhow::Error) -> bool {
    e.downcast_ref::<std::io::Error>()
        .is_some_and(|io| io.kind() == std::io::ErrorKind::NotFound)
}

fn load_file(path: &Path) -> anyhow::Result<Corpus> {
    let text = std::fs::read_to_string(path)?;
    let corpus: Corpus = toml::from_str(&text)?;
    // validate all entries parse cleanly
    for entry in &corpus.formats {
        entry
            .magic_bytes()
            .map_err(|e| anyhow::anyhow!("entry {:?}: {e}", entry.name))?;
    }
    Ok(corpus)
}

/// Paths checked for user-supplied formats, in priority order (last wins).
fn user_corpus_paths() -> Vec<PathBuf> {
    let mut paths = Vec::new();

    // ~/.config/tiltshift/magic.toml
    if let Some(cfg) = config_dir() {
        paths.push(cfg.join("tiltshift").join("magic.toml"));
    }

    // .tiltshift/magic.toml  (project-local, checked into the repo)
    paths.push(PathBuf::from(".tiltshift/magic.toml"));

    paths
}

/// A named format model: consensus signals saved via `corpus add`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FormatModel {
    pub name: String,
    pub signals: Vec<Signal>,
}

/// Directory that holds saved format models.
///
/// `~/.config/tiltshift/formats/`
pub fn formats_dir() -> Option<PathBuf> {
    config_dir().map(|c| c.join("tiltshift").join("formats"))
}

/// Path to the TOML file for a saved format model.
///
/// `~/.config/tiltshift/formats/<name>.toml`
pub fn format_path(name: &str) -> Option<PathBuf> {
    formats_dir().map(|d| d.join(format!("{name}.toml")))
}

/// Save consensus signals as a named format model.
///
/// Creates the formats directory if it doesn't exist; overwrites any previous
/// model with the same name.
pub fn save_format(name: &str, signals: &[Signal]) -> anyhow::Result<PathBuf> {
    let path = format_path(name).ok_or_else(|| {
        anyhow::anyhow!("cannot determine config dir (no HOME or XDG_CONFIG_HOME)")
    })?;
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let model = FormatModel {
        name: name.to_string(),
        signals: signals.to_vec(),
    };
    let text = toml::to_string_pretty(&model)?;
    std::fs::write(&path, text)?;
    Ok(path)
}

/// Load a previously saved format model by name.
///
/// Returns `None` if the model file does not exist.
pub fn load_format(name: &str) -> anyhow::Result<Option<FormatModel>> {
    let path = match format_path(name) {
        Some(p) => p,
        None => anyhow::bail!("cannot determine config dir (no HOME or XDG_CONFIG_HOME)"),
    };
    match std::fs::read_to_string(&path) {
        Ok(text) => {
            let model: FormatModel = toml::from_str(&text)?;
            Ok(Some(model))
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(e.into()),
    }
}

fn config_dir() -> Option<PathBuf> {
    // Prefer XDG_CONFIG_HOME, fall back to ~/.config
    if let Ok(xdg) = std::env::var("XDG_CONFIG_HOME") {
        return Some(PathBuf::from(xdg));
    }
    std::env::var("HOME")
        .ok()
        .map(|h| PathBuf::from(h).join(".config"))
}

/// Append a new entry to the user's global corpus file.
///
/// Creates the file (and parent dirs) if they don't exist.
pub fn add_entry(name: &str, magic_hex: &str) -> anyhow::Result<PathBuf> {
    // validate hex before writing
    parse_hex(magic_hex).map_err(|e| anyhow::anyhow!("invalid magic hex: {e}"))?;

    let path = config_dir()
        .ok_or_else(|| anyhow::anyhow!("cannot determine config dir (no HOME or XDG_CONFIG_HOME)"))?
        .join("tiltshift")
        .join("magic.toml");

    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }

    // Normalize hex: lowercase, space-separated pairs
    let normalized = normalize_hex(magic_hex)?;

    let name_escaped = name.replace('\\', "\\\\").replace('"', "\\\"");
    let entry = format!("\n[[format]]\nname  = \"{name_escaped}\"\nmagic = \"{normalized}\"\n");
    use std::io::Write;
    let mut file = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(&path)?;
    file.write_all(entry.as_bytes())?;

    Ok(path)
}

fn normalize_hex(s: &str) -> anyhow::Result<String> {
    let bytes = parse_hex(s).map_err(|e| anyhow::anyhow!("{e}"))?;
    Ok(bytes
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect::<Vec<_>>()
        .join(" "))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_hex_compact() {
        assert_eq!(parse_hex("89504e47").unwrap(), b"\x89\x50\x4e\x47");
    }

    #[test]
    fn parse_hex_spaced() {
        assert_eq!(parse_hex("89 50 4e 47").unwrap(), b"\x89\x50\x4e\x47");
    }

    #[test]
    fn parse_hex_odd_fails() {
        assert!(parse_hex("89 5").is_err());
    }

    #[test]
    fn parse_hex_invalid_chars_fails() {
        assert!(parse_hex("89 zz").is_err());
    }

    #[test]
    fn builtin_corpus_loads_and_all_entries_valid() {
        let corpus: Corpus = toml::from_str(BUILTIN).unwrap();
        assert!(!corpus.formats.is_empty());
        for entry in &corpus.formats {
            entry.magic_bytes().unwrap_or_else(|e| {
                panic!("built-in entry {:?} has invalid magic: {e}", entry.name)
            });
        }
    }
}
