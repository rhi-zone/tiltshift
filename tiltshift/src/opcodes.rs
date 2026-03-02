//! Opcode grammar files — human-authored lookup tables for the `decode` command.
//!
//! Grammar files are outputs of human verification, never read by signal
//! extractors.  The `BytecodeStream` signal discovers structure without them;
//! grammar files let you name the opcodes after you've identified the format.
//!
//! ## Storage
//!
//! `~/.config/tiltshift/opcodes/<name>.toml`
//!
//! ## TOML format
//!
//! ```toml
//! name        = "my-vm"
//! description = "Simple stack machine"
//!
//! [[opcodes]]
//! byte          = 0x01
//! mnemonic      = "PUSH"
//! operand_bytes = 1
//!
//! [[opcodes]]
//! byte          = 0x02
//! mnemonic      = "ADD"
//! operand_bytes = 0
//! ```

use std::path::PathBuf;

use serde::{Deserialize, Serialize};

/// A single opcode definition.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OpcodeEntry {
    /// The byte value that identifies this instruction.
    pub byte: u8,
    /// Short assembly-style mnemonic (e.g. "PUSH", "ADD", "JMP").
    pub mnemonic: String,
    /// Number of operand bytes that follow the opcode byte.
    pub operand_bytes: u8,
}

/// A complete opcode grammar loaded from a TOML file.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OpcodeGrammar {
    pub name: String,
    #[serde(default)]
    pub description: String,
    #[serde(rename = "opcodes", default)]
    pub entries: Vec<OpcodeEntry>,
}

impl OpcodeGrammar {
    /// Build a lookup table: opcode byte → entry.
    pub fn table(&self) -> [Option<&OpcodeEntry>; 256] {
        let mut table = [None; 256];
        for entry in &self.entries {
            table[entry.byte as usize] = Some(entry);
        }
        table
    }
}

// ── Storage ───────────────────────────────────────────────────────────────────

/// Directory where user grammar files are stored.
///
/// `~/.config/tiltshift/opcodes/`
pub fn grammar_dir() -> Option<PathBuf> {
    config_dir().map(|c| c.join("tiltshift").join("opcodes"))
}

/// Path for a named grammar file.
pub fn grammar_path(name: &str) -> Option<PathBuf> {
    grammar_dir().map(|d| d.join(format!("{name}.toml")))
}

/// Load a grammar by name from the user's config directory.
///
/// Returns an error if the file is missing or malformed.
pub fn load_grammar(name: &str) -> anyhow::Result<OpcodeGrammar> {
    let path = grammar_path(name).ok_or_else(|| anyhow::anyhow!("cannot determine config dir"))?;
    let text = std::fs::read_to_string(&path).map_err(|e| {
        if e.kind() == std::io::ErrorKind::NotFound {
            anyhow::anyhow!(
                "grammar {:?} not found — run `tiltshift opcodes list` to see available grammars",
                name
            )
        } else {
            anyhow::anyhow!("reading {}: {e}", path.display())
        }
    })?;
    let grammar: OpcodeGrammar =
        toml::from_str(&text).map_err(|e| anyhow::anyhow!("parsing {}: {e}", path.display()))?;
    Ok(grammar)
}

/// List all grammars installed in the user's config directory.
pub fn list_grammars() -> anyhow::Result<Vec<OpcodeGrammar>> {
    let dir = match grammar_dir() {
        Some(d) => d,
        None => anyhow::bail!("cannot determine config dir"),
    };
    if !dir.exists() {
        return Ok(vec![]);
    }
    let mut grammars = Vec::new();
    for entry in std::fs::read_dir(&dir)? {
        let entry = entry?;
        let path = entry.path();
        if path.extension().is_none_or(|e| e != "toml") {
            continue;
        }
        match std::fs::read_to_string(&path)
            .map_err(anyhow::Error::from)
            .and_then(|t| toml::from_str::<OpcodeGrammar>(&t).map_err(anyhow::Error::from))
        {
            Ok(g) => grammars.push(g),
            Err(e) => eprintln!("tiltshift: skipping {}: {e}", path.display()),
        }
    }
    grammars.sort_by(|a, b| a.name.cmp(&b.name));
    Ok(grammars)
}

/// Install a grammar file by copying it to the user's config directory.
///
/// The destination name is `<name>.toml`.  Overwrites any existing grammar
/// with the same name.
pub fn install_grammar(name: &str, src: &std::path::Path) -> anyhow::Result<PathBuf> {
    // Validate before installing.
    let text = std::fs::read_to_string(src)
        .map_err(|e| anyhow::anyhow!("reading {}: {e}", src.display()))?;
    let _grammar: OpcodeGrammar =
        toml::from_str(&text).map_err(|e| anyhow::anyhow!("{}: {e}", src.display()))?;

    let dest = grammar_path(name).ok_or_else(|| anyhow::anyhow!("cannot determine config dir"))?;
    if let Some(parent) = dest.parent() {
        std::fs::create_dir_all(parent)?;
    }
    std::fs::copy(src, &dest)?;
    Ok(dest)
}

fn config_dir() -> Option<PathBuf> {
    if let Ok(xdg) = std::env::var("XDG_CONFIG_HOME") {
        return Some(PathBuf::from(xdg));
    }
    std::env::var("HOME")
        .ok()
        .map(|h| PathBuf::from(h).join(".config"))
}
