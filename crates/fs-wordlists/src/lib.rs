use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::path::Path;
use thiserror::Error;

pub mod registry;
pub use registry::{builtin_sources, WordlistRegistry, WordlistSource, WordlistVersion};

pub type Result<T> = std::result::Result<T, WordlistError>;

#[derive(Debug, Error)]
pub enum WordlistError {
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
    #[error("invalid wordlist: {0}")]
    Invalid(String),
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct WordlistEntry {
    pub id: String,
    pub name: String,
    pub source: String,
    pub path: Option<String>,
    pub tags: Vec<String>,
    pub version: String,
    pub sha256: Option<String>,
    pub updated_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct WordlistPack {
    pub name: String,
    pub entries: Vec<WordlistEntry>,
    pub words: Vec<String>,
}

pub fn hash_bytes(bytes: &[u8]) -> String {
    let mut h = Sha256::new();
    h.update(bytes);
    hex::encode(h.finalize())
}

pub fn load_words_from_file(path: impl AsRef<Path>) -> Result<Vec<String>> {
    let bytes = std::fs::read(path)?;
    load_words_from_bytes(&bytes)
}

pub fn load_words_from_bytes(bytes: &[u8]) -> Result<Vec<String>> {
    let text = String::from_utf8_lossy(bytes);
    let mut out = Vec::new();
    for line in text.lines() {
        let w = line.trim();
        if w.is_empty() || w.starts_with('#') { continue; }
        out.push(w.to_string());
    }
    out.sort();
    out.dedup();
    Ok(out)
}

pub fn builtin_packs() -> Vec<WordlistPack> {
    vec![
        WordlistPack { name: "web-common".into(), entries: vec![], words: ["admin","api","login","dashboard","graphql","swagger",".env","config","backup"].into_iter().map(String::from).collect() },
        WordlistPack { name: "params-common".into(), entries: vec![], words: ["id","q","search","redirect","url","next","file","page","debug"].into_iter().map(String::from).collect() },
    ]
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn loads_and_dedups() {
        let words = load_words_from_bytes(b"admin\n#c\nadmin\napi\n").unwrap();
        assert_eq!(words, vec!["admin","api"]);
    }
    #[test]
    fn builtin_packs_present() {
        assert!(builtin_packs().iter().any(|p| p.name == "web-common"));
    }
}
