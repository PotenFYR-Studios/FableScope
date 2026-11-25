//! Wordlist source registry with immutable versions, integrity hashing,
//! provenance/attribution, and project-level pin/rollback — the Phase 1
//! "Wordlist registry + version pinning" surface.
//!
//! The registry is a pure in-memory/serializable model: it tracks *sources*
//! (SecLists, Assetnote, custom, …), the immutable *versions* fetched from each
//! (identified by content SHA-256), and which version a project has pinned. It
//! never mutates a version in place — a new fetch always creates a new version
//! entry, so rollback is always possible. Network fetching is intentionally out
//! of scope here; callers hand in already-fetched bytes.

use crate::hash_bytes;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use thiserror::Error;

#[derive(Debug, Error, PartialEq, Eq)]
pub enum RegistryError {
    #[error("source not found: {0}")]
    SourceNotFound(String),
    #[error("version not found: {0}")]
    VersionNotFound(String),
    #[error("integrity mismatch: expected {expected}, got {actual}")]
    Integrity { expected: String, actual: String },
    #[error("no versions available for source: {0}")]
    NoVersions(String),
}

pub type Result<T> = std::result::Result<T, RegistryError>;

/// A wordlist source definition (where lists come from + licensing/attribution).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WordlistSource {
    pub id: String,
    pub name: String,
    pub url: Option<String>,
    pub license: Option<String>,
    pub attribution: Option<String>,
    /// Update cadence hint in minutes (0 = manual only).
    pub cadence_minutes: u32,
    pub tags: Vec<String>,
}

/// An immutable, content-addressed version of a wordlist from a source.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WordlistVersion {
    pub version: String, // human label, e.g. "2024.11.01" or a commit hash
    pub sha256: String,  // content hash — the stable identity
    pub size_bytes: u64,
    pub entry_count: usize,
    pub fetched_at: DateTime<Utc>,
    pub source_commit: Option<String>,
}

/// All known versions of a single source, plus the active/pinned selection.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct SourceVersions {
    pub versions: Vec<WordlistVersion>,
    pub pinned_sha: Option<String>,
}

/// The registry: sources + their version histories + pins.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct WordlistRegistry {
    sources: BTreeMap<String, WordlistSource>,
    history: BTreeMap<String, SourceVersions>,
}

impl WordlistRegistry {
    pub fn new() -> Self {
        Self::default()
    }

    /// Seed the registry with the well-known public sources from the plan.
    pub fn with_builtin_sources() -> Self {
        let mut reg = Self::new();
        for s in builtin_sources() {
            reg.register_source(s);
        }
        reg
    }

    pub fn register_source(&mut self, source: WordlistSource) {
        self.history.entry(source.id.clone()).or_default();
        self.sources.insert(source.id.clone(), source);
    }

    pub fn sources(&self) -> Vec<WordlistSource> {
        self.sources.values().cloned().collect()
    }

    pub fn source(&self, id: &str) -> Option<&WordlistSource> {
        self.sources.get(id)
    }

    /// Record a freshly-fetched wordlist as a new immutable version. If a version
    /// with the same content hash already exists it is returned unchanged
    /// (idempotent — no duplicate, no in-place mutation). The newest version
    /// becomes the active pin only if nothing is pinned yet.
    pub fn add_version(
        &mut self,
        source_id: &str,
        version_label: impl Into<String>,
        bytes: &[u8],
        source_commit: Option<String>,
    ) -> Result<WordlistVersion> {
        if !self.sources.contains_key(source_id) {
            return Err(RegistryError::SourceNotFound(source_id.into()));
        }
        let sha = hash_bytes(bytes);
        let entry_count = crate::load_words_from_bytes(bytes).map(|w| w.len()).unwrap_or(0);
        let sv = self.history.entry(source_id.to_string()).or_default();
        if let Some(existing) = sv.versions.iter().find(|v| v.sha256 == sha) {
            return Ok(existing.clone());
        }
        let version = WordlistVersion {
            version: version_label.into(),
            sha256: sha,
            size_bytes: bytes.len() as u64,
            entry_count,
            fetched_at: Utc::now(),
            source_commit,
        };
        sv.versions.push(version.clone());
        if sv.pinned_sha.is_none() {
            sv.pinned_sha = Some(version.sha256.clone());
        }
        Ok(version)
    }

    pub fn versions(&self, source_id: &str) -> Result<&[WordlistVersion]> {
        self.history
            .get(source_id)
            .map(|sv| sv.versions.as_slice())
            .ok_or_else(|| RegistryError::SourceNotFound(source_id.into()))
    }

    /// Pin a project/workspace to a specific version by content hash.
    pub fn pin(&mut self, source_id: &str, sha256: &str) -> Result<()> {
        let sv = self
            .history
            .get_mut(source_id)
            .ok_or_else(|| RegistryError::SourceNotFound(source_id.into()))?;
        if !sv.versions.iter().any(|v| v.sha256 == sha256) {
            return Err(RegistryError::VersionNotFound(sha256.into()));
        }
        sv.pinned_sha = Some(sha256.to_string());
        Ok(())
    }

    /// Roll back to the previous version (the one fetched before the current pin).
    pub fn rollback(&mut self, source_id: &str) -> Result<WordlistVersion> {
        let sv = self
            .history
            .get_mut(source_id)
            .ok_or_else(|| RegistryError::SourceNotFound(source_id.into()))?;
        if sv.versions.is_empty() {
            return Err(RegistryError::NoVersions(source_id.into()));
        }
        let current_idx = sv
            .pinned_sha
            .as_ref()
            .and_then(|p| sv.versions.iter().position(|v| &v.sha256 == p))
            .unwrap_or(sv.versions.len() - 1);
        let prev_idx = current_idx.saturating_sub(1);
        let prev = sv.versions[prev_idx].clone();
        sv.pinned_sha = Some(prev.sha256.clone());
        Ok(prev)
    }

    /// The currently pinned version for a source (defaults to newest).
    pub fn active_version(&self, source_id: &str) -> Result<WordlistVersion> {
        let sv = self
            .history
            .get(source_id)
            .ok_or_else(|| RegistryError::SourceNotFound(source_id.into()))?;
        if let Some(p) = &sv.pinned_sha {
            if let Some(v) = sv.versions.iter().find(|v| &v.sha256 == p) {
                return Ok(v.clone());
            }
        }
        sv.versions.last().cloned().ok_or_else(|| RegistryError::NoVersions(source_id.into()))
    }

    /// Verify that supplied bytes match a known version's integrity hash.
    pub fn verify(&self, source_id: &str, sha256: &str, bytes: &[u8]) -> Result<()> {
        self.versions(source_id)?
            .iter()
            .find(|v| v.sha256 == sha256)
            .ok_or_else(|| RegistryError::VersionNotFound(sha256.into()))?;
        let actual = hash_bytes(bytes);
        if actual != sha256 {
            return Err(RegistryError::Integrity { expected: sha256.into(), actual });
        }
        Ok(())
    }

    /// Diff two versions by entry sets (added/removed). Caller supplies the bytes
    /// of each version (so the registry stays storage-agnostic).
    pub fn diff(old_bytes: &[u8], new_bytes: &[u8]) -> WordlistDiff {
        let old: std::collections::BTreeSet<String> =
            crate::load_words_from_bytes(old_bytes).unwrap_or_default().into_iter().collect();
        let new: std::collections::BTreeSet<String> =
            crate::load_words_from_bytes(new_bytes).unwrap_or_default().into_iter().collect();
        let added: Vec<String> = new.difference(&old).cloned().collect();
        let removed: Vec<String> = old.difference(&new).cloned().collect();
        WordlistDiff { added_count: added.len(), removed_count: removed.len(), added, removed }
    }
}

/// Added/removed entries between two wordlist versions.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WordlistDiff {
    pub added_count: usize,
    pub removed_count: usize,
    pub added: Vec<String>,
    pub removed: Vec<String>,
}

/// The well-known public wordlist sources described in the plan.
pub fn builtin_sources() -> Vec<WordlistSource> {
    vec![
        WordlistSource {
            id: "seclists".into(),
            name: "SecLists".into(),
            url: Some("https://github.com/danielmiessler/SecLists".into()),
            license: Some("MIT".into()),
            attribution: Some("Daniel Miessler, g0tmi1k, and SecLists contributors".into()),
            cadence_minutes: 60,
            tags: vec!["discovery".into(), "fuzzing".into(), "usernames".into(), "passwords".into()],
        },
        WordlistSource {
            id: "assetnote".into(),
            name: "Assetnote Wordlists".into(),
            url: Some("https://wordlists.assetnote.io".into()),
            license: Some("See source".into()),
            attribution: Some("Assetnote".into()),
            cadence_minutes: 1440,
            tags: vec!["subdomains".into(), "content".into()],
        },
        WordlistSource {
            id: "payloadsallthethings".into(),
            name: "PayloadsAllTheThings".into(),
            url: Some("https://github.com/swisskyrepo/PayloadsAllTheThings".into()),
            license: Some("MIT".into()),
            attribution: Some("swisskyrepo and contributors".into()),
            cadence_minutes: 1440,
            tags: vec!["payloads".into(), "bypass".into()],
        },
        WordlistSource {
            id: "fuzzdb".into(),
            name: "FuzzDB".into(),
            url: Some("https://github.com/fuzzdb-project/fuzzdb".into()),
            license: Some("Dual (Various)".into()),
            attribution: Some("FuzzDB Project".into()),
            cadence_minutes: 10080,
            tags: vec!["attack-patterns".into(), "discovery".into()],
        },
        WordlistSource {
            id: "custom".into(),
            name: "Custom / Engagement".into(),
            url: None,
            license: Some("Private".into()),
            attribution: Some("Operator-provided".into()),
            cadence_minutes: 0,
            tags: vec!["private".into(), "scoped".into()],
        },
    ]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn builtin_sources_present() {
        let reg = WordlistRegistry::with_builtin_sources();
        assert!(reg.source("seclists").is_some());
        assert_eq!(reg.sources().len(), 5);
    }

    #[test]
    fn add_version_is_immutable_and_idempotent() {
        let mut reg = WordlistRegistry::with_builtin_sources();
        let v1 = reg.add_version("seclists", "v1", b"admin\napi\n", None).unwrap();
        let v1_again = reg.add_version("seclists", "v1-dup", b"admin\napi\n", None).unwrap();
        // Same content => same version, no duplicate.
        assert_eq!(v1.sha256, v1_again.sha256);
        assert_eq!(reg.versions("seclists").unwrap().len(), 1);
        assert_eq!(v1.entry_count, 2);
    }

    #[test]
    fn pin_and_rollback() {
        let mut reg = WordlistRegistry::with_builtin_sources();
        let v1 = reg.add_version("seclists", "v1", b"admin\n", None).unwrap();
        let v2 = reg.add_version("seclists", "v2", b"admin\napi\n", None).unwrap();
        // Default pin stays on first-added until explicitly moved.
        reg.pin("seclists", &v2.sha256).unwrap();
        assert_eq!(reg.active_version("seclists").unwrap().sha256, v2.sha256);
        let back = reg.rollback("seclists").unwrap();
        assert_eq!(back.sha256, v1.sha256);
        assert_eq!(reg.active_version("seclists").unwrap().sha256, v1.sha256);
    }

    #[test]
    fn integrity_verification() {
        let mut reg = WordlistRegistry::with_builtin_sources();
        let v = reg.add_version("seclists", "v1", b"admin\napi\n", None).unwrap();
        assert!(reg.verify("seclists", &v.sha256, b"admin\napi\n").is_ok());
        assert!(matches!(
            reg.verify("seclists", &v.sha256, b"tampered"),
            Err(RegistryError::Integrity { .. })
        ));
    }

    #[test]
    fn diff_reports_changes() {
        let d = WordlistRegistry::diff(b"admin\napi\n", b"admin\nlogin\n");
        assert!(d.added.contains(&"login".to_string()));
        assert!(d.removed.contains(&"api".to_string()));
    }

    #[test]
    fn unknown_source_errors() {
        let mut reg = WordlistRegistry::new();
        assert!(matches!(
            reg.add_version("nope", "v", b"x", None),
            Err(RegistryError::SourceNotFound(_))
        ));
    }
}
