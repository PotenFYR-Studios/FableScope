use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use thiserror::Error;

pub type Result<T> = std::result::Result<T, ConfigError>;

#[derive(Debug, Error)]
pub enum ConfigError {
    #[error("invalid config: {0}")]
    Invalid(String),
    #[error("serialization error: {0}")]
    Serde(#[from] serde_json::Error),
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum AiProviderKind {
    OpenCode,
    OpenCodeGo,
    Zai,
    ZaiCoding,
    OpenAiCompatible,
    Anthropic,
    Gemini,
    AzureOpenAi,
    OpenRouter,
    Ollama,
    LocalCompatible,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct AiProviderProfile {
    pub id: String,
    pub kind: AiProviderKind,
    pub name: String,
    pub endpoint: Option<String>,
    pub model: Option<String>,
    pub enabled: bool,
    pub local_only: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
pub struct BugBountyProfile {
    pub program_name: Option<String>,
    pub in_scope: Vec<String>,
    pub out_of_scope: Vec<String>,
    pub excluded_vuln_types: Vec<String>,
    pub safe_mode: bool,
    pub requests_per_second: Option<u32>,
    pub notes: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ScanDefaults {
    pub concurrency: u32,
    pub rps: u32,
    pub timeout_ms: u64,
    pub safe_mode: bool,
}

impl Default for ScanDefaults {
    fn default() -> Self {
        Self { concurrency: 10, rps: 5, timeout_ms: 10_000, safe_mode: true }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct UpdatePolicy {
    pub startup_check: bool,
    pub periodic_minutes: u32,
    pub auto_download: bool,
}

impl Default for UpdatePolicy {
    fn default() -> Self {
        Self { startup_check: true, periodic_minutes: 60, auto_download: true }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct WorkspaceConfig {
    pub version: u32,
    pub created_at: DateTime<Utc>,
    pub scan_defaults: ScanDefaults,
    pub bug_bounty: BugBountyProfile,
    pub ai_providers: Vec<AiProviderProfile>,
    pub updates: BTreeMap<String, UpdatePolicy>, // source type -> policy
    pub custom: BTreeMap<String, serde_json::Value>,
}

impl Default for WorkspaceConfig {
    fn default() -> Self {
        let mut updates = BTreeMap::new();
        updates.insert("checklists".into(), UpdatePolicy { startup_check: true, periodic_minutes: 360, auto_download: true });
        updates.insert("skills".into(), UpdatePolicy { startup_check: true, periodic_minutes: 60, auto_download: true });
        updates.insert("wordlists".into(), UpdatePolicy { startup_check: true, periodic_minutes: 60, auto_download: true });
        updates.insert("tool_bundles".into(), UpdatePolicy { startup_check: true, periodic_minutes: 360, auto_download: true });
        Self {
            version: 1,
            created_at: Utc::now(),
            scan_defaults: ScanDefaults::default(),
            bug_bounty: BugBountyProfile { safe_mode: true, ..Default::default() },
            ai_providers: vec![],
            updates,
            custom: BTreeMap::new(),
        }
    }
}

impl WorkspaceConfig {
    pub fn validate(&self) -> Result<()> {
        if self.scan_defaults.concurrency == 0 || self.scan_defaults.rps == 0 {
            return Err(ConfigError::Invalid("concurrency/rps must be > 0".into()));
        }
        Ok(())
    }
    pub fn to_json_pretty(&self) -> Result<String> { Ok(serde_json::to_string_pretty(self)?) }
    pub fn from_json(s: &str) -> Result<Self> { let c: Self = serde_json::from_str(s)?; c.validate()?; Ok(c) }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_config_roundtrip() {
        let c = WorkspaceConfig::default();
        c.validate().unwrap();
        let j = c.to_json_pretty().unwrap();
        let c2 = WorkspaceConfig::from_json(&j).unwrap();
        assert_eq!(c.scan_defaults, c2.scan_defaults);
        assert_eq!(c.bug_bounty.safe_mode, true);
    }

    #[test]
    fn invalid_scan_defaults() {
        let mut c = WorkspaceConfig::default();
        c.scan_defaults.rps = 0;
        assert!(c.validate().is_err());
    }
}
