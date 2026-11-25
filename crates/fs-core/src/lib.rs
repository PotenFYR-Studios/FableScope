use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use thiserror::Error;
use uuid::Uuid;

pub type Result<T> = std::result::Result<T, FsError>;

#[derive(Debug, Error)]
pub enum FsError {
    #[error("invalid scope: {0}")]
    InvalidScope(String),
    #[error("validation failed: {0}")]
    Validation(String),
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Project {
    pub id: Uuid,
    pub name: String,
    pub created_at: DateTime<Utc>,
}

impl Project {
    pub fn new(name: impl Into<String>) -> Result<Self> {
        let name = name.into();
        if name.trim().is_empty() {
            return Err(FsError::Validation("project name cannot be empty".into()));
        }
        Ok(Self {
            id: Uuid::new_v4(),
            name,
            created_at: Utc::now(),
        })
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum TargetKind {
    Url,
    Host,
    Domain,
    Cidr,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Target {
    pub kind: TargetKind,
    pub value: String,
}

impl Target {
    pub fn new(kind: TargetKind, value: impl Into<String>) -> Result<Self> {
        let value = value.into();
        if value.trim().is_empty() {
            return Err(FsError::Validation("target value cannot be empty".into()));
        }
        Ok(Self { kind, value })
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
pub struct ScopePolicy {
    pub allow: Vec<String>,
    pub deny: Vec<String>,
}

impl ScopePolicy {
    pub fn is_allowed(&self, value: &str) -> bool {
        let value = value.to_lowercase();
        let allowed = self.allow.is_empty()
            || self
                .allow
                .iter()
                .any(|a| value.contains(&a.to_lowercase()));
        let denied = self
            .deny
            .iter()
            .any(|d| value.contains(&d.to_lowercase()));
        allowed && !denied
    }

    pub fn assert_allowed(&self, value: &str) -> Result<()> {
        if self.is_allowed(value) {
            Ok(())
        } else {
            Err(FsError::InvalidScope(value.to_string()))
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum JobState {
    Queued,
    Running,
    Completed,
    Failed,
    Cancelled,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ModuleKind {
    Dashboard, Recon, Web, Api, Cloud, Ad, Wifi, RedTeam, Mobile, Passwords, Reporting, Settings,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ModuleDescriptor {
    pub id: String,
    pub kind: ModuleKind,
    pub name: String,
    pub status: String, // planned, scaffolded, implemented
    pub description: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct AppEvent {
    pub id: Uuid,
    pub at: DateTime<Utc>,
    pub kind: String,
    pub project_id: Option<Uuid>,
    pub payload: serde_json::Value,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum AssetKind {
    Domain, Subdomain, Url, Host, Ip, Service, CloudResource, MobileApp, AdObject, WifiNetwork, Other,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct Asset {
    pub id: Uuid,
    pub project_id: Uuid,
    pub kind: AssetKind,
    pub value: String,
    pub source: String,
    pub meta: BTreeMap<String, serde_json::Value>,
    pub created_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct AdapterRecord {
    pub id: String,
    pub module: String,
    pub name: String,
    pub kind: String, // cli, api, import, mcp
    pub status: String, // planned, configured, available, disabled
    pub executable: Option<String>,
    pub notes: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Job {
    pub id: Uuid,
    pub project_id: Uuid,
    pub kind: String,
    pub state: JobState,
    pub created_at: DateTime<Utc>,
}

impl Job {
    pub fn new(project_id: Uuid, kind: impl Into<String>) -> Self {
        Self {
            id: Uuid::new_v4(),
            project_id,
            kind: kind.into(),
            state: JobState::Queued,
            created_at: Utc::now(),
        }
    }
}

pub fn builtin_modules() -> Vec<ModuleDescriptor> {
    vec![
        ModuleDescriptor { id:"dashboard".into(), kind:ModuleKind::Dashboard, name:"Dashboard".into(), status:"implemented".into(), description:"Overview, jobs, findings, stats, modules".into() },
        ModuleDescriptor { id:"recon".into(), kind:ModuleKind::Recon, name:"Recon".into(), status:"implemented".into(), description:"Scoped probe/fuzz, recon persistence, dedup, asset capture".into() },
        ModuleDescriptor { id:"web".into(), kind:ModuleKind::Web, name:"Web".into(), status:"implemented".into(), description:"Web checklist/tool execution, evidence, findings".into() },
        ModuleDescriptor { id:"api".into(), kind:ModuleKind::Api, name:"API".into(), status:"implemented".into(), description:"API checklist/template seeding and run flow".into() },
        ModuleDescriptor { id:"cloud".into(), kind:ModuleKind::Cloud, name:"Cloud".into(), status:"adapter".into(), description:"Cloud adapter registry/import/export; execution gated by external tools/credentials".into() },
        ModuleDescriptor { id:"ad".into(), kind:ModuleKind::Ad, name:"AD".into(), status:"adapter".into(), description:"AD adapter registry/import/export; execution gated by authorized lab/tools".into() },
        ModuleDescriptor { id:"wifi".into(), kind:ModuleKind::Wifi, name:"WiFi".into(), status:"adapter".into(), description:"WiFi adapter registry/import/export; execution gated by hardware/authorization".into() },
        ModuleDescriptor { id:"redteam".into(), kind:ModuleKind::RedTeam, name:"Red Team".into(), status:"adapter".into(), description:"Red team adapter/planning registry; execution gated by explicit authorization".into() },
        ModuleDescriptor { id:"mobile".into(), kind:ModuleKind::Mobile, name:"Mobile".into(), status:"adapter".into(), description:"Mobile artifact/import adapter registry; execution gated by external tooling".into() },
        ModuleDescriptor { id:"passwords".into(), kind:ModuleKind::Passwords, name:"Passwords".into(), status:"implemented".into(), description:"Hash identification and password policy/audit helpers (non-cracking by default)".into() },
        ModuleDescriptor { id:"reporting".into(), kind:ModuleKind::Reporting, name:"Reporting".into(), status:"implemented".into(), description:"JSON/MD/HTML/CSV/SARIF exports, CVSS, checklist/finding exports".into() },
        ModuleDescriptor { id:"settings".into(), kind:ModuleKind::Settings, name:"Settings".into(), status:"implemented".into(), description:"Config/scope/tool manifests/wordlists/audit".into() },
    ]
}

pub fn builtin_adapters() -> Vec<AdapterRecord> {
    vec![
        AdapterRecord { id:"cloud.prowler".into(), module:"cloud".into(), name:"Prowler".into(), kind:"cli".into(), status:"planned".into(), executable:Some("prowler".into()), notes:Some("Authorized cloud posture scan adapter".into()) },
        AdapterRecord { id:"ad.bloodhound".into(), module:"ad".into(), name:"BloodHound/SharpHound".into(), kind:"import".into(), status:"planned".into(), executable:None, notes:Some("Import AD graph artifacts; collection requires authorized environment".into()) },
        AdapterRecord { id:"wifi.aircrack".into(), module:"wifi".into(), name:"aircrack-ng suite".into(), kind:"cli".into(), status:"planned".into(), executable:Some("aircrack-ng".into()), notes:Some("Requires hardware and explicit authorization".into()) },
        AdapterRecord { id:"redteam.caldera".into(), module:"redteam".into(), name:"MITRE Caldera".into(), kind:"api".into(), status:"planned".into(), executable:None, notes:Some("External orchestrator adapter; gated".into()) },
        AdapterRecord { id:"mobile.mobsf".into(), module:"mobile".into(), name:"MobSF".into(), kind:"api".into(), status:"planned".into(), executable:None, notes:Some("Import/report adapter".into()) },
    ]
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum Severity {
    Info,
    Low,
    Medium,
    High,
    Critical,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum CheckStatus {
    NotStarted,
    InProgress,
    Pass,
    Fail,
    Potential,
    FalsePositive,
    NotApplicable,
    Blocked,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
pub struct OwaspRef {
    pub standard: String, // WSTG, ASVS, API_TOP10, MASTG, MASVS
    pub id: String,
    pub title: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct EvidenceRef {
    pub id: Uuid,
    pub kind: String, // http_exchange, screenshot, log, oob, command_output
    pub path: Option<String>,
    pub hash: Option<String>,
    pub caption: Option<String>,
    pub created_at: DateTime<Utc>,
    pub metadata: BTreeMap<String, serde_json::Value>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ChecklistItem {
    pub id: Uuid,
    pub project_id: Uuid,
    pub check_id: String, // FS-WEB-001
    pub title: String,
    pub owasp: Vec<OwaspRef>,
    pub status: CheckStatus,
    pub confidence: Option<f32>,
    pub evidence: Vec<EvidenceRef>,
    pub finding_id: Option<Uuid>,
    pub notes: Option<String>,
    pub updated_at: DateTime<Utc>,
}

impl ChecklistItem {
    pub fn new(project_id: Uuid, check_id: impl Into<String>, title: impl Into<String>) -> Self {
        Self {
            id: Uuid::new_v4(), project_id, check_id: check_id.into(), title: title.into(),
            owasp: vec![], status: CheckStatus::NotStarted, confidence: None, evidence: vec![],
            finding_id: None, notes: None, updated_at: Utc::now(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct Finding {
    pub id: Uuid,
    pub project_id: Uuid,
    pub title: String,
    pub severity: Severity,
    pub description: String,
    pub evidence: BTreeMap<String, serde_json::Value>,
    #[serde(default)]
    pub confidence: Option<f32>,
    #[serde(default)]
    pub status: Option<String>,
    #[serde(default)]
    pub correlation_id: Option<String>,
    #[serde(default)]
    pub source_check_id: Option<String>,
    #[serde(default)]
    pub source_tool_run_id: Option<Uuid>,
    pub created_at: DateTime<Utc>,
}

impl Finding {
    pub fn new(project_id: Uuid, title: impl Into<String>, severity: Severity) -> Result<Self> {
        let title = title.into();
        if title.trim().is_empty() {
            return Err(FsError::Validation("finding title cannot be empty".into()));
        }
        Ok(Self {
            id: Uuid::new_v4(),
            project_id,
            title,
            severity,
            description: String::new(),
            evidence: BTreeMap::new(),
            confidence: None,
            status: Some("candidate".into()),
            correlation_id: None,
            source_check_id: None,
            source_tool_run_id: None,
            created_at: Utc::now(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn scope_policy_allows_and_denies() {
        let scope = ScopePolicy {
            allow: vec!["example.com".into()],
            deny: vec!["admin.example.com".into()],
        };
        assert!(scope.is_allowed("https://api.example.com"));
        assert!(!scope.is_allowed("https://admin.example.com"));
        assert!(!scope.is_allowed("https://other.com"));
    }

    #[test]
    fn project_requires_name() {
        let err = Project::new("  ").unwrap_err();
        assert!(matches!(err, FsError::Validation(_)));
    }
}
