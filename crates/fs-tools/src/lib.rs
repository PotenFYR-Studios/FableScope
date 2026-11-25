use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::process::Stdio;
use thiserror::Error;
use tokio::io::AsyncWriteExt;
use tokio::process::Command;
use tokio::time::{timeout, Duration};
use uuid::Uuid;

pub mod codec;
pub mod credential_audit;
pub mod hashid;
pub mod password;
pub use codec::{decode as codec_decode, encode as codec_encode, Codec};
pub use credential_audit::{
    build_hashcat_args, build_john_args, parse_hashcat_potfile, parse_john_show, AttackMode,
    CredentialAuditJob,
};
pub use hashid::{best as identify_hash, identify as identify_hashes, HashCandidate};
pub use password::{
    estimate_entropy, generate as generate_passwords, generate_passphrase, mangle, Candidate,
    PasswordPolicy, Provenance,
};

pub type Result<T> = std::result::Result<T, ToolError>;

#[derive(Debug, Error)]
pub enum ToolError {
    #[error("tool not found: {0}")]
    NotFound(String),
    #[error("invalid manifest: {0}")]
    InvalidManifest(String),
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
    #[error("validation failed: {0}")]
    Validation(String),
    #[error("execution failed: {0}")]
    Execution(String),
    #[error("timeout after {0}ms")]
    Timeout(u64),
    #[error("network error: {0}")]
    Network(String),
    #[error("archive error: {0}")]
    Archive(String),
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ToolKind {
    PortableBundle,
    ManagedRuntime,
    SystemOverride,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ToolStatus {
    Ready,
    Missing,
    Invalid,
    Unsupported,
    Override,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
pub struct ToolBundleSource {
    pub url: Option<String>,
    pub sha256: Option<String>,
    pub size_bytes: Option<u64>,
    pub license: Option<String>,
    pub provenance: Option<String>,
    #[serde(default)]
    pub format: Option<String>, // "zip" | "raw"
}

pub fn current_platform_key() -> String {
    let os = if cfg!(target_os = "windows") { "windows" } else if cfg!(target_os = "macos") { "macos" } else { "linux" };
    let arch = if cfg!(target_arch = "x86_64") { "x86_64" } else if cfg!(target_arch = "aarch64") { "aarch64" } else { std::env::consts::ARCH };
    format!("{os}-{arch}")
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ToolProfile {
    pub id: String,
    pub name: String,
    pub description: String,
    pub args: Vec<String>,
    pub checklist_ids: Vec<String>, // mapped OWASP/FableScope check IDs
    pub risk_tier: String,          // low/medium/high
    pub template_ids: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ToolManifest {
    pub id: String,
    pub name: String,
    pub version: String,
    pub kind: ToolKind,
    pub executable: String, // relative to bundle dir or absolute for override
    pub bundle: ToolBundleSource,
    #[serde(default)]
    pub platform_bundles: BTreeMap<String, ToolBundleSource>,
    pub supported_os: Vec<String>,
    pub profiles: BTreeMap<String, ToolProfile>,
}

impl ToolManifest {
    pub fn validate(&self) -> Result<()> {
        if self.id.trim().is_empty() || self.name.trim().is_empty() {
            return Err(ToolError::InvalidManifest("id/name required".into()));
        }
        if self.executable.trim().is_empty() {
            return Err(ToolError::InvalidManifest("executable required".into()));
        }
        for (k, p) in &self.profiles {
            if k.trim().is_empty() || p.id.trim().is_empty() {
                return Err(ToolError::InvalidManifest("profile id required".into()));
            }
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ToolRunRequest {
    pub tool_id: String,
    pub profile: Option<String>,
    pub args: Vec<String>,
    #[serde(default)]
    pub project_id: Option<Uuid>,
    #[serde(default)]
    pub check_id: Option<String>,
    #[serde(default)]
    pub correlation_id: Option<String>,
    pub cwd: Option<PathBuf>,
    pub timeout_ms: u64,
    pub env: BTreeMap<String, String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ToolRunResult {
    pub run_id: Uuid,
    pub tool_id: String,
    pub profile: Option<String>,
    pub args: Vec<String>,
    #[serde(default)]
    pub project_id: Option<Uuid>,
    #[serde(default)]
    pub check_id: Option<String>,
    #[serde(default)]
    pub correlation_id: Option<String>,
    pub status: i32,
    pub stdout: String,
    pub stderr: String,
    pub started_at: DateTime<Utc>,
    pub finished_at: DateTime<Utc>,
    pub duration_ms: u64,
    pub artifact_dir: PathBuf,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ToolRecord {
    pub manifest: ToolManifest,
    pub status: ToolStatus,
    pub resolved_path: Option<PathBuf>,
    pub last_validated_at: Option<DateTime<Utc>>,
    pub last_error: Option<String>,
}

pub struct ToolManager {
    tools_dir: PathBuf,
    artifacts_dir: PathBuf,
    records: BTreeMap<String, ToolRecord>,
}

impl ToolManager {
    pub fn new(tools_dir: impl Into<PathBuf>, artifacts_dir: impl Into<PathBuf>) -> Self {
        Self {
            tools_dir: tools_dir.into(),
            artifacts_dir: artifacts_dir.into(),
            records: BTreeMap::new(),
        }
    }

    pub fn register(&mut self, manifest: ToolManifest) -> Result<()> {
        manifest.validate()?;
        let record = ToolRecord {
            status: ToolStatus::Missing,
            resolved_path: None,
            last_validated_at: None,
            last_error: None,
            manifest,
        };
        self.records.insert(record.manifest.id.clone(), record);
        Ok(())
    }

    pub fn list(&self) -> Vec<ToolRecord> {
        self.records.values().cloned().collect()
    }

    pub fn get(&self, id: &str) -> Option<&ToolRecord> {
        self.records.get(id)
    }

    pub fn resolve_path(&self, manifest: &ToolManifest) -> PathBuf {
        let p = PathBuf::from(&manifest.executable);
        if p.is_absolute() {
            p
        } else {
            self.tools_dir.join(&manifest.id).join(p)
        }
    }

    pub fn tools_dir(&self) -> &Path { &self.tools_dir }
    pub fn artifacts_dir(&self) -> &Path { &self.artifacts_dir }

    pub fn effective_bundle(&self, manifest: &ToolManifest) -> ToolBundleSource {
        let key = current_platform_key();
        manifest.platform_bundles.get(&key).cloned().unwrap_or_else(|| manifest.bundle.clone())
    }

    pub async fn provision(&mut self, id: &str) -> Result<ToolRecord> {
        let (manifest, dest) = {
            let rec = self.records.get(id).ok_or_else(|| ToolError::NotFound(id.into()))?;
            (rec.manifest.clone(), self.tools_dir.join(&rec.manifest.id))
        };
        let bundle = self.effective_bundle(&manifest);
        if let Some(url) = bundle.url.clone() {
            tokio::fs::create_dir_all(&dest).await?;
            let resp = reqwest::get(&url).await.map_err(|e| ToolError::Network(e.to_string()))?;
            if !resp.status().is_success() {
                return Err(ToolError::Network(format!("download failed: {}", resp.status())));
            }
            let bytes = resp.bytes().await.map_err(|e| ToolError::Network(e.to_string()))?;
            if let Some(expected) = &bundle.sha256 {
                let mut hasher = Sha256::new();
                hasher.update(&bytes);
                let actual = hex::encode(hasher.finalize());
                if &actual != expected {
                    return Err(ToolError::Validation(format!("bundle sha256 mismatch: expected {expected}, got {actual}")));
                }
            }
            let fmt = bundle.format.clone().unwrap_or_else(|| if url.ends_with(".zip") { "zip".into() } else { "raw".into() });
            if fmt == "zip" {
                extract_zip(&bytes, &dest)?;
            } else {
                let exe = dest.join(&manifest.executable);
                if let Some(p) = exe.parent() { tokio::fs::create_dir_all(p).await?; }
                let mut f = tokio::fs::File::create(&exe).await?;
                f.write_all(&bytes).await?;
                #[cfg(unix)]
                {
                    use std::os::unix::fs::PermissionsExt;
                    let mut perms = tokio::fs::metadata(&exe).await?.permissions();
                    perms.set_mode(0o755);
                    tokio::fs::set_permissions(&exe, perms).await?;
                }
            }
        }
        self.detect(id).await
    }

    pub async fn detect(&mut self, id: &str) -> Result<ToolRecord> {
        let (path, kind) = {
            let record = self.records.get(id).ok_or_else(|| ToolError::NotFound(id.into()))?;
            (self.resolve_path(&record.manifest), record.manifest.kind.clone())
        };
        let record = self.records.get_mut(id).ok_or_else(|| ToolError::NotFound(id.into()))?;
        if path.exists() {
            record.status = match kind {
                ToolKind::SystemOverride => ToolStatus::Override,
                _ => ToolStatus::Ready,
            };
            record.resolved_path = Some(path);
            record.last_error = None;
        } else {
            record.status = ToolStatus::Missing;
            record.resolved_path = None;
            record.last_error = Some(format!("missing {}", path.display()));
        }
        Ok(record.clone())
    }

    pub async fn validate(&mut self, id: &str) -> Result<ToolRecord> {
        let record = self.detect(id).await?;
        let path = record.resolved_path.clone().ok_or_else(|| ToolError::Validation("tool missing".into()))?;
        let bundle = self.effective_bundle(&record.manifest);
        if let Some(expected) = bundle.sha256.clone() {
            let actual = sha256_file(&path).await?;
            if actual != expected {
                let rec = self.records.get_mut(id).unwrap();
                rec.status = ToolStatus::Invalid;
                rec.last_error = Some(format!("sha256 mismatch: expected {expected}, got {actual}"));
                return Ok(rec.clone());
            }
        }
        let dry = Command::new(&path).arg("--version").stdout(Stdio::piped()).stderr(Stdio::piped()).output().await;
        let ok = dry.is_ok();
        let rec = self.records.get_mut(id).unwrap();
        rec.last_validated_at = Some(Utc::now());
        if ok {
            if rec.status == ToolStatus::Missing { rec.status = ToolStatus::Ready; }
            rec.last_error = None;
        } else {
            rec.status = ToolStatus::Invalid;
            rec.last_error = Some("failed to execute for validation".into());
        }
        Ok(rec.clone())
    }

    pub async fn run(&mut self, req: ToolRunRequest) -> Result<ToolRunResult> {
        let rec = self.detect(&req.tool_id).await?;
        let exe = rec.resolved_path.ok_or_else(|| ToolError::NotFound(req.tool_id.clone()))?;
        let run_id = Uuid::new_v4();
        let started_at = Utc::now();
        let artifact_dir = self.artifacts_dir.join(req.tool_id.clone()).join(run_id.to_string());
        tokio::fs::create_dir_all(&artifact_dir).await?;

        let mut args = req.args.clone();
        if let Some(profile) = &req.profile {
            if let Some(tpl) = rec.manifest.profiles.get(profile) {
                let mut merged = tpl.args.clone();
                merged.extend(args);
                args = merged;
            }
        }

        let mut cmd = Command::new(&exe);
        cmd.args(&args).stdout(Stdio::piped()).stderr(Stdio::piped());
        if let Some(cwd) = &req.cwd { cmd.current_dir(cwd); }
        for (k, v) in &req.env { cmd.env(k, v); }

        let out = timeout(Duration::from_millis(req.timeout_ms), cmd.output()).await
            .map_err(|_| ToolError::Timeout(req.timeout_ms))?
            .map_err(ToolError::Io)?;
        let finished_at = Utc::now();
        let duration_ms = (finished_at - started_at).num_milliseconds().max(0) as u64;
        let stdout = truncate_utf8(&out.stdout, 200_000);
        let stderr = truncate_utf8(&out.stderr, 200_000);
        tokio::fs::write(artifact_dir.join("stdout.log"), &stdout).await?;
        tokio::fs::write(artifact_dir.join("stderr.log"), &stderr).await?;
        let result = ToolRunResult {
            run_id,
            tool_id: req.tool_id,
            profile: req.profile,
            args,
            project_id: req.project_id,
            check_id: req.check_id,
            correlation_id: req.correlation_id,
            status: out.status.code().unwrap_or(-1),
            stdout,
            stderr,
            started_at,
            finished_at,
            duration_ms,
            artifact_dir: artifact_dir.clone(),
        };
        tokio::fs::write(artifact_dir.join("result.json"), serde_json::to_vec_pretty(&result).unwrap_or_default()).await?;
        Ok(result)
    }
}

async fn sha256_file(path: &Path) -> Result<String> {
    let bytes = tokio::fs::read(path).await?;
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    Ok(hex::encode(hasher.finalize()))
}

fn extract_zip(bytes: &[u8], dest: &Path) -> Result<()> {
    let reader = std::io::Cursor::new(bytes);
    let mut zip = zip::ZipArchive::new(reader).map_err(|e| ToolError::Archive(e.to_string()))?;
    for i in 0..zip.len() {
        let mut file = zip.by_index(i).map_err(|e| ToolError::Archive(e.to_string()))?;
        let Some(enclosed) = file.enclosed_name() else { continue };
        let outpath = dest.join(enclosed);
        if file.is_dir() {
            std::fs::create_dir_all(&outpath)?;
        } else {
            if let Some(p) = outpath.parent() { std::fs::create_dir_all(p)?; }
            let mut outfile = std::fs::File::create(&outpath)?;
            std::io::copy(&mut file, &mut outfile)?;
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                if let Some(mode) = file.unix_mode() {
                    std::fs::set_permissions(&outpath, std::fs::Permissions::from_mode(mode))?;
                }
            }
        }
    }
    Ok(())
}

fn truncate_utf8(bytes: &[u8], max: usize) -> String {
    let mut s = String::from_utf8_lossy(bytes).to_string();
    if s.len() > max { s.truncate(max); s.push_str("\n...[truncated]..."); }
    s
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn register_detect_run_echo_like() {
        let tmp = std::env::temp_dir().join(format!("fs-tools-{}", Uuid::new_v4()));
        let tools_dir = tmp.join("tools");
        let artifacts = tmp.join("artifacts");
        tokio::fs::create_dir_all(&tools_dir).await.unwrap();
        let mut mgr = ToolManager::new(&tools_dir, &artifacts);
        // Use system cmd as override for test portability on Windows
        let cmd_path = if cfg!(windows) { "C:\\Windows\\System32\\cmd.exe" } else { "/bin/sh" };
        mgr.register(ToolManifest {
            id: "cmd".into(), name: "Cmd".into(), version: "test".into(), kind: ToolKind::SystemOverride,
            executable: cmd_path.into(), bundle: ToolBundleSource::default(), platform_bundles: BTreeMap::new(), supported_os: vec!["windows".into(), "linux".into()],
            profiles: BTreeMap::new(),
        }).unwrap();
        let rec = mgr.detect("cmd").await.unwrap();
        assert!(matches!(rec.status, ToolStatus::Override | ToolStatus::Ready));
        let args = if cfg!(windows) { vec!["/C".into(), "echo".into(), "hello".into()] } else { vec!["-c".into(), "echo hello".into()] };
        let res = mgr.run(ToolRunRequest { tool_id: "cmd".into(), profile: None, args, project_id: None, check_id: None, correlation_id: None, cwd: None, timeout_ms: 10_000, env: BTreeMap::new() }).await.unwrap();
        assert_eq!(res.status, 0);
        assert!(res.stdout.to_lowercase().contains("hello"));
    }

    #[tokio::test]
    async fn detect_missing() {
        let tmp = std::env::temp_dir().join(format!("fs-tools-{}", Uuid::new_v4()));
        let mut mgr = ToolManager::new(tmp.join("tools"), tmp.join("artifacts"));
        mgr.register(ToolManifest { id:"x".into(), name:"x".into(), version:"1".into(), kind: ToolKind::PortableBundle, executable:"x.exe".into(), bundle: ToolBundleSource::default(), platform_bundles: BTreeMap::new(), supported_os:vec![], profiles:BTreeMap::new() }).unwrap();
        let rec = mgr.detect("x").await.unwrap();
        assert_eq!(rec.status, ToolStatus::Missing);
    }

    #[test]
    fn extract_zip_writes_files() {
        let mut buf = Vec::new();
        {
            let cursor = std::io::Cursor::new(&mut buf);
            let mut zip = zip::ZipWriter::new(cursor);
            let opts = zip::write::SimpleFileOptions::default();
            zip.start_file("tool/bin.txt", opts).unwrap();
            std::io::Write::write_all(&mut zip, b"hello").unwrap();
            zip.finish().unwrap();
        }
        let tmp = std::env::temp_dir().join(format!("fs-tools-zip-{}", Uuid::new_v4()));
        std::fs::create_dir_all(&tmp).unwrap();
        extract_zip(&buf, &tmp).unwrap();
        let got = std::fs::read_to_string(tmp.join("tool/bin.txt")).unwrap();
        assert_eq!(got, "hello");
    }
}
