//! Authorized credential-audit orchestration (Phase 2): build Hashcat / John
//! the Ripper command lines and parse their cracked output / potfiles.
//!
//! This module only *constructs* commands and *parses* results — execution is
//! performed by the gated [`crate::ToolManager`] after an explicit authorization
//! check. Building an intrusive job without `authorized = true` is refused, so
//! the UI/caller must record authorization before any cracking runs. No hashes
//! are generated or cracked here.

use crate::hashid;
use serde::{Deserialize, Serialize};
use std::path::PathBuf;

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum AuditError {
    #[error("authorization required: credential auditing must be explicitly authorized for this engagement")]
    NotAuthorized,
    #[error("invalid job: {0}")]
    Invalid(String),
}

pub type Result<T> = std::result::Result<T, AuditError>;

/// Supported attack strategies, mapped to Hashcat `-a` modes.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AttackMode {
    /// Wordlist / dictionary (optionally with rules).
    Dictionary { wordlist: PathBuf, rules: Option<PathBuf> },
    /// Mask / brute-force.
    Mask { mask: String },
    /// Hybrid wordlist + mask.
    HybridWordlistMask { wordlist: PathBuf, mask: String },
    /// Combinator (two wordlists).
    Combinator { left: PathBuf, right: PathBuf },
}

impl AttackMode {
    fn hashcat_a(&self) -> &'static str {
        match self {
            AttackMode::Dictionary { .. } => "0",
            AttackMode::Combinator { .. } => "1",
            AttackMode::Mask { .. } => "3",
            AttackMode::HybridWordlistMask { .. } => "6",
        }
    }
}

/// A credential-audit job description.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CredentialAuditJob {
    /// Path to the file containing the target hash(es).
    pub hash_file: PathBuf,
    /// Hashcat mode (`-m`). If `None`, it is inferred from the sample hash.
    pub hashcat_mode: Option<u32>,
    pub attack: AttackMode,
    pub potfile: Option<PathBuf>,
    /// Operator attestation that this audit is authorized for the engagement.
    pub authorized: bool,
    /// Extra safety: keep defaults conservative (no `--force`, status timer on).
    #[serde(default)]
    pub extra_args: Vec<String>,
}

impl CredentialAuditJob {
    fn ensure_ok(&self) -> Result<()> {
        if !self.authorized {
            return Err(AuditError::NotAuthorized);
        }
        if self.hash_file.as_os_str().is_empty() {
            return Err(AuditError::Invalid("hash_file is required".into()));
        }
        Ok(())
    }

    /// Resolve the Hashcat mode, inferring from a sample hash if not set.
    pub fn resolve_mode(&self, sample_hash: Option<&str>) -> Option<u32> {
        if let Some(m) = self.hashcat_mode {
            return Some(m);
        }
        sample_hash
            .and_then(hashid::best)
            .and_then(|c| c.hashcat_mode)
    }
}

/// Build a Hashcat argument vector for an authorized job.
pub fn build_hashcat_args(job: &CredentialAuditJob, sample_hash: Option<&str>) -> Result<Vec<String>> {
    job.ensure_ok()?;
    let mode = job
        .resolve_mode(sample_hash)
        .ok_or_else(|| AuditError::Invalid("could not resolve hashcat mode; set hashcat_mode explicitly".into()))?;
    let mut args = vec![
        "-m".into(),
        mode.to_string(),
        "-a".into(),
        job.attack.hashcat_a().to_string(),
        "--status".into(),
        "--quiet".into(),
    ];
    if let Some(pot) = &job.potfile {
        args.push("--potfile-path".into());
        args.push(pot.to_string_lossy().to_string());
    }
    args.push(job.hash_file.to_string_lossy().to_string());
    match &job.attack {
        AttackMode::Dictionary { wordlist, rules } => {
            args.push(wordlist.to_string_lossy().to_string());
            if let Some(r) = rules {
                args.push("-r".into());
                args.push(r.to_string_lossy().to_string());
            }
        }
        AttackMode::Mask { mask } => args.push(mask.clone()),
        AttackMode::HybridWordlistMask { wordlist, mask } => {
            args.push(wordlist.to_string_lossy().to_string());
            args.push(mask.clone());
        }
        AttackMode::Combinator { left, right } => {
            args.push(left.to_string_lossy().to_string());
            args.push(right.to_string_lossy().to_string());
        }
    }
    args.extend(job.extra_args.clone());
    Ok(args)
}

/// Build a John the Ripper argument vector for an authorized job.
pub fn build_john_args(job: &CredentialAuditJob, john_format: Option<&str>, sample_hash: Option<&str>) -> Result<Vec<String>> {
    job.ensure_ok()?;
    let mut args: Vec<String> = Vec::new();
    let fmt = john_format
        .map(String::from)
        .or_else(|| sample_hash.and_then(hashid::best).and_then(|c| c.john_format));
    if let Some(f) = fmt {
        args.push(format!("--format={f}"));
    }
    match &job.attack {
        AttackMode::Dictionary { wordlist, rules } => {
            args.push(format!("--wordlist={}", wordlist.to_string_lossy()));
            if rules.is_some() {
                args.push("--rules".into());
            }
        }
        AttackMode::Mask { mask } => args.push(format!("--mask={mask}")),
        AttackMode::HybridWordlistMask { wordlist, mask } => {
            args.push(format!("--wordlist={}", wordlist.to_string_lossy()));
            args.push(format!("--mask={mask}"));
        }
        AttackMode::Combinator { left, .. } => {
            // John has no native combinator; fall back to the first list.
            args.push(format!("--wordlist={}", left.to_string_lossy()));
        }
    }
    if let Some(pot) = &job.potfile {
        args.push(format!("--pot={}", pot.to_string_lossy()));
    }
    args.extend(job.extra_args.clone());
    args.push(job.hash_file.to_string_lossy().to_string());
    Ok(args)
}

/// A cracked credential parsed from tool output.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CrackedCredential {
    pub hash: String,
    pub plaintext: String,
    pub username: Option<String>,
}

/// Parse a Hashcat potfile (`hash:plaintext` per line; separators inside the
/// hash are tolerated by splitting on the last colon).
pub fn parse_hashcat_potfile(text: &str) -> Vec<CrackedCredential> {
    let mut out = Vec::new();
    for line in text.lines() {
        let line = line.trim_end_matches(['\r', '\n']);
        if line.is_empty() {
            continue;
        }
        if let Some(idx) = line.rfind(':') {
            let (hash, plain) = line.split_at(idx);
            out.push(CrackedCredential {
                hash: hash.to_string(),
                plaintext: plain[1..].to_string(),
                username: None,
            });
        }
    }
    out
}

/// Parse `john --show` output (`username:plaintext:...` per line). The trailing
/// summary line ("N password hashes cracked") is ignored.
pub fn parse_john_show(text: &str) -> Vec<CrackedCredential> {
    let mut out = Vec::new();
    for line in text.lines() {
        let line = line.trim();
        if line.is_empty() || line.contains("password hash") {
            continue;
        }
        let parts: Vec<&str> = line.splitn(3, ':').collect();
        if parts.len() >= 2 {
            out.push(CrackedCredential {
                username: Some(parts[0].to_string()),
                plaintext: parts[1].to_string(),
                hash: String::new(),
            });
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn job(authorized: bool) -> CredentialAuditJob {
        CredentialAuditJob {
            hash_file: PathBuf::from("hashes.txt"),
            hashcat_mode: Some(1000),
            attack: AttackMode::Dictionary { wordlist: PathBuf::from("rockyou.txt"), rules: Some(PathBuf::from("best64.rule")) },
            potfile: Some(PathBuf::from("out.pot")),
            authorized,
            extra_args: vec![],
        }
    }

    #[test]
    fn unauthorized_is_refused() {
        assert_eq!(build_hashcat_args(&job(false), None), Err(AuditError::NotAuthorized));
        assert_eq!(build_john_args(&job(false), None, None), Err(AuditError::NotAuthorized));
    }

    #[test]
    fn hashcat_args_dictionary_with_rules() {
        let args = build_hashcat_args(&job(true), None).unwrap();
        assert!(args.windows(2).any(|w| w == ["-m", "1000"]));
        assert!(args.windows(2).any(|w| w == ["-a", "0"]));
        assert!(args.iter().any(|a| a == "rockyou.txt"));
        assert!(args.windows(2).any(|w| w == ["-r", "best64.rule"]));
    }

    #[test]
    fn mode_inferred_from_sample_hash() {
        let mut j = job(true);
        j.hashcat_mode = None;
        let args = build_hashcat_args(&j, Some("5e884898da28047151d0e56f8dc6292773603d0d6aabbdd62a11ef721d1542d8")).unwrap();
        // SHA-256 => mode 1400.
        assert!(args.windows(2).any(|w| w == ["-m", "1400"]));
    }

    #[test]
    fn john_args_built() {
        let args = build_john_args(&job(true), Some("NT"), None).unwrap();
        assert!(args.iter().any(|a| a == "--format=NT"));
        assert!(args.iter().any(|a| a.starts_with("--wordlist=")));
        assert!(args.iter().any(|a| a == "--rules"));
    }

    #[test]
    fn parse_potfile_handles_colons_in_hash() {
        let creds = parse_hashcat_potfile("aad3b435b51404ee:summer2024\n$NT$abc:P@ss\n");
        assert_eq!(creds[0].plaintext, "summer2024");
        assert_eq!(creds[1].plaintext, "P@ss");
        assert_eq!(creds[1].hash, "$NT$abc");
    }

    #[test]
    fn parse_john_show_users() {
        let creds = parse_john_show("admin:Password1:1001:::\n2 password hashes cracked\n");
        assert_eq!(creds.len(), 1);
        assert_eq!(creds[0].username.as_deref(), Some("admin"));
        assert_eq!(creds[0].plaintext, "Password1");
    }
}
