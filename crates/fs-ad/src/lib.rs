//! Active Directory offline analysis (Phase 3, authorized use only).
//!
//! Native, deterministic parsing and normalization of AD credential artifacts
//! and graph imports — no collection, no execution, no cracking. It turns the
//! *outputs* of authorized tooling (secretsdump/NTDS dumps, NetNTLM captures,
//! Kerberos roast artifacts, BloodHound JSON) into normalized records with risk
//! scoring, so analysts can triage and report. Any live collection or cracking
//! stays gated behind the credential-audit adapters and an authorized lab.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

/// Kind of credential artifact recognised.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ArtifactKind {
    NtlmNtds,     // domain NTDS/secretsdump line (LM:NT)
    NetNtlmV1,    // captured NetNTLMv1
    NetNtlmV2,    // captured NetNTLMv2
    Kerberoast,   // $krb5tgs$
    AsRepRoast,   // $krb5asrep$
}

/// A normalized credential artifact (never contains a plaintext secret).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CredentialArtifact {
    pub kind: ArtifactKind,
    pub username: Option<String>,
    pub domain: Option<String>,
    /// The hash/material as presented (NT hash, blob, ticket) — opaque here.
    pub material: String,
    /// Hashcat mode mapped for authorized auditing.
    pub hashcat_mode: Option<u32>,
    /// Risk score 0..100 with a short rationale.
    pub risk: u8,
    pub rationale: Vec<String>,
}

const EMPTY_LM: &str = "aad3b435b51404eeaad3b435b51404ee";

/// Parse one NTDS/secretsdump line: `DOMAIN\user:rid:LM:NT:::` (or `user:rid:LM:NT:::`).
pub fn parse_ntds_line(line: &str) -> Option<CredentialArtifact> {
    let line = line.trim();
    if line.is_empty() || line.starts_with('#') {
        return None;
    }
    let parts: Vec<&str> = line.split(':').collect();
    if parts.len() < 4 {
        return None;
    }
    let lm = parts[2];
    let nt = parts[3];
    if lm.len() != 32 || nt.len() != 32 || !lm.chars().all(|c| c.is_ascii_hexdigit()) || !nt.chars().all(|c| c.is_ascii_hexdigit()) {
        return None;
    }
    let (domain, username) = match parts[0].split_once('\\') {
        Some((d, u)) => (Some(d.to_string()), Some(u.to_string())),
        None => (None, Some(parts[0].to_string())),
    };
    let mut rationale = Vec::new();
    let mut risk = 40u8;
    if lm.eq_ignore_ascii_case(EMPTY_LM) {
        rationale.push("LM hash disabled (good)".into());
    } else {
        rationale.push("LM hash present — weak legacy hashing enabled".into());
        risk += 25;
    }
    if username.as_deref().map(|u| {
        let u = u.to_lowercase();
        u == "administrator" || u.ends_with("admin") || u.ends_with("$") == false && u.contains("adm")
    }).unwrap_or(false) {
        rationale.push("Privileged-looking account name".into());
        risk += 20;
    }
    if username.as_deref().map(|u| u.ends_with('$')).unwrap_or(false) {
        rationale.push("Machine account".into());
        risk = risk.saturating_sub(10);
    }
    Some(CredentialArtifact {
        kind: ArtifactKind::NtlmNtds,
        username,
        domain,
        material: nt.to_lowercase(),
        hashcat_mode: Some(1000),
        risk: risk.min(100),
        rationale,
    })
}

/// Parse a NetNTLM capture line (Responder/ntlmrelayx style).
/// v2 form: `user::DOMAIN:serverchallenge:ntproofstr:blob`
/// v1 form: `user::DOMAIN:lmresp:ntresp:challenge`
pub fn parse_netntlm(line: &str) -> Option<CredentialArtifact> {
    let line = line.trim();
    if !line.contains("::") {
        return None;
    }
    let (user, rest) = line.split_once("::")?;
    let fields: Vec<&str> = rest.split(':').collect();
    if fields.len() < 4 {
        return None;
    }
    let domain = Some(fields[0].to_string());
    // Structure discriminator: NetNTLMv2 is `domain:srvchal(16):ntproof(32):blob`
    // (field[2] is a 32-hex NT-proof string); NetNTLMv1 is
    // `domain:lmresp(48):ntresp(48):srvchal(16)` (field[2] is 48 hex).
    let is_hex = |s: &str| !s.is_empty() && s.chars().all(|c| c.is_ascii_hexdigit());
    let looks_v2 = fields.get(2).map(|f| f.len() == 32 && is_hex(f)).unwrap_or(false);
    let (kind, mode) = if looks_v2 {
        (ArtifactKind::NetNtlmV2, 5600)
    } else {
        (ArtifactKind::NetNtlmV1, 5500)
    };
    let mut rationale = vec!["Captured network authentication — relayable/crackable if weak".into()];
    let mut risk = if looks_v2 { 55 } else { 70 };
    if !looks_v2 {
        rationale.push("NetNTLMv1 — downgradeable and fast to crack".into());
        risk += 10;
    }
    Some(CredentialArtifact {
        kind,
        username: Some(user.to_string()),
        domain,
        material: line.to_string(),
        hashcat_mode: Some(mode),
        risk: risk.min(100),
        rationale,
    })
}

/// Parse a Kerberos roast artifact (`$krb5tgs$` / `$krb5asrep$`).
pub fn parse_kerberos(blob: &str) -> Option<CredentialArtifact> {
    let b = blob.trim();
    let (kind, mode, base_risk) = if b.starts_with("$krb5tgs$") {
        (ArtifactKind::Kerberoast, 13100, 65)
    } else if b.starts_with("$krb5asrep$") {
        (ArtifactKind::AsRepRoast, 18200, 70)
    } else {
        return None;
    };
    // Username extraction differs by artifact shape:
    //  krb5tgs: `$krb5tgs$<etype>$*<user>$<realm>$<spn>*$<blob>`
    //  krb5asrep: `$krb5asrep$<etype>$<user>@<realm>:<blob>`
    let username = match kind {
        ArtifactKind::Kerberoast => b.split('*').nth(1).and_then(|s| s.split('$').next()),
        _ => b.strip_prefix("$krb5asrep$").and_then(|r| r.split('$').nth(1)).and_then(|r| r.split(['@', ':']).next()),
    }
    .map(|s| s.trim().to_string())
    .filter(|s| !s.is_empty());
    let rationale = match kind {
        ArtifactKind::Kerberoast => vec!["Service account TGS — crackable offline (Kerberoasting)".into()],
        _ => vec!["AS-REP without pre-auth — crackable offline (AS-REP Roasting)".into()],
    };
    Some(CredentialArtifact {
        kind,
        username,
        domain: None,
        material: b.to_string(),
        hashcat_mode: Some(mode),
        risk: base_risk,
        rationale,
    })
}

/// Best-effort parse of a single artifact line of any supported kind.
pub fn parse_artifact(line: &str) -> Option<CredentialArtifact> {
    parse_kerberos(line)
        .or_else(|| parse_netntlm(line))
        .or_else(|| parse_ntds_line(line))
}

/// Parse a whole dump (one artifact per line), skipping unrecognized lines.
pub fn parse_dump(text: &str) -> Vec<CredentialArtifact> {
    text.lines().filter_map(parse_artifact).collect()
}

// ---------------------------------------------------------------------------
// BloodHound graph import (offline)
// ---------------------------------------------------------------------------

/// A normalized AD object from a BloodHound export.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AdObject {
    pub kind: String, // user, group, computer, domain
    pub name: String,
    pub enabled: Option<bool>,
    pub admin_count: Option<bool>,
    pub spns: Vec<String>,
    pub risk_tags: Vec<String>,
}

/// Import a BloodHound users/computers JSON export (`{"data":[{"Properties":{...}}]}`
/// or `{"nodes":[...]}`) into normalized AD objects with risk tagging.
pub fn import_bloodhound(doc: &serde_json::Value, kind: &str) -> Vec<AdObject> {
    let items = doc
        .get("data")
        .and_then(|v| v.as_array())
        .or_else(|| doc.get("nodes").and_then(|v| v.as_array()))
        .cloned()
        .unwrap_or_default();
    let mut out = Vec::new();
    for it in items {
        let props = it.get("Properties").or_else(|| it.get("properties")).unwrap_or(&it);
        let name = props
            .get("name")
            .or_else(|| props.get("samaccountname"))
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string();
        if name.is_empty() {
            continue;
        }
        let enabled = props.get("enabled").and_then(|v| v.as_bool());
        let admin_count = props.get("admincount").and_then(|v| v.as_bool());
        let spns: Vec<String> = props
            .get("serviceprincipalnames")
            .and_then(|v| v.as_array())
            .map(|a| a.iter().filter_map(|x| x.as_str().map(String::from)).collect())
            .unwrap_or_default();
        let mut risk_tags = Vec::new();
        if admin_count == Some(true) {
            risk_tags.push("adminCount=1 (privileged/protected)".into());
        }
        if !spns.is_empty() {
            risk_tags.push("has SPN (Kerberoastable)".into());
        }
        if props.get("dontreqpreauth").and_then(|v| v.as_bool()) == Some(true) {
            risk_tags.push("no Kerberos pre-auth (AS-REP roastable)".into());
        }
        if props.get("unconstraineddelegation").and_then(|v| v.as_bool()) == Some(true) {
            risk_tags.push("unconstrained delegation".into());
        }
        if enabled == Some(false) {
            risk_tags.push("disabled".into());
        }
        out.push(AdObject { kind: kind.to_string(), name, enabled, admin_count, spns, risk_tags });
    }
    out
}

/// Summary of a credential-artifact set for reporting.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct AdSummary {
    pub total: usize,
    pub lm_enabled: usize,
    pub kerberoastable: usize,
    pub asrep_roastable: usize,
    pub high_risk: usize,
    pub generated_at: Option<DateTime<Utc>>,
}

pub fn summarize(artifacts: &[CredentialArtifact]) -> AdSummary {
    let mut s = AdSummary { total: artifacts.len(), generated_at: Some(Utc::now()), ..Default::default() };
    for a in artifacts {
        if matches!(a.kind, ArtifactKind::NtlmNtds) && a.rationale.iter().any(|r| r.contains("LM hash present")) {
            s.lm_enabled += 1;
        }
        if a.kind == ArtifactKind::Kerberoast {
            s.kerberoastable += 1;
        }
        if a.kind == ArtifactKind::AsRepRoast {
            s.asrep_roastable += 1;
        }
        if a.risk >= 70 {
            s.high_risk += 1;
        }
    }
    s
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_ntds_with_lm_enabled() {
        let a = parse_ntds_line("CORP\\admin:1104:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb:::").unwrap();
        assert_eq!(a.kind, ArtifactKind::NtlmNtds);
        assert_eq!(a.domain.as_deref(), Some("CORP"));
        assert_eq!(a.username.as_deref(), Some("admin"));
        assert!(a.rationale.iter().any(|r| r.contains("LM hash present")));
        assert!(a.risk > 50);
    }

    #[test]
    fn empty_lm_is_lower_risk() {
        let line = format!("CORP\\svc:1105:{}:cccccccccccccccccccccccccccccccc:::", EMPTY_LM);
        let a = parse_ntds_line(&line).unwrap();
        assert!(a.rationale.iter().any(|r| r.contains("LM hash disabled")));
    }

    #[test]
    fn parses_kerberoast() {
        let a = parse_kerberos("$krb5tgs$23$*svc_sql$CORP.LOCAL$MSSQLSvc/db*$aabbcc...").unwrap();
        assert_eq!(a.kind, ArtifactKind::Kerberoast);
        assert_eq!(a.hashcat_mode, Some(13100));
        assert_eq!(a.username.as_deref(), Some("svc_sql"));
    }

    #[test]
    fn parses_netntlmv2() {
        let line = "user::CORP:1122334455667788:1234567890abcdef1234567890abcdef:0101000000000000AABBCCDDEEFF00112233445566778899";
        let a = parse_netntlm(line).unwrap();
        assert_eq!(a.kind, ArtifactKind::NetNtlmV2);
        assert_eq!(a.hashcat_mode, Some(5600));
    }

    #[test]
    fn imports_bloodhound_with_risk_tags() {
        let doc = serde_json::json!({"data":[
            {"Properties":{"name":"SQLSVC@CORP","enabled":true,"serviceprincipalnames":["MSSQLSvc/db"],"admincount":true}}
        ]});
        let objs = import_bloodhound(&doc, "user");
        assert_eq!(objs.len(), 1);
        assert!(objs[0].risk_tags.iter().any(|t| t.contains("Kerberoastable")));
        assert!(objs[0].risk_tags.iter().any(|t| t.contains("adminCount")));
    }

    #[test]
    fn summary_counts() {
        let arts = parse_dump("$krb5tgs$23$*a$b$c*$dd\n$krb5asrep$23$u@R:aa$bb\nCORP\\u:1:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb:::");
        let s = summarize(&arts);
        assert_eq!(s.total, 3);
        assert_eq!(s.kerberoastable, 1);
        assert_eq!(s.asrep_roastable, 1);
        assert_eq!(s.lm_enabled, 1);
    }
}
