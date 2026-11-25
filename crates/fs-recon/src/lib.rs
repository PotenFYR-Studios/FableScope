use chrono::{DateTime, Utc};
use fs_core::{ScopePolicy, Severity};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use thiserror::Error;
use tokio::sync::Semaphore;
use url::Url;
use uuid::Uuid;

pub mod cloud;
pub mod filter;
pub mod fingerprint;
pub mod mutators;
pub mod subdomain;

pub use cloud::{exposure_indicators, storage_candidates_scoped, CloudProvider, ExposureIndicator};
pub use filter::{apply_filters, group, Filter, GroupBy};
pub use fingerprint::{calibrate, cluster, dedup, fingerprint as response_fingerprint, novelty_score, Baseline, Cluster};
pub use mutators::{default_strategies, generate as generate_payloads, generate_many, Mutator, Payload};
pub use subdomain::{candidate_urls, generate_candidates as subdomain_candidates, AssetGraph};

pub type Result<T> = std::result::Result<T, ReconError>;

#[derive(Debug, Error)]
pub enum ReconError {
    #[error("invalid target: {0}")]
    InvalidTarget(String),
    #[error("out of scope: {0}")]
    OutOfScope(String),
    #[error("http error: {0}")]
    Http(#[from] reqwest::Error),
    #[error("url error: {0}")]
    Url(#[from] url::ParseError),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReconConfig {
    pub concurrency: usize,
    pub timeout_ms: u64,
    pub user_agent: String,
    pub follow_redirects: bool,
}

impl Default for ReconConfig {
    fn default() -> Self {
        Self {
            concurrency: 10,
            timeout_ms: 8_000,
            user_agent: "FableScope/0.1".into(),
            follow_redirects: true,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HttpProbeResult {
    pub id: Uuid,
    pub url: String,
    pub status: Option<u16>,
    pub title: Option<String>,
    pub content_length: Option<u64>,
    pub content_type: Option<String>,
    pub final_url: Option<String>,
    pub error: Option<String>,
    pub severity_hint: Severity,
    pub timestamp: DateTime<Utc>,
    pub headers: BTreeMap<String, String>,
}

pub async fn probe_urls(urls: Vec<String>, scope: &ScopePolicy, cfg: &ReconConfig) -> Result<Vec<HttpProbeResult>> {
    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_millis(cfg.timeout_ms))
        .user_agent(&cfg.user_agent)
        .redirect(if cfg.follow_redirects { reqwest::redirect::Policy::limited(5) } else { reqwest::redirect::Policy::none() })
        .build()?;

    let sem = std::sync::Arc::new(Semaphore::new(cfg.concurrency.max(1)));
    let mut set = tokio::task::JoinSet::new();

    for raw in urls {
        let Ok(parsed) = Url::parse(&raw) else {
            continue;
        };
        let host = parsed.host_str().unwrap_or_default().to_string();
        if !scope.is_allowed(&host) && !scope.is_allowed(&raw) {
            continue;
        }
        let permit = sem.clone().acquire_owned().await.unwrap();
        let client = client.clone();
        set.spawn(async move {
            let _p = permit;
            probe_one(&client, raw).await
        });
    }

    let mut out = Vec::new();
    while let Some(r) = set.join_next().await {
        if let Ok(item) = r { out.push(item); }
    }
    out.sort_by(|a, b| a.url.cmp(&b.url));
    Ok(out)
}

async fn probe_one(client: &reqwest::Client, url: String) -> HttpProbeResult {
    let id = Uuid::new_v4();
    let timestamp = Utc::now();
    match client.get(&url).send().await {
        Ok(resp) => {
            let status = resp.status().as_u16();
            let final_url = Some(resp.url().to_string());
            let content_type = resp.headers().get(reqwest::header::CONTENT_TYPE).and_then(|v| v.to_str().ok()).map(|s| s.to_string());
            let content_length = resp.headers().get(reqwest::header::CONTENT_LENGTH).and_then(|v| v.to_str().ok()).and_then(|s| s.parse().ok());
            let mut headers = BTreeMap::new();
            for (k, v) in resp.headers().iter().take(20) {
                headers.insert(k.to_string(), v.to_str().unwrap_or("<bin>").to_string());
            }
            let body = resp.text().await.unwrap_or_default();
            let title = extract_title(&body);
            let severity_hint = if status >= 500 { Severity::Medium } else if status == 200 { Severity::Info } else { Severity::Low };
            HttpProbeResult { id, url, status: Some(status), title, content_length, content_type, final_url, error: None, severity_hint, timestamp, headers }
        }
        Err(e) => HttpProbeResult {
            id, url, status: None, title: None, content_length: None, content_type: None, final_url: None,
            error: Some(e.to_string()), severity_hint: Severity::Info, timestamp, headers: BTreeMap::new(),
        }
    }
}

fn extract_title(body: &str) -> Option<String> {
    let lower = body.to_lowercase();
    let start = lower.find("<title>")? + 7;
    let end = lower[start..].find("</title>")? + start;
    let t = body[start..end].trim();
    if t.is_empty() { None } else { Some(t.chars().take(120).collect()) }
}

pub fn build_fuzz_urls(base: &str, word: &str) -> Result<Vec<String>> {
    let mut u = Url::parse(base)?;
    let base_path = u.path().trim_end_matches('/').to_string();
    let w = word.trim().trim_start_matches('/');
    if w.is_empty() { return Ok(vec![]); }
    let mut out = Vec::new();
    u.set_path(&format!("{}/{}", if base_path.is_empty() { "" } else { &base_path }, w));
    out.push(u.to_string());
    let mut uq = Url::parse(base)?;
    uq.query_pairs_mut().append_pair(w, "FUZZ");
    out.push(uq.to_string());
    out.sort();
    out.dedup();
    Ok(out)
}

pub fn generate_fuzz_targets(base: &str, words: &[String], limit: usize) -> Result<Vec<String>> {
    let mut out = Vec::new();
    for w in words.iter().take(limit.max(1)) {
        for u in build_fuzz_urls(base, w)? {
            out.push(u);
        }
    }
    out.sort();
    out.dedup();
    Ok(out)
}

/// Build fuzz URLs from a base URL and a set of seed words using the mutator
/// engine. Each mutated payload is applied both as a path segment and as a query
/// parameter value, scope-filtered and capped.
pub fn generate_smart_fuzz_targets(
    base: &str,
    seeds: &[String],
    strategies: &[mutators::Mutator],
    scope: &ScopePolicy,
    limit: usize,
) -> Result<Vec<String>> {
    let payloads = mutators::generate_many(seeds, strategies, limit.saturating_mul(2).max(1));
    let mut out: std::collections::BTreeSet<String> = std::collections::BTreeSet::new();
    for p in payloads {
        for u in build_fuzz_urls(base, &p.value).unwrap_or_default() {
            if let Ok(parsed) = Url::parse(&u) {
                let host = parsed.host_str().unwrap_or_default();
                if scope.is_allowed(host) || scope.is_allowed(&u) {
                    out.insert(u);
                }
            }
        }
        if out.len() >= limit {
            break;
        }
    }
    Ok(out.into_iter().take(limit.max(1)).collect())
}

/// A probe result enriched with dedup/cluster/novelty signals.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EnrichedResults {
    pub total: usize,
    pub unique: usize,
    pub clusters: Vec<fingerprint::Cluster>,
    pub scored: Vec<ScoredResult>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScoredResult {
    pub url: String,
    pub status: Option<u16>,
    pub novelty: f32,
    pub cluster_id: usize,
}

/// Run the full smart-triage pipeline over probe results: dedup, cluster, and
/// score each result against an optional baseline. Results are sorted by
/// descending novelty so the most interesting responses surface first.
pub fn enrich_results(results: &[HttpProbeResult], baseline: Option<&fingerprint::Baseline>) -> EnrichedResults {
    let unique = fingerprint::dedup(results);
    let clusters = fingerprint::cluster(results, 3);
    let default_baseline = fingerprint::Baseline::default();
    let base = baseline.unwrap_or(&default_baseline);
    let mut scored: Vec<ScoredResult> = results
        .iter()
        .map(|r| {
            let cid = clusters
                .iter()
                .find(|c| c.members.contains(&r.url))
                .map(|c| c.id)
                .unwrap_or(0);
            ScoredResult {
                url: r.url.clone(),
                status: r.status,
                novelty: fingerprint::novelty_score(r, base),
                cluster_id: cid,
            }
        })
        .collect();
    scored.sort_by(|a, b| b.novelty.partial_cmp(&a.novelty).unwrap_or(std::cmp::Ordering::Equal));
    EnrichedResults { total: results.len(), unique: unique.len(), clusters, scored }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn smart_fuzz_targets_scoped() {
        let scope = ScopePolicy { allow: vec!["example.com".into()], deny: vec![] };
        let out = generate_smart_fuzz_targets(
            "https://example.com/app",
            &["admin".into()],
            &mutators::default_strategies(),
            &scope,
            50,
        )
        .unwrap();
        assert!(!out.is_empty());
        assert!(out.iter().all(|u| u.contains("example.com")));
    }

    #[test]
    fn extract_title_works() {
        assert_eq!(extract_title("<html><title>Hi</title></html>").as_deref(), Some("Hi"));
    }

    #[test]
    fn build_fuzz_urls_basic() {
        let out = build_fuzz_urls("https://example.com/app", "admin").unwrap();
        assert!(out.iter().any(|u| u.contains("/app/admin")));
    }

    #[test]
    fn generate_fuzz_targets_dedups() {
        let out = generate_fuzz_targets("https://example.com", &["admin".into(), "admin".into(), "api".into()], 10).unwrap();
        assert!(out.iter().any(|u| u.contains("/admin")));
        assert!(out.iter().any(|u| u.contains("/api")));
        let mut dedup = out.clone();
        dedup.sort(); dedup.dedup();
        assert_eq!(out.len(), dedup.len());
    }
}
