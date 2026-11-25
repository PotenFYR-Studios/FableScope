//! Cloud exposure recon: deterministic, offline generation of storage-bucket
//! candidates and cloud-host URLs, plus exposure-indicator scoring over probe
//! responses. Actual probing runs through the scope-guarded probe engine; this
//! module only *generates* candidates and *interprets* responses. No destructive
//! writes, ever: generated probes are read/list only.

use crate::HttpProbeResult;
use fs_core::{ScopePolicy, Severity};
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;

/// A cloud provider whose storage naming patterns we understand.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CloudProvider {
    Aws,
    Gcp,
    Azure,
    DigitalOcean,
}

impl CloudProvider {
    pub fn all() -> Vec<CloudProvider> {
        vec![CloudProvider::Aws, CloudProvider::Gcp, CloudProvider::Azure, CloudProvider::DigitalOcean]
    }
}

/// Default affixes applied to a base name when generating bucket candidates.
fn bucket_affixes() -> Vec<&'static str> {
    vec![
        "", "-prod", "-production", "-dev", "-staging", "-test", "-backup", "-backups", "-assets",
        "-static", "-media", "-uploads", "-data", "-logs", "-public", "-private", "-internal",
        "-cdn", "-images", "-files", "-archive", "-db", "-dump",
    ]
}

/// Build candidate storage URLs for a base name across providers. These are
/// read/list URLs only. Results are deduplicated.
pub fn storage_candidates(base_names: &[String], providers: &[CloudProvider]) -> Vec<String> {
    let mut out: BTreeSet<String> = BTreeSet::new();
    for base in base_names {
        let base = base.trim().to_lowercase();
        if base.is_empty() {
            continue;
        }
        for affix in bucket_affixes() {
            let name = format!("{base}{affix}");
            let name = name.trim_matches('-').to_string();
            if name.is_empty() {
                continue;
            }
            for p in providers {
                match p {
                    CloudProvider::Aws => {
                        out.insert(format!("https://{name}.s3.amazonaws.com/"));
                        out.insert(format!("https://s3.amazonaws.com/{name}/"));
                    }
                    CloudProvider::Gcp => {
                        out.insert(format!("https://storage.googleapis.com/{name}/"));
                        out.insert(format!("https://{name}.storage.googleapis.com/"));
                    }
                    CloudProvider::Azure => {
                        out.insert(format!("https://{name}.blob.core.windows.net/"));
                    }
                    CloudProvider::DigitalOcean => {
                        out.insert(format!("https://{name}.nyc3.digitaloceanspaces.com/"));
                    }
                }
            }
        }
    }
    out.into_iter().collect()
}

/// Generate storage candidates, filtered against scope and capped.
pub fn storage_candidates_scoped(
    base_names: &[String],
    providers: &[CloudProvider],
    scope: &ScopePolicy,
    limit: usize,
) -> Vec<String> {
    storage_candidates(base_names, providers)
        .into_iter()
        .filter(|u| scope.is_allowed(u))
        .take(limit.max(1))
        .collect()
}

/// An exposure indicator derived from a probe response.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExposureIndicator {
    pub url: String,
    pub provider: Option<String>,
    pub indicator: String,
    pub severity: Severity,
    pub detail: String,
}

fn detect_provider(url: &str) -> Option<&'static str> {
    let u = url.to_lowercase();
    if u.contains("amazonaws.com") || u.contains(".s3.") {
        Some("aws")
    } else if u.contains("googleapis.com") {
        Some("gcp")
    } else if u.contains("blob.core.windows.net") {
        Some("azure")
    } else if u.contains("digitaloceanspaces.com") {
        Some("digitalocean")
    } else {
        None
    }
}

/// Interpret a probe response for cloud-exposure indicators. Read-only
/// heuristics: public listing (200 + XML listing body hints), redirect to
/// cloud origin, and CDN/origin headers.
pub fn exposure_indicators(result: &HttpProbeResult) -> Vec<ExposureIndicator> {
    let mut out = Vec::new();
    let provider = detect_provider(&result.url).map(String::from);
    let title = result.title.as_deref().unwrap_or("");

    // Public bucket listing: cloud storage endpoints answering 200 are a strong
    // signal of a readable/listable bucket.
    if provider.is_some() && result.status == Some(200) {
        out.push(ExposureIndicator {
            url: result.url.clone(),
            provider: provider.clone(),
            indicator: "public_storage_200".into(),
            severity: Severity::High,
            detail: "Cloud storage endpoint returned 200 — possible public read/list access. Validate with authorized read-only check.".into(),
        });
    }

    // AccessDenied / NoSuchBucket discrimination (common provider bodies/titles).
    let t = title.to_lowercase();
    if provider.is_some() && (t.contains("accessdenied") || t.contains("access denied")) {
        out.push(ExposureIndicator {
            url: result.url.clone(),
            provider: provider.clone(),
            indicator: "storage_exists_private".into(),
            severity: Severity::Low,
            detail: "Storage endpoint exists but denies access (bucket present, not public).".into(),
        });
    }

    // CDN / origin headers worth mapping for origin-bypass research.
    for (k, v) in &result.headers {
        let kl = k.to_lowercase();
        if (kl == "server" && (v.to_lowercase().contains("cloudfront") || v.to_lowercase().contains("cloudflare")))
            || kl == "x-amz-cf-id"
            || kl == "cf-ray"
            || kl == "x-cache"
        {
            out.push(ExposureIndicator {
                url: result.url.clone(),
                provider: provider.clone(),
                indicator: "cdn_origin_header".into(),
                severity: Severity::Info,
                detail: format!("CDN indicator header {k}: {v} — candidate for origin mapping (non-destructive)."),
            });
            break;
        }
    }

    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Utc;
    use std::collections::BTreeMap;
    use uuid::Uuid;

    fn mk(url: &str, status: u16, title: &str, headers: BTreeMap<String, String>) -> HttpProbeResult {
        HttpProbeResult {
            id: Uuid::new_v4(),
            url: url.into(),
            status: Some(status),
            title: Some(title.into()),
            content_length: Some(100),
            content_type: Some("application/xml".into()),
            final_url: Some(url.into()),
            error: None,
            severity_hint: Severity::Info,
            timestamp: Utc::now(),
            headers,
        }
    }

    #[test]
    fn storage_candidates_cover_providers() {
        let c = storage_candidates(&["acme".into()], &CloudProvider::all());
        assert!(c.iter().any(|u| u.contains("acme.s3.amazonaws.com")));
        assert!(c.iter().any(|u| u.contains("storage.googleapis.com/acme")));
        assert!(c.iter().any(|u| u.contains("acme.blob.core.windows.net")));
    }

    #[test]
    fn scope_filters_storage() {
        let scope = ScopePolicy { allow: vec!["amazonaws.com".into()], deny: vec![] };
        let c = storage_candidates_scoped(&["acme".into()], &CloudProvider::all(), &scope, 1000);
        assert!(c.iter().all(|u| u.contains("amazonaws.com")));
    }

    #[test]
    fn public_bucket_flagged_high() {
        let r = mk("https://acme.s3.amazonaws.com/", 200, "ListBucketResult", BTreeMap::new());
        let ind = exposure_indicators(&r);
        assert!(ind.iter().any(|i| i.indicator == "public_storage_200" && i.severity == Severity::High));
    }

    #[test]
    fn private_bucket_flagged_low() {
        let r = mk("https://acme.s3.amazonaws.com/", 403, "AccessDenied", BTreeMap::new());
        let ind = exposure_indicators(&r);
        assert!(ind.iter().any(|i| i.indicator == "storage_exists_private"));
    }

    #[test]
    fn cdn_header_detected() {
        let mut h = BTreeMap::new();
        h.insert("cf-ray".into(), "abc123".into());
        let r = mk("https://www.acme.com/", 200, "Home", h);
        let ind = exposure_indicators(&r);
        assert!(ind.iter().any(|i| i.indicator == "cdn_origin_header"));
    }
}
