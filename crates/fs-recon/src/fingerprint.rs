//! Response fingerprinting, SimHash-based similarity clustering, baseline
//! calibration, and anomaly/novelty scoring for low-noise recon.
//!
//! All deterministic and offline: operates on the [`HttpProbeResult`] values
//! produced by the probe engine. Implements the Phase 1 "dedup / noise
//! reduction" surface (normalized fingerprints, SimHash/LSH-like clustering,
//! baseline-delta scoring, anomaly scoring).

use crate::HttpProbeResult;
use serde::{Deserialize, Serialize};
use std::collections::hash_map::DefaultHasher;
use std::collections::BTreeMap;
use std::hash::{Hash, Hasher};

/// A normalized fingerprint of a response, used for dedup and clustering.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ResponseFingerprint {
    /// Status class bucket (2xx, 3xx, 4xx, 5xx, err).
    pub status_class: String,
    /// Content-length rounded to a coarse bucket to tolerate minor variance.
    pub length_bucket: u64,
    /// Normalized content type (without charset).
    pub content_type: String,
    /// 64-bit SimHash over structural tokens (title + headers + ct + status).
    pub simhash: u64,
}

fn status_class(status: Option<u16>) -> String {
    match status {
        Some(s) if (200..300).contains(&s) => "2xx".into(),
        Some(s) if (300..400).contains(&s) => "3xx".into(),
        Some(s) if (400..500).contains(&s) => "4xx".into(),
        Some(s) if (500..600).contains(&s) => "5xx".into(),
        Some(_) => "other".into(),
        None => "err".into(),
    }
}

fn length_bucket(len: Option<u64>) -> u64 {
    match len {
        Some(0) | None => 0,
        Some(n) => {
            // Coarse logarithmic-ish buckets to absorb small variance.
            let mut bucket = 1u64;
            while bucket * 2 <= n.max(1) {
                bucket *= 2;
            }
            bucket
        }
    }
}

fn token_hash(token: &str) -> u64 {
    let mut h = DefaultHasher::new();
    token.hash(&mut h);
    h.finish()
}

/// Compute a 64-bit SimHash over a set of tokens.
pub fn simhash(tokens: &[String]) -> u64 {
    if tokens.is_empty() {
        return 0;
    }
    let mut v = [0i32; 64];
    for t in tokens {
        let h = token_hash(t);
        for (i, slot) in v.iter_mut().enumerate() {
            if (h >> i) & 1 == 1 {
                *slot += 1;
            } else {
                *slot -= 1;
            }
        }
    }
    let mut out = 0u64;
    for (i, &slot) in v.iter().enumerate() {
        if slot >= 0 {
            out |= 1 << i;
        }
    }
    out
}

/// Hamming distance between two SimHash values (0 = identical).
pub fn hamming(a: u64, b: u64) -> u32 {
    (a ^ b).count_ones()
}

fn normalized_content_type(ct: &Option<String>) -> String {
    ct.as_deref()
        .unwrap_or("")
        .split(';')
        .next()
        .unwrap_or("")
        .trim()
        .to_lowercase()
}

/// Build a structural fingerprint for a probe result.
pub fn fingerprint(result: &HttpProbeResult) -> ResponseFingerprint {
    let ct = normalized_content_type(&result.content_type);
    let mut tokens: Vec<String> = Vec::new();
    tokens.push(format!("status:{}", status_class(result.status)));
    tokens.push(format!("ct:{ct}"));
    if let Some(t) = &result.title {
        for w in t.split_whitespace() {
            tokens.push(format!("title:{}", w.to_lowercase()));
        }
    }
    for (k, _) in result.headers.iter() {
        tokens.push(format!("hdr:{}", k.to_lowercase()));
    }
    ResponseFingerprint {
        status_class: status_class(result.status),
        length_bucket: length_bucket(result.content_length),
        content_type: ct,
        simhash: simhash(&tokens),
    }
}

/// A cluster of similar results, keyed by a representative fingerprint.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Cluster {
    pub id: usize,
    pub representative: ResponseFingerprint,
    pub members: Vec<String>, // result URLs
    pub size: usize,
}

/// Cluster probe results by SimHash similarity. `max_distance` is the Hamming
/// threshold (e.g. 3) under which two responses are considered the same cluster.
pub fn cluster(results: &[HttpProbeResult], max_distance: u32) -> Vec<Cluster> {
    let mut clusters: Vec<Cluster> = Vec::new();
    for r in results {
        let fp = fingerprint(r);
        let mut placed = false;
        for c in clusters.iter_mut() {
            if c.representative.status_class == fp.status_class
                && hamming(c.representative.simhash, fp.simhash) <= max_distance
            {
                c.members.push(r.url.clone());
                c.size += 1;
                placed = true;
                break;
            }
        }
        if !placed {
            let id = clusters.len();
            clusters.push(Cluster { id, representative: fp, members: vec![r.url.clone()], size: 1 });
        }
    }
    clusters.sort_by(|a, b| b.size.cmp(&a.size));
    clusters
}

/// A calibrated baseline from control probes (e.g. random/unlikely paths).
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct Baseline {
    pub fingerprints: Vec<ResponseFingerprint>,
    pub common_status: Option<String>,
    pub common_length_bucket: Option<u64>,
}

/// Calibrate a baseline from a set of control responses (e.g. soft-404 probes).
pub fn calibrate(controls: &[HttpProbeResult]) -> Baseline {
    let fps: Vec<ResponseFingerprint> = controls.iter().map(fingerprint).collect();
    let mut status_counts: BTreeMap<String, usize> = BTreeMap::new();
    let mut length_counts: BTreeMap<u64, usize> = BTreeMap::new();
    for fp in &fps {
        *status_counts.entry(fp.status_class.clone()).or_default() += 1;
        *length_counts.entry(fp.length_bucket).or_default() += 1;
    }
    let common_status = status_counts.into_iter().max_by_key(|(_, c)| *c).map(|(s, _)| s);
    let common_length_bucket = length_counts.into_iter().max_by_key(|(_, c)| *c).map(|(l, _)| l);
    Baseline { fingerprints: fps, common_status, common_length_bucket }
}

/// Score a result against a baseline. Returns 0.0 (matches baseline noise) to
/// 1.0 (strongly novel / interesting). Higher = more worth triaging.
pub fn novelty_score(result: &HttpProbeResult, baseline: &Baseline) -> f32 {
    let fp = fingerprint(result);
    if baseline.fingerprints.is_empty() {
        return 0.5; // no baseline -> neutral
    }
    let min_dist = baseline
        .fingerprints
        .iter()
        .map(|b| hamming(b.simhash, fp.simhash))
        .min()
        .unwrap_or(64);
    let mut score = (min_dist as f32 / 64.0).clamp(0.0, 1.0);
    // Status divergence from baseline is a strong novelty signal.
    if let Some(cs) = &baseline.common_status {
        if cs != &fp.status_class {
            score = (score + 0.4).min(1.0);
        }
    }
    // Length divergence nudges the score up.
    if let Some(cl) = baseline.common_length_bucket {
        if cl != fp.length_bucket {
            score = (score + 0.1).min(1.0);
        }
    }
    score
}

/// Deduplicate results, keeping one representative per exact fingerprint.
pub fn dedup(results: &[HttpProbeResult]) -> Vec<HttpProbeResult> {
    let mut seen: std::collections::BTreeSet<(String, u64, u64)> = std::collections::BTreeSet::new();
    let mut out = Vec::new();
    for r in results {
        let fp = fingerprint(r);
        let key = (fp.status_class.clone(), fp.length_bucket, fp.simhash);
        if seen.insert(key) {
            out.push(r.clone());
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Utc;
    use fs_core::Severity;
    use uuid::Uuid;

    fn mk(url: &str, status: u16, len: u64, title: &str) -> HttpProbeResult {
        HttpProbeResult {
            id: Uuid::new_v4(),
            url: url.into(),
            status: Some(status),
            title: Some(title.into()),
            content_length: Some(len),
            content_type: Some("text/html; charset=utf-8".into()),
            final_url: Some(url.into()),
            error: None,
            severity_hint: Severity::Info,
            timestamp: Utc::now(),
            headers: BTreeMap::new(),
        }
    }

    #[test]
    fn simhash_identical_tokens_match() {
        let a = simhash(&["x".into(), "y".into()]);
        let b = simhash(&["x".into(), "y".into()]);
        assert_eq!(a, b);
        assert_eq!(hamming(a, b), 0);
    }

    #[test]
    fn clusters_group_similar_pages() {
        let results = vec![
            mk("https://a.com/1", 200, 1000, "Welcome home"),
            mk("https://a.com/2", 200, 1010, "Welcome home"),
            mk("https://a.com/admin", 403, 50, "Forbidden"),
        ];
        let clusters = cluster(&results, 3);
        // The two near-identical 200 pages collapse; the 403 is its own cluster.
        assert!(clusters.len() <= 2);
        assert_eq!(clusters[0].size, 2);
    }

    #[test]
    fn novelty_scores_admin_above_baseline() {
        let baseline = calibrate(&[mk("https://a.com/zzz-404", 404, 20, "Not Found")]);
        let interesting = mk("https://a.com/admin", 200, 4000, "Admin Console");
        let boring = mk("https://a.com/qqq-404", 404, 20, "Not Found");
        assert!(novelty_score(&interesting, &baseline) > novelty_score(&boring, &baseline));
    }

    #[test]
    fn dedup_collapses_identical() {
        let results = vec![
            mk("https://a.com/1", 404, 20, "Not Found"),
            mk("https://a.com/2", 404, 20, "Not Found"),
        ];
        assert_eq!(dedup(&results).len(), 1);
    }
}
