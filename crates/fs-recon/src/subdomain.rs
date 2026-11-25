//! Subdomain candidate generation and the recon asset graph.
//!
//! Offline, deterministic candidate generation (wordlist prefixes, permutations,
//! and n-gram/affix mutation of known names) plus a scope-aware helper to turn
//! candidates into probe URLs. Actual DNS resolution / HTTP probing is performed
//! by the probe engine under the scope guard; this module never emits a target
//! that fails the scope policy.

use fs_core::ScopePolicy;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};

/// Common subdomain prefixes used for brute/permutation candidate generation.
pub fn common_prefixes() -> Vec<&'static str> {
    vec![
        "www", "api", "dev", "staging", "stage", "test", "qa", "uat", "admin", "portal", "app",
        "apps", "mail", "smtp", "imap", "vpn", "git", "gitlab", "jenkins", "ci", "cd", "docs",
        "status", "dashboard", "internal", "intranet", "beta", "demo", "cdn", "assets", "static",
        "media", "img", "images", "files", "download", "support", "help", "blog", "shop", "store",
        "secure", "login", "sso", "auth", "id", "account", "accounts", "db", "database", "cache",
        "redis", "mongo", "s3", "storage", "backup", "old", "new", "mobile", "m", "ns1", "ns2",
        "mx", "autodiscover", "owa", "exchange", "remote", "gw", "proxy", "monitor", "grafana",
        "kibana", "prometheus", "k8s", "kube", "registry", "docker", "npm", "pypi", "artifactory",
    ]
}

/// Generate brute-force subdomain candidates from a root domain and prefixes.
pub fn brute_candidates(root: &str, prefixes: &[String]) -> Vec<String> {
    let root = root.trim().trim_start_matches('.').to_lowercase();
    let mut out = BTreeSet::new();
    for p in prefixes {
        let p = p.trim().trim_matches('.').to_lowercase();
        if p.is_empty() {
            continue;
        }
        out.insert(format!("{p}.{root}"));
    }
    out.into_iter().collect()
}

/// Generate permutation candidates around known subdomains (affix mutations:
/// environment suffixes, numeric suffixes, dash-joined words). This mirrors the
/// permutation/mutation approach of tools like altdns/dnsgen, offline.
pub fn permutation_candidates(root: &str, known: &[String]) -> Vec<String> {
    let root = root.trim().trim_start_matches('.').to_lowercase();
    let envs = ["dev", "staging", "test", "prod", "qa", "uat", "internal", "old", "new", "v2"];
    let mut out = BTreeSet::new();
    for k in known {
        // Extract the left-most label of a known subdomain.
        let label = k
            .trim()
            .to_lowercase()
            .strip_suffix(&format!(".{root}"))
            .map(|s| s.split('.').next().unwrap_or(s).to_string())
            .unwrap_or_else(|| k.split('.').next().unwrap_or(k).to_string());
        if label.is_empty() {
            continue;
        }
        for e in envs {
            out.insert(format!("{label}-{e}.{root}"));
            out.insert(format!("{e}-{label}.{root}"));
            out.insert(format!("{label}.{e}.{root}"));
        }
        for n in 1..=3 {
            out.insert(format!("{label}{n}.{root}"));
            out.insert(format!("{label}-{n}.{root}"));
        }
    }
    out.into_iter().collect()
}

/// Full candidate set = brute(prefixes) ∪ permutations(known), deduplicated,
/// filtered against scope, and capped.
pub fn generate_candidates(
    root: &str,
    extra_prefixes: &[String],
    known: &[String],
    scope: &ScopePolicy,
    limit: usize,
) -> Vec<String> {
    let mut prefixes: Vec<String> = common_prefixes().into_iter().map(String::from).collect();
    prefixes.extend(extra_prefixes.iter().cloned());
    let mut all: BTreeSet<String> = BTreeSet::new();
    for c in brute_candidates(root, &prefixes) {
        all.insert(c);
    }
    for c in permutation_candidates(root, known) {
        all.insert(c);
    }
    all.into_iter()
        .filter(|c| scope.is_allowed(c))
        .take(limit.max(1))
        .collect()
}

/// Turn subdomain candidates into http(s) probe URLs (both schemes).
pub fn candidate_urls(candidates: &[String]) -> Vec<String> {
    let mut out = Vec::new();
    for c in candidates {
        out.push(format!("https://{c}"));
        out.push(format!("http://{c}"));
    }
    out
}

// ----------------------------------------------------------------------------
// Asset graph
// ----------------------------------------------------------------------------

/// A node in the recon asset graph.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AssetNode {
    pub id: String,   // normalized value, used as the key
    pub kind: String, // domain, subdomain, url, ip, service
    pub source: String,
}

/// A directed relationship between two assets (e.g. subdomain -> resolves_to -> ip).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AssetEdge {
    pub from: String,
    pub to: String,
    pub relation: String,
}

/// The recon asset graph: deduplicated nodes plus relationships between them.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct AssetGraph {
    nodes: BTreeMap<String, AssetNode>,
    edges: Vec<AssetEdge>,
}

impl AssetGraph {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn add_node(&mut self, id: impl Into<String>, kind: impl Into<String>, source: impl Into<String>) {
        let id = id.into().trim().to_lowercase();
        if id.is_empty() {
            return;
        }
        self.nodes.entry(id.clone()).or_insert(AssetNode { id, kind: kind.into(), source: source.into() });
    }

    pub fn add_edge(&mut self, from: impl Into<String>, to: impl Into<String>, relation: impl Into<String>) {
        let edge = AssetEdge {
            from: from.into().trim().to_lowercase(),
            to: to.into().trim().to_lowercase(),
            relation: relation.into(),
        };
        if !self.edges.contains(&edge) {
            self.edges.push(edge);
        }
    }

    pub fn nodes(&self) -> Vec<AssetNode> {
        self.nodes.values().cloned().collect()
    }

    pub fn edges(&self) -> &[AssetEdge] {
        &self.edges
    }

    pub fn node_count(&self) -> usize {
        self.nodes.len()
    }

    /// Ingest a subdomain under a root, wiring the subdomain -> root relationship.
    pub fn ingest_subdomain(&mut self, root: &str, sub: &str, source: &str) {
        self.add_node(root, "domain", source);
        self.add_node(sub, "subdomain", source);
        self.add_edge(sub, root, "subdomain_of");
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn brute_generates_prefixed_names() {
        let c = brute_candidates("example.com", &["admin".into(), "api".into()]);
        assert!(c.contains(&"admin.example.com".to_string()));
        assert!(c.contains(&"api.example.com".to_string()));
    }

    #[test]
    fn permutations_from_known() {
        let c = permutation_candidates("example.com", &["api.example.com".into()]);
        assert!(c.iter().any(|x| x == "api-dev.example.com"));
        assert!(c.iter().any(|x| x == "api1.example.com"));
    }

    #[test]
    fn scope_filters_candidates() {
        let scope = ScopePolicy { allow: vec!["example.com".into()], deny: vec!["admin".into()] };
        let c = generate_candidates("example.com", &[], &[], &scope, 1000);
        assert!(c.iter().all(|x| x.contains("example.com")));
        assert!(!c.iter().any(|x| x.starts_with("admin.")));
    }

    #[test]
    fn asset_graph_dedups_and_links() {
        let mut g = AssetGraph::new();
        g.ingest_subdomain("example.com", "api.example.com", "brute");
        g.ingest_subdomain("example.com", "api.example.com", "ct"); // duplicate node
        assert_eq!(g.node_count(), 2); // example.com + api.example.com
        assert_eq!(g.edges().len(), 1);
    }
}
