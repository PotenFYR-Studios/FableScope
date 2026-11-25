//! External-tool adapter framework (Phase 3/4): a manifest-driven registry that
//! maps external security tools to FableScope modules plus **offline parsers**
//! that normalize their output into a common [`NormalizedFinding`] shape.
//!
//! This is the import/normalization half of the adapter story (the execution
//! half is the gated `fs-tools::ToolManager`). Parsers here are pure and
//! deterministic so imported artifacts become findings with provenance, ready
//! for dedup, scoring, and reporting. Nothing here runs a tool or hits the
//! network.

use serde::{Deserialize, Serialize};

/// How an adapter ingests results.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ParserKind {
    NucleiJsonl,
    NmapGrepable,
    GenericJsonArray,
}

/// An adapter manifest: which tool, which module, and how to parse its output.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AdapterManifest {
    pub id: String,
    pub tool: String,
    pub module: String, // web, network, cloud, mobile, ad, recon
    pub parser: ParserKind,
    pub description: String,
}

/// A normalized finding produced by importing external-tool output.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NormalizedFinding {
    pub source_tool: String,
    pub title: String,
    pub severity: String, // info/low/medium/high/critical
    pub target: String,
    pub reference: Option<String>, // CVE/template-id/port
    pub raw: Option<String>,
}

fn norm_severity(s: &str) -> String {
    match s.to_lowercase().as_str() {
        "critical" => "critical",
        "high" => "high",
        "medium" | "moderate" => "medium",
        "low" => "low",
        _ => "info",
    }
    .to_string()
}

/// Parse Nuclei JSONL (`-json`/`-jsonl` output: one JSON object per line).
pub fn parse_nuclei_jsonl(text: &str) -> Vec<NormalizedFinding> {
    let mut out = Vec::new();
    for line in text.lines() {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        let Ok(v) = serde_json::from_str::<serde_json::Value>(line) else { continue };
        let info = v.get("info");
        let title = info
            .and_then(|i| i.get("name"))
            .and_then(|x| x.as_str())
            .or_else(|| v.get("template-id").and_then(|x| x.as_str()))
            .unwrap_or("Nuclei finding")
            .to_string();
        let severity = info
            .and_then(|i| i.get("severity"))
            .and_then(|x| x.as_str())
            .map(norm_severity)
            .unwrap_or_else(|| "info".into());
        let target = v
            .get("matched-at")
            .or_else(|| v.get("host"))
            .and_then(|x| x.as_str())
            .unwrap_or("")
            .to_string();
        let reference = v.get("template-id").and_then(|x| x.as_str()).map(String::from);
        out.push(NormalizedFinding {
            source_tool: "nuclei".into(),
            title,
            severity,
            target,
            reference,
            raw: Some(line.to_string()),
        });
    }
    out
}

/// Parse Nmap greppable output (`-oG`): lines like
/// `Host: 1.2.3.4 () Ports: 22/open/tcp//ssh///, 80/open/tcp//http///`.
pub fn parse_nmap_grepable(text: &str) -> Vec<NormalizedFinding> {
    let mut out = Vec::new();
    for line in text.lines() {
        let line = line.trim();
        if !line.starts_with("Host:") || !line.contains("Ports:") {
            continue;
        }
        let host = line
            .strip_prefix("Host:")
            .and_then(|r| r.split_whitespace().next())
            .unwrap_or("")
            .to_string();
        let ports_part = line.split("Ports:").nth(1).unwrap_or("");
        for p in ports_part.split(',') {
            let fields: Vec<&str> = p.trim().split('/').collect();
            if fields.len() < 3 || fields[1] != "open" {
                continue;
            }
            let port = fields[0];
            let proto = fields[2];
            let service = fields.get(4).copied().unwrap_or("");
            out.push(NormalizedFinding {
                source_tool: "nmap".into(),
                title: format!("Open port {port}/{proto} {service}").trim().to_string(),
                severity: "info".into(),
                target: format!("{host}:{port}"),
                reference: Some(format!("{port}/{proto}")),
                raw: Some(p.trim().to_string()),
            });
        }
    }
    out
}

/// Field mapping for the generic JSON-array parser.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JsonMapping {
    pub title: String,
    pub severity: String,
    pub target: String,
    pub reference: Option<String>,
}

impl Default for JsonMapping {
    fn default() -> Self {
        Self { title: "title".into(), severity: "severity".into(), target: "target".into(), reference: None }
    }
}

/// Parse a generic JSON array of findings using a field mapping.
pub fn parse_generic_json(text: &str, tool: &str, mapping: &JsonMapping) -> Vec<NormalizedFinding> {
    let Ok(v) = serde_json::from_str::<serde_json::Value>(text) else { return vec![] };
    let arr = v.as_array().cloned().unwrap_or_default();
    arr.into_iter()
        .map(|item| {
            let get = |k: &str| item.get(k).and_then(|x| x.as_str()).unwrap_or("").to_string();
            NormalizedFinding {
                source_tool: tool.to_string(),
                title: {
                    let t = get(&mapping.title);
                    if t.is_empty() { "Finding".into() } else { t }
                },
                severity: norm_severity(&get(&mapping.severity)),
                target: get(&mapping.target),
                reference: mapping.reference.as_ref().map(|r| get(r)).filter(|s| !s.is_empty()),
                raw: Some(item.to_string()),
            }
        })
        .collect()
}

/// Dispatch to the right parser for a manifest's declared [`ParserKind`].
pub fn parse_with(manifest: &AdapterManifest, text: &str) -> Vec<NormalizedFinding> {
    match manifest.parser {
        ParserKind::NucleiJsonl => parse_nuclei_jsonl(text),
        ParserKind::NmapGrepable => parse_nmap_grepable(text),
        ParserKind::GenericJsonArray => parse_generic_json(text, &manifest.tool, &JsonMapping::default()),
    }
}

/// Built-in import adapters for common tools across gated modules.
pub fn builtin_adapters() -> Vec<AdapterManifest> {
    vec![
        AdapterManifest { id: "import.nuclei".into(), tool: "nuclei".into(), module: "web".into(), parser: ParserKind::NucleiJsonl, description: "Import Nuclei JSONL scan results".into() },
        AdapterManifest { id: "import.nmap".into(), tool: "nmap".into(), module: "network".into(), parser: ParserKind::NmapGrepable, description: "Import Nmap greppable (-oG) port/service results".into() },
        AdapterManifest { id: "import.prowler".into(), tool: "prowler".into(), module: "cloud".into(), parser: ParserKind::GenericJsonArray, description: "Import Prowler JSON cloud posture findings".into() },
        AdapterManifest { id: "import.mobsf".into(), tool: "mobsf".into(), module: "mobile".into(), parser: ParserKind::GenericJsonArray, description: "Import MobSF JSON findings".into() },
        AdapterManifest { id: "import.amass".into(), tool: "amass".into(), module: "recon".into(), parser: ParserKind::GenericJsonArray, description: "Import amass JSON subdomain results".into() },
    ]
}

/// A registry of adapter manifests, keyed by id.
#[derive(Default)]
pub struct AdapterRegistry {
    manifests: std::collections::BTreeMap<String, AdapterManifest>,
}

impl AdapterRegistry {
    pub fn with_builtins() -> Self {
        let mut r = Self::default();
        for m in builtin_adapters() {
            r.register(m);
        }
        r
    }
    pub fn register(&mut self, m: AdapterManifest) {
        self.manifests.insert(m.id.clone(), m);
    }
    pub fn get(&self, id: &str) -> Option<&AdapterManifest> {
        self.manifests.get(id)
    }
    pub fn list(&self) -> Vec<AdapterManifest> {
        self.manifests.values().cloned().collect()
    }
    pub fn by_module(&self, module: &str) -> Vec<AdapterManifest> {
        self.manifests.values().filter(|m| m.module == module).cloned().collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_nuclei_jsonl() {
        let text = r#"{"template-id":"CVE-2021-1234","info":{"name":"Example RCE","severity":"critical"},"matched-at":"https://a.com/x"}
{"template-id":"tech-detect","info":{"name":"Tech","severity":"info"},"host":"a.com"}"#;
        let f = parse_nuclei_jsonl(text);
        assert_eq!(f.len(), 2);
        assert_eq!(f[0].severity, "critical");
        assert_eq!(f[0].reference.as_deref(), Some("CVE-2021-1234"));
        assert_eq!(f[0].target, "https://a.com/x");
    }

    #[test]
    fn parses_nmap_grepable() {
        let text = "Host: 10.0.0.5 ()\tPorts: 22/open/tcp//ssh///, 443/open/tcp//https///\tIgnored State: closed (998)";
        let f = parse_nmap_grepable(text);
        assert_eq!(f.len(), 2);
        assert!(f.iter().any(|x| x.target == "10.0.0.5:22" && x.title.contains("ssh")));
        assert!(f.iter().any(|x| x.reference.as_deref() == Some("443/tcp")));
    }

    #[test]
    fn parses_generic_json() {
        let text = r#"[{"title":"Public bucket","severity":"High","target":"s3://acme"}]"#;
        let f = parse_generic_json(text, "prowler", &JsonMapping::default());
        assert_eq!(f.len(), 1);
        assert_eq!(f[0].severity, "high");
        assert_eq!(f[0].source_tool, "prowler");
    }

    #[test]
    fn registry_builtins_and_dispatch() {
        let reg = AdapterRegistry::with_builtins();
        let m = reg.get("import.nuclei").unwrap().clone();
        assert_eq!(m.module, "web");
        let f = parse_with(&m, "{\"info\":{\"name\":\"X\",\"severity\":\"low\"},\"host\":\"h\"}");
        assert_eq!(f.len(), 1);
        assert!(!reg.by_module("cloud").is_empty());
    }
}
