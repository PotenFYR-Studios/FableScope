use chrono::Utc;
use fs_core::Severity;
use serde::{Deserialize, Serialize};
use thiserror::Error;

pub type Result<T> = std::result::Result<T, ReportError>;

#[derive(Debug, Error)]
pub enum ReportError {
    #[error("invalid input: {0}")]
    Invalid(String),
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct CvssScore {
    pub version: String, // v3.1 or v4.0 (simplified calculator)
    pub vector: String,
    pub base_score: f32,
    pub severity: Severity,
}

pub fn severity_from_score(score: f32) -> Severity {
    match score {
        s if s >= 9.0 => Severity::Critical,
        s if s >= 7.0 => Severity::High,
        s if s >= 4.0 => Severity::Medium,
        s if s > 0.0 => Severity::Low,
        _ => Severity::Info,
    }
}

/// Simplified CVSS v3.1 base score calculator for common vectors.
/// Supports AV,AC,PR,UI,S,C,I,A with standard values.
pub fn calculate_cvss_v31(vector: &str) -> Result<CvssScore> {
    let mut map = std::collections::BTreeMap::new();
    for part in vector.split('/') {
        let mut kv = part.split(':');
        let k = kv.next().unwrap_or("");
        let v = kv.next().unwrap_or("");
        if !k.is_empty() { map.insert(k.to_string(), v.to_string()); }
    }
    let av = match map.get("AV").map(|s| s.as_str()) { Some("N")=>0.85, Some("A")=>0.62, Some("L")=>0.55, Some("P")=>0.2, _=>return Err(ReportError::Invalid("AV".into())) };
    let ac = match map.get("AC").map(|s| s.as_str()) { Some("L")=>0.77, Some("H")=>0.44, _=>return Err(ReportError::Invalid("AC".into())) };
    let s = map.get("S").map(|s| s.as_str()).unwrap_or("U");
    let pr = match (map.get("PR").map(|s| s.as_str()), s) {
        (Some("N"), _) => 0.85,
        (Some("L"), "U") => 0.62, (Some("L"), _) => 0.68,
        (Some("H"), "U") => 0.27, (Some("H"), _) => 0.5,
        _ => return Err(ReportError::Invalid("PR".into())),
    };
    let ui = match map.get("UI").map(|s| s.as_str()) { Some("N")=>0.85, Some("R")=>0.62, _=>return Err(ReportError::Invalid("UI".into())) };
    let c = match map.get("C").map(|s| s.as_str()) { Some("H")=>0.56, Some("L")=>0.22, Some("N")=>0.0, _=>return Err(ReportError::Invalid("C".into())) };
    let i = match map.get("I").map(|s| s.as_str()) { Some("H")=>0.56, Some("L")=>0.22, Some("N")=>0.0, _=>return Err(ReportError::Invalid("I".into())) };
    let a = match map.get("A").map(|s| s.as_str()) { Some("H")=>0.56, Some("L")=>0.22, Some("N")=>0.0, _=>return Err(ReportError::Invalid("A".into())) };

    let iss: f32 = 1.0 - ((1.0 - c) * (1.0 - i) * (1.0 - a));
    let impact: f32 = if s == "C" { 7.52 * (iss - 0.029) - 3.25 * (iss - 0.02).powf(15.0_f32) } else { 6.42 * iss };
    let exploitability: f32 = 8.22 * av * ac * pr * ui;
    let base = if impact <= 0.0 {
        0.0_f32
    } else if s == "C" {
        roundup((1.08_f32 * (impact + exploitability)).min(10.0_f32))
    } else {
        roundup((impact + exploitability).min(10.0_f32))
    };
    Ok(CvssScore { version: "3.1".into(), vector: vector.to_string(), base_score: base, severity: severity_from_score(base) })
}

fn roundup(v: f32) -> f32 {
    let i = (v * 100000.0) as i32;
    let rem = i % 10000;
    let base = i - rem;
    let bumped = if rem == 0 { base } else { base + 10000 };
    (bumped as f32 / 100000.0 * 10.0 * 10.0).round() / 10.0 / 10.0
}

pub fn render_report_json(project: &str, findings: &[serde_json::Value], checklist: &[serde_json::Value]) -> serde_json::Value {
    serde_json::json!({
        "generated_at": Utc::now().to_rfc3339(),
        "project": project,
        "summary": {
            "finding_count": findings.len(),
            "checklist_count": checklist.len(),
        },
        "findings": findings,
        "checklist_review": checklist,
    })
}

pub fn render_report_markdown(project: &str, findings: &[serde_json::Value]) -> String {
    let mut out = format!("# FableScope Report\n\nProject: {project}\n\n## Findings\n\n");
    if findings.is_empty() { out.push_str("No findings.\n"); }
    for f in findings {
        out.push_str(&format!(
            "- **{}** ({}) - {}\n",
            f.get("title").and_then(|v| v.as_str()).unwrap_or("Untitled"),
            f.get("severity").and_then(|v| v.as_str()).unwrap_or("info"),
            f.get("description").and_then(|v| v.as_str()).unwrap_or("")
        ));
    }
    out
}

pub fn render_report_html(project: &str, findings: &[serde_json::Value], checklist: &[serde_json::Value]) -> String {
    let mut rows = String::new();
    for f in findings {
        rows.push_str(&format!(
            "<tr><td>{}</td><td>{}</td><td>{}</td><td>{}</td></tr>",
            html_escape(f.get("title").and_then(|v| v.as_str()).unwrap_or("Untitled")),
            html_escape(f.get("severity").and_then(|v| v.as_str()).unwrap_or("info")),
            html_escape(f.get("status").and_then(|v| v.as_str()).unwrap_or("")),
            html_escape(f.get("description").and_then(|v| v.as_str()).unwrap_or("")),
        ));
    }
    if rows.is_empty() {
        rows.push_str("<tr><td colspan=\"4\">No findings</td></tr>");
    }
    format!(
        "<!doctype html><html><head><meta charset=\"utf-8\"><title>FableScope Report</title>\
        <style>body{{font-family:system-ui;margin:24px}}table{{border-collapse:collapse;width:100%}}td,th{{border:1px solid #ccc;padding:8px;text-align:left}}</style>\
        </head><body><h1>FableScope Report</h1><p>Project: {}</p><p>Findings: {} | Checklist: {}</p>\
        <h2>Findings</h2><table><thead><tr><th>Title</th><th>Severity</th><th>Status</th><th>Description</th></tr></thead><tbody>{}</tbody></table></body></html>",
        html_escape(project), findings.len(), checklist.len(), rows
    )
}

pub fn render_report_csv(findings: &[serde_json::Value]) -> String {
    let mut out = String::from("title,severity,status,source_check_id,description\n");
    for f in findings {
        let row = [
            f.get("title").and_then(|v| v.as_str()).unwrap_or(""),
            f.get("severity").and_then(|v| v.as_str()).unwrap_or(""),
            f.get("status").and_then(|v| v.as_str()).unwrap_or(""),
            f.get("source_check_id").and_then(|v| v.as_str()).unwrap_or(""),
            f.get("description").and_then(|v| v.as_str()).unwrap_or(""),
        ];
        let escaped: Vec<String> = row.iter().map(|c| csv_escape(c)).collect();
        out.push_str(&escaped.join(","));
        out.push('\n');
    }
    out
}

pub fn render_report_sarif_like(project: &str, findings: &[serde_json::Value]) -> serde_json::Value {
    let results: Vec<serde_json::Value> = findings.iter().map(|f| {
        serde_json::json!({
            "ruleId": f.get("source_check_id").and_then(|v| v.as_str()).unwrap_or("FABLESCOPE.FINDING"),
            "level": match f.get("severity").and_then(|v| v.as_str()).unwrap_or("info") {
                "critical" | "high" => "error",
                "medium" => "warning",
                _ => "note",
            },
            "message": {"text": f.get("title").and_then(|v| v.as_str()).unwrap_or("Finding")},
            "properties": {
                "status": f.get("status"),
                "description": f.get("description"),
                "correlation_id": f.get("correlation_id"),
            }
        })
    }).collect();
    serde_json::json!({
        "version": "2.1.0",
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "runs": [{
            "tool": {"driver": {"name": "FableScope", "informationUri": "https://github.com/FableScope/FableScope"}},
            "invocations": [{"executionSuccessful": true, "properties": {"project": project}}],
            "results": results
        }]
    })
}

fn csv_escape(s: &str) -> String {
    let s = s.replace('"', "\"\"");
    if s.contains(',') || s.contains('"') || s.contains('\n') { format!("\"{s}\"") } else { s }
}

fn html_escape(s: &str) -> String {
    s.replace('&', "&amp;").replace('<', "&lt;").replace('>', "&gt;").replace('"', "&quot;")
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn cvss_basic() {
        let s = calculate_cvss_v31("AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H").unwrap();
        assert_eq!(s.base_score, 9.8);
        assert_eq!(s.severity, Severity::Critical);
    }
    #[test]
    fn md_render() {
        let md = render_report_markdown("P", &[serde_json::json!({"title":"X","severity":"high","description":"d"})]);
        assert!(md.contains("X"));
    }
    #[test]
    fn html_and_csv_render() {
        let findings = vec![serde_json::json!({"title":"X","severity":"high","status":"confirmed","description":"d","source_check_id":"FS-WEB-001"})];
        let html = render_report_html("P", &findings, &[]);
        let csv = render_report_csv(&findings);
        assert!(html.contains("<table>"));
        assert!(csv.contains("FS-WEB-001"));
    }
    #[test]
    fn sarif_like_render() {
        let findings = vec![serde_json::json!({"title":"X","severity":"high","source_check_id":"FS-WEB-001"})];
        let s = render_report_sarif_like("P", &findings);
        assert_eq!(s["version"], "2.1.0");
        assert_eq!(s["runs"][0]["results"][0]["ruleId"], "FS-WEB-001");
    }
}
