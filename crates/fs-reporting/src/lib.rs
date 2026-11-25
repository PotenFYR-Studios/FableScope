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

/// Severity breakdown counts for a set of findings.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
pub struct SeverityBreakdown {
    pub critical: usize,
    pub high: usize,
    pub medium: usize,
    pub low: usize,
    pub info: usize,
}

impl SeverityBreakdown {
    pub fn total(&self) -> usize {
        self.critical + self.high + self.medium + self.low + self.info
    }
}

/// Tally findings by severity string.
pub fn severity_breakdown(findings: &[serde_json::Value]) -> SeverityBreakdown {
    let mut b = SeverityBreakdown::default();
    for f in findings {
        match f.get("severity").and_then(|v| v.as_str()).unwrap_or("info") {
            "critical" => b.critical += 1,
            "high" => b.high += 1,
            "medium" => b.medium += 1,
            "low" => b.low += 1,
            _ => b.info += 1,
        }
    }
    b
}

/// Checklist coverage: fraction of items with a decided status (not
/// not_started / in_progress).
pub fn checklist_coverage(checklist: &[serde_json::Value]) -> (usize, usize, f32) {
    let total = checklist.len();
    let done = checklist
        .iter()
        .filter(|i| {
            !matches!(i.get("status").and_then(|v| v.as_str()).unwrap_or("not_started"), "not_started" | "in_progress")
        })
        .count();
    let pct = if total == 0 { 100.0 } else { (done as f32 / total as f32) * 100.0 };
    (done, total, pct)
}

/// Render an enterprise-grade HTML report: executive summary, severity
/// breakdown, checklist coverage, and a per-finding technical section with
/// evidence and remediation placeholders.
pub fn render_enterprise_html(project: &str, findings: &[serde_json::Value], checklist: &[serde_json::Value]) -> String {
    let b = severity_breakdown(findings);
    let (done, total, pct) = checklist_coverage(checklist);
    let generated = Utc::now().to_rfc3339();

    let mut finding_rows = String::new();
    // Order findings by severity rank for the technical section.
    let rank = |s: &str| match s { "critical" => 0, "high" => 1, "medium" => 2, "low" => 3, _ => 4 };
    let mut sorted: Vec<&serde_json::Value> = findings.iter().collect();
    sorted.sort_by_key(|f| rank(f.get("severity").and_then(|v| v.as_str()).unwrap_or("info")));
    for f in sorted {
        let sev = f.get("severity").and_then(|v| v.as_str()).unwrap_or("info");
        finding_rows.push_str(&format!(
            "<section class='finding sev-{}'><h3>{} <span class='badge'>{}</span></h3>\
             <p class='meta'>Status: {} · Check: {} · Confidence: {}</p>\
             <p>{}</p>\
             <details><summary>Evidence</summary><pre>{}</pre></details></section>",
            html_escape(sev),
            html_escape(f.get("title").and_then(|v| v.as_str()).unwrap_or("Untitled")),
            html_escape(sev),
            html_escape(f.get("status").and_then(|v| v.as_str()).unwrap_or("candidate")),
            html_escape(f.get("source_check_id").and_then(|v| v.as_str()).unwrap_or("—")),
            html_escape(&f.get("confidence").map(|v| v.to_string()).unwrap_or_else(|| "—".into())),
            html_escape(f.get("description").and_then(|v| v.as_str()).unwrap_or("")),
            html_escape(&f.get("evidence").map(|v| serde_json::to_string_pretty(v).unwrap_or_default()).unwrap_or_default()),
        ));
    }
    if finding_rows.is_empty() {
        finding_rows.push_str("<p>No findings recorded.</p>");
    }

    format!(
        "<!doctype html><html><head><meta charset='utf-8'><title>FableScope Report — {proj}</title>\
        <style>body{{font-family:system-ui,Segoe UI,Arial;margin:0;color:#1a2233;background:#f5f7fb}}\
        header{{background:#0b1020;color:#fff;padding:28px 32px}}main{{padding:24px 32px;max-width:1000px;margin:0 auto}}\
        h1{{margin:0}}.sub{{color:#9fb0d0}}.cards{{display:flex;gap:12px;flex-wrap:wrap;margin:16px 0}}\
        .kpi{{background:#fff;border:1px solid #dde3ef;border-radius:10px;padding:14px 18px;min-width:120px}}\
        .kpi b{{font-size:24px;display:block}}.bar{{height:10px;border-radius:5px;background:#e3e8f2;overflow:hidden}}\
        .bar>i{{display:block;height:100%;background:#4f8cff}}.finding{{background:#fff;border:1px solid #dde3ef;border-left-width:5px;border-radius:8px;padding:14px 18px;margin:12px 0}}\
        .sev-critical{{border-left-color:#b00020}}.sev-high{{border-left-color:#e4572e}}.sev-medium{{border-left-color:#f3a712}}\
        .sev-low{{border-left-color:#3fa34d}}.sev-info{{border-left-color:#4f8cff}}\
        .badge{{font-size:12px;text-transform:uppercase;background:#eef2fb;padding:2px 8px;border-radius:10px;vertical-align:middle}}\
        .meta{{color:#64748b;font-size:13px}}pre{{white-space:pre-wrap;background:#0c1428;color:#e7ecf5;padding:10px;border-radius:6px}}</style></head>\
        <body><header><h1>FableScope Security Assessment</h1><div class='sub'>{proj} · generated {gen}</div></header><main>\
        <h2>Executive Summary</h2>\
        <div class='cards'>\
        <div class='kpi'><b>{total_f}</b>Findings</div>\
        <div class='kpi sev-critical'><b>{crit}</b>Critical</div>\
        <div class='kpi sev-high'><b>{high}</b>High</div>\
        <div class='kpi sev-medium'><b>{med}</b>Medium</div>\
        <div class='kpi sev-low'><b>{low}</b>Low</div>\
        <div class='kpi'><b>{info}</b>Info</div>\
        </div>\
        <h2>Checklist Coverage</h2>\
        <p>{done} / {ctotal} checks reviewed ({pct:.0}%)</p>\
        <div class='bar'><i style='width:{pct:.0}%'></i></div>\
        <h2>Findings</h2>{rows}\
        <h2>Methodology &amp; Scope</h2><p class='meta'>Testing performed under explicit authorization and scope policy. \
        Active checks are rate-limited and scope-gated; blind/OOB validation uses correlation IDs. \
        All tool runs are logged, version-pinned, and mapped to checklist/finding IDs.</p>\
        </main></body></html>",
        proj = html_escape(project), gen = html_escape(&generated),
        total_f = b.total(), crit = b.critical, high = b.high, med = b.medium, low = b.low, info = b.info,
        done = done, ctotal = total, pct = pct, rows = finding_rows,
    )
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
    fn severity_breakdown_and_coverage() {
        let findings = vec![
            serde_json::json!({"severity":"critical"}),
            serde_json::json!({"severity":"high"}),
            serde_json::json!({"severity":"high"}),
        ];
        let b = severity_breakdown(&findings);
        assert_eq!(b.critical, 1);
        assert_eq!(b.high, 2);
        assert_eq!(b.total(), 3);
        let checklist = vec![
            serde_json::json!({"status":"pass"}),
            serde_json::json!({"status":"not_started"}),
        ];
        let (done, total, pct) = checklist_coverage(&checklist);
        assert_eq!((done, total), (1, 2));
        assert!((pct - 50.0).abs() < 0.01);
    }

    #[test]
    fn enterprise_html_has_sections() {
        let findings = vec![serde_json::json!({"title":"XSS","severity":"high","status":"confirmed","description":"d"})];
        let html = render_enterprise_html("Acme", &findings, &[serde_json::json!({"status":"pass"})]);
        assert!(html.contains("Executive Summary"));
        assert!(html.contains("Checklist Coverage"));
        assert!(html.contains("sev-high"));
        assert!(html.contains("Acme"));
    }

    #[test]
    fn sarif_like_render() {
        let findings = vec![serde_json::json!({"title":"X","severity":"high","source_check_id":"FS-WEB-001"})];
        let s = render_report_sarif_like("P", &findings);
        assert_eq!(s["version"], "2.1.0");
        assert_eq!(s["runs"][0]["results"][0]["ruleId"], "FS-WEB-001");
    }
}
