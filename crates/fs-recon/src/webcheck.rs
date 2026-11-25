//! Native web security checks (Phase 2, WSTG-aligned): security-header, CORS,
//! and cookie-flag analysis plus baseline response diffing. Deterministic and
//! offline — operates on [`HttpProbeResult`] values from the probe engine. Each
//! observation carries its WSTG reference and a severity, ready to become a
//! checklist signal or finding.

use crate::HttpProbeResult;
use fs_core::Severity;
use serde::{Deserialize, Serialize};

/// A single web-check observation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WebObservation {
    pub check: String,
    pub wstg: String,
    pub severity: Severity,
    pub passed: bool,
    pub detail: String,
}

fn header<'a>(r: &'a HttpProbeResult, name: &str) -> Option<&'a String> {
    r.headers.iter().find(|(k, _)| k.eq_ignore_ascii_case(name)).map(|(_, v)| v)
}

fn obs(check: &str, wstg: &str, sev: Severity, passed: bool, detail: impl Into<String>) -> WebObservation {
    WebObservation { check: check.into(), wstg: wstg.into(), severity: sev, passed, detail: detail.into() }
}

/// Analyze security response headers (WSTG-CONF-07/-12, WSTG-CLNT-*).
pub fn analyze_headers(r: &HttpProbeResult) -> Vec<WebObservation> {
    let mut out = Vec::new();
    let https = r.url.starts_with("https://");

    // HSTS (only meaningful over HTTPS).
    if https {
        match header(r, "strict-transport-security") {
            Some(v) => out.push(obs("HSTS present", "WSTG-CONF-07", Severity::Info, true, format!("Strict-Transport-Security: {v}"))),
            None => out.push(obs("HSTS missing", "WSTG-CONF-07", Severity::Low, false, "No Strict-Transport-Security header over HTTPS.")),
        }
    }
    // CSP.
    match header(r, "content-security-policy") {
        Some(v) => out.push(obs("CSP present", "WSTG-CLNT-12", Severity::Info, true, format!("Content-Security-Policy set ({} bytes)", v.len()))),
        None => out.push(obs("CSP missing", "WSTG-CLNT-12", Severity::Low, false, "No Content-Security-Policy header.")),
    }
    // X-Frame-Options or frame-ancestors.
    let frame_ok = header(r, "x-frame-options").is_some()
        || header(r, "content-security-policy").map(|v| v.to_lowercase().contains("frame-ancestors")).unwrap_or(false);
    out.push(if frame_ok {
        obs("Clickjacking protection", "WSTG-CLNT-09", Severity::Info, true, "X-Frame-Options or frame-ancestors present.")
    } else {
        obs("Clickjacking protection missing", "WSTG-CLNT-09", Severity::Medium, false, "No X-Frame-Options / frame-ancestors; page may be framable.")
    });
    // X-Content-Type-Options.
    out.push(match header(r, "x-content-type-options") {
        Some(v) if v.eq_ignore_ascii_case("nosniff") => obs("nosniff set", "WSTG-CONF-07", Severity::Info, true, "X-Content-Type-Options: nosniff"),
        _ => obs("nosniff missing", "WSTG-CONF-07", Severity::Low, false, "Missing X-Content-Type-Options: nosniff."),
    });
    // Server/version disclosure.
    if let Some(v) = header(r, "server") {
        if v.chars().any(|c| c.is_ascii_digit()) {
            out.push(obs("Server version disclosure", "WSTG-INFO-02", Severity::Low, false, format!("Server header leaks version: {v}")));
        }
    }
    if header(r, "x-powered-by").is_some() {
        out.push(obs("X-Powered-By disclosure", "WSTG-INFO-02", Severity::Info, false, format!("X-Powered-By: {}", header(r, "x-powered-by").unwrap())));
    }
    out
}

/// Analyze CORS configuration for common misconfigurations (WSTG-CLNT-07).
pub fn analyze_cors(r: &HttpProbeResult) -> Vec<WebObservation> {
    let mut out = Vec::new();
    let acao = header(r, "access-control-allow-origin");
    let acac = header(r, "access-control-allow-credentials").map(|v| v.eq_ignore_ascii_case("true")).unwrap_or(false);
    if let Some(origin) = acao {
        if origin == "*" && acac {
            out.push(obs("CORS wildcard + credentials", "WSTG-CLNT-07", Severity::High, false, "Access-Control-Allow-Origin: * with credentials=true is invalid/insecure."));
        } else if origin == "*" {
            out.push(obs("CORS wildcard origin", "WSTG-CLNT-07", Severity::Low, false, "Access-Control-Allow-Origin: * — any origin may read responses."));
        } else if origin.eq_ignore_ascii_case("null") {
            out.push(obs("CORS null origin", "WSTG-CLNT-07", Severity::Medium, false, "Access-Control-Allow-Origin: null is exploitable from sandboxed contexts."));
        } else if acac {
            out.push(obs("CORS reflects origin + credentials", "WSTG-CLNT-07", Severity::Medium, false, format!("ACAO echoes {origin} with credentials — verify origin allowlist.")));
        } else {
            out.push(obs("CORS configured", "WSTG-CLNT-07", Severity::Info, true, format!("Access-Control-Allow-Origin: {origin}")));
        }
    }
    out
}

/// Analyze Set-Cookie flags (WSTG-SESS-02).
pub fn analyze_cookies(r: &HttpProbeResult) -> Vec<WebObservation> {
    let mut out = Vec::new();
    let https = r.url.starts_with("https://");
    for (k, v) in &r.headers {
        if !k.eq_ignore_ascii_case("set-cookie") {
            continue;
        }
        let lower = v.to_lowercase();
        let name = v.split('=').next().unwrap_or("cookie").trim().to_string();
        if !lower.contains("httponly") {
            out.push(obs("Cookie missing HttpOnly", "WSTG-SESS-02", Severity::Low, false, format!("Cookie '{name}' lacks HttpOnly.")));
        }
        if https && !lower.contains("secure") {
            out.push(obs("Cookie missing Secure", "WSTG-SESS-02", Severity::Low, false, format!("Cookie '{name}' lacks Secure over HTTPS.")));
        }
        if !lower.contains("samesite") {
            out.push(obs("Cookie missing SameSite", "WSTG-SESS-02", Severity::Info, false, format!("Cookie '{name}' lacks SameSite.")));
        }
    }
    out
}

/// Run all native web checks on a response.
pub fn analyze_all(r: &HttpProbeResult) -> Vec<WebObservation> {
    let mut out = analyze_headers(r);
    out.extend(analyze_cors(r));
    out.extend(analyze_cookies(r));
    out
}

/// A structural diff between two responses (e.g. test vs baseline).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ResponseDiff {
    pub status_changed: bool,
    pub length_delta: i64,
    pub title_changed: bool,
    pub added_headers: Vec<String>,
    pub removed_headers: Vec<String>,
    /// True if the responses look materially different (worth analyst attention).
    pub significant: bool,
}

/// Diff a candidate response against a baseline response.
pub fn diff_responses(baseline: &HttpProbeResult, candidate: &HttpProbeResult) -> ResponseDiff {
    let status_changed = baseline.status != candidate.status;
    let length_delta = candidate.content_length.unwrap_or(0) as i64 - baseline.content_length.unwrap_or(0) as i64;
    let title_changed = baseline.title != candidate.title;
    let base_keys: std::collections::BTreeSet<String> = baseline.headers.keys().map(|k| k.to_lowercase()).collect();
    let cand_keys: std::collections::BTreeSet<String> = candidate.headers.keys().map(|k| k.to_lowercase()).collect();
    let added: Vec<String> = cand_keys.difference(&base_keys).cloned().collect();
    let removed: Vec<String> = base_keys.difference(&cand_keys).cloned().collect();
    let significant = status_changed || title_changed || length_delta.abs() > 64 || !added.is_empty();
    ResponseDiff { status_changed, length_delta, title_changed, added_headers: added, removed_headers: removed, significant }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Utc;
    use std::collections::BTreeMap;
    use uuid::Uuid;

    fn mk(url: &str, headers: &[(&str, &str)]) -> HttpProbeResult {
        let mut h = BTreeMap::new();
        for (k, v) in headers {
            h.insert(k.to_string(), v.to_string());
        }
        HttpProbeResult {
            id: Uuid::new_v4(), url: url.into(), status: Some(200), title: Some("T".into()),
            content_length: Some(1000), content_type: Some("text/html".into()), final_url: Some(url.into()),
            error: None, severity_hint: Severity::Info, timestamp: Utc::now(), headers: h,
        }
    }

    #[test]
    fn flags_missing_security_headers() {
        let r = mk("https://a.com/", &[]);
        let obs = analyze_headers(&r);
        assert!(obs.iter().any(|o| o.check == "HSTS missing" && !o.passed));
        assert!(obs.iter().any(|o| o.check == "CSP missing"));
        assert!(obs.iter().any(|o| o.check.contains("Clickjacking")));
    }

    #[test]
    fn passes_when_headers_present() {
        let r = mk("https://a.com/", &[
            ("Strict-Transport-Security", "max-age=63072000"),
            ("Content-Security-Policy", "default-src 'self'"),
            ("X-Frame-Options", "DENY"),
            ("X-Content-Type-Options", "nosniff"),
        ]);
        let obs = analyze_headers(&r);
        assert!(obs.iter().filter(|o| o.check.contains("missing")).count() == 0);
    }

    #[test]
    fn cors_wildcard_with_creds_is_high() {
        let r = mk("https://a.com/", &[("Access-Control-Allow-Origin", "*"), ("Access-Control-Allow-Credentials", "true")]);
        let obs = analyze_cors(&r);
        assert!(obs.iter().any(|o| o.severity == Severity::High));
    }

    #[test]
    fn cookie_flag_checks() {
        let r = mk("https://a.com/", &[("Set-Cookie", "sid=abc; Path=/")]);
        let obs = analyze_cookies(&r);
        assert!(obs.iter().any(|o| o.check.contains("HttpOnly")));
        assert!(obs.iter().any(|o| o.check.contains("Secure")));
    }

    #[test]
    fn response_diff_detects_change() {
        let base = mk("https://a.com/x", &[]);
        let mut cand = mk("https://a.com/x", &[("X-New", "1")]);
        cand.status = Some(500);
        cand.content_length = Some(5000);
        let d = diff_responses(&base, &cand);
        assert!(d.status_changed && d.significant);
        assert!(d.added_headers.contains(&"x-new".to_string()));
    }
}
