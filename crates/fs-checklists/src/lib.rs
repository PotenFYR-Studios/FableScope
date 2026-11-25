use fs_core::{ChecklistItem, CheckStatus, OwaspRef};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChecklistTemplate {
    pub id: String,
    pub name: String,
    pub domain: String, // web, api, mobile, cloud, ad, wifi
    pub items: Vec<ChecklistTemplateItem>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChecklistTemplateItem {
    pub check_id: String,
    pub title: String,
    pub description: String,
    pub owasp: Vec<OwaspRef>,
    pub default_tools: Vec<String>,
    pub default_profiles: Vec<String>,
}

pub fn instantiate(template: &ChecklistTemplate, project_id: Uuid) -> Vec<ChecklistItem> {
    template.items.iter().map(|i| {
        let mut item = ChecklistItem::new(project_id, &i.check_id, &i.title);
        item.owasp = i.owasp.clone();
        item
    }).collect()
}

pub fn template_for_check(check_id: &str) -> Option<ChecklistTemplateItem> {
    for t in builtin_templates() {
        if let Some(i) = t.items.into_iter().find(|i| i.check_id == check_id) { return Some(i); }
    }
    None
}

pub fn coverage(items: &[ChecklistItem]) -> (usize, usize, f32) {
    let total = items.len();
    let done = items.iter().filter(|i| !matches!(i.status, CheckStatus::NotStarted | CheckStatus::InProgress)).count();
    let pct = if total == 0 { 100.0 } else { (done as f32 / total as f32) * 100.0 };
    (done, total, pct)
}

pub fn builtin_web_minimal() -> ChecklistTemplate {
    ChecklistTemplate {
        id: "owasp-web-minimal".into(), name: "OWASP Web Minimal".into(), domain: "web".into(),
        items: vec![
            ChecklistTemplateItem { check_id: "FS-WEB-001".into(), title: "Fingerprint web server and technologies".into(), description: "Identify server, framework, headers".into(), owasp: vec![OwaspRef{standard:"WSTG".into(), id:"WSTG-INFO-02".into(), title:Some("Fingerprint Web Server".into())}], default_tools: vec!["nmap".into(),"httpx".into()], default_profiles: vec!["safe".into()] },
            ChecklistTemplateItem { check_id: "FS-WEB-002".into(), title: "Check security headers and TLS config".into(), description: "CSP, HSTS, XFO, TLS/ciphers".into(), owasp: vec![OwaspRef{standard:"WSTG".into(), id:"WSTG-CONF-07".into(), title:Some("Test HTTP Strict Transport Security".into())}], default_tools: vec!["nikto".into(),"nuclei".into()], default_profiles: vec!["safe".into()] },
            ChecklistTemplateItem { check_id: "FS-WEB-003".into(), title: "Test for SQL injection candidates".into(), description: "Validate params/forms/API inputs safely".into(), owasp: vec![OwaspRef{standard:"WSTG".into(), id:"WSTG-INPV-05".into(), title:Some("SQL Injection".into())}], default_tools: vec!["sqlmap".into()], default_profiles: vec!["detect-safe".into()] },
            ChecklistTemplateItem { check_id: "FS-WEB-004".into(), title: "Test for SSRF/OOB interactions".into(), description: "Use public OOB provider with correlation IDs".into(), owasp: vec![OwaspRef{standard:"WSTG".into(), id:"WSTG-INPV-19".into(), title:Some("Server-Side Request Forgery".into())}], default_tools: vec!["nuclei".into()], default_profiles: vec!["oob-safe".into()] },
        ],
    }
}

pub fn builtin_api_minimal() -> ChecklistTemplate {
    ChecklistTemplate {
        id: "owasp-api-minimal".into(), name: "OWASP API Minimal".into(), domain: "api".into(),
        items: vec![
            ChecklistTemplateItem { check_id: "FS-API-001".into(), title: "Inventory API endpoints and auth".into(), description: "Enumerate endpoints and auth schemes".into(), owasp: vec![OwaspRef{standard:"OWASP_API_TOP10".into(), id:"API9:2023".into(), title:Some("Improper Inventory Management".into())}], default_tools: vec!["httpx".into()], default_profiles: vec!["safe".into()] },
            ChecklistTemplateItem { check_id: "FS-API-002".into(), title: "Test BOLA/IDOR candidates".into(), description: "Object-level auth checks with scope/safety".into(), owasp: vec![OwaspRef{standard:"OWASP_API_TOP10".into(), id:"API1:2023".into(), title:Some("Broken Object Level Authorization".into())}], default_tools: vec!["nuclei".into()], default_profiles: vec!["safe".into()] },
        ],
    }
}

pub fn builtin_templates() -> Vec<ChecklistTemplate> {
    vec![builtin_web_minimal(), builtin_api_minimal()]
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn instantiate_and_coverage() {
        let t = builtin_web_minimal();
        let mut items = instantiate(&t, Uuid::new_v4());
        assert_eq!(items.len(), 4);
        let (_d,t0,p0) = coverage(&items);
        assert_eq!(t0,4); assert_eq!(p0, 0.0);
        items[0].status = CheckStatus::Pass;
        let (d,_,p) = coverage(&items);
        assert_eq!(d,1); assert!(p > 0.0);
    }
}
