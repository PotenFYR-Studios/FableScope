//! Native HTML/JS extraction for the Web crawler (Phase 2): pull links, forms,
//! and JS-referenced endpoints out of a response body and normalize them to
//! absolute, in-scope URLs. Pure/offline parsing; the async crawl loop drives
//! it through the scope-guarded probe engine.

use fs_core::ScopePolicy;
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;
use url::Url;

/// A discovered HTML form.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FormInfo {
    pub action: String,
    pub method: String,
    pub inputs: Vec<String>,
}

/// Everything extracted from one page.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct PageExtract {
    pub links: Vec<String>,
    pub forms: Vec<FormInfo>,
    pub js_endpoints: Vec<String>,
    pub param_names: Vec<String>,
}

fn attr_value<'a>(tag: &'a str, attr: &str) -> Option<&'a str> {
    let lower = tag.to_lowercase();
    let key = format!("{attr}=");
    let pos = lower.find(&key)? + key.len();
    let rest = &tag[pos..];
    let bytes = rest.as_bytes();
    if bytes.is_empty() {
        return None;
    }
    let quote = bytes[0];
    if quote == b'"' || quote == b'\'' {
        let end = rest[1..].find(quote as char)? + 1;
        Some(&rest[1..end])
    } else {
        let end = rest.find([' ', '>', '\t', '\n']).unwrap_or(rest.len());
        Some(&rest[..end])
    }
}

fn resolve(base: &Url, raw: &str) -> Option<String> {
    let raw = raw.trim();
    if raw.is_empty() || raw.starts_with('#') || raw.starts_with("javascript:") || raw.starts_with("mailto:") || raw.starts_with("data:") {
        return None;
    }
    base.join(raw).ok().map(|u| {
        let mut u = u;
        u.set_fragment(None);
        u.to_string()
    })
}

fn find_tags<'a>(body: &'a str, tag: &str) -> Vec<&'a str> {
    let lower = body.to_lowercase();
    let open = format!("<{tag}");
    let mut out = Vec::new();
    let mut i = 0;
    while let Some(p) = lower[i..].find(&open) {
        let start = i + p;
        let end = body[start..].find('>').map(|e| start + e + 1).unwrap_or(body.len());
        out.push(&body[start..end]);
        i = end;
    }
    out
}

/// Extract links, forms, JS endpoints, and query-param names from a page body.
pub fn extract(base_url: &str, body: &str) -> PageExtract {
    let Ok(base) = Url::parse(base_url) else { return PageExtract::default() };
    let mut links: BTreeSet<String> = BTreeSet::new();
    let mut js: BTreeSet<String> = BTreeSet::new();
    let mut params: BTreeSet<String> = BTreeSet::new();

    // href / src attributes across anchors, scripts, links, imgs, forms.
    for tag in ["a", "link", "script", "img", "iframe", "source"] {
        for t in find_tags(body, tag) {
            for attr in ["href", "src"] {
                if let Some(v) = attr_value(t, attr) {
                    if let Some(abs) = resolve(&base, v) {
                        collect_params(&abs, &mut params);
                        links.insert(abs);
                    }
                }
            }
        }
    }

    // Forms.
    let mut forms = Vec::new();
    for ftag in find_tags(body, "form") {
        let action = attr_value(ftag, "action").and_then(|a| resolve(&base, a)).unwrap_or_else(|| base_url.to_string());
        let method = attr_value(ftag, "method").unwrap_or("get").to_uppercase();
        // Inputs: find input/select/textarea name= within the following slice.
        let start = body.find(ftag).map(|p| p + ftag.len()).unwrap_or(0);
        let rest = &body[start..];
        let end = rest.to_lowercase().find("</form>").map(|e| e).unwrap_or(rest.len());
        let inner = &rest[..end];
        let mut inputs = Vec::new();
        for itag in ["input", "select", "textarea"] {
            for t in find_tags(inner, itag) {
                if let Some(n) = attr_value(t, "name") {
                    inputs.push(n.to_string());
                    params.insert(n.to_string());
                }
            }
        }
        forms.push(FormInfo { action, method, inputs });
    }

    // JS endpoints: quoted strings that look like paths/URLs, and fetch()/url:
    for quote in ['"', '\''] {
        let mut chars = body.char_indices().peekable();
        while let Some((i, c)) = chars.next() {
            if c == quote {
                if let Some(close) = body[i + 1..].find(quote) {
                    let s = &body[i + 1..i + 1 + close];
                    if looks_like_endpoint(s) {
                        if let Some(abs) = resolve(&base, s) {
                            collect_params(&abs, &mut params);
                            js.insert(abs);
                        }
                    }
                    // Skip past the closing quote.
                    for _ in 0..close + 1 {
                        chars.next();
                    }
                }
            }
        }
    }

    PageExtract {
        links: links.into_iter().collect(),
        forms,
        js_endpoints: js.into_iter().collect(),
        param_names: params.into_iter().collect(),
    }
}

fn looks_like_endpoint(s: &str) -> bool {
    if s.len() < 2 || s.len() > 2048 || s.contains(' ') || s.contains('\n') {
        return false;
    }
    (s.starts_with('/') && !s.starts_with("//") && s.chars().nth(1).map(|c| c.is_ascii_alphanumeric() || c == '_').unwrap_or(false))
        || s.starts_with("http://")
        || s.starts_with("https://")
        || s.starts_with("/api/")
        || (s.contains('/') && (s.ends_with(".json") || s.ends_with(".php") || s.ends_with(".aspx") || s.contains("/api")))
}

fn collect_params(url: &str, out: &mut BTreeSet<String>) {
    if let Ok(u) = Url::parse(url) {
        for (k, _) in u.query_pairs() {
            out.insert(k.to_string());
        }
    }
}

/// Filter extracted links to those in scope and on the same registrable host as
/// the base (keeps a crawl from wandering off-target).
pub fn in_scope_links(extract: &PageExtract, base_url: &str, scope: &ScopePolicy) -> Vec<String> {
    let base_host = Url::parse(base_url).ok().and_then(|u| u.host_str().map(String::from)).unwrap_or_default();
    extract
        .links
        .iter()
        .chain(extract.js_endpoints.iter())
        .filter(|l| {
            let host = Url::parse(l).ok().and_then(|u| u.host_str().map(String::from)).unwrap_or_default();
            !host.is_empty() && host == base_host && (scope.is_allowed(&host) || scope.is_allowed(l))
        })
        .cloned()
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect()
}

/// Aggregated result of a crawl.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct CrawlResult {
    pub pages_visited: usize,
    pub urls: Vec<String>,
    pub forms: Vec<FormInfo>,
    pub param_names: Vec<String>,
    pub js_endpoints: Vec<String>,
}

/// Breadth-first, scope-guarded crawl from one or more start URLs, visiting at
/// most `max_pages`. Only same-host, in-scope links are followed. HTML bodies
/// are fetched directly; non-HTML responses are recorded but not parsed.
pub async fn crawl(
    start_urls: Vec<String>,
    scope: &ScopePolicy,
    cfg: &crate::ReconConfig,
    max_pages: usize,
) -> crate::Result<CrawlResult> {
    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_millis(cfg.timeout_ms))
        .user_agent(&cfg.user_agent)
        .redirect(reqwest::redirect::Policy::limited(5))
        .build()?;

    let mut queue: std::collections::VecDeque<String> = start_urls.into_iter().collect();
    let mut visited: BTreeSet<String> = BTreeSet::new();
    let mut all_urls: BTreeSet<String> = BTreeSet::new();
    let mut all_params: BTreeSet<String> = BTreeSet::new();
    let mut all_js: BTreeSet<String> = BTreeSet::new();
    let mut forms: Vec<FormInfo> = Vec::new();

    while let Some(url) = queue.pop_front() {
        if visited.len() >= max_pages.max(1) {
            break;
        }
        if visited.contains(&url) {
            continue;
        }
        let host = Url::parse(&url).ok().and_then(|u| u.host_str().map(String::from)).unwrap_or_default();
        if host.is_empty() || (!scope.is_allowed(&host) && !scope.is_allowed(&url)) {
            continue;
        }
        visited.insert(url.clone());

        let Ok(resp) = client.get(&url).send().await else { continue };
        let ct = resp.headers().get(reqwest::header::CONTENT_TYPE).and_then(|v| v.to_str().ok()).unwrap_or("").to_string();
        let final_url = resp.url().to_string();
        if !ct.contains("html") {
            all_urls.insert(final_url);
            continue;
        }
        let body = resp.text().await.unwrap_or_default();
        let extract = extract(&final_url, &body);
        for l in &extract.links {
            all_urls.insert(l.clone());
        }
        for p in &extract.param_names {
            all_params.insert(p.clone());
        }
        for j in &extract.js_endpoints {
            all_js.insert(j.clone());
        }
        forms.extend(extract.forms.clone());
        for next in in_scope_links(&extract, &final_url, scope) {
            if !visited.contains(&next) {
                queue.push_back(next);
            }
        }
    }

    Ok(CrawlResult {
        pages_visited: visited.len(),
        urls: all_urls.into_iter().collect(),
        forms,
        param_names: all_params.into_iter().collect(),
        js_endpoints: all_js.into_iter().collect(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    const PAGE: &str = r#"
        <html><body>
          <a href="/about">About</a>
          <a href="https://example.com/contact?ref=nav">Contact</a>
          <a href="https://evil.com/out">Out</a>
          <form action="/login" method="post">
            <input name="username"><input name="password" type="password">
          </form>
          <script>fetch("/api/v1/users?page=1"); var u = "/api/v1/orders.json";</script>
        </body></html>
    "#;

    #[test]
    fn extracts_links_and_params() {
        let e = extract("https://example.com/", PAGE);
        assert!(e.links.iter().any(|l| l == "https://example.com/about"));
        assert!(e.links.iter().any(|l| l.contains("/contact?ref=nav")));
        assert!(e.param_names.contains(&"ref".to_string()));
    }

    #[test]
    fn extracts_forms() {
        let e = extract("https://example.com/", PAGE);
        let f = e.forms.iter().find(|f| f.action.ends_with("/login")).unwrap();
        assert_eq!(f.method, "POST");
        assert!(f.inputs.contains(&"username".to_string()));
        assert!(e.param_names.contains(&"password".to_string()));
    }

    #[test]
    fn extracts_js_endpoints() {
        let e = extract("https://example.com/", PAGE);
        assert!(e.js_endpoints.iter().any(|j| j.contains("/api/v1/users")));
        assert!(e.js_endpoints.iter().any(|j| j.contains("/api/v1/orders.json")));
        assert!(e.param_names.contains(&"page".to_string()));
    }

    #[test]
    fn scope_keeps_same_host_only() {
        let e = extract("https://example.com/", PAGE);
        let scope = ScopePolicy { allow: vec!["example.com".into()], deny: vec![] };
        let links = in_scope_links(&e, "https://example.com/", &scope);
        assert!(links.iter().all(|l| l.contains("example.com")));
        assert!(!links.iter().any(|l| l.contains("evil.com")));
    }
}
