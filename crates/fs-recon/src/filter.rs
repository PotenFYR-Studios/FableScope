//! Filtering and grouping of recon/probe results, backing the Phase 1
//! "Filters & Grouping" surface. Operates on serialized result rows
//! (`serde_json::Value`) so it works uniformly over probe, fuzz, and imported
//! results persisted by storage.

use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

/// A single filter predicate over a result row.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "op", rename_all = "snake_case")]
pub enum Filter {
    /// status code is one of the given values.
    StatusIn { values: Vec<u16> },
    /// status class matches (2xx/3xx/4xx/5xx/err).
    StatusClass { class: String },
    /// content length within [min, max].
    LengthBetween { min: u64, max: u64 },
    /// title contains the substring (case-insensitive).
    TitleContains { needle: String },
    /// content-type contains the substring.
    ContentTypeContains { needle: String },
    /// response has a header with this (case-insensitive) name.
    HasHeader { name: String },
    /// logical negation.
    Not { inner: Box<Filter> },
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

fn row_status(row: &serde_json::Value) -> Option<u16> {
    row.get("status").and_then(|v| v.as_u64()).map(|n| n as u16)
}

impl Filter {
    pub fn matches(&self, row: &serde_json::Value) -> bool {
        match self {
            Filter::StatusIn { values } => row_status(row).map(|s| values.contains(&s)).unwrap_or(false),
            Filter::StatusClass { class } => &status_class(row_status(row)) == class,
            Filter::LengthBetween { min, max } => {
                let len = row.get("content_length").and_then(|v| v.as_u64()).unwrap_or(0);
                len >= *min && len <= *max
            }
            Filter::TitleContains { needle } => row
                .get("title")
                .and_then(|v| v.as_str())
                .map(|t| t.to_lowercase().contains(&needle.to_lowercase()))
                .unwrap_or(false),
            Filter::ContentTypeContains { needle } => row
                .get("content_type")
                .and_then(|v| v.as_str())
                .map(|t| t.to_lowercase().contains(&needle.to_lowercase()))
                .unwrap_or(false),
            Filter::HasHeader { name } => row
                .get("headers")
                .and_then(|v| v.as_object())
                .map(|h| h.keys().any(|k| k.eq_ignore_ascii_case(name)))
                .unwrap_or(false),
            Filter::Not { inner } => !inner.matches(row),
        }
    }
}

/// Apply all filters (logical AND) to a set of rows.
pub fn apply_filters(rows: &[serde_json::Value], filters: &[Filter]) -> Vec<serde_json::Value> {
    rows.iter()
        .filter(|r| filters.iter().all(|f| f.matches(r)))
        .cloned()
        .collect()
}

/// A grouping dimension.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum GroupBy {
    Status,
    StatusClass,
    ContentType,
    Host,
}

fn host_of(row: &serde_json::Value) -> String {
    let url = row.get("url").and_then(|v| v.as_str()).unwrap_or("");
    url.split("://")
        .nth(1)
        .and_then(|rest| rest.split('/').next())
        .unwrap_or("")
        .to_string()
}

/// Group rows and return a map of group key -> count, plus the rows per group.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GroupResult {
    pub key: String,
    pub count: usize,
    pub rows: Vec<serde_json::Value>,
}

pub fn group(rows: &[serde_json::Value], by: GroupBy) -> Vec<GroupResult> {
    let mut groups: BTreeMap<String, Vec<serde_json::Value>> = BTreeMap::new();
    for r in rows {
        let key = match by {
            GroupBy::Status => row_status(r).map(|s| s.to_string()).unwrap_or_else(|| "err".into()),
            GroupBy::StatusClass => status_class(row_status(r)),
            GroupBy::ContentType => r
                .get("content_type")
                .and_then(|v| v.as_str())
                .map(|t| t.split(';').next().unwrap_or("").trim().to_lowercase())
                .filter(|s| !s.is_empty())
                .unwrap_or_else(|| "unknown".into()),
            GroupBy::Host => {
                let h = host_of(r);
                if h.is_empty() { "unknown".into() } else { h }
            }
        };
        groups.entry(key).or_default().push(r.clone());
    }
    let mut out: Vec<GroupResult> = groups
        .into_iter()
        .map(|(key, rows)| GroupResult { key, count: rows.len(), rows })
        .collect();
    out.sort_by(|a, b| b.count.cmp(&a.count));
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rows() -> Vec<serde_json::Value> {
        vec![
            serde_json::json!({"url":"https://a.com/1","status":200,"content_length":1000,"title":"Home","content_type":"text/html"}),
            serde_json::json!({"url":"https://a.com/admin","status":403,"content_length":50,"title":"Forbidden","content_type":"text/html"}),
            serde_json::json!({"url":"https://b.com/api","status":200,"content_length":200,"title":"API","content_type":"application/json"}),
        ]
    }

    #[test]
    fn status_filter() {
        let out = apply_filters(&rows(), &[Filter::StatusIn { values: vec![200] }]);
        assert_eq!(out.len(), 2);
    }

    #[test]
    fn title_and_negation() {
        let out = apply_filters(&rows(), &[Filter::Not { inner: Box::new(Filter::TitleContains { needle: "forbidden".into() }) }]);
        assert_eq!(out.len(), 2);
    }

    #[test]
    fn group_by_status_class() {
        let g = group(&rows(), GroupBy::StatusClass);
        let two_xx = g.iter().find(|x| x.key == "2xx").unwrap();
        assert_eq!(two_xx.count, 2);
    }

    #[test]
    fn group_by_host() {
        let g = group(&rows(), GroupBy::Host);
        assert!(g.iter().any(|x| x.key == "a.com" && x.count == 2));
        assert!(g.iter().any(|x| x.key == "b.com" && x.count == 1));
    }
}
