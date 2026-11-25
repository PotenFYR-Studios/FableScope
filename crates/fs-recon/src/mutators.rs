//! Fuzz payload mutation engine.
//!
//! Deterministic, offline payload generation across the fuzz surfaces described
//! in the FableScope Phase 1 plan: wordlist, numeric/range, boolean, type
//! juggling, boundary values, encoding chains, case/path normalization, and
//! prefix/suffix mutations. Every generated payload carries a `family` label so
//! results can be grouped and triaged, and the engine deduplicates its output.

use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;

/// A mutation strategy. Strategies are composable; the engine applies each one
/// requested and unions the (deduplicated) output.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Mutator {
    /// Emit the seed word unchanged (plain wordlist entry).
    Wordlist,
    /// Numeric neighbours and a small range around a parsed integer seed.
    Numeric,
    /// Boundary / off-by-one values (0, -1, max ints, empty, overlong).
    Boundary,
    /// Boolean and truthy/falsy variants for type-juggling probes.
    Boolean,
    /// Type juggling: array/object/null shapes for JSON-aware fuzzing.
    TypeJuggle,
    /// Case variations (lower, upper, title, swap).
    Case,
    /// Encoding chains (url, double-url, base64, hex).
    Encoding,
    /// Path traversal / normalization variants.
    PathTraversal,
    /// Prefix/suffix mutations (., _, -, ~, year, .bak).
    Affix,
}

impl Mutator {
    pub fn family(&self) -> &'static str {
        match self {
            Mutator::Wordlist => "wordlist",
            Mutator::Numeric => "numeric",
            Mutator::Boundary => "boundary",
            Mutator::Boolean => "boolean",
            Mutator::TypeJuggle => "type_juggle",
            Mutator::Case => "case",
            Mutator::Encoding => "encoding",
            Mutator::PathTraversal => "path_traversal",
            Mutator::Affix => "affix",
        }
    }
}

/// The default balanced strategy set used by the "balanced" fuzz profile.
pub fn default_strategies() -> Vec<Mutator> {
    vec![
        Mutator::Wordlist,
        Mutator::Case,
        Mutator::Affix,
        Mutator::Encoding,
        Mutator::PathTraversal,
    ]
}

/// A generated payload plus the family it belongs to.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Payload {
    pub value: String,
    pub family: String,
    pub mutator: Mutator,
}

fn url_encode(s: &str) -> String {
    let mut out = String::with_capacity(s.len() * 3);
    for b in s.bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => out.push(b as char),
            _ => out.push_str(&format!("%{b:02X}")),
        }
    }
    out
}

fn base64_encode(s: &str) -> String {
    const T: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let bytes = s.as_bytes();
    let mut out = String::new();
    for chunk in bytes.chunks(3) {
        let b0 = chunk[0] as u32;
        let b1 = *chunk.get(1).unwrap_or(&0) as u32;
        let b2 = *chunk.get(2).unwrap_or(&0) as u32;
        let n = (b0 << 16) | (b1 << 8) | b2;
        out.push(T[((n >> 18) & 63) as usize] as char);
        out.push(T[((n >> 12) & 63) as usize] as char);
        out.push(if chunk.len() > 1 { T[((n >> 6) & 63) as usize] as char } else { '=' });
        out.push(if chunk.len() > 2 { T[(n & 63) as usize] as char } else { '=' });
    }
    out
}

fn hex_encode(s: &str) -> String {
    let mut out = String::new();
    for b in s.bytes() {
        out.push_str(&format!("{b:02x}"));
    }
    out
}

fn title_case(s: &str) -> String {
    let mut c = s.chars();
    match c.next() {
        Some(f) => f.to_uppercase().collect::<String>() + &c.as_str().to_lowercase(),
        None => String::new(),
    }
}

fn swap_case(s: &str) -> String {
    s.chars()
        .map(|c| if c.is_uppercase() { c.to_ascii_lowercase() } else { c.to_ascii_uppercase() })
        .collect()
}

/// Apply a single mutator to a seed, returning its raw variants.
pub fn apply(mutator: Mutator, seed: &str) -> Vec<String> {
    let s = seed.trim();
    match mutator {
        Mutator::Wordlist => vec![s.to_string()],
        Mutator::Numeric => {
            if let Ok(n) = s.parse::<i64>() {
                vec![
                    (n - 1).to_string(),
                    (n + 1).to_string(),
                    (n * 2).to_string(),
                    "0".to_string(),
                    n.to_string(),
                ]
            } else {
                vec!["0".into(), "1".into(), "2".into(), "100".into(), "9999".into()]
            }
        }
        Mutator::Boundary => vec![
            "".into(),
            "0".into(),
            "-1".into(),
            "2147483647".into(),
            "2147483648".into(),
            "9223372036854775807".into(),
            "A".repeat(256),
        ],
        Mutator::Boolean => vec!["true".into(), "false".into(), "1".into(), "0".into(), "yes".into(), "no".into()],
        Mutator::TypeJuggle => vec![
            "null".into(),
            "[]".into(),
            "{}".into(),
            "[0]".into(),
            format!("\"{s}\""),
            format!("[\"{s}\"]"),
        ],
        Mutator::Case => {
            let mut v = vec![s.to_lowercase(), s.to_uppercase(), title_case(s), swap_case(s)];
            v.retain(|x| !x.is_empty());
            v
        }
        Mutator::Encoding => vec![
            url_encode(s),
            url_encode(&url_encode(s)),
            base64_encode(s),
            hex_encode(s),
        ],
        Mutator::PathTraversal => vec![
            format!("../{s}"),
            format!("../../{s}"),
            format!("..%2f{s}"),
            format!("%2e%2e%2f{s}"),
            format!("/{s}"),
            format!("{s}/"),
        ],
        Mutator::Affix => vec![
            format!(".{s}"),
            format!("_{s}"),
            format!("{s}_"),
            format!("{s}-old"),
            format!("{s}.bak"),
            format!("{s}~"),
            format!("{s}2024"),
            format!("{s}2025"),
        ],
    }
}

/// Generate deduplicated payloads for a seed across the requested strategies.
pub fn generate(seed: &str, strategies: &[Mutator]) -> Vec<Payload> {
    let mut seen: BTreeSet<String> = BTreeSet::new();
    let mut out = Vec::new();
    for &m in strategies {
        for v in apply(m, seed) {
            if v.is_empty() && m != Mutator::Boundary && m != Mutator::TypeJuggle {
                continue;
            }
            // Dedup across families but keep the first family that produced it.
            if seen.insert(v.clone()) {
                out.push(Payload { value: v, family: m.family().to_string(), mutator: m });
            }
        }
    }
    out
}

/// Generate payloads for a list of seeds, capped at `limit` total payloads.
pub fn generate_many(seeds: &[String], strategies: &[Mutator], limit: usize) -> Vec<Payload> {
    let mut out = Vec::new();
    for seed in seeds {
        for p in generate(seed, strategies) {
            out.push(p);
            if out.len() >= limit {
                return out;
            }
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn wordlist_is_identity() {
        assert_eq!(apply(Mutator::Wordlist, "admin"), vec!["admin"]);
    }

    #[test]
    fn case_variants() {
        let v = apply(Mutator::Case, "Admin");
        assert!(v.contains(&"admin".to_string()));
        assert!(v.contains(&"ADMIN".to_string()));
    }

    #[test]
    fn encoding_chain() {
        let v = apply(Mutator::Encoding, "a b");
        assert!(v.iter().any(|x| x == "a%20b"));
        assert!(v.iter().any(|x| x == "YSBi")); // base64("a b")
        assert!(v.iter().any(|x| x == "612062")); // hex
    }

    #[test]
    fn numeric_neighbours() {
        let v = apply(Mutator::Numeric, "10");
        assert!(v.contains(&"9".to_string()));
        assert!(v.contains(&"11".to_string()));
    }

    #[test]
    fn generate_dedups_and_labels() {
        let payloads = generate("admin", &[Mutator::Wordlist, Mutator::Case]);
        // "admin" appears once even though wordlist and lowercase-case both emit it.
        let admins: Vec<_> = payloads.iter().filter(|p| p.value == "admin").collect();
        assert_eq!(admins.len(), 1);
        assert!(payloads.iter().all(|p| !p.family.is_empty()));
    }

    #[test]
    fn generate_many_respects_limit() {
        let seeds = vec!["a".to_string(), "b".to_string(), "c".to_string()];
        let out = generate_many(&seeds, &default_strategies(), 5);
        assert_eq!(out.len(), 5);
    }
}
