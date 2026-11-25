//! Algorithmic (offline) password & passphrase generator for authorized
//! credential-audit workflows — the Phase 1 "Password generator (algorithmic
//! mode first)" surface.
//!
//! CSPRNG-backed generation, policy-constrained output, Diceware-style
//! passphrases, mangling rules, Shannon entropy estimation, near-duplicate
//! suppression, and provenance labels. No AI/intel here: every candidate is
//! labelled `algorithmic`. Intel/AI-assisted modes are layered on separately and
//! remain opt-in.

use rand::rngs::StdRng;
use rand::seq::SliceRandom;
use rand::{Rng, SeedableRng};
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;

const LOWER: &[u8] = b"abcdefghijklmnopqrstuvwxyz";
const UPPER: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ";
const DIGITS: &[u8] = b"0123456789";
const SYMBOLS: &[u8] = b"!@#$%^&*()-_=+[]{};:,.?";

/// A password policy constraining generated output.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PasswordPolicy {
    pub length: usize,
    pub lower: bool,
    pub upper: bool,
    pub digits: bool,
    pub symbols: bool,
    /// Characters to exclude (e.g. ambiguous `O0l1I`).
    pub exclude: String,
}

impl Default for PasswordPolicy {
    fn default() -> Self {
        Self { length: 16, lower: true, upper: true, digits: true, symbols: true, exclude: String::new() }
    }
}

impl PasswordPolicy {
    fn charset(&self) -> Vec<u8> {
        let mut set: Vec<u8> = Vec::new();
        if self.lower {
            set.extend_from_slice(LOWER);
        }
        if self.upper {
            set.extend_from_slice(UPPER);
        }
        if self.digits {
            set.extend_from_slice(DIGITS);
        }
        if self.symbols {
            set.extend_from_slice(SYMBOLS);
        }
        let exclude: BTreeSet<u8> = self.exclude.bytes().collect();
        set.retain(|b| !exclude.contains(b));
        if set.is_empty() {
            set.extend_from_slice(LOWER);
        }
        set
    }

    fn required_classes(&self) -> Vec<Vec<u8>> {
        let exclude: BTreeSet<u8> = self.exclude.bytes().collect();
        let filt = |c: &[u8]| -> Vec<u8> { c.iter().copied().filter(|b| !exclude.contains(b)).collect() };
        let mut v = Vec::new();
        if self.lower {
            v.push(filt(LOWER));
        }
        if self.upper {
            v.push(filt(UPPER));
        }
        if self.digits {
            v.push(filt(DIGITS));
        }
        if self.symbols {
            v.push(filt(SYMBOLS));
        }
        v.retain(|c| !c.is_empty());
        v
    }
}

/// Provenance of a generated candidate.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Provenance {
    Algorithmic,
    Intel,
    Ai,
    Hybrid,
}

/// A generated credential candidate.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Candidate {
    pub value: String,
    pub entropy_bits: f32,
    pub provenance: Provenance,
}

/// Shannon entropy estimate (bits) based on the realized character set and
/// length — a conservative lower bound for policy/CSPRNG output.
pub fn estimate_entropy(password: &str) -> f32 {
    if password.is_empty() {
        return 0.0;
    }
    let mut pool = 0usize;
    if password.bytes().any(|b| LOWER.contains(&b)) {
        pool += 26;
    }
    if password.bytes().any(|b| UPPER.contains(&b)) {
        pool += 26;
    }
    if password.bytes().any(|b| DIGITS.contains(&b)) {
        pool += 10;
    }
    if password.bytes().any(|b| SYMBOLS.contains(&b)) {
        pool += SYMBOLS.len();
    }
    if password.bytes().any(|b| !b.is_ascii()) {
        pool += 100; // rough allowance for non-ascii
    }
    let pool = pool.max(1) as f32;
    password.chars().count() as f32 * pool.log2()
}

fn rng(seed: Option<u64>) -> StdRng {
    match seed {
        Some(s) => StdRng::seed_from_u64(s),
        None => StdRng::from_entropy(),
    }
}

/// Generate a single policy-constrained password, guaranteeing at least one
/// character from each required class.
pub fn generate_one(policy: &PasswordPolicy, rng: &mut StdRng) -> String {
    let charset = policy.charset();
    let len = policy.length.max(1);
    let required = policy.required_classes();
    let mut chars: Vec<u8> = Vec::with_capacity(len);
    // Seed required classes first (if they fit).
    for class in required.iter().take(len) {
        let c = class[rng.gen_range(0..class.len())];
        chars.push(c);
    }
    while chars.len() < len {
        chars.push(charset[rng.gen_range(0..charset.len())]);
    }
    chars.shuffle(rng);
    String::from_utf8_lossy(&chars).to_string()
}

/// Generate `count` policy-constrained passwords with near-duplicate
/// suppression. `seed` makes output deterministic (for tests / reproducible
/// fixtures); pass `None` for CSPRNG entropy.
pub fn generate(policy: &PasswordPolicy, count: usize, seed: Option<u64>) -> Vec<Candidate> {
    let mut r = rng(seed);
    let mut seen: BTreeSet<String> = BTreeSet::new();
    let mut out = Vec::new();
    let mut attempts = 0;
    let max_attempts = count.saturating_mul(10).max(20);
    while out.len() < count && attempts < max_attempts {
        attempts += 1;
        let pw = generate_one(policy, &mut r);
        if seen.insert(pw.clone()) {
            let entropy_bits = estimate_entropy(&pw);
            out.push(Candidate { value: pw, entropy_bits, provenance: Provenance::Algorithmic });
        }
    }
    out
}

/// Default Diceware-style wordlist (compact built-in; real deployments load a
/// full EFF list via the wordlist registry).
pub fn default_passphrase_words() -> Vec<&'static str> {
    vec![
        "apple", "river", "stone", "cloud", "ember", "maple", "quartz", "harbor", "meadow", "lantern",
        "copper", "willow", "cedar", "falcon", "pebble", "thunder", "marble", "cobalt", "violet", "amber",
        "crystal", "jungle", "orbit", "prairie", "silver", "velvet", "walnut", "zephyr", "glacier", "nectar",
        "comet", "dagger", "fern", "garnet", "hollow", "indigo", "jasper", "kettle", "ladder", "mango",
    ]
}

/// Generate a Diceware-style passphrase from a wordlist.
pub fn generate_passphrase(words: &[&str], count: usize, separator: &str, seed: Option<u64>) -> Candidate {
    let mut r = rng(seed);
    let picks: Vec<&str> = (0..count.max(1)).map(|_| *words.choose(&mut r).unwrap_or(&"word")).collect();
    let value = picks.join(separator);
    // Passphrase entropy = count * log2(wordlist size).
    let entropy_bits = count as f32 * (words.len().max(2) as f32).log2();
    Candidate { value, entropy_bits, provenance: Provenance::Algorithmic }
}

/// Mangling rules applied to a base word to derive candidate variants
/// (leet-speak, case, year/season and separator suffixes). Output is
/// deduplicated. Candidates are labelled `algorithmic`.
pub fn mangle(base: &str, provenance: Provenance) -> Vec<Candidate> {
    let base = base.trim();
    if base.is_empty() {
        return vec![];
    }
    let leet = base
        .replace('a', "@")
        .replace('A', "@")
        .replace('e', "3")
        .replace('E', "3")
        .replace('o', "0")
        .replace('O', "0")
        .replace('i', "1")
        .replace('s', "$");
    let title = {
        let mut c = base.chars();
        match c.next() {
            Some(f) => f.to_uppercase().collect::<String>() + &c.as_str().to_lowercase(),
            None => String::new(),
        }
    };
    let mut variants: BTreeSet<String> = BTreeSet::new();
    let bases = [base.to_string(), base.to_lowercase(), base.to_uppercase(), title, leet];
    let suffixes = ["", "1", "123", "!", "@123", "2024", "2025", "#1"];
    for b in &bases {
        if b.is_empty() {
            continue;
        }
        for suf in suffixes {
            variants.insert(format!("{b}{suf}"));
        }
    }
    variants
        .into_iter()
        .map(|v| {
            let entropy_bits = estimate_entropy(&v);
            Candidate { value: v, entropy_bits, provenance }
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn respects_length_and_classes() {
        let policy = PasswordPolicy { length: 20, ..Default::default() };
        let out = generate(&policy, 5, Some(42));
        assert_eq!(out.len(), 5);
        for c in &out {
            assert_eq!(c.value.chars().count(), 20);
            assert!(c.value.bytes().any(|b| b.is_ascii_lowercase()));
            assert!(c.value.bytes().any(|b| b.is_ascii_uppercase()));
            assert!(c.value.bytes().any(|b| b.is_ascii_digit()));
        }
    }

    #[test]
    fn exclusions_honoured() {
        let policy = PasswordPolicy { length: 30, exclude: "0Oo".into(), ..Default::default() };
        let out = generate(&policy, 3, Some(7));
        for c in &out {
            assert!(!c.value.contains('0'));
            assert!(!c.value.contains('O'));
            assert!(!c.value.contains('o'));
        }
    }

    #[test]
    fn deterministic_with_seed() {
        let policy = PasswordPolicy::default();
        let a = generate(&policy, 3, Some(99));
        let b = generate(&policy, 3, Some(99));
        assert_eq!(a.iter().map(|c| &c.value).collect::<Vec<_>>(), b.iter().map(|c| &c.value).collect::<Vec<_>>());
    }

    #[test]
    fn no_duplicates() {
        let policy = PasswordPolicy { length: 12, ..Default::default() };
        let out = generate(&policy, 20, Some(5));
        let uniq: BTreeSet<_> = out.iter().map(|c| c.value.clone()).collect();
        assert_eq!(uniq.len(), out.len());
    }

    #[test]
    fn entropy_increases_with_length() {
        assert!(estimate_entropy("abcdefghij") < estimate_entropy("abcdefghijklmnopqrst"));
        assert!(estimate_entropy("abc") < estimate_entropy("aB3!xyz"));
    }

    #[test]
    fn passphrase_word_count() {
        let words = default_passphrase_words();
        let p = generate_passphrase(&words, 5, "-", Some(1));
        assert_eq!(p.value.split('-').count(), 5);
        assert!(p.entropy_bits > 20.0);
    }

    #[test]
    fn mangle_produces_variants() {
        let v = mangle("password", Provenance::Algorithmic);
        assert!(v.iter().any(|c| c.value == "Password123" || c.value == "password123"));
        assert!(v.iter().any(|c| c.value.contains('@'))); // leet
    }
}
