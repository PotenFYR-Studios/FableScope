//! Hash identification for authorized credential-audit workflows (Phase 2).
//!
//! Deterministic, offline identification of common hash and credential-artifact
//! formats by structure/length/prefix, mapping each to its Hashcat mode and John
//! format name so the credential-audit adapters can orchestrate authorized
//! cracking jobs. Identification is best-effort and returns ranked candidates;
//! it never cracks or validates secrets.

use serde::{Deserialize, Serialize};

/// A candidate hash-type identification.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HashCandidate {
    pub name: String,
    /// Hashcat `-m` mode, when known.
    pub hashcat_mode: Option<u32>,
    /// John the Ripper `--format=` name, when known.
    pub john_format: Option<String>,
    /// Confidence 0..100 (prefix matches rank above pure length matches).
    pub confidence: u8,
}

fn is_hex(s: &str) -> bool {
    !s.is_empty() && s.chars().all(|c| c.is_ascii_hexdigit())
}

fn hc(name: &str, mode: Option<u32>, john: Option<&str>, conf: u8) -> HashCandidate {
    HashCandidate { name: name.into(), hashcat_mode: mode, john_format: john.map(String::from), confidence: conf }
}

/// Identify likely hash types for a single hash string, ranked by confidence.
pub fn identify(input: &str) -> Vec<HashCandidate> {
    let h = input.trim();
    let mut out: Vec<HashCandidate> = Vec::new();
    if h.is_empty() {
        return out;
    }

    // --- Prefixed / structured formats (high confidence) ---
    if h.starts_with("$2a$") || h.starts_with("$2b$") || h.starts_with("$2y$") {
        out.push(hc("bcrypt", Some(3200), Some("bcrypt"), 99));
    }
    if h.starts_with("$1$") {
        out.push(hc("md5crypt", Some(500), Some("md5crypt"), 98));
    }
    if h.starts_with("$5$") {
        out.push(hc("sha256crypt", Some(7400), Some("sha256crypt"), 98));
    }
    if h.starts_with("$6$") {
        out.push(hc("sha512crypt", Some(1800), Some("sha512crypt"), 98));
    }
    if h.starts_with("$y$") || h.starts_with("$7$") {
        out.push(hc("yescrypt/scrypt", Some(9300), Some("scrypt"), 80));
    }
    if h.starts_with("$argon2") {
        out.push(hc("Argon2", None, Some("argon2"), 98));
    }
    if h.starts_with("$pbkdf2") || h.starts_with("$pbkdf2-sha256") {
        out.push(hc("PBKDF2", Some(10900), Some("PBKDF2-HMAC-SHA256"), 90));
    }
    if h.starts_with("sha1$") || h.starts_with("pbkdf2_sha256$") {
        out.push(hc("Django PBKDF2-SHA256", Some(10000), Some("django"), 95));
    }
    if h.starts_with("{SSHA}") {
        out.push(hc("LDAP SSHA", Some(111), Some("ssha"), 97));
    }
    if h.starts_with("{SHA}") {
        out.push(hc("LDAP SHA", Some(101), Some("Raw-SHA1"), 95));
    }
    if h.starts_with("0x") && is_hex(&h[2..]) {
        out.push(hc("MSSQL (hex-prefixed)", Some(1731), Some("mssql"), 70));
    }

    // --- NetNTLM / Kerberos artifacts (colon/$-delimited) ---
    if h.contains("::") && h.to_uppercase().contains(":") {
        // user::DOMAIN:challenge:... shapes
        let colons = h.matches(':').count();
        if colons >= 4 && h.matches("::").count() >= 1 {
            // NetNTLMv2 has a long blob after the server challenge.
            out.push(hc("NetNTLMv2", Some(5600), Some("netntlmv2"), 85));
            out.push(hc("NetNTLMv1", Some(5500), Some("netntlm"), 60));
        }
    }
    if h.starts_with("$krb5tgs$") {
        out.push(hc("Kerberos 5 TGS-REP (Kerberoast)", Some(13100), Some("krb5tgs"), 99));
    }
    if h.starts_with("$krb5asrep$") {
        out.push(hc("Kerberos 5 AS-REP (AS-REP Roast)", Some(18200), Some("krb5asrep"), 99));
    }
    if h.starts_with("$krb5pa$") {
        out.push(hc("Kerberos 5 AS-REQ Pre-Auth", Some(7500), Some("krb5pa-md5"), 97));
    }

    // --- NTLM / DCC (structured colon forms) ---
    if h.contains(':') && !h.contains("::") {
        let parts: Vec<&str> = h.split(':').collect();
        // pwdump line: user:rid:LM:NT:::
        if parts.len() >= 4 && parts[2].len() == 32 && parts[3].len() == 32 && is_hex(parts[2]) && is_hex(parts[3]) {
            out.push(hc("NTLM (from pwdump line)", Some(1000), Some("NT"), 90));
            out.push(hc("LM (from pwdump line)", Some(3000), Some("LM"), 70));
        }
    }

    // --- Raw hex digests (ranked by length) ---
    if is_hex(h) {
        match h.len() {
            32 => {
                out.push(hc("NTLM", Some(1000), Some("NT"), 70));
                out.push(hc("MD5", Some(0), Some("Raw-MD5"), 65));
                out.push(hc("MD4", Some(900), Some("Raw-MD4"), 40));
                out.push(hc("LM", Some(3000), Some("LM"), 35));
            }
            40 => {
                out.push(hc("SHA-1", Some(100), Some("Raw-SHA1"), 70));
                out.push(hc("MySQL 4.1+ (SHA1)", Some(300), Some("mysql-sha1"), 45));
            }
            56 => out.push(hc("SHA-224", Some(1300), Some("Raw-SHA224"), 70)),
            64 => {
                out.push(hc("SHA-256", Some(1400), Some("Raw-SHA256"), 70));
                out.push(hc("SHA3-256/Keccak-256", Some(17600), Some("Raw-Keccak-256"), 35));
            }
            96 => out.push(hc("SHA-384", Some(10800), Some("Raw-SHA384"), 70)),
            128 => {
                out.push(hc("SHA-512", Some(1700), Some("Raw-SHA512"), 70));
                out.push(hc("Whirlpool", Some(6100), Some("whirlpool"), 40));
            }
            16 => out.push(hc("MySQL 3.x (pre-4.1)", Some(200), Some("mysql"), 60)),
            _ => {}
        }
    }

    // Stable deterministic ordering: confidence desc, then name.
    out.sort_by(|a, b| b.confidence.cmp(&a.confidence).then(a.name.cmp(&b.name)));
    out.dedup_by(|a, b| a.name == b.name);
    out
}

/// Identify the single best candidate (highest confidence), if any.
pub fn best(input: &str) -> Option<HashCandidate> {
    identify(input).into_iter().next()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn identifies_bcrypt() {
        let c = best("$2b$12$R9h/cIPz0gi.URNNX3kh2OPST9/PgBkqquzi.Ss7KIUgO2t0jWMUW").unwrap();
        assert_eq!(c.name, "bcrypt");
        assert_eq!(c.hashcat_mode, Some(3200));
    }

    #[test]
    fn identifies_ntlm_and_md5_for_32hex() {
        let got = identify("8846f7eaee8fb117ad06bdd830b7586c");
        assert!(got.iter().any(|c| c.name == "NTLM"));
        assert!(got.iter().any(|c| c.name == "MD5"));
        // NTLM ranks above MD5 by confidence.
        assert_eq!(got[0].name, "NTLM");
    }

    #[test]
    fn identifies_sha256_by_length() {
        let c = best("5e884898da28047151d0e56f8dc6292773603d0d6aabbdd62a11ef721d1542d8").unwrap();
        assert_eq!(c.name, "SHA-256");
    }

    #[test]
    fn identifies_kerberoast() {
        let c = best("$krb5tgs$23$*user$DOMAIN$cifs/host*$abcdef...").unwrap();
        assert_eq!(c.hashcat_mode, Some(13100));
    }

    #[test]
    fn identifies_sha512crypt() {
        let c = best("$6$rounds=5000$salt$hashhashhash").unwrap();
        assert_eq!(c.hashcat_mode, Some(1800));
    }

    #[test]
    fn empty_is_empty() {
        assert!(identify("   ").is_empty());
    }
}
