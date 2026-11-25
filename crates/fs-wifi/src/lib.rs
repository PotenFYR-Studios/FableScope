//! WiFi module — authorized wireless assessment support (Phase 3).
//!
//! Offline, deterministic: a hardware/OS capability matrix (so the UI can
//! disable unsupported actions with a reason), parsing of capture artifacts
//! (Hashcat 22000 PMKID/EAPOL lines), and authorization-gated audit planning.
//! No radio access, no capture, no cracking happens here — those require
//! hardware, drivers, and explicit authorization and stay gated.

use serde::{Deserialize, Serialize};

/// A wireless capability and whether the current platform/driver supports it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Capability {
    pub name: String,
    pub supported: bool,
    pub reason: String,
}

/// Report the capability matrix for the current OS. Wireless features are
/// hardware/driver dependent; this gives the UI a reason to gray out actions.
pub fn capability_matrix() -> Vec<Capability> {
    let (monitor, injection, reason) = if cfg!(target_os = "linux") {
        (true, true, "Linux with a compatible adapter/driver (mac80211) typically supports monitor mode and injection.")
    } else if cfg!(target_os = "macos") {
        (true, false, "macOS supports monitor-mode sniffing via the system airport tooling; packet injection is not supported.")
    } else {
        (false, false, "Windows lacks native monitor mode / injection for most adapters; use an external Linux capture host or a supported USB adapter.")
    };
    vec![
        Capability { name: "monitor_mode".into(), supported: monitor, reason: reason.into() },
        Capability { name: "packet_injection".into(), supported: injection, reason: reason.into() },
        Capability { name: "pmkid_capture".into(), supported: monitor, reason: "Requires monitor mode.".into() },
        Capability { name: "handshake_capture".into(), supported: monitor, reason: "Requires monitor mode; deauth needs injection.".into() },
        Capability { name: "offline_audit".into(), supported: true, reason: "Offline audit of already-captured material is always available (authorized).".into() },
    ]
}

/// A captured key-exchange artifact type.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CaptureKind {
    Pmkid,
    Eapol,
}

/// A normalized WPA capture record (no secret material is crackable here).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WifiCapture {
    pub kind: CaptureKind,
    pub bssid: Option<String>,
    pub station: Option<String>,
    pub essid: Option<String>,
    pub hashcat_mode: u32, // 22000 (WPA-PBKDF2-PMKID+EAPOL)
    pub raw: String,
}

fn hex_to_ascii(h: &str) -> Option<String> {
    if h.is_empty() || h.len() % 2 != 0 || !h.chars().all(|c| c.is_ascii_hexdigit()) {
        return None;
    }
    let mut out = Vec::new();
    let b = h.as_bytes();
    let mut i = 0;
    while i < b.len() {
        out.push(u8::from_str_radix(std::str::from_utf8(&b[i..i + 2]).ok()?, 16).ok()?);
        i += 2;
    }
    String::from_utf8(out).ok()
}

fn fmt_mac(h: &str) -> Option<String> {
    if h.len() != 12 || !h.chars().all(|c| c.is_ascii_hexdigit()) {
        return None;
    }
    Some(h.as_bytes().chunks(2).map(|c| std::str::from_utf8(c).unwrap_or("")).collect::<Vec<_>>().join(":").to_lowercase())
}

/// Parse a Hashcat 22000 line: `WPA*TYPE*HASH*MAC_AP*MAC_STA*ESSID_HEX*...`
/// TYPE 01 = PMKID, 02 = EAPOL.
pub fn parse_hc22000_line(line: &str) -> Option<WifiCapture> {
    let line = line.trim();
    if !line.starts_with("WPA*") {
        return None;
    }
    let f: Vec<&str> = line.split('*').collect();
    if f.len() < 6 {
        return None;
    }
    let kind = match f[1] {
        "01" => CaptureKind::Pmkid,
        "02" => CaptureKind::Eapol,
        _ => return None,
    };
    Some(WifiCapture {
        kind,
        bssid: fmt_mac(f[3]),
        station: fmt_mac(f[4]),
        essid: hex_to_ascii(f[5]),
        hashcat_mode: 22000,
        raw: line.to_string(),
    })
}

/// Parse a whole capture file (one hc22000 line per entry).
pub fn parse_captures(text: &str) -> Vec<WifiCapture> {
    text.lines().filter_map(parse_hc22000_line).collect()
}

/// An authorization-gated WiFi audit plan (command built for review, not run).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WifiAuditPlan {
    pub hashcat_args: Vec<String>,
    pub capture_count: usize,
    pub networks: Vec<String>,
}

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum WifiError {
    #[error("authorization required for wireless credential auditing")]
    NotAuthorized,
    #[error("no captures provided")]
    NoCaptures,
}

/// Build a Hashcat `-m 22000` audit plan for captured material. Refused unless
/// `authorized` is true; builds the command only (execution stays gated).
pub fn plan_audit(captures: &[WifiCapture], hash_file: &str, wordlist: &str, authorized: bool) -> Result<WifiAuditPlan, WifiError> {
    if !authorized {
        return Err(WifiError::NotAuthorized);
    }
    if captures.is_empty() {
        return Err(WifiError::NoCaptures);
    }
    let mut networks: Vec<String> = captures.iter().filter_map(|c| c.essid.clone()).collect();
    networks.sort();
    networks.dedup();
    Ok(WifiAuditPlan {
        hashcat_args: vec!["-m".into(), "22000".into(), "-a".into(), "0".into(), hash_file.into(), wordlist.into()],
        capture_count: captures.len(),
        networks,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn capability_matrix_has_offline_audit() {
        let caps = capability_matrix();
        assert!(caps.iter().any(|c| c.name == "offline_audit" && c.supported));
        assert!(caps.iter().any(|c| c.name == "monitor_mode"));
    }

    #[test]
    fn parses_pmkid_line() {
        // WPA*01*<pmkid>*<ap mac>*<sta mac>*<essid hex "Corp">
        let line = "WPA*01*0123456789abcdef0123456789abcdef*aabbccddeeff*112233445566*436f7270";
        let c = parse_hc22000_line(line).unwrap();
        assert_eq!(c.kind, CaptureKind::Pmkid);
        assert_eq!(c.bssid.as_deref(), Some("aa:bb:cc:dd:ee:ff"));
        assert_eq!(c.essid.as_deref(), Some("Corp"));
        assert_eq!(c.hashcat_mode, 22000);
    }

    #[test]
    fn audit_requires_authorization() {
        let caps = parse_captures("WPA*02*aa*bbccddeeff00*112233445566*4e6574");
        assert_eq!(plan_audit(&caps, "h.22000", "rockyou.txt", false), Err(WifiError::NotAuthorized));
        let plan = plan_audit(&caps, "h.22000", "rockyou.txt", true).unwrap();
        assert!(plan.hashcat_args.windows(2).any(|w| w == ["-m", "22000"]));
    }
}
