//! Mobile module — offline Android manifest analysis (Phase 3, MASTG/MASVS).
//!
//! Deterministic, offline parsing of an `AndroidManifest.xml` (text form) for
//! common MASVS-relevant weaknesses: dangerous permissions, exported components
//! without permission, debuggable/backup flags, and cleartext traffic. Produces
//! normalized observations with MASVS references for the checklist/report.
//! Dynamic/runtime mobile testing is tool/device dependent and imported via the
//! adapter framework (e.g. MobSF); it is not performed here.

use serde::{Deserialize, Serialize};

/// A mobile static-analysis observation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MobileObservation {
    pub check: String,
    pub masvs: String,
    pub severity: String, // info/low/medium/high
    pub detail: String,
}

fn obs(check: &str, masvs: &str, sev: &str, detail: impl Into<String>) -> MobileObservation {
    MobileObservation { check: check.into(), masvs: masvs.into(), severity: sev.into(), detail: detail.into() }
}

/// Dangerous Android permissions worth flagging for review.
fn dangerous_permissions() -> &'static [&'static str] {
    &[
        "READ_SMS", "SEND_SMS", "RECEIVE_SMS", "READ_CONTACTS", "WRITE_CONTACTS",
        "ACCESS_FINE_LOCATION", "ACCESS_BACKGROUND_LOCATION", "RECORD_AUDIO", "CAMERA",
        "READ_EXTERNAL_STORAGE", "WRITE_EXTERNAL_STORAGE", "READ_CALL_LOG", "READ_PHONE_STATE",
        "REQUEST_INSTALL_PACKAGES", "SYSTEM_ALERT_WINDOW",
    ]
}

fn find_tags<'a>(xml: &'a str, tag: &str) -> Vec<&'a str> {
    let open = format!("<{tag}");
    let mut out = Vec::new();
    let mut i = 0;
    while let Some(p) = xml[i..].find(&open) {
        let start = i + p;
        let end = xml[start..].find('>').map(|e| start + e + 1).unwrap_or(xml.len());
        out.push(&xml[start..end]);
        i = end;
    }
    out
}

fn attr<'a>(tag: &'a str, name: &str) -> Option<&'a str> {
    let key = format!("{name}=\"");
    let p = tag.find(&key)? + key.len();
    let rest = &tag[p..];
    let end = rest.find('"')?;
    Some(&rest[..end])
}

/// Analyze an AndroidManifest.xml (text) for MASVS-relevant issues.
pub fn analyze_android_manifest(xml: &str) -> Vec<MobileObservation> {
    let mut out = Vec::new();

    // Permissions.
    for t in find_tags(xml, "uses-permission") {
        if let Some(name) = attr(t, "android:name") {
            let short = name.rsplit('.').next().unwrap_or(name);
            if dangerous_permissions().contains(&short) {
                out.push(obs("Dangerous permission", "MASVS-PLATFORM-1", "low", format!("Requests dangerous permission: {short}")));
            }
        }
    }

    // application-level flags.
    for app in find_tags(xml, "application") {
        if attr(app, "android:debuggable") == Some("true") {
            out.push(obs("Debuggable application", "MASVS-RESILIENCE-2", "high", "android:debuggable=\"true\" ships a debuggable build."));
        }
        match attr(app, "android:allowBackup") {
            Some("true") | None => out.push(obs("Backups allowed", "MASVS-STORAGE-2", "medium", "android:allowBackup is true/unset — app data can be extracted via adb backup.")),
            _ => {}
        }
        if attr(app, "android:usesCleartextTraffic") == Some("true") {
            out.push(obs("Cleartext traffic allowed", "MASVS-NETWORK-1", "high", "android:usesCleartextTraffic=\"true\" permits unencrypted HTTP."));
        }
    }

    // Exported components without a permission guard.
    for comp in ["activity", "service", "receiver", "provider"] {
        for t in find_tags(xml, comp) {
            let exported = attr(t, "android:exported");
            let has_perm = attr(t, "android:permission").is_some();
            // Exported=true (or a provider defaulting exported) without a permission is risky.
            if exported == Some("true") && !has_perm {
                let name = attr(t, "android:name").unwrap_or("<unnamed>");
                out.push(obs(
                    "Exported component without permission",
                    "MASVS-PLATFORM-1",
                    if comp == "provider" { "high" } else { "medium" },
                    format!("Exported {comp} '{name}' has no android:permission guard — reachable by other apps."),
                ));
            }
        }
    }

    out
}

/// Count observations by severity for a quick summary.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct MobileSummary {
    pub total: usize,
    pub high: usize,
    pub medium: usize,
    pub low: usize,
}

pub fn summarize(obs: &[MobileObservation]) -> MobileSummary {
    let mut s = MobileSummary { total: obs.len(), ..Default::default() };
    for o in obs {
        match o.severity.as_str() {
            "high" => s.high += 1,
            "medium" => s.medium += 1,
            "low" => s.low += 1,
            _ => {}
        }
    }
    s
}

#[cfg(test)]
mod tests {
    use super::*;

    const MANIFEST: &str = r#"
        <manifest xmlns:android="http://schemas.android.com/apk/res/android">
          <uses-permission android:name="android.permission.READ_SMS"/>
          <uses-permission android:name="android.permission.INTERNET"/>
          <application android:debuggable="true" android:allowBackup="true" android:usesCleartextTraffic="true">
            <activity android:name=".Main" android:exported="true"/>
            <provider android:name=".Data" android:exported="true"/>
            <service android:name=".Safe" android:exported="true" android:permission="x.PERM"/>
          </application>
        </manifest>
    "#;

    #[test]
    fn flags_dangerous_permission() {
        let o = analyze_android_manifest(MANIFEST);
        assert!(o.iter().any(|x| x.check == "Dangerous permission" && x.detail.contains("READ_SMS")));
        // INTERNET is not dangerous -> not flagged.
        assert!(!o.iter().any(|x| x.detail.contains("INTERNET")));
    }

    #[test]
    fn flags_app_flags() {
        let o = analyze_android_manifest(MANIFEST);
        assert!(o.iter().any(|x| x.check == "Debuggable application" && x.severity == "high"));
        assert!(o.iter().any(|x| x.check == "Backups allowed"));
        assert!(o.iter().any(|x| x.check == "Cleartext traffic allowed"));
    }

    #[test]
    fn flags_exported_without_permission_but_not_guarded() {
        let o = analyze_android_manifest(MANIFEST);
        assert!(o.iter().any(|x| x.check.contains("Exported") && x.detail.contains("provider") && x.severity == "high"));
        assert!(o.iter().any(|x| x.detail.contains("activity")));
        // The service has a permission guard -> not flagged.
        assert!(!o.iter().any(|x| x.detail.contains("'.Safe'")));
    }

    #[test]
    fn summary() {
        let s = summarize(&analyze_android_manifest(MANIFEST));
        assert!(s.total >= 5 && s.high >= 2);
    }
}
