//! Red Team module — authorized adversary-emulation planning (Phase 3).
//!
//! Offline, deterministic: a curated MITRE ATT&CK technique catalog subset, an
//! emulation-plan builder that sequences techniques into phases, and
//! evidence-to-technique mapping for reporting. No execution, no C2, no tooling
//! orchestration happens here — operations run only under explicit authorization
//! through gated adapters. This is the planning/reporting half.

use serde::{Deserialize, Serialize};

/// A MITRE ATT&CK tactic (kill-chain phase).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Tactic {
    Reconnaissance,
    InitialAccess,
    Execution,
    Persistence,
    PrivilegeEscalation,
    DefenseEvasion,
    CredentialAccess,
    Discovery,
    LateralMovement,
    Collection,
    Exfiltration,
    Impact,
}

/// An ATT&CK technique entry.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Technique {
    pub id: String, // e.g. T1078
    pub name: String,
    pub tactic: Tactic,
    pub detection_hint: String,
}

/// A curated subset of ATT&CK techniques for emulation planning.
pub fn technique_catalog() -> Vec<Technique> {
    use Tactic::*;
    let t = |id: &str, name: &str, tactic: Tactic, det: &str| Technique { id: id.into(), name: name.into(), tactic, detection_hint: det.into() };
    vec![
        t("T1595", "Active Scanning", Reconnaissance, "IDS on scan patterns; rate anomalies"),
        t("T1190", "Exploit Public-Facing Application", InitialAccess, "WAF/app logs; anomalous payloads"),
        t("T1566", "Phishing", InitialAccess, "Mail gateway; user reporting"),
        t("T1059", "Command and Scripting Interpreter", Execution, "EDR process/command-line logging"),
        t("T1053", "Scheduled Task/Job", Persistence, "Task creation auditing"),
        t("T1547", "Boot or Logon Autostart Execution", Persistence, "Autorun key monitoring"),
        t("T1068", "Exploitation for Privilege Escalation", PrivilegeEscalation, "Kernel/EDR telemetry"),
        t("T1055", "Process Injection", DefenseEvasion, "EDR memory telemetry"),
        t("T1003", "OS Credential Dumping", CredentialAccess, "LSASS access auditing"),
        t("T1558", "Steal or Forge Kerberos Tickets", CredentialAccess, "Kerberoast/TGS request anomalies"),
        t("T1087", "Account Discovery", Discovery, "LDAP query auditing"),
        t("T1021", "Remote Services", LateralMovement, "Auth logs; lateral SMB/RDP"),
        t("T1005", "Data from Local System", Collection, "File access auditing"),
        t("T1048", "Exfiltration Over Alternative Protocol", Exfiltration, "Egress/DNS monitoring"),
        t("T1486", "Data Encrypted for Impact", Impact, "Mass file-change detection"),
    ]
}

/// Look up a technique by ATT&CK ID.
pub fn technique(id: &str) -> Option<Technique> {
    technique_catalog().into_iter().find(|t| t.id.eq_ignore_ascii_case(id))
}

/// A step in an emulation plan.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PlanStep {
    pub order: usize,
    pub tactic: Tactic,
    pub technique: Technique,
    pub objective: String,
}

/// An authorized emulation plan, ordered by kill-chain phase.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EmulationPlan {
    pub name: String,
    pub authorized: bool,
    pub steps: Vec<PlanStep>,
    pub attack_ids: Vec<String>,
}

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum RedTeamError {
    #[error("authorization required to build an emulation plan")]
    NotAuthorized,
    #[error("unknown technique: {0}")]
    UnknownTechnique(String),
}

/// Build an emulation plan from a set of ATT&CK technique IDs, ordered by
/// tactic. Refused unless `authorized` is true.
pub fn build_plan(name: &str, technique_ids: &[String], objective: &str, authorized: bool) -> Result<EmulationPlan, RedTeamError> {
    if !authorized {
        return Err(RedTeamError::NotAuthorized);
    }
    let mut techs = Vec::new();
    for id in technique_ids {
        techs.push(technique(id).ok_or_else(|| RedTeamError::UnknownTechnique(id.clone()))?);
    }
    techs.sort_by(|a, b| a.tactic.cmp(&b.tactic));
    let steps: Vec<PlanStep> = techs
        .iter()
        .enumerate()
        .map(|(i, t)| PlanStep { order: i + 1, tactic: t.tactic, technique: t.clone(), objective: objective.to_string() })
        .collect();
    Ok(EmulationPlan {
        name: name.to_string(),
        authorized,
        attack_ids: techs.iter().map(|t| t.id.clone()).collect(),
        steps,
    })
}

/// Evidence mapped to an ATT&CK technique for the report's narrative/coverage.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TechniqueEvidence {
    pub technique_id: String,
    pub technique_name: String,
    pub tactic: Tactic,
    pub evidence: String,
}

/// Map a free-text evidence note to a technique (by ID) for reporting.
pub fn map_evidence(technique_id: &str, evidence: &str) -> Result<TechniqueEvidence, RedTeamError> {
    let t = technique(technique_id).ok_or_else(|| RedTeamError::UnknownTechnique(technique_id.into()))?;
    Ok(TechniqueEvidence { technique_id: t.id, technique_name: t.name, tactic: t.tactic, evidence: evidence.to_string() })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn catalog_and_lookup() {
        assert!(technique_catalog().len() >= 15);
        assert_eq!(technique("T1003").unwrap().name, "OS Credential Dumping");
        assert!(technique("T9999").is_none());
    }

    #[test]
    fn plan_requires_authorization_and_orders_by_tactic() {
        let ids = vec!["T1048".into(), "T1190".into(), "T1003".into()];
        assert_eq!(build_plan("op", &ids, "goal", false), Err(RedTeamError::NotAuthorized));
        let plan = build_plan("op", &ids, "goal", true).unwrap();
        // Initial Access (T1190) should come before Credential Access (T1003) before Exfiltration (T1048).
        assert_eq!(plan.steps[0].technique.id, "T1190");
        assert_eq!(plan.steps.last().unwrap().technique.id, "T1048");
    }

    #[test]
    fn unknown_technique_errors() {
        assert!(matches!(build_plan("op", &["T0000".into()], "g", true), Err(RedTeamError::UnknownTechnique(_))));
    }

    #[test]
    fn evidence_mapping() {
        let e = map_evidence("T1558", "Obtained TGS for MSSQLSvc and cracked offline").unwrap();
        assert_eq!(e.tactic, Tactic::CredentialAccess);
    }
}
