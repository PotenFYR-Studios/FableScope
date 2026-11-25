#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

use fs_ai::provider_from_config;
use fs_checklists::{builtin_templates, builtin_web_minimal, instantiate};
use fs_config::WorkspaceConfig;
use fs_core::{builtin_adapters, builtin_modules, Project, ScopePolicy, Severity};
use fs_recon::{
    apply_filters, cloud, enrich_results, generate_fuzz_targets, generate_smart_fuzz_targets, group,
    mutators, probe_urls, subdomain, Filter, GroupBy, ReconConfig,
};
use fs_reporting::{calculate_cvss_v31, render_enterprise_html, render_report_csv, render_report_html, render_report_json, render_report_markdown, render_report_sarif_like};
use fs_storage::Storage;
use fs_tools::{codec, credential_audit, hashid, password, ToolBundleSource, ToolKind, ToolManager, ToolManifest, ToolRunRequest};
use fs_wordlists::{builtin_packs, WordlistRegistry};
use std::collections::BTreeMap;
use std::path::PathBuf;
use std::sync::Mutex;
use tauri::{Manager, State};

struct AppState {
    db_path: PathBuf,
}

impl AppState {
    fn storage(&self) -> Result<Storage, String> {
        Storage::open(&self.db_path).map_err(|e| e.to_string())
    }
}

#[tauri::command]
fn get_default_config() -> WorkspaceConfig {
    WorkspaceConfig::default()
}

#[tauri::command]
fn health() -> &'static str {
    "ok"
}

#[tauri::command]
fn app_info(state: State<'_, Mutex<AppState>>) -> Result<serde_json::Value, String> {
    let st = state.lock().map_err(|_| "state lock")?;
    Ok(serde_json::json!({ "db_path": st.db_path, "modules": builtin_modules() }))
}

#[tauri::command]
fn dashboard_stats(project_id: Option<String>, state: State<'_, Mutex<AppState>>) -> Result<serde_json::Value, String> {
    let st = state.lock().map_err(|_| "state lock")?;
    let s = st.storage()?;
    let pid = project_id.as_deref();
    Ok(serde_json::json!({
        "projects": s.count_table("projects", None).map_err(|e| e.to_string())?,
        "jobs": s.count_table("jobs", pid).map_err(|e| e.to_string())?,
        "findings": s.count_table("findings", pid).map_err(|e| e.to_string())?,
        "checklist_items": s.count_table("checklist_items", pid).map_err(|e| e.to_string())?,
        "tool_runs": s.count_table("tool_runs", None).map_err(|e| e.to_string())?,
        "audit_log": s.count_table("audit_log", None).map_err(|e| e.to_string())?,
        "recon_results": s.count_table("recon_results", pid).map_err(|e| e.to_string())?,
        "wordlist_packs": s.count_table("wordlist_packs", None).map_err(|e| e.to_string())?,
    }))
}

#[tauri::command]
fn list_jobs(project_id: Option<String>, state: State<'_, Mutex<AppState>>) -> Result<serde_json::Value, String> {
    let st = state.lock().map_err(|_| "state lock")?;
    let s = st.storage()?;
    let jobs = s.list_jobs(project_id.as_deref(), 100).map_err(|e| e.to_string())?;
    serde_json::to_value(jobs).map_err(|e| e.to_string())
}

#[tauri::command]
fn create_job(project_id: String, kind: String, state: State<'_, Mutex<AppState>>) -> Result<serde_json::Value, String> {
    let st = state.lock().map_err(|_| "state lock")?;
    let s = st.storage()?;
    let pid = uuid::Uuid::parse_str(&project_id).map_err(|e| e.to_string())?;
    let job = fs_core::Job::new(pid, kind);
    s.save_job(&job).map_err(|e| e.to_string())?;
    serde_json::to_value(job).map_err(|e| e.to_string())
}

#[tauri::command]
fn list_modules() -> serde_json::Value { serde_json::to_value(builtin_modules()).unwrap_or(serde_json::json!([])) }

#[tauri::command]
fn list_adapters(module: Option<String>, state: State<'_, Mutex<AppState>>) -> Result<serde_json::Value, String> {
    let st = state.lock().map_err(|_| "state lock")?; let s = st.storage()?;
    let existing = s.list_adapters(module.as_deref()).map_err(|e| e.to_string())?;
    if existing.is_empty() && module.is_none() {
        for a in builtin_adapters() { let _ = s.upsert_adapter(&serde_json::to_value(a).unwrap()); }
        let seeded = s.list_adapters(None).map_err(|e| e.to_string())?;
        return Ok(serde_json::json!(seeded));
    }
    Ok(serde_json::json!(existing))
}

#[tauri::command]
fn upsert_adapter(adapter_json: String, state: State<'_, Mutex<AppState>>) -> Result<serde_json::Value, String> {
    let st = state.lock().map_err(|_| "state lock")?; let s = st.storage()?;
    let v: serde_json::Value = serde_json::from_str(&adapter_json).map_err(|e| e.to_string())?;
    s.upsert_adapter(&v).map_err(|e| e.to_string())?;
    Ok(serde_json::json!({"ok": true}))
}

#[tauri::command]
fn list_assets(project_id: String, state: State<'_, Mutex<AppState>>) -> Result<serde_json::Value, String> {
    let st = state.lock().map_err(|_| "state lock")?; let s = st.storage()?;
    let rows = s.list_assets(&project_id, 500).map_err(|e| e.to_string())?;
    serde_json::to_value(rows).map_err(|e| e.to_string())
}

#[tauri::command]
fn list_checklist_templates() -> serde_json::Value {
    serde_json::to_value(builtin_templates()).unwrap_or(serde_json::json!([]))
}

#[tauri::command]
fn seed_checklist_template(project_id: String, template_id: String, state: State<'_, Mutex<AppState>>) -> Result<serde_json::Value, String> {
    let st = state.lock().map_err(|_| "state lock")?;
    let s = st.storage()?;
    let pid = uuid::Uuid::parse_str(&project_id).map_err(|e| e.to_string())?;
    let t = builtin_templates().into_iter().find(|t| t.id == template_id).ok_or("template not found")?;
    let items = instantiate(&t, pid);
    for i in &items { s.save_checklist_item(i).map_err(|e| e.to_string())?; }
    Ok(serde_json::json!({"seeded": items.len(), "template_id": template_id}))
}

#[tauri::command]
fn list_projects(state: State<'_, Mutex<AppState>>) -> Result<serde_json::Value, String> {
    let st = state.lock().map_err(|_| "state lock")?;
    let s = st.storage()?;
    let projects = s.list_projects().map_err(|e| e.to_string())?;
    serde_json::to_value(projects).map_err(|e| e.to_string())
}

#[tauri::command]
fn create_project(name: String, state: State<'_, Mutex<AppState>>) -> Result<serde_json::Value, String> {
    let st = state.lock().map_err(|_| "state lock")?;
    let s = st.storage()?;
    let p = Project::new(name).map_err(|e| e.to_string())?;
    s.save_project(&p).map_err(|e| e.to_string())?;

    // Seed default checklist for quick start
    let template = builtin_web_minimal();
    for item in instantiate(&template, p.id) {
        s.save_checklist_item(&item).map_err(|e| e.to_string())?;
    }
    serde_json::to_value(p).map_err(|e| e.to_string())
}

#[tauri::command]
fn list_checklist(project_id: String, state: State<'_, Mutex<AppState>>) -> Result<serde_json::Value, String> {
    let st = state.lock().map_err(|_| "state lock")?;
    let s = st.storage()?;
    let items = s.list_checklist_items(&project_id).map_err(|e| e.to_string())?;
    serde_json::to_value(items).map_err(|e| e.to_string())
}

#[tauri::command]
fn update_checklist_item(project_id: String, check_id: String, status: String, notes: Option<String>, state: State<'_, Mutex<AppState>>) -> Result<serde_json::Value, String> {
    let status = match status.as_str() {
        "not_started" => fs_core::CheckStatus::NotStarted,
        "in_progress" => fs_core::CheckStatus::InProgress,
        "pass" => fs_core::CheckStatus::Pass,
        "fail" => fs_core::CheckStatus::Fail,
        "potential" => fs_core::CheckStatus::Potential,
        "false_positive" => fs_core::CheckStatus::FalsePositive,
        "not_applicable" => fs_core::CheckStatus::NotApplicable,
        "blocked" => fs_core::CheckStatus::Blocked,
        _ => return Err("invalid status".into()),
    };
    let st = state.lock().map_err(|_| "state lock")?;
    let s = st.storage()?;
    let item = s.update_checklist_status(&project_id, &check_id, status, notes).map_err(|e| e.to_string())?;
    serde_json::to_value(item).map_err(|e| e.to_string())
}

#[tauri::command]
fn get_config(state: State<'_, Mutex<AppState>>) -> Result<WorkspaceConfig, String> {
    let st = state.lock().map_err(|_| "state lock")?;
    let s = st.storage()?;
    if let Some(cfg) = s.latest_config().map_err(|e| e.to_string())? {
        return Ok(cfg);
    }
    let cfg = WorkspaceConfig::default();
    s.save_config_snapshot(&cfg).map_err(|e| e.to_string())?;
    Ok(cfg)
}

#[tauri::command]
fn save_config(config_json: String, state: State<'_, Mutex<AppState>>) -> Result<WorkspaceConfig, String> {
    let cfg = WorkspaceConfig::from_json(&config_json).map_err(|e| e.to_string())?;
    let st = state.lock().map_err(|_| "state lock")?;
    let s = st.storage()?;
    s.save_config_snapshot(&cfg).map_err(|e| e.to_string())?;
    Ok(cfg)
}

fn builtin_manifests() -> Vec<ToolManifest> {
    let mut nuclei_profiles = BTreeMap::new();
    nuclei_profiles.insert("safe".into(), fs_tools::ToolProfile { id:"safe".into(), name:"Safe".into(), description:"Safe templates".into(), args:vec!["-severity".into(),"low,medium,high,critical".into()], checklist_ids:vec!["FS-WEB-002".into(),"FS-WEB-004".into()], risk_tier:"low".into(), template_ids:vec![] });
    vec![
        ToolManifest { id: "nikto".into(), name: "Nikto".into(), version: "managed".into(), kind: ToolKind::PortableBundle, executable: if cfg!(windows) { "nikto.exe".into() } else { "nikto".into() }, bundle: ToolBundleSource { url: None, sha256: None, size_bytes: None, license: Some("GPL".into()), provenance: Some("builtin-managed".into()), format: None }, platform_bundles: BTreeMap::new(), supported_os: vec!["windows".into(),"linux".into(),"macos".into()], profiles: BTreeMap::new() },
        ToolManifest { id: "sqlmap".into(), name: "SQLMap".into(), version: "managed".into(), kind: ToolKind::PortableBundle, executable: if cfg!(windows) { "sqlmap.exe".into() } else { "sqlmap".into() }, bundle: ToolBundleSource { url: None, sha256: None, size_bytes: None, license: Some("GPLv2".into()), provenance: Some("builtin-managed".into()), format: None }, platform_bundles: BTreeMap::new(), supported_os: vec!["windows".into(),"linux".into(),"macos".into()], profiles: BTreeMap::new() },
        ToolManifest { id: "nuclei".into(), name: "Nuclei".into(), version: "managed".into(), kind: ToolKind::PortableBundle, executable: if cfg!(windows) { "nuclei.exe".into() } else { "nuclei".into() }, bundle: ToolBundleSource { url: None, sha256: None, size_bytes: None, license: Some("MIT".into()), provenance: Some("builtin-managed".into()), format: None }, platform_bundles: BTreeMap::new(), supported_os: vec!["windows".into(),"linux".into(),"macos".into()], profiles: nuclei_profiles },
        ToolManifest { id: "nmap".into(), name: "Nmap".into(), version: "managed".into(), kind: ToolKind::PortableBundle, executable: if cfg!(windows) { "nmap.exe".into() } else { "nmap".into() }, bundle: ToolBundleSource { url: None, sha256: None, size_bytes: None, license: Some("Nmap".into()), provenance: Some("builtin-managed".into()), format: None }, platform_bundles: BTreeMap::new(), supported_os: vec!["windows".into(),"linux".into(),"macos".into()], profiles: BTreeMap::new() },
        ToolManifest { id: "rustscan".into(), name: "RustScan".into(), version: "managed".into(), kind: ToolKind::PortableBundle, executable: if cfg!(windows) { "rustscan.exe".into() } else { "rustscan".into() }, bundle: ToolBundleSource { url: None, sha256: None, size_bytes: None, license: Some("GPL".into()), provenance: Some("builtin-managed".into()), format: None }, platform_bundles: BTreeMap::new(), supported_os: vec!["windows".into(),"linux".into(),"macos".into()], profiles: BTreeMap::new() },
        ToolManifest { id: "hashcat".into(), name: "Hashcat".into(), version: "managed".into(), kind: ToolKind::PortableBundle, executable: if cfg!(windows) { "hashcat.exe".into() } else { "hashcat".into() }, bundle: ToolBundleSource { url: None, sha256: None, size_bytes: None, license: Some("MIT".into()), provenance: Some("builtin-managed; authorized credential audit only".into()), format: None }, platform_bundles: BTreeMap::new(), supported_os: vec!["windows".into(),"linux".into(),"macos".into()], profiles: BTreeMap::new() },
        ToolManifest { id: "john".into(), name: "John the Ripper".into(), version: "managed".into(), kind: ToolKind::PortableBundle, executable: if cfg!(windows) { "john.exe".into() } else { "john".into() }, bundle: ToolBundleSource { url: None, sha256: None, size_bytes: None, license: Some("GPLv2".into()), provenance: Some("builtin-managed; authorized credential audit only".into()), format: None }, platform_bundles: BTreeMap::new(), supported_os: vec!["windows".into(),"linux".into(),"macos".into()], profiles: BTreeMap::new() },
    ]
}

fn tool_manager(app: &tauri::AppHandle) -> Result<ToolManager, String> {
    let dir = app.path().app_data_dir().map_err(|e| e.to_string())?;
    let tools_dir = dir.join("tools");
    let artifacts_dir = dir.join("artifacts");
    std::fs::create_dir_all(&tools_dir).map_err(|e| e.to_string())?;
    std::fs::create_dir_all(&artifacts_dir).map_err(|e| e.to_string())?;
    let mut mgr = ToolManager::new(tools_dir, artifacts_dir);
    for m in builtin_manifests() { let _ = mgr.register(m); }

    let manifest_path = dir.join("tool-manifests.json");
    if manifest_path.exists() {
        if let Ok(text) = std::fs::read_to_string(&manifest_path) {
            if let Ok(custom) = serde_json::from_str::<Vec<ToolManifest>>(&text) {
                for m in custom { let _ = mgr.register(m); } // overrides by id
            }
        }
    }
    Ok(mgr)
}

#[tauri::command]
async fn list_tools(app: tauri::AppHandle) -> Result<serde_json::Value, String> {
    let mut mgr = tool_manager(&app)?;
    let ids: Vec<String> = mgr.list().iter().map(|r| r.manifest.id.clone()).collect();
    let mut out = Vec::new();
    for id in ids { out.push(mgr.detect(&id).await.map_err(|e| e.to_string())?); }
    serde_json::to_value(out).map_err(|e| e.to_string())
}

#[tauri::command]
async fn provision_tool(tool_id: String, app: tauri::AppHandle) -> Result<serde_json::Value, String> {
    let mut mgr = tool_manager(&app)?;
    let rec = mgr.provision(&tool_id).await.map_err(|e| e.to_string())?;
    serde_json::to_value(rec).map_err(|e| e.to_string())
}

#[tauri::command]
fn export_tool_manifests(app: tauri::AppHandle) -> Result<serde_json::Value, String> {
    let mgr = tool_manager(&app)?;
    let manifests: Vec<_> = mgr.list().into_iter().map(|r| r.manifest).collect();
    serde_json::to_value(manifests).map_err(|e| e.to_string())
}

#[tauri::command]
fn import_tool_manifests(manifests_json: String, app: tauri::AppHandle) -> Result<serde_json::Value, String> {
    let manifests: Vec<ToolManifest> = serde_json::from_str(&manifests_json).map_err(|e| e.to_string())?;
    for m in &manifests { m.validate().map_err(|e| e.to_string())?; }
    let dir = app.path().app_data_dir().map_err(|e| e.to_string())?;
    std::fs::create_dir_all(&dir).map_err(|e| e.to_string())?;
    let path = dir.join("tool-manifests.json");
    std::fs::write(&path, serde_json::to_string_pretty(&manifests).map_err(|e| e.to_string())?).map_err(|e| e.to_string())?;
    Ok(serde_json::json!({"saved": path, "count": manifests.len()}))
}

#[tauri::command]
async fn run_tool(tool_id: String, args: Vec<String>, profile: Option<String>, project_id: Option<String>, check_id: Option<String>, app: tauri::AppHandle, state: State<'_, Mutex<AppState>>) -> Result<serde_json::Value, String> {
    let mut mgr = tool_manager(&app)?;
    let rec = mgr.detect(&tool_id).await.map_err(|e| e.to_string())?;
    let bundle = mgr.effective_bundle(&rec.manifest);
    if rec.status == fs_tools::ToolStatus::Missing && bundle.url.is_some() {
        mgr.provision(&tool_id).await.map_err(|e| e.to_string())?;
    }
    let pid = project_id.as_ref().and_then(|s| uuid::Uuid::parse_str(s).ok());
    let correlation_id = Some(format!("corr-{}", uuid::Uuid::new_v4()));
    let result = mgr.run(ToolRunRequest {
        tool_id: tool_id.clone(),
        profile,
        args,
        project_id: pid,
        check_id: check_id.clone(),
        correlation_id: correlation_id.clone(),
        cwd: None,
        timeout_ms: 30_000,
        env: BTreeMap::new(),
    }).await.map_err(|e| e.to_string())?;

    let st = state.lock().map_err(|_| "state lock")?;
    let s = st.storage()?;
    s.save_tool_run(&result).map_err(|e| e.to_string())?;
    if let (Some(pid_str), Some(cid)) = (project_id.clone(), check_id.clone()) {
        let status = if result.status == 0 { fs_core::CheckStatus::InProgress } else { fs_core::CheckStatus::Blocked };
        let note = format!("tool={} run={} status={} corr={}", result.tool_id, result.run_id, result.status, result.correlation_id.clone().unwrap_or_default());
        let _ = s.update_checklist_status(&pid_str, &cid, status, Some(note));
        let mut meta = BTreeMap::new();
        meta.insert("tool_id".into(), serde_json::json!(result.tool_id));
        meta.insert("run_id".into(), serde_json::json!(result.run_id));
        meta.insert("correlation_id".into(), serde_json::json!(result.correlation_id));
        meta.insert("status".into(), serde_json::json!(result.status));
        let ev = fs_core::EvidenceRef {
            id: uuid::Uuid::new_v4(),
            kind: "command_output".into(),
            path: Some(result.artifact_dir.to_string_lossy().to_string()),
            hash: None,
            caption: Some(format!("{} run {}", result.tool_id, result.run_id)),
            created_at: chrono::Utc::now(),
            metadata: meta,
        };
        let _ = s.append_checklist_evidence(&pid_str, &cid, ev);

        if result.status != 0 {
            let pid = uuid::Uuid::parse_str(&pid_str).map_err(|e| e.to_string())?;
            let mut f = fs_core::Finding::new(pid, format!("Tool failure: {} on {}", result.tool_id, cid), Severity::Info).map_err(|e| e.to_string())?;
            f.status = Some("tool_error".into());
            f.source_check_id = Some(cid.clone());
            f.source_tool_run_id = Some(result.run_id);
            f.correlation_id = result.correlation_id.clone();
            f.description = format!("Tool exited with status {}. See artifact_dir.", result.status);
            f.evidence.insert("artifact_dir".into(), serde_json::json!(result.artifact_dir));
            f.evidence.insert("stderr".into(), serde_json::json!(result.stderr));
            let _ = s.save_finding(&f);
        }
    }
    serde_json::to_value(result).map_err(|e| e.to_string())
}

#[tauri::command]
fn list_tool_runs(state: State<'_, Mutex<AppState>>) -> Result<serde_json::Value, String> {
    let st = state.lock().map_err(|_| "state lock")?;
    let s = st.storage()?;
    let runs = s.list_tool_runs(50).map_err(|e| e.to_string())?;
    serde_json::to_value(runs).map_err(|e| e.to_string())
}

#[tauri::command]
fn list_audit(state: State<'_, Mutex<AppState>>) -> Result<serde_json::Value, String> {
    let st = state.lock().map_err(|_| "state lock")?;
    let s = st.storage()?;
    let logs = s.list_audit(100).map_err(|e| e.to_string())?;
    serde_json::to_value(logs).map_err(|e| e.to_string())
}

#[tauri::command]
fn list_findings(project_id: String, state: State<'_, Mutex<AppState>>) -> Result<serde_json::Value, String> {
    let st = state.lock().map_err(|_| "state lock")?;
    let s = st.storage()?;
    let rows = s.list_findings(&project_id).map_err(|e| e.to_string())?;
    serde_json::to_value(rows).map_err(|e| e.to_string())
}

#[tauri::command]
fn promote_check_to_finding(project_id: String, check_id: String, severity: String, title: Option<String>, state: State<'_, Mutex<AppState>>) -> Result<serde_json::Value, String> {
    let st = state.lock().map_err(|_| "state lock")?;
    let s = st.storage()?;
    let item = s.get_checklist_item(&project_id, &check_id).map_err(|e| e.to_string())?;
    let sev = match severity.as_str() {
        "info" => Severity::Info, "low" => Severity::Low, "medium" => Severity::Medium, "high" => Severity::High, "critical" => Severity::Critical,
        _ => return Err("invalid severity".into()),
    };
    let pid = uuid::Uuid::parse_str(&project_id).map_err(|e| e.to_string())?;
    let mut f = fs_core::Finding::new(pid, title.unwrap_or_else(|| format!("{} - {}", item.check_id, item.title)), sev).map_err(|e| e.to_string())?;
    f.description = item.notes.clone().unwrap_or_default();
    f.source_check_id = Some(item.check_id.clone());
    f.status = Some("confirmed".into());
    f.confidence = item.confidence;
    f.evidence.insert("check_id".into(), serde_json::json!(item.check_id));
    f.evidence.insert("status".into(), serde_json::json!(item.status));
    f.evidence.insert("evidence_refs".into(), serde_json::to_value(&item.evidence).unwrap_or(serde_json::json!([])));
    s.save_finding(&f).map_err(|e| e.to_string())?;
    let mut updated_item = item.clone();
    updated_item.finding_id = Some(f.id);
    updated_item.updated_at = chrono::Utc::now();
    s.save_checklist_item(&updated_item).map_err(|e| e.to_string())?;
    serde_json::to_value(f).map_err(|e| e.to_string())
}

#[tauri::command]
fn save_scope(project_id: String, allow: Vec<String>, deny: Vec<String>, state: State<'_, Mutex<AppState>>) -> Result<serde_json::Value, String> {
    let st = state.lock().map_err(|_| "state lock")?;
    let s = st.storage()?;
    let scope = ScopePolicy { allow, deny };
    s.save_scope(&project_id, &scope).map_err(|e| e.to_string())?;
    serde_json::to_value(scope).map_err(|e| e.to_string())
}

#[tauri::command]
fn get_scope(project_id: String, state: State<'_, Mutex<AppState>>) -> Result<serde_json::Value, String> {
    let st = state.lock().map_err(|_| "state lock")?;
    let s = st.storage()?;
    let scope = s.get_scope(&project_id).map_err(|e| e.to_string())?.unwrap_or_default();
    serde_json::to_value(scope).map_err(|e| e.to_string())
}

#[tauri::command]
fn export_project(project_id: String, state: State<'_, Mutex<AppState>>) -> Result<serde_json::Value, String> {
    let st = state.lock().map_err(|_| "state lock")?;
    let s = st.storage()?;
    s.export_project_bundle(&project_id).map_err(|e| e.to_string())
}

#[tauri::command]
fn export_confirmed_checklist(project_id: String, state: State<'_, Mutex<AppState>>) -> Result<serde_json::Value, String> {
    let st = state.lock().map_err(|_| "state lock")?;
    let s = st.storage()?;
    s.export_confirmed_checklist(&project_id).map_err(|e| e.to_string())
}

#[tauri::command]
fn export_confirmed_checklist_csv(project_id: String, state: State<'_, Mutex<AppState>>) -> Result<String, String> {
    let st = state.lock().map_err(|_| "state lock")?;
    let s = st.storage()?;
    s.export_confirmed_checklist_csv(&project_id).map_err(|e| e.to_string())
}

#[tauri::command]
fn export_confirmed_checklist_html(project_id: String, state: State<'_, Mutex<AppState>>) -> Result<String, String> {
    let st = state.lock().map_err(|_| "state lock")?;
    let s = st.storage()?;
    s.export_confirmed_checklist_html(&project_id).map_err(|e| e.to_string())
}

#[tauri::command]
fn project_timeline(project_id: String, state: State<'_, Mutex<AppState>>) -> Result<serde_json::Value, String> {
    let st = state.lock().map_err(|_| "state lock")?;
    let s = st.storage()?;
    let rows = s.project_timeline(&project_id, 200).map_err(|e| e.to_string())?;
    serde_json::to_value(rows).map_err(|e| e.to_string())
}

#[tauri::command]
async fn probe_targets(project_id: Option<String>, targets: Vec<String>, allow: Vec<String>, deny: Vec<String>, state: State<'_, Mutex<AppState>>) -> Result<serde_json::Value, String> {
    let scope = ScopePolicy { allow, deny };
    let cfg = ReconConfig::default();
    let results = probe_urls(targets, &scope, &cfg).await.map_err(|e| e.to_string())?;
    let json = serde_json::to_value(&results).map_err(|e| e.to_string())?;
    if let Some(pid) = project_id.clone() {
        let st = state.lock().map_err(|_| "state lock")?;
        let s = st.storage()?;
        let arr = json.as_array().cloned().unwrap_or_default();
        let _ = s.save_recon_results(Some(&pid), "probe", &arr);
        for r in &arr {
            if let Some(url) = r.get("url").and_then(|v| v.as_str()) {
                let asset = serde_json::json!({"id":uuid::Uuid::new_v4().to_string(),"project_id":pid,"kind":"url","value":url,"source":"probe","created_at":chrono::Utc::now().to_rfc3339(),"meta":{"status":r.get("status")}});
                let _ = s.save_asset(&asset);
            }
        }
    }
    Ok(json)
}

#[tauri::command]
async fn fuzz_probe(project_id: Option<String>, base_url: String, words: Vec<String>, wordlist_pack: Option<String>, allow: Vec<String>, deny: Vec<String>, state: State<'_, Mutex<AppState>>) -> Result<serde_json::Value, String> {
    let scope = ScopePolicy { allow, deny };
    let mut all_words = words;
    if let Some(pack) = wordlist_pack {
        let packs = list_wordlist_packs(state.clone())?;
        if let Some(arr) = packs.as_array() {
            if let Some(p) = arr.iter().find(|p| p.get("name").and_then(|n| n.as_str()) == Some(pack.as_str())) {
                if let Some(ws) = p.get("words").and_then(|w| w.as_array()) {
                    all_words.extend(ws.iter().filter_map(|w| w.as_str().map(String::from)));
                }
            }
        }
    }
    all_words.sort(); all_words.dedup();
    let targets = generate_fuzz_targets(&base_url, &all_words, 300).map_err(|e| e.to_string())?;
    let cfg = ReconConfig::default();
    let results = probe_urls(targets, &scope, &cfg).await.map_err(|e| e.to_string())?;
    let json = serde_json::to_value(&results).map_err(|e| e.to_string())?;
    if let Some(pid) = project_id.clone() {
        let st = state.lock().map_err(|_| "state lock")?;
        let s = st.storage()?;
        let arr = json.as_array().cloned().unwrap_or_default();
        let _ = s.save_recon_results(Some(&pid), "fuzz_probe", &arr);
        for r in &arr {
            if let Some(url) = r.get("url").and_then(|v| v.as_str()) {
                let asset = serde_json::json!({"id":uuid::Uuid::new_v4().to_string(),"project_id":pid,"kind":"url","value":url,"source":"fuzz_probe","created_at":chrono::Utc::now().to_rfc3339(),"meta":{"status":r.get("status")}});
                let _ = s.save_asset(&asset);
            }
        }
    }
    Ok(json)
}

#[tauri::command]
fn list_recon_results(project_id: Option<String>, state: State<'_, Mutex<AppState>>) -> Result<serde_json::Value, String> {
    let st = state.lock().map_err(|_| "state lock")?;
    let s = st.storage()?;
    let rows = s.list_recon_results(project_id.as_deref(), 200).map_err(|e| e.to_string())?;
    serde_json::to_value(rows).map_err(|e| e.to_string())
}

#[tauri::command]
fn list_wordlist_packs(state: State<'_, Mutex<AppState>>) -> Result<serde_json::Value, String> {
    let mut packs = builtin_packs();
    let st = state.lock().map_err(|_| "state lock")?;
    let s = st.storage()?;
    let custom = s.list_wordlist_packs_db(200).map_err(|e| e.to_string())?;
    for v in custom {
        let name = v.get("name").and_then(|x| x.as_str()).unwrap_or("custom").to_string();
        let words = v.get("words").and_then(|x| x.as_array()).map(|a| a.iter().filter_map(|x| x.as_str().map(String::from)).collect()).unwrap_or_default();
        packs.push(fs_wordlists::WordlistPack { name, entries: vec![], words });
    }
    serde_json::to_value(packs).map_err(|e| e.to_string())
}

#[tauri::command]
fn save_wordlist_pack(pack_json: String, state: State<'_, Mutex<AppState>>) -> Result<serde_json::Value, String> {
    let v: serde_json::Value = serde_json::from_str(&pack_json).map_err(|e| e.to_string())?;
    let st = state.lock().map_err(|_| "state lock")?;
    let s = st.storage()?;
    s.save_wordlist_pack(&v).map_err(|e| e.to_string())?;
    Ok(serde_json::json!({"ok": true}))
}

#[tauri::command]
fn calc_cvss(vector: String) -> Result<serde_json::Value, String> {
    let score = calculate_cvss_v31(&vector).map_err(|e| e.to_string())?;
    serde_json::to_value(score).map_err(|e| e.to_string())
}

#[tauri::command]
fn export_project_report(project_id: String, format: String, state: State<'_, Mutex<AppState>>) -> Result<serde_json::Value, String> {
    let st = state.lock().map_err(|_| "state lock")?;
    let s = st.storage()?;
    let bundle = s.export_project_bundle(&project_id).map_err(|e| e.to_string())?;
    let project = bundle.get("project").and_then(|p| p.get("name")).and_then(|v| v.as_str()).unwrap_or(&project_id);
    let findings = bundle.get("findings").and_then(|v| v.as_array()).cloned().unwrap_or_default();
    let checklist = bundle.get("checklist_review").and_then(|v| v.as_array()).cloned().unwrap_or_default();
    let out = match format.as_str() {
        "json" => render_report_json(project, &findings, &checklist).to_string(),
        "md" | "markdown" => render_report_markdown(project, &findings),
        "html" => render_report_html(project, &findings, &checklist),
        "enterprise" => render_enterprise_html(project, &findings, &checklist),
        "csv" => render_report_csv(&findings),
        "sarif" => render_report_sarif_like(project, &findings).to_string(),
        _ => return Err("unsupported format; use json, md, html, enterprise, csv, or sarif".into()),
    };
    Ok(serde_json::json!({"format": format, "content": out}))
}

#[tauri::command]
async fn ai_complete(prompt: String, agent: Option<String>, state: State<'_, Mutex<AppState>>) -> Result<serde_json::Value, String> {
    let cfg = {
        let st = state.lock().map_err(|_| "state lock")?;
        let s = st.storage()?;
        s.latest_config().map_err(|e| e.to_string())?.unwrap_or_default()
    };
    let provider = provider_from_config(&cfg);
    let req = fs_ai::AiRequest { agent: agent.unwrap_or_else(|| "project".into()), prompt, context: serde_json::json!({}) };
    let resp = provider.complete(&req).await.map_err(|e| e.to_string())?;
    serde_json::to_value(resp).map_err(|e| e.to_string())
}

#[tauri::command]
async fn run_check(project_id: String, check_id: String, target: String, app: tauri::AppHandle, state: State<'_, Mutex<AppState>>) -> Result<serde_json::Value, String> {
    let scope = {
        let st = state.lock().map_err(|_| "state lock")?;
        let s = st.storage()?;
        s.get_scope(&project_id).map_err(|e| e.to_string())?.unwrap_or_default()
    };
    if !scope.allow.is_empty() || !scope.deny.is_empty() {
        scope.assert_allowed(&target).map_err(|e| e.to_string())?;
    }
    let tpl = fs_checklists::template_for_check(&check_id).ok_or_else(|| format!("unknown check_id: {check_id}"))?;
    let tool_id = tpl.default_tools.first().cloned().ok_or_else(|| "no default tool mapped".to_string())?;
    let args = match tool_id.as_str() {
        "nuclei" => vec!["-u".into(), target.clone(), "-severity".into(), "low,medium,high,critical".into()],
        "nikto" => vec!["-h".into(), target.clone()],
        "sqlmap" => vec!["-u".into(), target.clone(), "--batch".into(), "--level=1".into(), "--risk=1".into()],
        "nmap" => vec!["-sV".into(), target.clone()],
        _ => vec![target.clone()],
    };
    let profile = tpl.default_profiles.first().cloned();
    let run = run_tool(tool_id.clone(), args, profile, Some(project_id.clone()), Some(check_id.clone()), app, state).await?;
    Ok(serde_json::json!({"check_id": check_id, "tool_id": tool_id, "target": target, "run": run}))
}

// ---------------------------------------------------------------------------
// Phase 1: smart fuzzing, subdomain/cloud recon, triage, password gen, wordlist
// registry.
// ---------------------------------------------------------------------------

fn parse_strategies(names: Option<Vec<String>>) -> Vec<mutators::Mutator> {
    let Some(names) = names else { return mutators::default_strategies() };
    let mut out = Vec::new();
    for n in names {
        let m = match n.as_str() {
            "wordlist" => mutators::Mutator::Wordlist,
            "numeric" => mutators::Mutator::Numeric,
            "boundary" => mutators::Mutator::Boundary,
            "boolean" => mutators::Mutator::Boolean,
            "type_juggle" => mutators::Mutator::TypeJuggle,
            "case" => mutators::Mutator::Case,
            "encoding" => mutators::Mutator::Encoding,
            "path_traversal" => mutators::Mutator::PathTraversal,
            "affix" => mutators::Mutator::Affix,
            _ => continue,
        };
        out.push(m);
    }
    if out.is_empty() { mutators::default_strategies() } else { out }
}

fn persist_probe(s: &Storage, project_id: &Option<String>, kind: &str, json: &serde_json::Value) {
    if let Some(pid) = project_id {
        let arr = json.as_array().cloned().unwrap_or_default();
        let _ = s.save_recon_results(Some(pid), kind, &arr);
        for r in &arr {
            if let Some(url) = r.get("url").and_then(|v| v.as_str()) {
                let asset = serde_json::json!({"id":uuid::Uuid::new_v4().to_string(),"project_id":pid,"kind":"url","value":url,"source":kind,"created_at":chrono::Utc::now().to_rfc3339(),"meta":{"status":r.get("status")}});
                let _ = s.save_asset(&asset);
            }
        }
    }
}

/// Smart fuzzing: mutator-driven payload generation + scoped probing + triage
/// (dedup, SimHash clustering, novelty scoring against a soft-404 baseline).
#[tauri::command]
async fn smart_fuzz(project_id: Option<String>, base_url: String, words: Vec<String>, strategies: Option<Vec<String>>, allow: Vec<String>, deny: Vec<String>, state: State<'_, Mutex<AppState>>) -> Result<serde_json::Value, String> {
    let scope = ScopePolicy { allow, deny };
    let strat = parse_strategies(strategies);
    let targets = generate_smart_fuzz_targets(&base_url, &words, &strat, &scope, 300).map_err(|e| e.to_string())?;
    let cfg = ReconConfig::default();
    // Baseline calibration via unlikely control paths (soft-404 detection).
    let controls: Vec<String> = (0..2).map(|i| format!("{}/fablescope-control-{}-{}", base_url.trim_end_matches('/'), i, uuid::Uuid::new_v4())).collect();
    let baseline_results = probe_urls(controls, &scope, &cfg).await.map_err(|e| e.to_string())?;
    let baseline = fs_recon::calibrate(&baseline_results);
    let results = probe_urls(targets, &scope, &cfg).await.map_err(|e| e.to_string())?;
    let enriched = enrich_results(&results, Some(&baseline));
    let json = serde_json::to_value(&results).map_err(|e| e.to_string())?;
    {
        let st = state.lock().map_err(|_| "state lock")?;
        let s = st.storage()?;
        persist_probe(&s, &project_id, "smart_fuzz", &json);
    }
    Ok(serde_json::json!({"results": json, "triage": enriched, "strategies": strat}))
}

/// Subdomain recon: offline candidate generation (brute + permutation), scoped
/// probing, and asset-graph construction.
#[tauri::command]
async fn subdomain_scan(project_id: Option<String>, root: String, extra_prefixes: Vec<String>, known: Vec<String>, probe: bool, allow: Vec<String>, deny: Vec<String>, state: State<'_, Mutex<AppState>>) -> Result<serde_json::Value, String> {
    let mut scope = ScopePolicy { allow, deny };
    if scope.allow.is_empty() { scope.allow.push(root.clone()); }
    let candidates = subdomain::generate_candidates(&root, &extra_prefixes, &known, &scope, 500);
    let mut graph = subdomain::AssetGraph::new();
    for c in &candidates { graph.ingest_subdomain(&root, c, "candidate"); }
    let mut results_json = serde_json::json!([]);
    if probe {
        let urls = subdomain::candidate_urls(&candidates);
        let cfg = ReconConfig::default();
        let results = probe_urls(urls, &scope, &cfg).await.map_err(|e| e.to_string())?;
        for r in &results {
            if r.status.is_some() {
                let host = r.url.split("://").nth(1).and_then(|rest| rest.split('/').next()).unwrap_or("");
                if !host.is_empty() { graph.ingest_subdomain(&root, host, "resolved"); }
            }
        }
        results_json = serde_json::to_value(&results).map_err(|e| e.to_string())?;
        let st = state.lock().map_err(|_| "state lock")?;
        let s = st.storage()?;
        persist_probe(&s, &project_id, "subdomain", &results_json);
    }
    Ok(serde_json::json!({
        "root": root,
        "candidate_count": candidates.len(),
        "candidates": candidates,
        "graph": {"nodes": graph.nodes(), "edges": graph.edges(), "node_count": graph.node_count()},
        "results": results_json,
    }))
}

/// Cloud exposure recon: storage-bucket candidate generation + scoped read-only
/// probing + exposure-indicator scoring.
#[tauri::command]
async fn cloud_scan(project_id: Option<String>, base_names: Vec<String>, probe: bool, allow: Vec<String>, deny: Vec<String>, state: State<'_, Mutex<AppState>>) -> Result<serde_json::Value, String> {
    let scope = ScopePolicy { allow, deny };
    let providers = cloud::CloudProvider::all();
    let candidates = cloud::storage_candidates_scoped(&base_names, &providers, &scope, 400);
    let mut indicators: Vec<cloud::ExposureIndicator> = Vec::new();
    let mut results_json = serde_json::json!([]);
    if probe {
        let cfg = ReconConfig::default();
        let results = probe_urls(candidates.clone(), &scope, &cfg).await.map_err(|e| e.to_string())?;
        for r in &results { indicators.extend(cloud::exposure_indicators(r)); }
        results_json = serde_json::to_value(&results).map_err(|e| e.to_string())?;
        let st = state.lock().map_err(|_| "state lock")?;
        let s = st.storage()?;
        persist_probe(&s, &project_id, "cloud", &results_json);
        // Persist high-signal exposure indicators as findings.
        if let Some(pid_str) = &project_id {
            if let Ok(pid) = uuid::Uuid::parse_str(pid_str) {
                for ind in indicators.iter().filter(|i| matches!(i.severity, Severity::High | Severity::Critical)) {
                    if let Ok(mut f) = fs_core::Finding::new(pid, format!("Cloud exposure: {}", ind.indicator), ind.severity.clone()) {
                        f.description = ind.detail.clone();
                        f.status = Some("potential".into());
                        f.evidence.insert("url".into(), serde_json::json!(ind.url));
                        f.evidence.insert("provider".into(), serde_json::json!(ind.provider));
                        let _ = s.save_finding(&f);
                    }
                }
            }
        }
    }
    Ok(serde_json::json!({
        "candidate_count": candidates.len(),
        "candidates": candidates,
        "indicators": indicators,
        "results": results_json,
    }))
}

/// Triage saved recon results: dedup, cluster, novelty-score.
#[tauri::command]
fn triage_recon(project_id: String, state: State<'_, Mutex<AppState>>) -> Result<serde_json::Value, String> {
    let st = state.lock().map_err(|_| "state lock")?;
    let s = st.storage()?;
    let rows = s.list_recon_results(Some(&project_id), 1000).map_err(|e| e.to_string())?;
    let results: Vec<fs_recon::HttpProbeResult> = rows.iter().filter_map(|r| serde_json::from_value(r.clone()).ok()).collect();
    let enriched = enrich_results(&results, None);
    serde_json::to_value(enriched).map_err(|e| e.to_string())
}

/// Filter + group saved recon results. `filters` is a JSON array of filter
/// predicates; `group_by` is one of status/status_class/content_type/host.
#[tauri::command]
fn query_recon(project_id: String, filters: Option<String>, group_by: Option<String>, state: State<'_, Mutex<AppState>>) -> Result<serde_json::Value, String> {
    let st = state.lock().map_err(|_| "state lock")?;
    let s = st.storage()?;
    let rows = s.list_recon_results(Some(&project_id), 1000).map_err(|e| e.to_string())?;
    let filters: Vec<Filter> = match filters {
        Some(f) if !f.trim().is_empty() => serde_json::from_str(&f).map_err(|e| e.to_string())?,
        _ => vec![],
    };
    let filtered = apply_filters(&rows, &filters);
    let grouped = match group_by.as_deref() {
        Some("status") => serde_json::to_value(group(&filtered, GroupBy::Status)).ok(),
        Some("status_class") => serde_json::to_value(group(&filtered, GroupBy::StatusClass)).ok(),
        Some("content_type") => serde_json::to_value(group(&filtered, GroupBy::ContentType)).ok(),
        Some("host") => serde_json::to_value(group(&filtered, GroupBy::Host)).ok(),
        _ => None,
    };
    Ok(serde_json::json!({"count": filtered.len(), "results": filtered, "groups": grouped}))
}

/// Generate algorithmic passwords under a policy (CSPRNG, offline).
#[tauri::command]
fn generate_passwords(policy_json: Option<String>, count: usize) -> Result<serde_json::Value, String> {
    let policy: password::PasswordPolicy = match policy_json {
        Some(p) if !p.trim().is_empty() => serde_json::from_str(&p).map_err(|e| e.to_string())?,
        _ => password::PasswordPolicy::default(),
    };
    let out = password::generate(&policy, count.clamp(1, 1000), None);
    serde_json::to_value(out).map_err(|e| e.to_string())
}

/// Generate a Diceware-style passphrase (offline).
#[tauri::command]
fn generate_passphrase(words: usize, separator: Option<String>) -> Result<serde_json::Value, String> {
    let list = password::default_passphrase_words();
    let c = password::generate_passphrase(&list, words.clamp(2, 32), &separator.unwrap_or_else(|| "-".into()), None);
    serde_json::to_value(c).map_err(|e| e.to_string())
}

/// Apply mangling rules to a base word (authorized credential-audit use).
#[tauri::command]
fn mangle_word(base: String) -> Result<serde_json::Value, String> {
    let out = password::mangle(&base, password::Provenance::Algorithmic);
    serde_json::to_value(out).map_err(|e| e.to_string())
}

fn registry_path(app: &tauri::AppHandle) -> Result<PathBuf, String> {
    let dir = app.path().app_data_dir().map_err(|e| e.to_string())?;
    std::fs::create_dir_all(&dir).map_err(|e| e.to_string())?;
    Ok(dir.join("wordlist-registry.json"))
}

fn load_registry(app: &tauri::AppHandle) -> Result<WordlistRegistry, String> {
    let path = registry_path(app)?;
    if path.exists() {
        let text = std::fs::read_to_string(&path).map_err(|e| e.to_string())?;
        if let Ok(reg) = serde_json::from_str::<WordlistRegistry>(&text) {
            return Ok(reg);
        }
    }
    Ok(WordlistRegistry::with_builtin_sources())
}

fn save_registry(app: &tauri::AppHandle, reg: &WordlistRegistry) -> Result<(), String> {
    let path = registry_path(app)?;
    std::fs::write(&path, serde_json::to_string_pretty(reg).map_err(|e| e.to_string())?).map_err(|e| e.to_string())
}

/// List wordlist sources and their active pinned versions.
#[tauri::command]
fn list_wordlist_sources(app: tauri::AppHandle) -> Result<serde_json::Value, String> {
    let reg = load_registry(&app)?;
    let sources: Vec<serde_json::Value> = reg.sources().into_iter().map(|src| {
        let active = reg.active_version(&src.id).ok();
        let versions = reg.versions(&src.id).map(|v| v.len()).unwrap_or(0);
        serde_json::json!({"source": src, "active_version": active, "version_count": versions})
    }).collect();
    Ok(serde_json::json!(sources))
}

/// Register a fetched wordlist as a new immutable version (content-addressed).
#[tauri::command]
fn add_wordlist_version(app: tauri::AppHandle, source_id: String, version: String, content: String) -> Result<serde_json::Value, String> {
    let mut reg = load_registry(&app)?;
    let v = reg.add_version(&source_id, version, content.as_bytes(), None).map_err(|e| e.to_string())?;
    save_registry(&app, &reg)?;
    serde_json::to_value(v).map_err(|e| e.to_string())
}

/// Pin a source to a specific version hash, or roll back to the previous one.
#[tauri::command]
fn pin_wordlist_version(app: tauri::AppHandle, source_id: String, sha256: Option<String>, rollback: bool) -> Result<serde_json::Value, String> {
    let mut reg = load_registry(&app)?;
    let result = if rollback {
        let v = reg.rollback(&source_id).map_err(|e| e.to_string())?;
        serde_json::to_value(v).map_err(|e| e.to_string())?
    } else {
        let sha = sha256.ok_or("sha256 required when not rolling back")?;
        reg.pin(&source_id, &sha).map_err(|e| e.to_string())?;
        serde_json::json!({"pinned": sha})
    };
    save_registry(&app, &reg)?;
    Ok(result)
}

/// List the immutable version history for a wordlist source.
#[tauri::command]
fn list_wordlist_versions(app: tauri::AppHandle, source_id: String) -> Result<serde_json::Value, String> {
    let reg = load_registry(&app)?;
    let versions = reg.versions(&source_id).map_err(|e| e.to_string())?;
    serde_json::to_value(versions).map_err(|e| e.to_string())
}

// ---------------------------------------------------------------------------
// Phase 2: hash identification, encoders/decoders, credential-audit adapters.
// ---------------------------------------------------------------------------

/// Identify likely hash types for an input, ranked by confidence.
#[tauri::command]
fn identify_hash(input: String) -> Result<serde_json::Value, String> {
    serde_json::to_value(hashid::identify(&input)).map_err(|e| e.to_string())
}

/// Encode or decode a string with a codec (base64/hex/url/html_entity/rot13).
#[tauri::command]
fn codec_transform(codec_name: String, input: String, decode: bool) -> Result<serde_json::Value, String> {
    let c = match codec_name.as_str() {
        "base64" => codec::Codec::Base64,
        "hex" => codec::Codec::Hex,
        "url" => codec::Codec::Url,
        "html_entity" => codec::Codec::HtmlEntity,
        "rot13" => codec::Codec::Rot13,
        _ => return Err("unknown codec; use base64/hex/url/html_entity/rot13".into()),
    };
    let out = if decode {
        codec::decode(c, &input).map_err(|e| e.to_string())?
    } else {
        codec::encode(c, &input)
    };
    Ok(serde_json::json!({"codec": codec_name, "decode": decode, "output": out}))
}

/// Build an authorized Hashcat/John command for a credential-audit job. Does NOT
/// execute — returns the argument vector for review; execution runs through the
/// gated tool manager. `authorized` must be true or the build is refused.
#[tauri::command]
fn build_credential_audit(job_json: String, engine: String, sample_hash: Option<String>, john_format: Option<String>) -> Result<serde_json::Value, String> {
    let job: credential_audit::CredentialAuditJob = serde_json::from_str(&job_json).map_err(|e| e.to_string())?;
    let args = match engine.as_str() {
        "hashcat" => credential_audit::build_hashcat_args(&job, sample_hash.as_deref()).map_err(|e| e.to_string())?,
        "john" => credential_audit::build_john_args(&job, john_format.as_deref(), sample_hash.as_deref()).map_err(|e| e.to_string())?,
        _ => return Err("engine must be 'hashcat' or 'john'".into()),
    };
    Ok(serde_json::json!({"engine": engine, "args": args, "resolved_mode": job.resolve_mode(sample_hash.as_deref())}))
}

fn main() {
    tauri::Builder::default()
        .setup(|app| {
            let dir = app.path().app_data_dir().map_err(|e| e.to_string())?;
            std::fs::create_dir_all(&dir).map_err(|e| e.to_string())?;
            let db_path = dir.join("fablescope.db");
            app.manage(Mutex::new(AppState { db_path }));
            Ok(())
        })
        .invoke_handler(tauri::generate_handler![
            health,
            app_info,
            dashboard_stats,
            list_jobs,
            create_job,
            list_modules,
            list_adapters,
            upsert_adapter,
            list_assets,
            get_default_config,
            get_config,
            save_config,
            save_scope,
            get_scope,
            list_projects,
            create_project,
            list_checklist,
            update_checklist_item,
            export_project,
            export_confirmed_checklist,
            export_confirmed_checklist_csv,
            export_confirmed_checklist_html,
            export_project_report,
            project_timeline,
            probe_targets,
            fuzz_probe,
            list_recon_results,
            list_wordlist_packs,
            save_wordlist_pack,
            calc_cvss,
            ai_complete,
            run_check,
            list_checklist_templates,
            seed_checklist_template,
            list_tools,
            provision_tool,
            export_tool_manifests,
            import_tool_manifests,
            run_tool,
            list_tool_runs,
            list_findings,
            promote_check_to_finding,
            list_audit,
            smart_fuzz,
            subdomain_scan,
            cloud_scan,
            triage_recon,
            query_recon,
            generate_passwords,
            generate_passphrase,
            mangle_word,
            list_wordlist_sources,
            add_wordlist_version,
            pin_wordlist_version,
            list_wordlist_versions,
            identify_hash,
            codec_transform,
            build_credential_audit
        ])
        .run(tauri::generate_context!())
        .expect("error while running FableScope");
}
