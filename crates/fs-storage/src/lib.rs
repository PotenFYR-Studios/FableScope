use chrono::Utc;
use fs_config::WorkspaceConfig;
use fs_core::{ChecklistItem, Finding, Job, Project, ScopePolicy};
use fs_tools::ToolRunResult;
use rusqlite::{params, Connection, OptionalExtension};
use std::path::Path;
use thiserror::Error;

pub type Result<T> = std::result::Result<T, StorageError>;

#[derive(Debug, Error)]
pub enum StorageError {
    #[error("sqlite error: {0}")]
    Sqlite(#[from] rusqlite::Error),
    #[error("serialization error: {0}")]
    Serde(#[from] serde_json::Error),
    #[error("not found: {0}")]
    NotFound(String),
}

pub struct Storage {
    conn: Connection,
}

impl Storage {
    pub fn open(path: impl AsRef<Path>) -> Result<Self> {
        if let Some(parent) = path.as_ref().parent() {
            std::fs::create_dir_all(parent).ok();
        }
        let conn = Connection::open(path)?;
        let mut s = Self { conn };
        s.migrate()?;
        Ok(s)
    }

    pub fn open_memory() -> Result<Self> {
        let conn = Connection::open_in_memory()?;
        let mut s = Self { conn };
        s.migrate()?;
        Ok(s)
    }

    fn migrate(&mut self) -> Result<()> {
        self.conn.execute_batch(
            r#"
            PRAGMA journal_mode=WAL;
            CREATE TABLE IF NOT EXISTS projects (
              id TEXT PRIMARY KEY,
              name TEXT NOT NULL,
              created_at TEXT NOT NULL,
              data_json TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS scope_policies (
              project_id TEXT PRIMARY KEY,
              data_json TEXT NOT NULL,
              updated_at TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS jobs (
              id TEXT PRIMARY KEY,
              project_id TEXT NOT NULL,
              kind TEXT NOT NULL,
              state TEXT NOT NULL,
              created_at TEXT NOT NULL,
              data_json TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS findings (
              id TEXT PRIMARY KEY,
              project_id TEXT NOT NULL,
              severity TEXT NOT NULL,
              title TEXT NOT NULL,
              created_at TEXT NOT NULL,
              data_json TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS checklist_items (
              id TEXT PRIMARY KEY,
              project_id TEXT NOT NULL,
              check_id TEXT NOT NULL,
              status TEXT NOT NULL,
              updated_at TEXT NOT NULL,
              data_json TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS config_snapshots (
              id INTEGER PRIMARY KEY AUTOINCREMENT,
              created_at TEXT NOT NULL,
              data_json TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS tool_runs (
              id TEXT PRIMARY KEY,
              tool_id TEXT NOT NULL,
              status INTEGER NOT NULL,
              started_at TEXT NOT NULL,
              finished_at TEXT NOT NULL,
              duration_ms INTEGER NOT NULL,
              artifact_dir TEXT NOT NULL,
              data_json TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS audit_log (
              id INTEGER PRIMARY KEY AUTOINCREMENT,
              created_at TEXT NOT NULL,
              actor TEXT NOT NULL,
              action TEXT NOT NULL,
              entity_type TEXT NOT NULL,
              entity_id TEXT,
              details_json TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS recon_results (
              id TEXT PRIMARY KEY,
              project_id TEXT,
              kind TEXT NOT NULL,
              created_at TEXT NOT NULL,
              data_json TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS wordlist_packs (
              id TEXT PRIMARY KEY,
              name TEXT NOT NULL,
              source TEXT NOT NULL,
              created_at TEXT NOT NULL,
              updated_at TEXT NOT NULL,
              data_json TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS assets (
              id TEXT PRIMARY KEY,
              project_id TEXT NOT NULL,
              kind TEXT NOT NULL,
              value TEXT NOT NULL,
              source TEXT NOT NULL,
              created_at TEXT NOT NULL,
              data_json TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS adapters (
              id TEXT PRIMARY KEY,
              module TEXT NOT NULL,
              status TEXT NOT NULL,
              data_json TEXT NOT NULL
            );
            CREATE INDEX IF NOT EXISTS idx_jobs_project ON jobs(project_id);
            CREATE INDEX IF NOT EXISTS idx_findings_project ON findings(project_id);
            CREATE INDEX IF NOT EXISTS idx_checklist_project ON checklist_items(project_id);
            CREATE INDEX IF NOT EXISTS idx_tool_runs_tool ON tool_runs(tool_id);
            CREATE INDEX IF NOT EXISTS idx_audit_entity ON audit_log(entity_type, entity_id);
            CREATE INDEX IF NOT EXISTS idx_recon_project ON recon_results(project_id, created_at DESC);
            CREATE INDEX IF NOT EXISTS idx_wordlists_name ON wordlist_packs(name);
            CREATE INDEX IF NOT EXISTS idx_assets_project ON assets(project_id, kind);
            CREATE INDEX IF NOT EXISTS idx_adapters_module ON adapters(module);
            "#,
        )?;
        Ok(())
    }

    pub fn save_project(&self, p: &Project) -> Result<()> {
        self.conn.execute(
            "INSERT OR REPLACE INTO projects(id,name,created_at,data_json) VALUES(?1,?2,?3,?4)",
            params![p.id.to_string(), p.name, p.created_at.to_rfc3339(), serde_json::to_string(p)?],
        )?;
        self.audit("system", "save", "project", Some(&p.id.to_string()), serde_json::json!({"name": p.name}))?;
        Ok(())
    }

    pub fn list_projects(&self) -> Result<Vec<Project>> {
        let mut stmt = self.conn.prepare("SELECT data_json FROM projects ORDER BY created_at DESC")?;
        let rows = stmt.query_map([], |r| r.get::<_, String>(0))?;
        let mut out = Vec::new();
        for r in rows { out.push(serde_json::from_str(&r?)?); }
        Ok(out)
    }

    pub fn save_scope(&self, project_id: &str, scope: &ScopePolicy) -> Result<()> {
        self.conn.execute(
            "INSERT OR REPLACE INTO scope_policies(project_id,data_json,updated_at) VALUES(?1,?2,?3)",
            params![project_id, serde_json::to_string(scope)?, Utc::now().to_rfc3339()],
        )?;
        self.audit("system", "save", "scope_policy", Some(project_id), serde_json::json!({}))?;
        Ok(())
    }

    pub fn get_scope(&self, project_id: &str) -> Result<Option<ScopePolicy>> {
        let mut stmt = self.conn.prepare("SELECT data_json FROM scope_policies WHERE project_id=?1")?;
        let v: Option<String> = stmt.query_row(params![project_id], |r| r.get(0)).optional()?;
        Ok(match v { Some(s) => Some(serde_json::from_str(&s)?), None => None })
    }

    pub fn save_job(&self, job: &Job) -> Result<()> {
        self.conn.execute(
            "INSERT OR REPLACE INTO jobs(id,project_id,kind,state,created_at,data_json) VALUES(?1,?2,?3,?4,?5,?6)",
            params![job.id.to_string(), job.project_id.to_string(), job.kind, serde_json::to_string(&job.state)?, job.created_at.to_rfc3339(), serde_json::to_string(job)?],
        )?;
        self.audit("system", "save", "job", Some(&job.id.to_string()), serde_json::json!({"kind": job.kind, "state": job.state}))?;
        Ok(())
    }

    pub fn list_jobs(&self, project_id: Option<&str>, limit: usize) -> Result<Vec<Job>> {
        let (sql, params_vec): (&str, Vec<rusqlite::types::Value>) = if let Some(pid) = project_id {
            ("SELECT data_json FROM jobs WHERE project_id=?1 ORDER BY created_at DESC LIMIT ?2", vec![pid.to_string().into(), (limit as i64).into()])
        } else {
            ("SELECT data_json FROM jobs ORDER BY created_at DESC LIMIT ?1", vec![(limit as i64).into()])
        };
        let mut stmt = self.conn.prepare(sql)?;
        let mut rows = stmt.query(rusqlite::params_from_iter(params_vec.iter()))?;
        let mut out = Vec::new();
        while let Some(r) = rows.next()? { let s: String = r.get(0)?; out.push(serde_json::from_str(&s)?); }
        Ok(out)
    }

    pub fn count_table(&self, table: &str, project_id: Option<&str>) -> Result<i64> {
        let allowed = ["projects","jobs","findings","checklist_items","tool_runs","audit_log","recon_results","wordlist_packs"];
        if !allowed.contains(&table) { return Ok(0); }
        let (sql, params_vec): (String, Vec<rusqlite::types::Value>) = match (table, project_id) {
            ("projects", _) => (format!("SELECT COUNT(*) FROM {table}"), vec![]),
            (_, Some(pid)) => (format!("SELECT COUNT(*) FROM {table} WHERE project_id=?1"), vec![pid.to_string().into()]),
            (_, None) => (format!("SELECT COUNT(*) FROM {table}"), vec![]),
        };
        let mut stmt = self.conn.prepare(&sql)?;
        let c: i64 = stmt.query_row(rusqlite::params_from_iter(params_vec.iter()), |r| r.get(0))?;
        Ok(c)
    }

    pub fn save_finding(&self, f: &Finding) -> Result<()> {
        self.conn.execute(
            "INSERT OR REPLACE INTO findings(id,project_id,severity,title,created_at,data_json) VALUES(?1,?2,?3,?4,?5,?6)",
            params![f.id.to_string(), f.project_id.to_string(), serde_json::to_string(&f.severity)?, f.title, f.created_at.to_rfc3339(), serde_json::to_string(f)?],
        )?;
        self.audit("system", "save", "finding", Some(&f.id.to_string()), serde_json::json!({"title": f.title}))?;
        Ok(())
    }

    pub fn list_findings(&self, project_id: &str) -> Result<Vec<Finding>> {
        let mut stmt = self.conn.prepare("SELECT data_json FROM findings WHERE project_id=?1 ORDER BY created_at DESC")?;
        let rows = stmt.query_map(params![project_id], |r| r.get::<_, String>(0))?;
        let mut out = Vec::new();
        for r in rows { out.push(serde_json::from_str(&r?)?); }
        Ok(out)
    }

    pub fn save_checklist_item(&self, item: &ChecklistItem) -> Result<()> {
        self.conn.execute(
            "INSERT OR REPLACE INTO checklist_items(id,project_id,check_id,status,updated_at,data_json) VALUES(?1,?2,?3,?4,?5,?6)",
            params![
                item.id.to_string(),
                item.project_id.to_string(),
                item.check_id,
                serde_json::to_string(&item.status)?,
                item.updated_at.to_rfc3339(),
                serde_json::to_string(item)?
            ],
        )?;
        Ok(())
    }

    pub fn list_checklist_items(&self, project_id: &str) -> Result<Vec<ChecklistItem>> {
        let mut stmt = self.conn.prepare("SELECT data_json FROM checklist_items WHERE project_id=?1 ORDER BY check_id")?;
        let rows = stmt.query_map(params![project_id], |r| r.get::<_, String>(0))?;
        let mut out = Vec::new();
        for r in rows { out.push(serde_json::from_str(&r?)?); }
        Ok(out)
    }

    pub fn get_checklist_item(&self, project_id: &str, check_id: &str) -> Result<ChecklistItem> {
        let mut stmt = self.conn.prepare("SELECT data_json FROM checklist_items WHERE project_id=?1 AND check_id=?2 LIMIT 1")?;
        let v: Option<String> = stmt.query_row(params![project_id, check_id], |r| r.get(0)).optional()?;
        let item: ChecklistItem = serde_json::from_str(&v.ok_or_else(|| StorageError::NotFound(check_id.to_string()))?)?;
        Ok(item)
    }

    pub fn update_checklist_status(&self, project_id: &str, check_id: &str, status: fs_core::CheckStatus, notes: Option<String>) -> Result<ChecklistItem> {
        let mut item = self.get_checklist_item(project_id, check_id)?;
        item.status = status;
        item.notes = notes;
        item.updated_at = Utc::now();
        self.save_checklist_item(&item)?;
        self.audit("user", "update_status", "checklist_item", Some(&item.id.to_string()), serde_json::json!({"check_id": item.check_id, "status": item.status}))?;
        Ok(item)
    }

    pub fn append_checklist_evidence(&self, project_id: &str, check_id: &str, evidence: fs_core::EvidenceRef) -> Result<ChecklistItem> {
        let mut item = self.get_checklist_item(project_id, check_id)?;
        item.evidence.push(evidence.clone());
        item.updated_at = Utc::now();
        self.save_checklist_item(&item)?;
        self.audit("system", "append_evidence", "checklist_item", Some(&item.id.to_string()), serde_json::json!({"check_id": check_id, "evidence_id": evidence.id, "kind": evidence.kind}))?;
        Ok(item)
    }

    pub fn save_tool_run(&self, run: &ToolRunResult) -> Result<()> {
        self.conn.execute(
            "INSERT OR REPLACE INTO tool_runs(id,tool_id,status,started_at,finished_at,duration_ms,artifact_dir,data_json) VALUES(?1,?2,?3,?4,?5,?6,?7,?8)",
            params![
                run.run_id.to_string(),
                run.tool_id,
                run.status,
                run.started_at.to_rfc3339(),
                run.finished_at.to_rfc3339(),
                run.duration_ms as i64,
                run.artifact_dir.to_string_lossy().to_string(),
                serde_json::to_string(run)?
            ],
        )?;
        self.audit("system", "run", "tool", Some(&run.run_id.to_string()), serde_json::json!({"tool_id": run.tool_id, "status": run.status}))?;
        Ok(())
    }

    pub fn list_tool_runs(&self, limit: usize) -> Result<Vec<ToolRunResult>> {
        let mut stmt = self.conn.prepare("SELECT data_json FROM tool_runs ORDER BY started_at DESC LIMIT ?1")?;
        let rows = stmt.query_map(params![limit as i64], |r| r.get::<_, String>(0))?;
        let mut out = Vec::new();
        for r in rows { out.push(serde_json::from_str(&r?)?); }
        Ok(out)
    }

    pub fn save_config_snapshot(&self, cfg: &WorkspaceConfig) -> Result<()> {
        self.conn.execute(
            "INSERT INTO config_snapshots(created_at,data_json) VALUES(?1,?2)",
            params![Utc::now().to_rfc3339(), serde_json::to_string(cfg)?],
        )?;
        self.audit("system", "snapshot", "config", None, serde_json::json!({"version": cfg.version}))?;
        Ok(())
    }

    pub fn latest_config(&self) -> Result<Option<WorkspaceConfig>> {
        let mut stmt = self.conn.prepare("SELECT data_json FROM config_snapshots ORDER BY id DESC LIMIT 1")?;
        let v: Option<String> = stmt.query_row([], |r| r.get(0)).optional()?;
        Ok(match v { Some(s) => Some(serde_json::from_str(&s)?), None => None })
    }

    pub fn audit(&self, actor: &str, action: &str, entity_type: &str, entity_id: Option<&str>, details: serde_json::Value) -> Result<()> {
        self.conn.execute(
            "INSERT INTO audit_log(created_at,actor,action,entity_type,entity_id,details_json) VALUES(?1,?2,?3,?4,?5,?6)",
            params![Utc::now().to_rfc3339(), actor, action, entity_type, entity_id, serde_json::to_string(&details)?],
        )?;
        Ok(())
    }

    pub fn audit_count(&self) -> Result<i64> {
        let mut stmt = self.conn.prepare("SELECT COUNT(*) FROM audit_log")?;
        let c: i64 = stmt.query_row([], |r| r.get(0))?;
        Ok(c)
    }

    pub fn list_audit(&self, limit: usize) -> Result<Vec<serde_json::Value>> {
        let mut stmt = self.conn.prepare(
            "SELECT created_at, actor, action, entity_type, entity_id, details_json FROM audit_log ORDER BY id DESC LIMIT ?1",
        )?;
        let rows = stmt.query_map(params![limit as i64], |r| {
            let details: String = r.get(5)?;
            Ok(serde_json::json!({
                "created_at": r.get::<_, String>(0)?,
                "actor": r.get::<_, String>(1)?,
                "action": r.get::<_, String>(2)?,
                "entity_type": r.get::<_, String>(3)?,
                "entity_id": r.get::<_, Option<String>>(4)?,
                "details": serde_json::from_str::<serde_json::Value>(&details).unwrap_or(serde_json::json!(details)),
            }))
        })?;
        let mut out = Vec::new();
        for r in rows { out.push(r?); }
        Ok(out)
    }

    pub fn save_recon_results(&self, project_id: Option<&str>, kind: &str, results: &[serde_json::Value]) -> Result<usize> {
        let now = Utc::now().to_rfc3339();
        let mut n = 0usize;
        for r in results {
            let id = r.get("id").and_then(|v| v.as_str()).map(|s| s.to_string()).unwrap_or_else(|| uuid::Uuid::new_v4().to_string());
            let url = r.get("url").and_then(|v| v.as_str()).unwrap_or("");
            let status = r.get("status").and_then(|v| v.as_i64()).unwrap_or(-1);
            if let Some(pid) = project_id {
                let mut stmt = self.conn.prepare("SELECT 1 FROM recon_results WHERE project_id=?1 AND kind=?2 AND json_extract(data_json,'$.url')=?3 AND COALESCE(json_extract(data_json,'$.status'),-1)=?4 LIMIT 1")?;
                let exists: Option<i32> = stmt.query_row(params![pid, kind, url, status], |row| row.get(0)).optional()?;
                if exists.is_some() { continue; }
            }
            self.conn.execute(
                "INSERT OR REPLACE INTO recon_results(id,project_id,kind,created_at,data_json) VALUES(?1,?2,?3,?4,?5)",
                params![id, project_id, kind, now, serde_json::to_string(r)?],
            )?;
            n += 1;
        }
        if n > 0 {
            self.audit("system", "save", "recon_result", project_id, serde_json::json!({"kind": kind, "count": n}))?;
        }
        Ok(n)
    }

    pub fn list_recon_results(&self, project_id: Option<&str>, limit: usize) -> Result<Vec<serde_json::Value>> {
        let (sql, pid): (&str, Option<String>) = if let Some(p) = project_id {
            ("SELECT data_json FROM recon_results WHERE project_id=?1 ORDER BY created_at DESC LIMIT ?2", Some(p.to_string()))
        } else {
            ("SELECT data_json FROM recon_results ORDER BY created_at DESC LIMIT ?1", None)
        };
        let mut stmt = self.conn.prepare(sql)?;
        let mut out = Vec::new();
        if let Some(p) = pid {
            let rows = stmt.query_map(params![p, limit as i64], |r| r.get::<_, String>(0))?;
            for r in rows { out.push(serde_json::from_str(&r?)?); }
        } else {
            let rows = stmt.query_map(params![limit as i64], |r| r.get::<_, String>(0))?;
            for r in rows { out.push(serde_json::from_str(&r?)?); }
        }
        Ok(out)
    }

    pub fn export_project_bundle(&self, project_id: &str) -> Result<serde_json::Value> {
        let project: Option<Project> = {
            let mut stmt = self.conn.prepare("SELECT data_json FROM projects WHERE id=?1")?;
            let v: Option<String> = stmt.query_row(params![project_id], |r| r.get(0)).optional()?;
            match v { Some(s) => Some(serde_json::from_str(&s)?), None => None }
        };
        let project = project.ok_or_else(|| StorageError::NotFound(project_id.to_string()))?;
        let scope = self.get_scope(project_id)?;
        let checklist = self.list_checklist_items(project_id)?;
        let runs = self.list_tool_runs(200)?;
        let recon = self.list_recon_results(Some(project_id), 200)?;
        let findings = self.list_findings(project_id)?;
        let audit = self.list_audit(200)?;
        let checklist_review: Vec<serde_json::Value> = checklist.iter().map(|i| {
            serde_json::json!({
                "check_id": i.check_id,
                "title": i.title,
                "status": i.status,
                "confidence": i.confidence,
                "owasp": i.owasp,
                "notes": i.notes,
                "evidence_count": i.evidence.len(),
                "evidence": i.evidence,
                "updated_at": i.updated_at,
            })
        }).collect();
        Ok(serde_json::json!({
            "exported_at": Utc::now().to_rfc3339(),
            "project": project,
            "scope": scope,
            "checklist": checklist,
            "checklist_review": checklist_review,
            "findings": findings,
            "tool_runs": runs,
            "recon_results": recon,
            "audit": audit,
        }))
    }

    pub fn export_confirmed_checklist(&self, project_id: &str) -> Result<serde_json::Value> {
        let bundle = self.export_project_bundle(project_id)?;
        let empty = vec![];
        let items = bundle.get("checklist_review").and_then(|v| v.as_array()).unwrap_or(&empty);
        let confirmed: Vec<serde_json::Value> = items.iter().filter(|i| {
            let s = i.get("status").and_then(|v| v.as_str()).unwrap_or("");
            matches!(s, "pass" | "fail" | "potential" | "false_positive" | "not_applicable" | "blocked")
        }).cloned().collect();
        Ok(serde_json::json!({
            "exported_at": Utc::now().to_rfc3339(),
            "project_id": project_id,
            "total": items.len(),
            "confirmed_count": confirmed.len(),
            "items": confirmed,
        }))
    }

    pub fn export_confirmed_checklist_csv(&self, project_id: &str) -> Result<String> {
        let v = self.export_confirmed_checklist(project_id)?;
        let empty = vec![];
        let items = v.get("items").and_then(|x| x.as_array()).unwrap_or(&empty);
        let mut out = String::from("check_id,title,status,confidence,evidence_count,updated_at,notes\n");
        for i in items {
            let row = [
                i.get("check_id").and_then(|x| x.as_str()).unwrap_or(""),
                i.get("title").and_then(|x| x.as_str()).unwrap_or(""),
                i.get("status").and_then(|x| x.as_str()).unwrap_or(""),
                &i.get("confidence").map(|x| x.to_string()).unwrap_or_default(),
                &i.get("evidence_count").map(|x| x.to_string()).unwrap_or_default(),
                i.get("updated_at").and_then(|x| x.as_str()).unwrap_or(""),
                i.get("notes").and_then(|x| x.as_str()).unwrap_or(""),
            ];
            let escaped: Vec<String> = row.iter().map(|c| {
                let s = c.replace('"', "\"\"");
                if s.contains(',') || s.contains('"') || s.contains('\n') { format!("\"{s}\"") } else { s }
            }).collect();
            out.push_str(&escaped.join(","));
            out.push('\n');
        }
        Ok(out)
    }

    pub fn export_confirmed_checklist_html(&self, project_id: &str) -> Result<String> {
        let v = self.export_confirmed_checklist(project_id)?;
        let empty = vec![];
        let items = v.get("items").and_then(|x| x.as_array()).unwrap_or(&empty);
        let mut rows = String::new();
        for i in items {
            rows.push_str(&format!(
                "<tr><td>{}</td><td>{}</td><td>{}</td><td>{}</td><td>{}</td><td>{}</td></tr>",
                Self::html_escape(i.get("check_id").and_then(|x| x.as_str()).unwrap_or("")),
                Self::html_escape(i.get("title").and_then(|x| x.as_str()).unwrap_or("")),
                Self::html_escape(i.get("status").and_then(|x| x.as_str()).unwrap_or("")),
                Self::html_escape(&i.get("confidence").map(|x| x.to_string()).unwrap_or_default()),
                Self::html_escape(&i.get("evidence_count").map(|x| x.to_string()).unwrap_or_default()),
                Self::html_escape(i.get("notes").and_then(|x| x.as_str()).unwrap_or("")),
            ));
        }
        if rows.is_empty() { rows.push_str("<tr><td colspan='6'>No confirmed items</td></tr>"); }
        Ok(format!(
            "<!doctype html><html><head><meta charset='utf-8'><title>Confirmed Checklist</title><style>body{{font-family:system-ui;margin:24px}}table{{border-collapse:collapse;width:100%}}td,th{{border:1px solid #ccc;padding:8px;text-align:left}}</style></head><body><h1>Confirmed Checklist</h1><p>Project: {}</p><table><thead><tr><th>Check</th><th>Title</th><th>Status</th><th>Confidence</th><th>Evidence</th><th>Notes</th></tr></thead><tbody>{}</tbody></table></body></html>",
            Self::html_escape(project_id), rows
        ))
    }

    fn html_escape(s: &str) -> String {
        s.replace('&', "&amp;").replace('<', "&lt;").replace('>', "&gt;").replace('"', "&quot;")
    }

    pub fn save_wordlist_pack(&self, pack: &serde_json::Value) -> Result<()> {
        let id = pack.get("id").and_then(|v| v.as_str()).map(|s| s.to_string()).unwrap_or_else(|| uuid::Uuid::new_v4().to_string());
        let name = pack.get("name").and_then(|v| v.as_str()).unwrap_or("unnamed").to_string();
        let source = pack.get("source").and_then(|v| v.as_str()).unwrap_or("custom").to_string();
        let now = Utc::now().to_rfc3339();
        self.conn.execute(
            "INSERT OR REPLACE INTO wordlist_packs(id,name,source,created_at,updated_at,data_json) VALUES(?1,?2,?3,COALESCE((SELECT created_at FROM wordlist_packs WHERE id=?1),?4),?5,?6)",
            params![id, name, source, now, now, serde_json::to_string(pack)?],
        )?;
        self.audit("user", "save", "wordlist_pack", Some(&id), serde_json::json!({"name": name}))?;
        Ok(())
    }

    pub fn list_wordlist_packs_db(&self, limit: usize) -> Result<Vec<serde_json::Value>> {
        let mut stmt = self.conn.prepare("SELECT data_json FROM wordlist_packs ORDER BY updated_at DESC LIMIT ?1")?;
        let rows = stmt.query_map(params![limit as i64], |r| r.get::<_, String>(0))?;
        let mut out = Vec::new();
        for r in rows { out.push(serde_json::from_str(&r?)?); }
        Ok(out)
    }

    pub fn save_asset(&self, asset: &serde_json::Value) -> Result<()> {
        let id = asset.get("id").and_then(|v| v.as_str()).unwrap_or_default();
        let project_id = asset.get("project_id").and_then(|v| v.as_str()).unwrap_or_default();
        let kind = asset.get("kind").and_then(|v| v.as_str()).unwrap_or("other");
        let value = asset.get("value").and_then(|v| v.as_str()).unwrap_or_default();
        let source = asset.get("source").and_then(|v| v.as_str()).unwrap_or("unknown");
        let created_at = asset.get("created_at").and_then(|v| v.as_str()).unwrap_or(&Utc::now().to_rfc3339()).to_string();
        self.conn.execute(
            "INSERT OR REPLACE INTO assets(id,project_id,kind,value,source,created_at,data_json) VALUES(?1,?2,?3,?4,?5,?6,?7)",
            params![id, project_id, kind, value, source, created_at, serde_json::to_string(asset)?],
        )?;
        Ok(())
    }

    pub fn list_assets(&self, project_id: &str, limit: usize) -> Result<Vec<serde_json::Value>> {
        let mut stmt = self.conn.prepare("SELECT data_json FROM assets WHERE project_id=?1 ORDER BY created_at DESC LIMIT ?2")?;
        let rows = stmt.query_map(params![project_id, limit as i64], |r| r.get::<_, String>(0))?;
        let mut out = Vec::new(); for r in rows { out.push(serde_json::from_str(&r?)?); } Ok(out)
    }

    pub fn upsert_adapter(&self, adapter: &serde_json::Value) -> Result<()> {
        let id = adapter.get("id").and_then(|v| v.as_str()).unwrap_or_default();
        let module = adapter.get("module").and_then(|v| v.as_str()).unwrap_or("unknown");
        let status = adapter.get("status").and_then(|v| v.as_str()).unwrap_or("planned");
        self.conn.execute("INSERT OR REPLACE INTO adapters(id,module,status,data_json) VALUES(?1,?2,?3,?4)", params![id, module, status, serde_json::to_string(adapter)?])?;
        Ok(())
    }

    pub fn list_adapters(&self, module: Option<&str>) -> Result<Vec<serde_json::Value>> {
        let (sql, p): (&str, Vec<rusqlite::types::Value>) = if let Some(m) = module {
            ("SELECT data_json FROM adapters WHERE module=?1 ORDER BY id", vec![m.to_string().into()])
        } else {
            ("SELECT data_json FROM adapters ORDER BY module,id", vec![])
        };
        let mut stmt = self.conn.prepare(sql)?;
        let mut rows = stmt.query(rusqlite::params_from_iter(p.iter()))?;
        let mut out = Vec::new(); while let Some(r) = rows.next()? { let s: String = r.get(0)?; out.push(serde_json::from_str(&s)?); } Ok(out)
    }

    pub fn project_timeline(&self, project_id: &str, limit: usize) -> Result<Vec<serde_json::Value>> {
        let mut events = Vec::new();
        for a in self.list_audit(limit)? {
            let eid = a.get("entity_id").and_then(|v| v.as_str()).unwrap_or("");
            let details = a.get("details").cloned().unwrap_or(serde_json::json!({}));
            let relates = eid == project_id || details.get("project_id").and_then(|v| v.as_str()) == Some(project_id);
            if relates || a.get("entity_type").and_then(|v| v.as_str()) == Some("project") {
                events.push(serde_json::json!({"kind":"audit","at":a.get("created_at"),"data":a}));
            }
        }
        for r in self.list_tool_runs(limit)? {
            if r.project_id.map(|id| id.to_string()) == Some(project_id.to_string()) {
                events.push(serde_json::json!({"kind":"tool_run","at":r.finished_at.to_rfc3339(),"data":r}));
            }
        }
        for r in self.list_recon_results(Some(project_id), limit)? {
            events.push(serde_json::json!({"kind":"recon","at":r.get("timestamp").or_else(|| r.get("created_at")).cloned().unwrap_or(serde_json::Value::Null),"data":r}));
        }
        events.sort_by(|a,b| b.get("at").and_then(|v| v.as_str()).cmp(&a.get("at").and_then(|v| v.as_str())));
        events.truncate(limit);
        Ok(events)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use fs_core::Severity;

    #[test]
    fn project_scope_config_roundtrip() {
        let s = Storage::open_memory().unwrap();
        let p = Project::new("Acme").unwrap();
        s.save_project(&p).unwrap();
        let projects = s.list_projects().unwrap();
        assert_eq!(projects.len(), 1);
        assert_eq!(projects[0].name, "Acme");

        let scope = ScopePolicy { allow: vec!["example.com".into()], deny: vec![] };
        s.save_scope(&p.id.to_string(), &scope).unwrap();
        let got = s.get_scope(&p.id.to_string()).unwrap().unwrap();
        assert_eq!(got.allow, vec!["example.com"]);

        let cfg = WorkspaceConfig::default();
        s.save_config_snapshot(&cfg).unwrap();
        let cfg2 = s.latest_config().unwrap().unwrap();
        assert_eq!(cfg2.scan_defaults.rps, cfg.scan_defaults.rps);
        assert!(s.audit_count().unwrap() >= 3);
    }

    #[test]
    fn save_job_and_finding() {
        let s = Storage::open_memory().unwrap();
        let p = Project::new("P").unwrap();
        s.save_project(&p).unwrap();
        let j = Job::new(p.id, "recon");
        s.save_job(&j).unwrap();
        let f = Finding::new(p.id, "Test finding", Severity::Low).unwrap();
        s.save_finding(&f).unwrap();
        assert!(s.audit_count().unwrap() >= 2);
    }

    #[test]
    fn checklist_items_roundtrip() {
        let s = Storage::open_memory().unwrap();
        let p = Project::new("P").unwrap();
        s.save_project(&p).unwrap();
        let item = fs_core::ChecklistItem::new(p.id, "FS-WEB-001", "Test");
        s.save_checklist_item(&item).unwrap();
        let items = s.list_checklist_items(&p.id.to_string()).unwrap();
        assert_eq!(items.len(), 1);
        assert_eq!(items[0].check_id, "FS-WEB-001");
    }

    #[test]
    fn tool_runs_roundtrip() {
        let s = Storage::open_memory().unwrap();
        let run = fs_tools::ToolRunResult {
            run_id: uuid::Uuid::new_v4(),
            tool_id: "nikto".into(),
            profile: Some("default".into()),
            args: vec!["-h".into()],
            project_id: None,
            check_id: Some("FS-WEB-002".into()),
            correlation_id: Some("corr-1".into()),
            status: 0,
            stdout: "ok".into(),
            stderr: "".into(),
            started_at: Utc::now(),
            finished_at: Utc::now(),
            duration_ms: 1,
            artifact_dir: std::path::PathBuf::from("artifacts"),
        };
        s.save_tool_run(&run).unwrap();
        let runs = s.list_tool_runs(10).unwrap();
        assert_eq!(runs.len(), 1);
        assert_eq!(runs[0].tool_id, "nikto");
    }

    #[test]
    fn recon_results_roundtrip() {
        let s = Storage::open_memory().unwrap();
        let p = Project::new("P").unwrap();
        s.save_project(&p).unwrap();
        let res = vec![serde_json::json!({"id":"r1","url":"https://example.com","status":200})];
        let n = s.save_recon_results(Some(&p.id.to_string()), "probe", &res).unwrap();
        assert_eq!(n, 1);
        let got = s.list_recon_results(Some(&p.id.to_string()), 10).unwrap();
        assert_eq!(got.len(), 1);
        assert_eq!(got[0]["url"], "https://example.com");
    }

    #[test]
    fn wordlist_packs_roundtrip() {
        let s = Storage::open_memory().unwrap();
        let pack = serde_json::json!({"id":"wl1","name":"custom","source":"user","words":["admin","api"]});
        s.save_wordlist_pack(&pack).unwrap();
        let got = s.list_wordlist_packs_db(10).unwrap();
        assert_eq!(got.len(), 1);
        assert_eq!(got[0]["name"], "custom");
    }
}
