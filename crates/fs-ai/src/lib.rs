use async_trait::async_trait;
use fs_config::{AiProviderProfile, WorkspaceConfig};
use serde::{Deserialize, Serialize};
use thiserror::Error;

pub type Result<T> = std::result::Result<T, AiError>;

#[derive(Debug, Error)]
pub enum AiError {
    #[error("ai disabled")]
    Disabled,
    #[error("no provider configured")]
    NoProvider,
    #[error("provider error: {0}")]
    Provider(String),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AiRequest {
    pub agent: String,
    pub prompt: String,
    pub context: serde_json::Value,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AiResponse {
    pub provider: String,
    pub model: String,
    pub content: String,
    pub redacted: bool,
}

#[async_trait]
pub trait AiProvider: Send + Sync {
    fn name(&self) -> &str;
    async fn complete(&self, req: &AiRequest) -> Result<AiResponse>;
}

pub struct DisabledProvider;
#[async_trait]
impl AiProvider for DisabledProvider {
    fn name(&self) -> &str { "disabled" }
    async fn complete(&self, _req: &AiRequest) -> Result<AiResponse> { Err(AiError::Disabled) }
}

pub struct DeterministicProvider { profile: AiProviderProfile }
impl DeterministicProvider { pub fn new(profile: AiProviderProfile) -> Self { Self { profile } } }
#[async_trait]
impl AiProvider for DeterministicProvider {
    fn name(&self) -> &str { &self.profile.name }
    async fn complete(&self, req: &AiRequest) -> Result<AiResponse> {
        let content = format!("[deterministic:{:?}] agent={} prompt_summary={}", self.profile.kind, req.agent, req.prompt.chars().take(120).collect::<String>());
        Ok(AiResponse { provider: self.profile.name.clone(), model: self.profile.model.clone().unwrap_or_default(), content, redacted: true })
    }
}

pub fn provider_from_config(cfg: &WorkspaceConfig) -> Box<dyn AiProvider> {
    if let Some(p) = cfg.ai_providers.iter().find(|p| p.enabled) {
        return Box::new(DeterministicProvider::new(p.clone()));
    }
    Box::new(DisabledProvider)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[tokio::test]
    async fn disabled_by_default() {
        let cfg = WorkspaceConfig::default();
        let p = provider_from_config(&cfg);
        let err = p.complete(&AiRequest { agent:"project".into(), prompt:"x".into(), context:serde_json::json!({}) }).await.unwrap_err();
        assert!(matches!(err, AiError::Disabled));
    }
}
