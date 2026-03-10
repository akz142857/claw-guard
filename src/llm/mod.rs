pub mod local;
pub mod prompt;
pub mod remote;

use anyhow::Result;
use serde::{Deserialize, Serialize};

use crate::report::AuditReport;

/// LLM analysis result — structured intelligent report
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AnalysisReport {
    /// One paragraph executive summary
    pub executive_summary: String,
    /// Attack chain analysis — combinations of findings that create exploitable paths
    pub risk_chains: Vec<RiskChain>,
    /// Prioritized remediation actions
    pub priority_actions: Vec<Action>,
    /// Environment-specific notes
    pub context_notes: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RiskChain {
    pub name: String,
    pub finding_ids: Vec<String>,
    pub impact: String,
    pub likelihood: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Action {
    pub priority: u8,
    pub command: String,
    pub reason: String,
    pub finding_ids: Vec<String>,
}

/// Provider selection
#[derive(Debug, Clone, clap::ValueEnum)]
pub enum Provider {
    Anthropic,
    Openai,
    Ollama,
}

impl std::fmt::Display for Provider {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Provider::Anthropic => write!(f, "anthropic"),
            Provider::Openai => write!(f, "openai"),
            Provider::Ollama => write!(f, "ollama"),
        }
    }
}

/// Result from an analyzer — analysis + optional web URL (remote mode)
pub struct AnalysisResult {
    pub analysis: AnalysisReport,
    pub web_url: Option<String>,
}

/// Analyzer trait — local and remote each implement this
#[async_trait::async_trait]
pub trait Analyzer: Send + Sync {
    async fn analyze(&self, report: &AuditReport) -> Result<AnalysisResult>;
}
