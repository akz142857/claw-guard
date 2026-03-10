use anyhow::Result;
use tracing::info;

use super::adapter::{self, ResolvedConfig};
use super::{AnalysisReport, AnalysisResult, Analyzer};
use crate::report::AuditReport;

pub struct LocalAnalyzer {
    pub config: ResolvedConfig,
}

#[async_trait::async_trait]
impl Analyzer for LocalAnalyzer {
    async fn analyze(&self, report: &AuditReport) -> Result<AnalysisResult> {
        let prompt = super::prompt::build_prompt(report);
        info!(
            "Analyzing with {} (model: {})...",
            self.config.provider_name, self.config.model
        );

        let client = reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(120))
            .build()?;

        let response_text = adapter::call_llm(&client, &self.config, &prompt).await?;
        let analysis: AnalysisReport = parse_llm_response(&response_text)?;
        Ok(AnalysisResult {
            analysis,
            web_url: None,
        })
    }
}

/// Parse LLM response text into AnalysisReport.
/// Handles markdown fencing, leading/trailing text, and JSON strings with braces.
fn parse_llm_response(text: &str) -> Result<AnalysisReport> {
    // Try direct parse first
    if let Ok(report) = serde_json::from_str::<AnalysisReport>(text) {
        return Ok(report);
    }

    // Extract JSON from markdown code blocks
    let extracted = extract_json_block(text);
    let candidate = extracted.trim();

    if let Ok(report) = serde_json::from_str::<AnalysisReport>(candidate) {
        return Ok(report);
    }

    // Last resort: try finding valid JSON by trimming to first `{`
    if let Some(start) = candidate.find('{') {
        let substr = &candidate[start..];
        if let Ok(report) = serde_json::from_str::<AnalysisReport>(substr) {
            return Ok(report);
        }
    }

    Err(anyhow::anyhow!(
        "Failed to parse LLM response as AnalysisReport. Response preview: {}",
        &text[..text.len().min(500)]
    ))
}

/// Extract JSON from markdown-fenced or raw text.
fn extract_json_block(text: &str) -> &str {
    // Try ```json ... ``` first
    if let Some(start) = text.find("```json") {
        let after = &text[start + 7..];
        if let Some(end) = after.find("```") {
            return &after[..end];
        }
        return after;
    }

    // Try ``` ... ```
    if let Some(start) = text.find("```") {
        let after = &text[start + 3..];
        // Skip optional language tag on same line
        let after = if let Some(nl) = after.find('\n') {
            &after[nl + 1..]
        } else {
            after
        };
        if let Some(end) = after.find("```") {
            return &after[..end];
        }
        return after;
    }

    text
}
