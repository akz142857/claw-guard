use anyhow::Result;
use std::io::Write;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Instant;

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

        let client = reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(120))
            .build()?;

        // Start spinner
        let running = Arc::new(AtomicBool::new(true));
        let spinner_handle = {
            let running = running.clone();
            let provider = self.config.provider_name.clone();
            let model = self.config.model.clone();
            tokio::spawn(async move {
                let frames = ["⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"];
                let start = Instant::now();
                let mut i = 0;
                while running.load(Ordering::Relaxed) {
                    let elapsed = start.elapsed().as_secs();
                    eprint!(
                        "\r  {} Analyzing with {} ({})... {}s ",
                        frames[i % frames.len()],
                        provider,
                        model,
                        elapsed,
                    );
                    let _ = std::io::stderr().flush();
                    i += 1;
                    tokio::time::sleep(std::time::Duration::from_millis(80)).await;
                }
                let elapsed = start.elapsed().as_secs_f64();
                // Clear spinner line and print completion
                eprint!("\r  ✓ Analysis complete ({:.1}s)                              \n", elapsed);
                let _ = std::io::stderr().flush();
            })
        };

        let result = adapter::call_llm(&client, &self.config, &prompt).await;

        // Stop spinner
        running.store(false, Ordering::Relaxed);
        let _ = spinner_handle.await;

        let response_text = result?;
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
