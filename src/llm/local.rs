use anyhow::{bail, Result};
use tracing::info;

use super::{AnalysisReport, AnalysisResult, Analyzer, Provider};
use crate::report::AuditReport;

pub struct LocalAnalyzer {
    pub provider: Provider,
    pub api_key: String,
    pub model: String,
    pub ollama_url: String,
}

#[async_trait::async_trait]
impl Analyzer for LocalAnalyzer {
    async fn analyze(&self, report: &AuditReport) -> Result<AnalysisResult> {
        let prompt = super::prompt::build_prompt(report);
        info!("Analyzing with {} (model: {})...", self.provider, self.model);

        let client = reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(120))
            .build()?;

        let response_text = match self.provider {
            Provider::Anthropic => self.call_anthropic(&client, &prompt).await?,
            Provider::Openai => self.call_openai(&client, &prompt).await?,
            Provider::Ollama => self.call_ollama(&client, &prompt).await?,
        };

        let analysis: AnalysisReport = parse_llm_response(&response_text)?;
        Ok(AnalysisResult {
            analysis,
            web_url: None,
        })
    }
}

impl LocalAnalyzer {
    async fn call_anthropic(&self, client: &reqwest::Client, prompt: &str) -> Result<String> {
        let body = serde_json::json!({
            "model": self.model,
            "max_tokens": 4096,
            "messages": [
                {"role": "user", "content": prompt}
            ]
        });

        let resp = client
            .post("https://api.anthropic.com/v1/messages")
            .header("x-api-key", &self.api_key)
            .header("anthropic-version", "2023-06-01")
            .header("content-type", "application/json")
            .json(&body)
            .send()
            .await?;

        if !resp.status().is_success() {
            let status = resp.status();
            let text = resp.text().await.unwrap_or_default();
            bail!("Anthropic API error ({}): {}", status, text);
        }

        let json: serde_json::Value = resp.json().await?;
        let text = json["content"][0]["text"]
            .as_str()
            .unwrap_or("")
            .to_string();
        Ok(text)
    }

    async fn call_openai(&self, client: &reqwest::Client, prompt: &str) -> Result<String> {
        let body = serde_json::json!({
            "model": self.model,
            "messages": [
                {"role": "system", "content": "You are a security analyst. Output only valid JSON."},
                {"role": "user", "content": prompt}
            ],
            "temperature": 0.3,
            "max_tokens": 4096,
        });

        let resp = client
            .post("https://api.openai.com/v1/chat/completions")
            .header("Authorization", format!("Bearer {}", self.api_key))
            .header("Content-Type", "application/json")
            .json(&body)
            .send()
            .await?;

        if !resp.status().is_success() {
            let status = resp.status();
            let text = resp.text().await.unwrap_or_default();
            bail!("OpenAI API error ({}): {}", status, text);
        }

        let json: serde_json::Value = resp.json().await?;
        let text = json["choices"][0]["message"]["content"]
            .as_str()
            .unwrap_or("")
            .to_string();
        Ok(text)
    }

    async fn call_ollama(&self, client: &reqwest::Client, prompt: &str) -> Result<String> {
        let url = format!("{}/api/generate", self.ollama_url.trim_end_matches('/'));
        let body = serde_json::json!({
            "model": self.model,
            "prompt": prompt,
            "stream": false,
            "options": {
                "temperature": 0.3,
                "num_predict": 4096,
            }
        });

        let resp = client
            .post(&url)
            .json(&body)
            .send()
            .await?;

        if !resp.status().is_success() {
            let status = resp.status();
            let text = resp.text().await.unwrap_or_default();
            bail!("Ollama API error ({}): {}", status, text);
        }

        let json: serde_json::Value = resp.json().await?;
        let text = json["response"]
            .as_str()
            .unwrap_or("")
            .to_string();
        Ok(text)
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

    // Last resort: try serde_json's streaming parser to find valid JSON
    // by trimming from the front until we find a `{`
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
/// Uses serde_json's parser for brace matching to correctly handle
/// braces inside JSON strings (e.g., "summary": "fix {dir}").
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

    // No fencing — return as-is, let the caller handle it
    text
}
