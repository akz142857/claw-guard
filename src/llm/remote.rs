use anyhow::{bail, Result};
use tracing::info;

use super::{AnalysisReport, AnalysisResult, Analyzer};
use crate::report::AuditReport;

pub struct RemoteAnalyzer {
    pub api_url: String,
    pub platform_id: String,
}

#[async_trait::async_trait]
impl Analyzer for RemoteAnalyzer {
    async fn analyze(&self, report: &AuditReport) -> Result<AnalysisResult> {
        let url = format!("{}/analyze", self.api_url.trim_end_matches('/'));
        info!("Sending report to {} for analysis...", url);

        let client = reqwest::Client::new();
        let resp = client
            .post(&url)
            .header("X-Platform-Id", &self.platform_id)
            .json(report)
            .send()
            .await?;

        if !resp.status().is_success() {
            let status = resp.status();
            let text = resp.text().await.unwrap_or_default();
            bail!("Remote analysis failed ({}): {}", status, text);
        }

        #[derive(serde::Deserialize)]
        struct RemoteResponse {
            analysis: AnalysisReport,
            #[serde(default)]
            web_url: Option<String>,
        }

        let remote_resp: RemoteResponse = resp.json().await?;

        if let Some(ref url) = remote_resp.web_url {
            info!("Web report: {}", url);
        }

        Ok(AnalysisResult {
            analysis: remote_resp.analysis,
            web_url: remote_resp.web_url,
        })
    }
}
