/// Protocol adapters — unified interface for calling different LLM APIs.

use anyhow::{bail, Result};
use tracing::debug;

use super::providers::{AuthType, Protocol, ProviderConfig};

/// Resolved runtime configuration — registry defaults merged with CLI overrides.
#[derive(Debug, Clone)]
pub struct ResolvedConfig {
    pub provider_name: String,
    pub base_url: String,
    pub api_path: String,
    pub api_key: String,
    pub model: String,
    pub auth_type: AuthType,
    pub protocol: Protocol,
}

impl ResolvedConfig {
    /// Build from a ProviderConfig + CLI overrides.
    pub fn from_provider(
        config: &ProviderConfig,
        api_key: String,
        model_override: Option<String>,
        base_url_override: Option<String>,
    ) -> Self {
        Self {
            provider_name: config.name.to_string(),
            base_url: base_url_override
                .unwrap_or_else(|| config.base_url.to_string())
                .trim_end_matches('/')
                .to_string(),
            api_path: config.api_path.to_string(),
            api_key,
            model: model_override.unwrap_or_else(|| config.default_model.to_string()),
            auth_type: config.auth_type,
            protocol: config.protocol,
        }
    }

    /// Build for a custom (unknown) provider — assumes OpenAI-compatible.
    pub fn custom(
        provider_name: String,
        base_url: String,
        api_key: String,
        model: String,
    ) -> Self {
        Self {
            provider_name,
            base_url: base_url.trim_end_matches('/').to_string(),
            api_path: "/v1/chat/completions".to_string(),
            auth_type: if api_key.is_empty() {
                AuthType::None
            } else {
                AuthType::BearerToken
            },
            api_key,
            model,
            protocol: Protocol::OpenAiCompat,
        }
    }

    fn endpoint_url(&self) -> String {
        format!("{}{}", self.base_url, self.api_path)
    }
}

/// Call the LLM provider and return the response text.
pub async fn call_llm(
    client: &reqwest::Client,
    config: &ResolvedConfig,
    prompt: &str,
) -> Result<String> {
    match config.protocol {
        Protocol::OpenAiCompat => call_openai_compat(client, config, prompt).await,
        Protocol::Anthropic => call_anthropic(client, config, prompt).await,
    }
}

/// Generic OpenAI-compatible chat completions call.
/// Works for: OpenAI, Ollama, OpenRouter, Together, Mistral, NVIDIA,
/// GLM, Qwen, Moonshot, MiniMax, DeepSeek, HuggingFace, vLLM, LiteLLM,
/// Cloudflare, Vercel, Venice, Xiaomi, Z.AI, Kilocode, OpenCode Zen, etc.
async fn call_openai_compat(
    client: &reqwest::Client,
    config: &ResolvedConfig,
    prompt: &str,
) -> Result<String> {
    let url = config.endpoint_url();
    debug!("OpenAI-compat POST {}", url);

    // Newer OpenAI models (o1, gpt-4.1, gpt-5, etc.) require max_completion_tokens
    // instead of max_tokens. Use max_completion_tokens for OpenAI provider,
    // keep max_tokens for other OpenAI-compatible providers (broader compat).
    let token_limit_key = if config.provider_name == "openai" {
        "max_completion_tokens"
    } else {
        "max_tokens"
    };

    let body = serde_json::json!({
        "model": config.model,
        "messages": [
            {"role": "system", "content": "You are a security analyst. Output only valid JSON."},
            {"role": "user", "content": prompt}
        ],
        "temperature": 0.3,
        token_limit_key: 4096,
    });

    let mut req = client.post(&url).header("Content-Type", "application/json");

    req = match config.auth_type {
        AuthType::BearerToken => {
            req.header("Authorization", format!("Bearer {}", config.api_key))
        }
        AuthType::XApiKey => req.header("x-api-key", &config.api_key),
        AuthType::None => req,
    };

    let resp = req.json(&body).send().await?;

    if !resp.status().is_success() {
        let status = resp.status();
        let text = resp.text().await.unwrap_or_default();
        // Try to extract error message from JSON response
        let detail = extract_error_message(&text).unwrap_or(text);
        bail!("{} API error ({}): {}", config.provider_name, status, detail);
    }

    let json: serde_json::Value = resp.json().await?;
    let text = json["choices"][0]["message"]["content"]
        .as_str()
        .unwrap_or("")
        .to_string();
    Ok(text)
}

/// Anthropic Messages API call.
async fn call_anthropic(
    client: &reqwest::Client,
    config: &ResolvedConfig,
    prompt: &str,
) -> Result<String> {
    let url = config.endpoint_url();
    debug!("Anthropic POST {}", url);

    let body = serde_json::json!({
        "model": config.model,
        "max_tokens": 4096,
        "messages": [
            {"role": "user", "content": prompt}
        ]
    });

    let resp = client
        .post(&url)
        .header("x-api-key", &config.api_key)
        .header("anthropic-version", "2023-06-01")
        .header("content-type", "application/json")
        .json(&body)
        .send()
        .await?;

    if !resp.status().is_success() {
        let status = resp.status();
        let text = resp.text().await.unwrap_or_default();
        let detail = extract_error_message(&text).unwrap_or(text);
        bail!("Anthropic API error ({}): {}", status, detail);
    }

    let json: serde_json::Value = resp.json().await?;
    let text = json["content"][0]["text"]
        .as_str()
        .unwrap_or("")
        .to_string();
    Ok(text)
}

/// Try to extract a human-readable error message from a JSON error response.
fn extract_error_message(body: &str) -> Option<String> {
    let json: serde_json::Value = serde_json::from_str(body).ok()?;
    // OpenAI style: {"error": {"message": "..."}}
    if let Some(msg) = json["error"]["message"].as_str() {
        return Some(msg.to_string());
    }
    // Anthropic style: {"error": {"type": "...", "message": "..."}}
    if let Some(msg) = json["message"].as_str() {
        return Some(msg.to_string());
    }
    None
}
