mod engine;
mod llm;
mod platform;
mod report;
mod rules;

use anyhow::{Context, Result};
use clap::Parser;
use serde::{Deserialize, Serialize};
use std::path::PathBuf;
use tracing::{error, info, warn};

const API_URL: &str = "https://install9.ai/api/claw-guard";

#[derive(Parser, Debug)]
#[command(name = "claw-guard")]
#[command(about = "AI Agent host system security audit tool")]
#[command(version)]
struct Cli {
    /// Skip uploading report to platform (disables agent registration, report upload,
    /// and server-side analysis — fully offline mode)
    #[arg(long)]
    no_upload: bool,

    /// List all detection rules and exit
    #[arg(long)]
    list_rules: bool,

    // ── LLM Analysis ────────────────────────────────────────────────────

    /// LLM provider API key for local analysis (e.g. Anthropic, OpenAI).
    /// Not needed for install9 platform access — that uses auto-registration.
    /// Prefer CLAW_GUARD_API_KEY env var to avoid process list exposure.
    #[arg(long, env = "CLAW_GUARD_API_KEY", hide_env_values = true)]
    api_key: Option<String>,

    /// LLM provider name (anthropic, openai, ollama, openrouter, together, mistral,
    /// deepseek, moonshot, glm, qwen, nvidia, minimax, huggingface, cloudflare, etc.)
    /// Use --list-providers to see all supported providers.
    #[arg(long, default_value = "anthropic")]
    provider: String,

    /// LLM model name (overrides provider default)
    #[arg(long)]
    model: Option<String>,

    /// Custom base URL for any OpenAI-compatible endpoint.
    /// Overrides the provider's default URL. Useful for proxies, gateways, or unlisted providers.
    #[arg(long)]
    base_url: Option<String>,

    /// List all supported LLM providers and exit
    #[arg(long)]
    list_providers: bool,
}

// ── Agent registration ──────────────────────────────────────────────────

#[derive(Debug, Serialize, Deserialize)]
struct AgentConfig {
    agent_id: String,
    api_url: String,
}

/// Returns the path to ~/.claw-guard/agent.json
fn agent_config_path() -> PathBuf {
    platform::home_dir().join(".claw-guard").join("agent.json")
}

/// Auto-register with the backend, caching agent_id locally.
///
/// - If `~/.claw-guard/agent.json` exists and its `api_url` matches, returns the saved agent_id.
/// - Otherwise, calls `POST {api_url}/register` and saves the response.
async fn get_or_register_agent(api_url: &str) -> Result<String> {
    let config_path = agent_config_path();

    // Try to read existing config
    if config_path.exists() {
        let data = std::fs::read_to_string(&config_path)
            .context("Failed to read agent.json")?;
        if let Ok(config) = serde_json::from_str::<AgentConfig>(&data) {
            if config.api_url == api_url {
                info!("Using cached agent_id: {}", config.agent_id);
                return Ok(config.agent_id);
            }
            info!("API URL changed, re-registering agent");
        }
    }

    // Register with backend
    let hostname = gethostname::gethostname().to_string_lossy().to_string();
    let register_url = format!("{}/register", api_url.trim_end_matches('/'));
    info!("Registering agent at {}...", register_url);

    #[derive(Serialize)]
    struct RegisterRequest {
        hostname: String,
        os: String,
        arch: String,
        version: String,
    }

    #[derive(Deserialize)]
    struct RegisterResponse {
        agent_id: String,
    }

    let client = reqwest::Client::new();
    let resp = client
        .post(&register_url)
        .json(&RegisterRequest {
            hostname,
            os: std::env::consts::OS.to_string(),
            arch: std::env::consts::ARCH.to_string(),
            version: env!("CARGO_PKG_VERSION").to_string(),
        })
        .send()
        .await
        .context("Failed to connect to registration endpoint")?;

    if !resp.status().is_success() {
        let status = resp.status();
        let text = resp.text().await.unwrap_or_default();
        anyhow::bail!("Registration failed ({}): {}", status, text);
    }

    let reg_resp: RegisterResponse = resp.json().await
        .context("Failed to parse registration response")?;

    // Save to disk
    let config = AgentConfig {
        agent_id: reg_resp.agent_id.clone(),
        api_url: api_url.to_string(),
    };

    if let Some(parent) = config_path.parent() {
        std::fs::create_dir_all(parent)
            .context("Failed to create ~/.claw-guard directory")?;
    }
    let json = serde_json::to_string_pretty(&config)?;
    std::fs::write(&config_path, &json)
        .context("Failed to write agent.json")?;

    info!("Agent registered: {}", config.agent_id);
    Ok(config.agent_id)
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .with_target(false)
        .with_writer(std::io::stderr)
        .init();

    let cli = Cli::parse();

    // ── Load built-in rules ─────────────────────────────────────────────
    let mut all_rules = engine::registry::all_rules();
    let builtin_count = all_rules.len();

    // ── Load skills from ~/.claw-guard/skills/ ────────────────────────
    let mut skills_loaded: usize = 0;
    {
        let skill_dir = default_skill_dir();
        match engine::skill::load_skills(&skill_dir) {
            Ok(skill_rules) => {
                skills_loaded = skill_rules.len();
                all_rules.extend(skill_rules);
            }
            Err(e) => {
                warn!("Failed to load skills from {}: {}", skill_dir.display(), e);
            }
        }
    }

    // ── --list-providers ──────────────────────────────────────────────
    if cli.list_providers {
        println!(
            "{:<16} {:<28} {:<30} {}",
            "PROVIDER", "DISPLAY NAME", "DEFAULT MODEL", "BASE URL"
        );
        println!("{}", "-".repeat(100));
        for p in llm::providers::all_providers() {
            println!(
                "{:<16} {:<28} {:<30} {}",
                p.name, p.display_name, p.default_model, p.base_url
            );
        }
        println!(
            "\nTip: use --base-url to override any provider's URL, or connect to unlisted OpenAI-compatible endpoints."
        );
        return Ok(());
    }

    // ── --list-rules ────────────────────────────────────────────────────
    if cli.list_rules {
        println!(
            "{:<12} {:<8} {:<22} {}",
            "ID", "SEV", "CATEGORY", "NAME"
        );
        println!("{}", "-".repeat(76));
        for rule in &all_rules {
            println!(
                "{:<12} {:<8} {:<22} {}",
                rule.id(), rule.severity(), rule.category(), rule.name()
            );
            println!("             {}", rule.description());
        }
        if skills_loaded > 0 {
            println!("\n({} built-in rules + {} skills)", builtin_count, skills_loaded);
        }
        return Ok(());
    }

    info!(
        "claw-guard v{} — {} rules + {} skills loaded",
        env!("CARGO_PKG_VERSION"),
        builtin_count,
        skills_loaded,
    );

    // ── Evaluate rules ──────────────────────────────────────────────────
    let mut all_findings = Vec::new();
    let mut rules_run = 0usize;

    for rule in &all_rules {

        rules_run += 1;
        info!("[{}] {}", rule.id(), rule.name());

        match rule.evaluate() {
            Ok(findings) => all_findings.extend(findings),
            Err(e) => {
                error!("[{}] Rule failed: {}", rule.id(), e);
                all_findings.push(engine::Finding {
                    rule_id: rule.id().to_string(),
                    rule_name: rule.name().to_string(),
                    category: rule.category(),
                    severity: rule.severity(),
                    status: engine::Status::Error,
                    detail: format!("Rule evaluation failed: {}", e),
                    evidence: None,
                    remediation: rule.remediation().to_string(),
                });
            }
        }
    }

    // ── Auto-register + get agent_id (unless --no-upload) ──────────────
    let agent_id = if !cli.no_upload {
        match get_or_register_agent(API_URL).await {
            Ok(id) => Some(id),
            Err(e) => {
                error!("Agent registration failed: {}", e);
                None
            }
        }
    } else {
        None
    };

    // ── Build report ────────────────────────────────────────────────────
    let mut report = report::AuditReport::new(all_findings, rules_run, agent_id.clone());

    if skills_loaded > 0 {
        report.skills_loaded = Some(skills_loaded);
    }

    // ── LLM Analysis ────────────────────────────────────────────────────
    //
    // Automatic mode selection:
    //   - Has API key (or no-auth provider) → local LLM analysis
    //   - No API key + upload enabled → server-side analysis during upload
    //   - No API key + --no-upload → no analysis
    //
    let mut local_analysis_done = false;
    match run_local_analysis(&cli, &report).await {
        Ok(Some(result)) => {
            report.analysis = Some(result.analysis);
            report.web_url = result.web_url;
            local_analysis_done = true;
        }
        Ok(None) => {
            // No API key — will let server analyze during upload
            if !cli.no_upload {
                info!("No LLM API key configured — analysis will be performed by install9 server during upload");
            }
        }
        Err(e) => {
            error!("LLM analysis failed: {}", e);
        }
    }

    // ── Upload report ───────────────────────────────────────────────────
    //
    // If local analysis was skipped (no API key), ask the server to
    // analyze during upload (analyze=true query param).
    //
    if !cli.no_upload {
        if agent_id.is_some() {
            let need_remote_analysis = !local_analysis_done;
            let upload_url = format!("{}/reports", API_URL.trim_end_matches('/'));
            info!("Uploading report to {}...", upload_url);
            match upload_report(&upload_url, &report, need_remote_analysis).await {
                Ok(upload_resp) => {
                    // If server returned analysis, merge it into the report
                    if let Some(analysis) = upload_resp.analysis {
                        report.analysis = Some(analysis);
                    }
                    if upload_resp.web_url.is_some() {
                        report.web_url = upload_resp.web_url;
                    }
                    println!("\n\u{2714} Report: https://install9.ai/reports/{}", upload_resp.report_id);
                }
                Err(e) => error!("Failed to upload report: {}", e),
            }
        }
    }

    // ── Output ──────────────────────────────────────────────────────────
    report.print_terminal();

    // ── Exit code ───────────────────────────────────────────────────────
    if report.summary.critical_findings > 0 {
        std::process::exit(2);
    } else if report.summary.high_findings > 0 {
        std::process::exit(1);
    }

    Ok(())
}

/// Run local LLM analysis if an API key / provider is configured.
async fn run_local_analysis(
    cli: &Cli,
    report: &report::AuditReport,
) -> Result<Option<llm::AnalysisResult>> {
    use llm::Analyzer;

    let api_key = match &cli.api_key {
        Some(k) if !k.is_empty() => k.clone(),
        _ => {
            // Allow empty key for providers that don't require auth (ollama, vllm, etc.)
            let provider = llm::providers::find_provider(&cli.provider);
            let needs_key = provider
                .map(|p| p.auth_type != llm::providers::AuthType::None)
                .unwrap_or(true);
            if needs_key {
                info!("No API key provided, skipping local LLM analysis. Use --api-key or set CLAW_GUARD_API_KEY");
                return Ok(None);
            }
            String::new()
        }
    };

    let config = match llm::providers::find_provider(&cli.provider) {
        Some(provider_config) => llm::adapter::ResolvedConfig::from_provider(
            provider_config,
            api_key,
            cli.model.clone(),
            cli.base_url.clone(),
        ),
        None => {
            // Unknown provider — require --base-url, assume OpenAI-compatible
            let base_url = match &cli.base_url {
                Some(url) => url.clone(),
                None => {
                    let known: Vec<_> = llm::providers::all_providers()
                        .iter()
                        .map(|p| p.name)
                        .collect();
                    error!(
                        "Unknown provider '{}'. Known providers: {}. Or use --base-url for custom endpoints.",
                        cli.provider,
                        known.join(", ")
                    );
                    return Ok(None);
                }
            };
            let model = cli.model.clone().unwrap_or_else(|| "default".to_string());
            llm::adapter::ResolvedConfig::custom(
                cli.provider.clone(),
                base_url,
                api_key,
                model,
            )
        }
    };

    let analyzer = llm::local::LocalAnalyzer { config };
    let result = analyzer.analyze(report).await?;
    Ok(Some(result))
}

#[derive(Debug, Deserialize)]
struct UploadResponse {
    report_id: String,
    #[serde(default)]
    web_url: Option<String>,
    /// Server-side analysis result (returned when analyze=true)
    #[serde(default)]
    analysis: Option<llm::AnalysisReport>,
}

async fn upload_report(
    api_url: &str,
    report: &report::AuditReport,
    request_analysis: bool,
) -> Result<UploadResponse> {
    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(if request_analysis { 120 } else { 30 }))
        .build()?;

    let url = if request_analysis {
        format!("{}?analyze=true", api_url)
    } else {
        api_url.to_string()
    };

    if request_analysis {
        info!("Requesting server-side analysis (no local API key)...");
    }

    let resp = client.post(&url).json(report).send().await?;
    if resp.status().is_success() {
        let upload_resp: UploadResponse = resp.json().await
            .context("Failed to parse upload response")?;
        Ok(upload_resp)
    } else {
        anyhow::bail!("Upload failed with status: {}", resp.status());
    }
}

/// Default skill directory: ~/.claw-guard/skills/
fn default_skill_dir() -> PathBuf {
    platform::home_dir().join(".claw-guard").join("skills")
}
