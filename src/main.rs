mod engine;
mod llm;
mod platform;
mod report;
mod rules;

use anyhow::Result;
use clap::Parser;
use std::path::PathBuf;
use tracing::{error, info, warn};

#[derive(Parser, Debug)]
#[command(name = "claw-guard")]
#[command(about = "AI Agent host system security audit tool")]
#[command(version)]
struct Cli {
    /// Platform ID for report upload
    #[arg(long)]
    platform_id: Option<String>,

    /// Output report as JSON to stdout
    #[arg(long)]
    json: bool,

    /// Save report to file
    #[arg(long)]
    output: Option<String>,

    /// API base URL for the install9 platform
    #[arg(long, default_value = "https://install9.ai/api/claw-guard")]
    api_url: String,

    /// Skip uploading report to platform
    #[arg(long)]
    no_upload: bool,

    /// Only run rules matching this category (e.g. credential, gateway, sandbox, skill)
    #[arg(long)]
    category: Option<String>,

    /// List all detection rules and exit
    #[arg(long)]
    list_rules: bool,

    // ── Skills ──────────────────────────────────────────────────────────

    /// Directory to load skill .md files from (default: ~/.claw-guard/skills/)
    #[arg(long)]
    skill_dir: Option<String>,

    /// Skip loading external skills
    #[arg(long)]
    no_skills: bool,

    // ── LLM Analysis ────────────────────────────────────────────────────

    /// Analysis mode: local (use your own API key) or remote (send to install9 platform)
    #[arg(long, value_enum, default_value_t = Mode::Local)]
    mode: Mode,

    /// Skip LLM analysis, only output raw findings (classic behavior)
    #[arg(long)]
    no_analyze: bool,

    /// LLM API key (prefer CLAW_GUARD_API_KEY env var to avoid process list exposure)
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

#[derive(Debug, Clone, clap::ValueEnum)]
enum Mode {
    Local,
    Remote,
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

    // ── Load skills ─────────────────────────────────────────────────────
    let mut skills_loaded: usize = 0;
    if !cli.no_skills {
        let skill_dir = match &cli.skill_dir {
            Some(d) => PathBuf::from(d),
            None => default_skill_dir(),
        };

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
    let category_filter = cli.category.as_deref().map(|c| c.to_lowercase());

    let mut all_findings = Vec::new();
    let mut rules_run = 0usize;

    for rule in &all_rules {
        // Category filter
        if let Some(ref filter) = category_filter {
            let cat_str = format!("{:?}", rule.category()).to_lowercase();
            if !cat_str.contains(filter) {
                continue;
            }
        }

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

    // ── Build report ────────────────────────────────────────────────────
    let mut report = report::AuditReport::new(all_findings, rules_run, cli.platform_id.clone());

    if skills_loaded > 0 {
        report.skills_loaded = Some(skills_loaded);
    }

    // ── LLM Analysis ────────────────────────────────────────────────────
    if !cli.no_analyze {
        match run_analysis(&cli, &report).await {
            Ok(Some(result)) => {
                report.analysis = Some(result.analysis);
                report.web_url = result.web_url;
            }
            Ok(None) => {
                // Analysis skipped (no API key, etc.)
            }
            Err(e) => {
                error!("LLM analysis failed: {}", e);
            }
        }
    }

    // ── Output ──────────────────────────────────────────────────────────
    if cli.json {
        println!("{}", serde_json::to_string_pretty(&report)?);
    } else {
        report.print_terminal();
    }

    // Save to file
    if let Some(ref path) = cli.output {
        let json = serde_json::to_string_pretty(&report)?;
        std::fs::write(path, &json)?;
        info!("Report saved to {}", path);
    }

    // Upload (raw report, separate from analysis)
    if !cli.no_upload {
        if let Some(ref _pid) = cli.platform_id {
            let upload_url = format!("{}/report", cli.api_url.trim_end_matches('/'));
            info!("Uploading report to {}...", upload_url);
            match upload_report(&upload_url, &report).await {
                Ok(_) => info!("Report uploaded successfully"),
                Err(e) => error!("Failed to upload report: {}", e),
            }
        }
    }

    // ── Exit code ───────────────────────────────────────────────────────
    if report.summary.critical_findings > 0 {
        std::process::exit(2);
    } else if report.summary.high_findings > 0 {
        std::process::exit(1);
    }

    Ok(())
}

/// Run LLM analysis based on mode (local or remote).
/// Returns (AnalysisReport, Option<web_url>).
async fn run_analysis(
    cli: &Cli,
    report: &report::AuditReport,
) -> Result<Option<llm::AnalysisResult>> {
    use llm::Analyzer;

    match cli.mode {
        Mode::Local => {
            let api_key = match &cli.api_key {
                Some(k) if !k.is_empty() => k.clone(),
                _ => {
                    // Allow empty key for providers that don't require auth (ollama, vllm, etc.)
                    let provider = llm::providers::find_provider(&cli.provider);
                    let needs_key = provider
                        .map(|p| p.auth_type != llm::providers::AuthType::None)
                        .unwrap_or(true);
                    if needs_key {
                        info!("No API key provided, skipping LLM analysis. Use --api-key or set CLAW_GUARD_API_KEY");
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

        Mode::Remote => {
            let platform_id = match &cli.platform_id {
                Some(id) => id.clone(),
                None => {
                    info!("Remote mode requires --platform-id, skipping analysis");
                    return Ok(None);
                }
            };

            let analyzer = llm::remote::RemoteAnalyzer {
                api_url: cli.api_url.clone(),
                platform_id,
            };

            let result = analyzer.analyze(report).await?;
            Ok(Some(result))
        }
    }
}

async fn upload_report(api_url: &str, report: &report::AuditReport) -> Result<()> {
    let client = reqwest::Client::new();
    let resp = client.post(api_url).json(report).send().await?;
    if resp.status().is_success() {
        Ok(())
    } else {
        anyhow::bail!("Upload failed with status: {}", resp.status());
    }
}

/// Default skill directory: ~/.claw-guard/skills/
fn default_skill_dir() -> PathBuf {
    platform::home_dir().join(".claw-guard").join("skills")
}
