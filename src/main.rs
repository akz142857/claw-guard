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

    /// LLM provider for local mode
    #[arg(long, value_enum, default_value_t = llm::Provider::Anthropic)]
    provider: llm::Provider,

    /// LLM model name
    #[arg(long)]
    model: Option<String>,

    /// Ollama server URL (local mode only)
    #[arg(long, default_value = "http://localhost:11434")]
    ollama_url: String,
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

    // ── --list-rules ────────────────────────────────────────────────────
    if cli.list_rules {
        println!(
            "{:<12} {:<8} {:<22} {}",
            "ID", "SEV", "CATEGORY", "NAME"
        );
        println!("{}", "-".repeat(76));
        for rule in &all_rules {
            let m = rule.meta();
            println!(
                "{:<12} {:<8} {:<22} {}",
                m.id, m.severity, m.category, m.name
            );
            println!("             {}", m.description);
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
        let meta = rule.meta();

        // Category filter
        if let Some(ref filter) = category_filter {
            let cat_str = format!("{:?}", meta.category).to_lowercase();
            if !cat_str.contains(filter) {
                continue;
            }
        }

        rules_run += 1;
        info!("[{}] {}", meta.id, meta.name);

        match rule.evaluate() {
            Ok(findings) => all_findings.extend(findings),
            Err(e) => {
                error!("[{}] Rule failed: {}", meta.id, e);
                all_findings.push(meta.finding(
                    engine::Status::Error,
                    format!("Rule evaluation failed: {}", e),
                ));
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
                    info!("No API key provided, skipping LLM analysis. Use --api-key or set CLAW_GUARD_API_KEY");
                    return Ok(None);
                }
            };

            // Default model per provider
            let model = cli.model.clone().unwrap_or_else(|| {
                match cli.provider {
                    llm::Provider::Anthropic => "claude-sonnet-4-20250514".to_string(),
                    llm::Provider::Openai => "gpt-4o".to_string(),
                    llm::Provider::Ollama => "llama3".to_string(),
                }
            });

            let analyzer = llm::local::LocalAnalyzer {
                provider: cli.provider.clone(),
                api_key,
                model,
                ollama_url: cli.ollama_url.clone(),
            };

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
