mod engine;
mod platform;
mod report;
mod rules;

use anyhow::Result;
use clap::Parser;
use tracing::{error, info};

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

    /// API endpoint for uploading reports
    #[arg(long, default_value = "https://install9.ai/api/claw-guard/report")]
    api_url: String,

    /// Skip uploading report to platform
    #[arg(long)]
    no_upload: bool,

    /// Only run rules matching this category (e.g. credential, gateway, sandbox)
    #[arg(long)]
    category: Option<String>,

    /// List all detection rules and exit
    #[arg(long)]
    list_rules: bool,
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .with_target(false)
        .init();

    let cli = Cli::parse();

    let all_rules = engine::registry::all_rules();

    // --list-rules: print rule table and exit
    if cli.list_rules {
        println!(
            "{:<10} {:<8} {:<22} {}",
            "ID", "SEV", "CATEGORY", "NAME"
        );
        println!("{}", "-".repeat(72));
        for rule in &all_rules {
            let m = rule.meta();
            println!(
                "{:<10} {:<8} {:<22} {}",
                m.id, m.severity, m.category, m.name
            );
            println!("           {}", m.description);
        }
        return Ok(());
    }

    info!(
        "claw-guard v{} — {} detection rules loaded",
        env!("CARGO_PKG_VERSION"),
        all_rules.len()
    );

    // Filter by category if requested
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

    // Build report
    let report = report::AuditReport::new(all_findings, rules_run, cli.platform_id.clone());

    // Output
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

    // Upload
    if !cli.no_upload {
        if let Some(ref _pid) = cli.platform_id {
            info!("Uploading report to {}...", cli.api_url);
            match upload_report(&cli.api_url, &report).await {
                Ok(_) => info!("Report uploaded successfully"),
                Err(e) => error!("Failed to upload report: {}", e),
            }
        }
    }

    // Exit code
    if report.summary.critical_findings > 0 {
        std::process::exit(2);
    } else if report.summary.high_findings > 0 {
        std::process::exit(1);
    }

    Ok(())
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
