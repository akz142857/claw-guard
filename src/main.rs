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
const GITHUB_REPO: &str = "akz142857/claw-guard";

#[derive(Deserialize)]
struct GithubRelease {
    tag_name: String,
}

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

    /// Remove all claw-guard data (~/.claw-guard/) and exit
    #[arg(long)]
    purge_data: bool,

    /// Uninstall claw-guard completely (remove data + binary) and exit
    #[arg(long)]
    uninstall: bool,

    /// Check for updates and upgrade to the latest version
    #[arg(long)]
    upgrade: bool,

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

    // ── --purge-data ──────────────────────────────────────────────────
    if cli.purge_data {
        let data_dir = platform::home_dir().join(".claw-guard");
        if data_dir.exists() {
            std::fs::remove_dir_all(&data_dir)
                .context("Failed to remove ~/.claw-guard")?;
            println!("\u{2714} Removed {}", data_dir.display());
        } else {
            println!("Nothing to remove ({}/ does not exist)", data_dir.display());
        }
        println!("Data purged. To fully uninstall, also delete the binary.");
        return Ok(());
    }

    // ── --uninstall ─────────────────────────────────────────────────────
    if cli.uninstall {
        let data_dir = platform::home_dir().join(".claw-guard");
        if data_dir.exists() {
            std::fs::remove_dir_all(&data_dir)
                .context("Failed to remove ~/.claw-guard")?;
            println!("\u{2714} Removed {}", data_dir.display());
        }

        let exe = std::env::current_exe()
            .context("Failed to determine current executable path")?;
        // On some OS the running binary can't delete itself directly;
        // spawn a background process to remove it after we exit.
        if cfg!(target_os = "windows") {
            let _ = std::process::Command::new("cmd")
                .args(["/C", "ping", "127.0.0.1", "-n", "2", ">nul", "&", "del", "/f"])
                .arg(&exe)
                .spawn();
        } else {
            let _ = std::process::Command::new("sh")
                .args(["-c", &format!("sleep 1 && rm -f '{}'", exe.display())])
                .spawn();
        }
        println!("\u{2714} claw-guard has been uninstalled.");
        return Ok(());
    }

    // ── --upgrade ──────────────────────────────────────────────────────
    if cli.upgrade {
        return self_upgrade().await;
    }

    // ── Background version check (non-blocking, once per day) ─────────
    let version_check = tokio::spawn(check_latest_version());

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

    // ── Auto-open web report in browser ──────────────────────────────
    if let Some(ref url) = report.web_url {
        open_browser(url);
    }

    // ── Version check notice ─────────────────────────────────────────
    if let Ok(Some(latest)) = version_check.await {
        eprintln!(
            "\n\u{26A0}  New version available: v{} (current: v{})",
            latest,
            env!("CARGO_PKG_VERSION")
        );
        eprintln!("   Run: claw-guard --upgrade");
    }

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

// ── Open browser ────────────────────────────────────────────────────────

fn open_browser(url: &str) {
    let result = if cfg!(target_os = "macos") {
        std::process::Command::new("open").arg(url).spawn()
    } else if cfg!(target_os = "windows") {
        std::process::Command::new("cmd").args(["/C", "start", url]).spawn()
    } else {
        std::process::Command::new("xdg-open").arg(url).spawn()
    };
    if let Err(e) = result {
        info!("Could not open browser: {}", e);
    }
}

// ── Background version check ────────────────────────────────────────────

#[derive(Serialize, Deserialize)]
struct VersionCache {
    latest_version: String,
    checked_at: i64, // unix timestamp
}

fn version_cache_path() -> PathBuf {
    platform::home_dir().join(".claw-guard").join("version-check.json")
}

/// Non-blocking version check with daily cache.
/// Returns `Some(latest)` if a newer version is available, `None` otherwise.
/// Silently returns `None` on any error (network, parsing, etc.).
async fn check_latest_version() -> Option<String> {
    let current = semver::Version::parse(env!("CARGO_PKG_VERSION")).ok()?;
    let cache_path = version_cache_path();
    let now = chrono::Utc::now().timestamp();

    // Check cache first (valid for 24 hours)
    if cache_path.exists() {
        if let Ok(data) = std::fs::read_to_string(&cache_path) {
            if let Ok(cache) = serde_json::from_str::<VersionCache>(&data) {
                if now - cache.checked_at < 86400 {
                    if let Ok(cached) = semver::Version::parse(&cache.latest_version) {
                        if cached > current {
                            return Some(cache.latest_version);
                        }
                    }
                    return None;
                }
            }
        }
    }

    // Query GitHub API (5-second timeout to avoid blocking)
    let client = reqwest::Client::builder()
        .user_agent(format!("claw-guard/{}", current))
        .timeout(std::time::Duration::from_secs(5))
        .build()
        .ok()?;

    let api_url = format!("https://api.github.com/repos/{}/releases/latest", GITHUB_REPO);
    let resp = client.get(&api_url).send().await.ok()?;

    if !resp.status().is_success() {
        return None;
    }

    let release: GithubRelease = resp.json().await.ok()?;
    let latest = release.tag_name.trim_start_matches('v').to_string();

    // Update cache
    let cache = VersionCache {
        latest_version: latest.clone(),
        checked_at: now,
    };
    if let Some(parent) = cache_path.parent() {
        let _ = std::fs::create_dir_all(parent);
    }
    if let Ok(json) = serde_json::to_string(&cache) {
        let _ = std::fs::write(&cache_path, json);
    }

    let latest_ver = semver::Version::parse(&latest).ok()?;
    if latest_ver > current {
        Some(latest)
    } else {
        None
    }
}

// ── Self-upgrade ────────────────────────────────────────────────────────

/// Map Rust target triples to release asset names.
fn release_asset_name(version: &str) -> Option<String> {
    let os = match std::env::consts::OS {
        "macos" => "darwin",
        "linux" => "linux",
        "windows" => "windows",
        _ => return None,
    };
    let arch = match std::env::consts::ARCH {
        "aarch64" => "arm64",
        "x86_64" => "amd64",
        _ => return None,
    };
    let ext = if std::env::consts::OS == "windows" { "zip" } else { "tar.gz" };
    Some(format!("claw-guard-{}-{}-{}.{}", version, os, arch, ext))
}

/// Clean up the temporary upgrade directory, ignoring errors.
fn cleanup_tmp_dir(tmp_dir: &std::path::Path) {
    let _ = std::fs::remove_dir_all(tmp_dir);
}

async fn self_upgrade() -> Result<()> {
    let current_str = env!("CARGO_PKG_VERSION");
    let current = semver::Version::parse(current_str)
        .context("Failed to parse current version")?;
    println!("Current version: v{}", current);
    println!("Checking for updates...");

    let client = reqwest::Client::builder()
        .user_agent(format!("claw-guard/{}", current))
        .timeout(std::time::Duration::from_secs(15))
        .build()?;

    let api_url = format!("https://api.github.com/repos/{}/releases/latest", GITHUB_REPO);
    let resp = client.get(&api_url).send().await
        .context("Failed to check for updates")?;

    if !resp.status().is_success() {
        anyhow::bail!("GitHub API returned {}", resp.status());
    }

    let release: GithubRelease = resp.json().await
        .context("Failed to parse GitHub release")?;

    let latest_str = release.tag_name.trim_start_matches('v');
    let latest = semver::Version::parse(latest_str)
        .context("Failed to parse latest version")?;

    if latest <= current {
        println!("\u{2714} Already up to date (v{})", current);
        return Ok(());
    }

    println!("Latest version:  v{}", latest);

    let asset_name = release_asset_name(&format!("v{}", latest))
        .context("Unsupported platform for auto-upgrade")?;

    let download_url = format!(
        "https://github.com/{}/releases/download/{}/{}",
        GITHUB_REPO, release.tag_name, asset_name
    );
    let checksums_url = format!(
        "https://github.com/{}/releases/download/{}/checksums.txt",
        GITHUB_REPO, release.tag_name
    );

    // Always print manual commands as fallback
    println!("\nManual upgrade:");
    if std::env::consts::OS == "windows" {
        println!("  Invoke-WebRequest -Uri {} -OutFile {}", download_url, asset_name);
        println!("  Expand-Archive {} -DestinationPath .", asset_name);
    } else {
        println!("  curl -LO {}", download_url);
        println!("  tar xzf {}", asset_name);
        println!("  chmod +x claw-guard");
    }

    // Auto-upgrade: download, verify checksum, extract, replace
    println!("\nDownloading {}...", asset_name);
    let dl_resp = client.get(&download_url).send().await
        .context("Failed to download release")?;

    if !dl_resp.status().is_success() {
        anyhow::bail!("Download failed ({}). Use the manual commands above.", dl_resp.status());
    }

    let bytes = dl_resp.bytes().await
        .context("Failed to read download")?;

    // Verify SHA256 checksum if checksums.txt is available
    if let Ok(cs_resp) = client.get(&checksums_url).send().await {
        if cs_resp.status().is_success() {
            if let Ok(checksums_text) = cs_resp.text().await {
                verify_checksum(&bytes, &asset_name, &checksums_text)?;
                println!("\u{2714} Checksum verified");
            }
        }
    }

    // Save to temp directory
    let tmp_dir = std::env::temp_dir().join("claw-guard-upgrade");
    std::fs::create_dir_all(&tmp_dir)?;
    let archive_path = tmp_dir.join(&asset_name);
    std::fs::write(&archive_path, &bytes)?;

    // Extract
    let extract_ok = if std::env::consts::OS == "windows" {
        std::process::Command::new("powershell")
            .args(["Expand-Archive", "-Force", "-Path"])
            .arg(&archive_path)
            .arg("-DestinationPath")
            .arg(&tmp_dir)
            .status()
            .map(|s| s.success())
            .unwrap_or(false)
    } else {
        std::process::Command::new("tar")
            .args(["xzf"])
            .arg(&archive_path)
            .arg("-C")
            .arg(&tmp_dir)
            .status()
            .map(|s| s.success())
            .unwrap_or(false)
    };

    if !extract_ok {
        cleanup_tmp_dir(&tmp_dir);
        anyhow::bail!("Failed to extract archive. Use the manual commands above.");
    }

    // Find extracted binary — may be inside a subdirectory
    let binary_name = if std::env::consts::OS == "windows" { "claw-guard.exe" } else { "claw-guard" };
    let new_binary = find_binary_in_dir(&tmp_dir, binary_name);
    let new_binary = match new_binary {
        Some(p) => p,
        None => {
            cleanup_tmp_dir(&tmp_dir);
            anyhow::bail!("Extracted binary not found. Use the manual commands above.");
        }
    };

    let current_exe = std::env::current_exe()
        .context("Failed to determine current executable path")?;

    // Atomic replacement: copy new binary to a staging path next to the
    // target, then rename (atomic on the same filesystem).
    let staging = current_exe.with_extension("new");
    if let Err(e) = std::fs::copy(&new_binary, &staging) {
        cleanup_tmp_dir(&tmp_dir);
        anyhow::bail!("Cannot stage new binary ({}). Try: sudo claw-guard --upgrade", e);
    }

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(&staging, std::fs::Permissions::from_mode(0o755));
    }

    if let Err(e) = std::fs::rename(&staging, &current_exe) {
        let _ = std::fs::remove_file(&staging);
        cleanup_tmp_dir(&tmp_dir);
        anyhow::bail!("Cannot replace binary ({}). Try: sudo claw-guard --upgrade", e);
    }

    cleanup_tmp_dir(&tmp_dir);
    println!("\u{2714} Upgraded to v{}", latest);
    Ok(())
}

/// Verify SHA256 checksum of downloaded bytes against checksums.txt content.
fn verify_checksum(bytes: &[u8], asset_name: &str, checksums_text: &str) -> Result<()> {
    use std::io::Write;

    // checksums.txt format: "<sha256>  <filename>" per line
    let expected = checksums_text
        .lines()
        .find(|line| line.ends_with(asset_name))
        .and_then(|line| line.split_whitespace().next())
        .context("Checksum for this asset not found in checksums.txt")?;

    // Compute SHA256 using shasum command
    let mut child = std::process::Command::new("shasum")
        .args(["-a", "256"])
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .spawn()
        .context("Failed to run shasum")?;

    child.stdin.take().unwrap().write_all(bytes)?;
    let output = child.wait_with_output()?;
    let actual = String::from_utf8_lossy(&output.stdout);
    let actual = actual.split_whitespace().next().unwrap_or("");

    if !actual.eq_ignore_ascii_case(expected) {
        anyhow::bail!(
            "Checksum mismatch! Expected: {}, Got: {}. Download may be corrupted.",
            expected, actual
        );
    }
    Ok(())
}

/// Recursively find a binary by name in a directory (checks one level of subdirs).
fn find_binary_in_dir(dir: &std::path::Path, name: &str) -> Option<PathBuf> {
    let direct = dir.join(name);
    if direct.exists() {
        return Some(direct);
    }
    // Check one level of subdirectories (e.g., claw-guard-v0.5.0-darwin-arm64/)
    if let Ok(entries) = std::fs::read_dir(dir) {
        for entry in entries.flatten() {
            if entry.file_type().map(|t| t.is_dir()).unwrap_or(false) {
                let nested = entry.path().join(name);
                if nested.exists() {
                    return Some(nested);
                }
            }
        }
    }
    None
}
