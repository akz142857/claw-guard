use anyhow::{bail, Result};
use std::path::Path;

use super::SkillRule;
use crate::engine::{Category, RuleMeta, Severity};

/// Parsed frontmatter from a Skill file
struct SkillFrontmatter {
    name: String,
    description: String,
    #[allow(dead_code)]
    version: String,
    #[allow(dead_code)]
    tags: Vec<String>,
    category: Option<String>,
    severity: Option<String>,
    id: Option<String>,
    remediation: Option<String>,
    timeout: Option<u64>,
}

/// Parse a skill .md file into a SkillRule.
/// Returns Ok(None) if the file is valid markdown but not a claw-guard skill
/// (i.e., it has no ## Evaluate section).
pub fn parse_skill_file(path: &Path) -> Result<Option<SkillRule>> {
    let content = std::fs::read_to_string(path)?;

    // Parse frontmatter
    let fm = parse_frontmatter(&content)?;

    // Extract ## Evaluate section's bash command
    let evaluate_cmd = match extract_evaluate_command(&content) {
        Some(cmd) => cmd,
        None => return Ok(None), // Not a claw-guard audit skill
    };

    // Build rule ID: use frontmatter id or generate from name
    let id = fm.id.unwrap_or_else(|| {
        format!(
            "SK-{}",
            fm.name
                .to_uppercase()
                .replace(|c: char| !c.is_alphanumeric(), "")
        )
    });

    // Map category string to Category enum
    let category = match fm.category.as_deref() {
        Some("credential") => Category::Credential,
        Some("filesystem") => Category::FileSystem,
        Some("network") => Category::Network,
        Some("process") => Category::Process,
        Some("gateway") => Category::GatewayConfig,
        Some("sandbox") => Category::Sandbox,
        Some("plugin") => Category::Plugin,
        Some("dataleak") => Category::DataLeak,
        Some("docker") => Category::Docker,
        _ => Category::Skill,
    };

    // Map severity string
    let severity = match fm.severity.as_deref() {
        Some("critical") => Severity::Critical,
        Some("high") => Severity::High,
        Some("medium") => Severity::Medium,
        Some("low") => Severity::Low,
        Some("info") => Severity::Info,
        _ => Severity::Medium,
    };

    let remediation = fm
        .remediation
        .unwrap_or_else(|| "See skill documentation.".to_string());
    let timeout = fm.timeout.unwrap_or(30);

    // Use Box::leak to create &'static str from owned Strings
    // This is safe because skills are loaded once and live for the program's lifetime
    let meta = RuleMeta {
        id: Box::leak(id.into_boxed_str()),
        name: Box::leak(fm.name.into_boxed_str()),
        description: Box::leak(fm.description.into_boxed_str()),
        category,
        severity,
        remediation: Box::leak(remediation.into_boxed_str()),
    };

    Ok(Some(SkillRule {
        meta,
        evaluate_cmd,
        timeout_secs: timeout,
    }))
}

fn parse_frontmatter(content: &str) -> Result<SkillFrontmatter> {
    // Expect --- delimited YAML frontmatter at the start
    let content = content.trim_start();
    if !content.starts_with("---") {
        bail!("Missing frontmatter (expected --- at start)");
    }

    let after_first = &content[3..];
    let end = after_first
        .find("\n---")
        .ok_or_else(|| anyhow::anyhow!("Missing closing --- for frontmatter"))?;
    let fm_text = &after_first[..end];

    // Simple key: value parsing (no full YAML dependency needed)
    let mut name = None;
    let mut description = None;
    let mut version = String::from("0.0.0");
    let mut tags = Vec::new();
    let mut category = None;
    let mut severity = None;
    let mut id = None;
    let mut remediation = None;
    let mut timeout = None;

    for line in fm_text.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        if let Some((key, value)) = line.split_once(':') {
            let key = key.trim();
            let value = value.trim();
            match key {
                "name" => name = Some(value.to_string()),
                "description" => description = Some(value.to_string()),
                "version" => version = value.to_string(),
                "tags" => {
                    tags = value.split(',').map(|t| t.trim().to_string()).collect();
                }
                "category" => category = Some(value.to_lowercase()),
                "severity" => severity = Some(value.to_lowercase()),
                "id" => id = Some(value.to_string()),
                "remediation" => remediation = Some(value.to_string()),
                "timeout" => timeout = value.parse().ok(),
                _ => {}
            }
        }
    }

    let name = name.ok_or_else(|| anyhow::anyhow!("Frontmatter missing 'name' field"))?;
    let description = description.unwrap_or_else(|| format!("Skill: {}", name));

    Ok(SkillFrontmatter {
        name,
        description,
        version,
        tags,
        category,
        severity,
        id,
        remediation,
        timeout,
    })
}

/// Extract the bash command from the ## Evaluate section
fn extract_evaluate_command(content: &str) -> Option<String> {
    // Find ## Evaluate heading
    let mut in_evaluate = false;
    let mut in_code_block = false;
    let mut command = String::new();

    for line in content.lines() {
        if line.starts_with("## Evaluate") {
            in_evaluate = true;
            continue;
        }

        // Stop at next heading
        if in_evaluate && line.starts_with("## ") && !line.starts_with("## Evaluate") {
            break;
        }

        if in_evaluate {
            if line.starts_with("```bash") || line.starts_with("```sh") {
                in_code_block = true;
                continue;
            }
            if in_code_block && line.starts_with("```") {
                in_code_block = false;
                continue;
            }
            if in_code_block {
                if !command.is_empty() {
                    command.push('\n');
                }
                command.push_str(line);
            }
        }
    }

    if command.is_empty() {
        None
    } else {
        Some(command)
    }
}
