pub mod parser;
pub mod runner;

use anyhow::Result;
use std::path::Path;
use tracing::{info, warn};

use super::{Finding, OwnedRuleMeta, Rule};

/// A rule loaded from a Skill .md file.
/// Uses OwnedRuleMeta to avoid Box::leak memory leak.
pub struct SkillRule {
    pub(crate) meta: OwnedRuleMeta,
    pub(crate) evaluate_cmd: String,
    pub(crate) timeout_secs: u64,
    #[allow(dead_code)]
    pub(crate) source_path: String,
}

impl Rule for SkillRule {
    fn id(&self) -> &str {
        &self.meta.id
    }
    fn name(&self) -> &str {
        &self.meta.name
    }
    fn description(&self) -> &str {
        &self.meta.description
    }
    fn category(&self) -> super::Category {
        self.meta.category
    }
    fn severity(&self) -> super::Severity {
        self.meta.severity
    }
    fn remediation(&self) -> &str {
        &self.meta.remediation
    }

    fn evaluate(&self) -> Result<Vec<Finding>> {
        runner::run_skill_command(&self.meta, &self.evaluate_cmd, self.timeout_secs)
    }
}

/// Load all skill files from a directory.
/// Looks for *.md files with valid frontmatter containing an `## Evaluate` section.
pub fn load_skills(dir: &Path) -> Result<Vec<Box<dyn Rule>>> {
    let mut skills: Vec<Box<dyn Rule>> = Vec::new();

    if !dir.exists() {
        info!("Skill directory {} does not exist, skipping", dir.display());
        return Ok(skills);
    }

    let entries = std::fs::read_dir(dir)?;
    for entry in entries {
        let entry = entry?;
        let path = entry.path();

        // Support both flat .md files and subdirectory/SKILL.md
        let skill_path = if path.is_dir() {
            let skill_md = path.join("SKILL.md");
            if skill_md.exists() {
                skill_md
            } else {
                continue;
            }
        } else if path.extension().map_or(false, |e| e == "md") {
            let name = path.file_stem().unwrap_or_default().to_string_lossy();
            if name.eq_ignore_ascii_case("readme") {
                continue;
            }
            path.clone()
        } else {
            continue;
        };

        match parser::parse_skill_file(&skill_path) {
            Ok(Some(skill)) => {
                info!("Loaded skill: {} ({})", skill.id(), skill.name());
                skills.push(Box::new(skill));
            }
            Ok(None) => {
                info!("Skipped {}: not a security audit skill", skill_path.display());
            }
            Err(e) => {
                warn!("Failed to load skill {}: {}", skill_path.display(), e);
            }
        }
    }

    info!("Loaded {} skill(s)", skills.len());
    Ok(skills)
}
