pub mod parser;
pub mod runner;

use anyhow::Result;
use std::path::Path;
use tracing::{info, warn};

use super::{Finding, Rule, RuleMeta};

/// A rule loaded from a Skill .md file
pub struct SkillRule {
    meta: RuleMeta,
    evaluate_cmd: String,
    timeout_secs: u64,
}

impl Rule for SkillRule {
    fn meta(&self) -> &RuleMeta {
        &self.meta
    }

    fn evaluate(&self) -> Result<Vec<Finding>> {
        runner::run_skill_command(&self.meta, &self.evaluate_cmd, self.timeout_secs)
    }
}

/// Load all skill files from a directory
/// Looks for *.md files with valid frontmatter containing `evaluate` section
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
            // Skip files that don't look like skill files (e.g. README.md)
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
                info!("Loaded skill: {} ({})", skill.meta().id, skill.meta().name);
                skills.push(Box::new(skill));
            }
            Ok(None) => {
                // Not a valid claw-guard skill (e.g. missing evaluate section)
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
