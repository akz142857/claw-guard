use crate::engine::*;
use crate::platform;
use anyhow::Result;

/// CG-F003: Legacy OpenClaw data directories with potentially stale credentials
pub struct CgF003;

static META: RuleMeta = RuleMeta {
    id: "CG-F003",
    name: "Legacy config data residue",
    description: "Checks for leftover data from previous OpenClaw versions (~/.clawdbot, \
                  ~/.moldbot, ~/.moltbot) that may contain stale credentials and tokens.",
    category: Category::FileSystem,
    severity: Severity::Medium,
    remediation: "Remove legacy directories after migrating data: \
                  rm -rf ~/.clawdbot ~/.moldbot ~/.moltbot",
};

impl Rule for CgF003 {
    fn meta(&self) -> &RuleMeta {
        &META
    }

    fn evaluate(&self) -> Result<Vec<Finding>> {
        let home = platform::home_dir();
        let legacy_dirs = vec![
            home.join(".clawdbot"),
            home.join(".moldbot"),
            home.join(".moltbot"),
        ];

        let mut found = Vec::new();
        for dir in &legacy_dirs {
            if dir.exists() {
                found.push(dir.display().to_string());
            }
        }

        if found.is_empty() {
            Ok(vec![META.finding(Status::Pass, "No legacy data directories found")])
        } else {
            Ok(vec![META.finding_with_evidence(
                Status::Warn,
                format!("{} legacy directory(s) with potentially stale credentials", found.len()),
                format!("dirs=[{}]", found.join(", ")),
            )])
        }
    }
}
