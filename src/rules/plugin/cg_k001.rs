use crate::engine::*;
use crate::platform;
use anyhow::Result;

/// CG-K001: Installed plugins inventory (plugins execute with full host privileges)
pub struct CgK001;

static META: RuleMeta = RuleMeta {
    id: "CG-K001",
    name: "Plugin inventory audit",
    description: "Lists all installed OpenClaw plugins/extensions. Plugins run in-process with \
                  the same OS privileges as the gateway. The built-in security scanner is \
                  warn-only and never blocks installation of malicious code.",
    category: Category::Plugin,
    severity: Severity::High,
    remediation: "Review all installed plugins. Remove unknown or unused plugins. \
                  Only install plugins from trusted sources. Monitor ~/.openclaw/extensions/ \
                  for unauthorized changes.",
};

impl StaticRule for CgK001 {
    fn meta(&self) -> &RuleMeta {
        &META
    }

    fn evaluate(&self) -> Result<Vec<Finding>> {
        let ext_dir = platform::home_dir().join(".openclaw/extensions");

        if !ext_dir.exists() {
            return Ok(vec![META.finding(Status::Pass, "No plugin directory found (~/.openclaw/extensions)")]);
        }

        let entries = match std::fs::read_dir(&ext_dir) {
            Ok(e) => e,
            Err(e) => return Ok(vec![META.finding(Status::Error, format!("Cannot read extensions dir: {}", e))]),
        };

        let mut plugins = Vec::new();
        for entry in entries.flatten() {
            if entry.path().is_dir() {
                plugins.push(entry.file_name().to_string_lossy().to_string());
            }
        }

        if plugins.is_empty() {
            Ok(vec![META.finding(Status::Pass, "No plugins installed")])
        } else {
            Ok(vec![META.finding_with_evidence(
                Status::Warn,
                format!(
                    "{} plugin(s) installed — each has full host access, review recommended",
                    plugins.len()
                ),
                format!("plugins=[{}]", plugins.join(", ")),
            )])
        }
    }
}
