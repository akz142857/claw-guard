use crate::engine::*;
use crate::platform;
use anyhow::Result;

/// CG-K002: Plugin/extension directory permissions
pub struct CgK002;

static META: RuleMeta = RuleMeta {
    id: "CG-K002",
    name: "Plugin directory write protection",
    description: "Checks if the plugin directory is writable by non-owner users. \
                  Write access to ~/.openclaw/extensions equals arbitrary code execution \
                  under the gateway process.",
    category: Category::Plugin,
    severity: Severity::High,
    remediation: "chmod 700 ~/.openclaw/extensions. Ensure only the owner can write plugins.",
};

impl Rule for CgK002 {
    fn meta(&self) -> &RuleMeta {
        &META
    }

    fn evaluate(&self) -> Result<Vec<Finding>> {
        let ext_dir = platform::home_dir().join(".openclaw/extensions");

        if !ext_dir.exists() {
            return Ok(vec![META.finding(Status::Skip, "Plugin directory does not exist")]);
        }

        #[cfg(unix)]
        {
            use std::os::unix::fs::MetadataExt;
            if let Ok(meta) = std::fs::metadata(&ext_dir) {
                let mode = meta.mode() & 0o777;
                if mode & 0o022 != 0 {
                    // Writable by group/others = can inject malicious plugins
                    return Ok(vec![META.finding_with_evidence(
                        Status::Fail,
                        format!(
                            "Plugin directory is writable by group/others (mode {:o})",
                            mode
                        ),
                        format!("path={} mode={:o}", ext_dir.display(), mode),
                    )]);
                }
                if mode & 0o055 != 0 {
                    // Readable/executable by group/others = plugin code is exposed
                    return Ok(vec![META.finding_with_evidence(
                        Status::Warn,
                        format!(
                            "Plugin directory is readable by group/others (mode {:o}), recommend 700",
                            mode
                        ),
                        format!("path={} mode={:o}", ext_dir.display(), mode),
                    )]);
                }
                return Ok(vec![META.finding(
                    Status::Pass,
                    format!("Plugin directory has secure permissions (mode {:o})", mode),
                )]);
            }
        }

        #[cfg(windows)]
        {
            return Ok(vec![META.finding(
                Status::Warn,
                "Plugin directory exists, verify ACLs manually on Windows",
            )]);
        }

        #[allow(unreachable_code)]
        Ok(vec![META.finding(Status::Skip, "Permission check not supported")])
    }
}
