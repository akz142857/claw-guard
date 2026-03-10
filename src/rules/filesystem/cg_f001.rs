use crate::engine::*;
use crate::platform;
use anyhow::Result;

/// CG-F001: Sensitive system files readable by AI agent process
pub struct CgF001;

static META: RuleMeta = RuleMeta {
    id: "CG-F001",
    name: "Sensitive system file access",
    description: "Checks if critical system files (/etc/shadow, SAM, sudoers) are accessible \
                  by the AI agent process, excluding expected defaults like /etc/passwd.",
    category: Category::FileSystem,
    severity: Severity::Critical,
    remediation: "Ensure sensitive files are only readable by root/owner. \
                  Run OpenClaw under a dedicated user with minimal file access.",
};

/// Files that are world-readable by design and not a real risk.
const EXPECTED_READABLE: &[&str] = &["/etc/passwd"];

impl Rule for CgF001 {
    fn meta(&self) -> &RuleMeta {
        &META
    }

    fn evaluate(&self) -> Result<Vec<Finding>> {
        let mut findings = Vec::new();

        for (name, path) in platform::sensitive_system_paths() {
            let path_str = path.display().to_string();

            if !path.exists() {
                continue;
            }

            #[cfg(unix)]
            {
                use std::os::unix::fs::MetadataExt;
                if let Ok(meta) = std::fs::metadata(&path) {
                    let mode = meta.mode() & 0o777;
                    if mode & 0o004 != 0 {
                        if EXPECTED_READABLE.contains(&path_str.as_str()) {
                            // Expected — not a finding
                            continue;
                        }
                        findings.push(META.finding_with_evidence(
                            Status::Fail,
                            format!("{} is world-readable (mode {:o})", path_str, mode),
                            format!("file={} mode={:o} type={}", path_str, mode, name),
                        ));
                    } else {
                        findings.push(META.finding(
                            Status::Pass,
                            format!("{} has appropriate permissions (mode {:o})", path_str, mode),
                        ));
                    }
                }
            }

            #[cfg(windows)]
            {
                let is_critical = matches!(name, "sam_file" | "system_file" | "security_file");
                match std::fs::metadata(&path) {
                    Ok(_) if is_critical => {
                        findings.push(META.finding(
                            Status::Fail,
                            format!("{} is accessible by current process", path_str),
                        ));
                    }
                    Ok(_) => {
                        findings.push(META.finding(Status::Pass, format!("{} exists with system defaults", path_str)));
                    }
                    Err(_) => {
                        findings.push(META.finding(Status::Pass, format!("{} is properly protected", path_str)));
                    }
                }
            }
        }

        if findings.is_empty() {
            findings.push(META.finding(Status::Pass, "No sensitive system files found"));
        }

        Ok(findings)
    }
}
