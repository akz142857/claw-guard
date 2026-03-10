use crate::engine::*;
use crate::platform;
use anyhow::Result;

/// CG-C001: Credential directories accessible by AI agent
pub struct CgC001;

static META: RuleMeta = RuleMeta {
    id: "CG-C001",
    name: "Credential directory permissions",
    description: "Checks if cloud credential directories (~/.ssh, ~/.aws, ~/.kube, etc.) \
                  have overly permissive access that allows AI agent processes to read them.",
    category: Category::Credential,
    severity: Severity::Critical,
    remediation: "Restrict permissions: chmod 700 on credential directories. \
                  Consider using OpenClaw sandbox mode to isolate agent file access.",
};

impl Rule for CgC001 {
    fn meta(&self) -> &RuleMeta {
        &META
    }

    fn evaluate(&self) -> Result<Vec<Finding>> {
        let mut findings = Vec::new();

        for (name, path) in platform::credential_paths() {
            if !path.exists() {
                continue; // not present = not a risk
            }

            #[cfg(unix)]
            {
                use std::os::unix::fs::MetadataExt;
                if let Ok(meta) = std::fs::metadata(&path) {
                    let mode = meta.mode() & 0o777;
                    if mode & 0o004 != 0 {
                        findings.push(META.finding_with_evidence(
                            Status::Fail,
                            format!("{} is world-readable (mode {:o})", path.display(), mode),
                            format!("path={} mode={:o} name={}", path.display(), mode, name),
                        ));
                    } else if mode & 0o040 != 0 {
                        findings.push(META.finding_with_evidence(
                            Status::Warn,
                            format!("{} is group-readable (mode {:o})", path.display(), mode),
                            format!("path={} mode={:o} name={}", path.display(), mode, name),
                        ));
                    } else {
                        findings.push(META.finding(
                            Status::Pass,
                            format!("{} has restrictive permissions (mode {:o})", path.display(), mode),
                        ));
                    }
                }
            }

            #[cfg(windows)]
            {
                if let Ok(output) = std::process::Command::new("icacls")
                    .arg(path.as_os_str())
                    .output()
                {
                    let stdout = String::from_utf8_lossy(&output.stdout).to_lowercase();
                    if stdout.contains("everyone") || stdout.contains("\\users") {
                        findings.push(META.finding_with_evidence(
                            Status::Fail,
                            format!("{} accessible by Everyone/Users group", path.display()),
                            format!("path={} name={}", path.display(), name),
                        ));
                    } else {
                        findings.push(META.finding(
                            Status::Pass,
                            format!("{} has restrictive ACLs", path.display()),
                        ));
                    }
                }
            }
        }

        if findings.is_empty() {
            findings.push(META.finding(Status::Pass, "No credential directories found on system"));
        }

        Ok(findings)
    }
}
