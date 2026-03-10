use crate::engine::*;
use crate::platform;
use anyhow::Result;

/// CG-F002: SSH host key private files permissions
pub struct CgF002;

static META: RuleMeta = RuleMeta {
    id: "CG-F002",
    name: "SSH host key permissions",
    description: "Checks individual SSH host private key files inside the SSH directory. \
                  Private keys should be mode 600 (owner-only).",
    category: Category::FileSystem,
    severity: Severity::Critical,
    remediation: "chmod 600 /etc/ssh/ssh_host_*_key (exclude .pub files).",
};

impl StaticRule for CgF002 {
    fn meta(&self) -> &RuleMeta {
        &META
    }

    fn evaluate(&self) -> Result<Vec<Finding>> {
        let mut findings = Vec::new();
        let ssh_dir = platform::ssh_host_key_dir();

        if !ssh_dir.exists() {
            return Ok(vec![META.finding(Status::Skip, format!("{} not present", ssh_dir.display()))]);
        }

        let entries = match std::fs::read_dir(&ssh_dir) {
            Ok(e) => e,
            Err(_) => return Ok(vec![META.finding(Status::Pass, format!("{} not accessible", ssh_dir.display()))]),
        };

        for entry in entries.flatten() {
            let path = entry.path();
            let name = path.file_name().unwrap_or_default().to_string_lossy().to_string();

            if !name.starts_with("ssh_host_") || name.ends_with(".pub") {
                continue;
            }

            #[cfg(unix)]
            {
                use std::os::unix::fs::MetadataExt;
                if let Ok(meta) = std::fs::metadata(&path) {
                    let mode = meta.mode() & 0o777;
                    if mode & 0o077 != 0 {
                        findings.push(META.finding_with_evidence(
                            Status::Fail,
                            format!("{} mode {:o}, should be 600", path.display(), mode),
                            format!("file={} mode={:o}", path.display(), mode),
                        ));
                    } else {
                        findings.push(META.finding(
                            Status::Pass,
                            format!("{} has correct permissions ({:o})", path.display(), mode),
                        ));
                    }
                }
            }

            #[cfg(windows)]
            {
                match std::fs::metadata(&path) {
                    Ok(_) => findings.push(META.finding(
                        Status::Warn,
                        format!("{} is accessible, verify ACLs", path.display()),
                    )),
                    Err(_) => findings.push(META.finding(
                        Status::Pass,
                        format!("{} is properly protected", path.display()),
                    )),
                }
            }
        }

        if findings.is_empty() {
            findings.push(META.finding(Status::Pass, "No SSH host private keys found"));
        }

        Ok(findings)
    }
}
