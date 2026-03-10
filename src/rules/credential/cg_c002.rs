use crate::engine::*;
use crate::platform;
use anyhow::Result;
use std::path::PathBuf;

/// CG-C002: OpenClaw config/env files contain plaintext secrets with weak permissions
pub struct CgC002;

static META: RuleMeta = RuleMeta {
    id: "CG-C002",
    name: "OpenClaw config file security",
    description: "Checks permissions on openclaw.json, .env, and OAuth credential files. \
                  These files may contain gateway tokens, API keys, and session secrets.",
    category: Category::Credential,
    severity: Severity::High,
    remediation: "chmod 600 on config files. Use environment variables or a secret manager \
                  instead of storing secrets in config files.",
};

impl Rule for CgC002 {
    fn meta(&self) -> &RuleMeta {
        &META
    }

    fn evaluate(&self) -> Result<Vec<Finding>> {
        let mut findings = Vec::new();
        let home = platform::home_dir();

        let config_files = vec![
            ("openclaw.json", home.join(".openclaw/openclaw.json")),
            ("dotenv", home.join(".openclaw/.env")),
            ("oauth_credentials", home.join(".openclaw/credentials/oauth.json")),
            ("local_dotenv", PathBuf::from(".env")),
            // Legacy paths
            ("legacy_clawdbot", home.join(".clawdbot/clawdbot.json")),
            ("legacy_moldbot", home.join(".moldbot/moldbot.json")),
        ];

        for (name, path) in &config_files {
            if !path.exists() {
                continue;
            }

            #[cfg(unix)]
            {
                use std::os::unix::fs::MetadataExt;
                if let Ok(meta) = std::fs::metadata(path) {
                    let mode = meta.mode() & 0o777;
                    if mode & 0o077 != 0 {
                        findings.push(META.finding_with_evidence(
                            Status::Fail,
                            format!(
                                "{} has overly permissive mode {:o}, may expose secrets",
                                path.display(), mode
                            ),
                            format!("file={} mode={:o} type={}", path.display(), mode, name),
                        ));
                    } else {
                        findings.push(META.finding(
                            Status::Pass,
                            format!("{} has secure permissions (mode {:o})", path.display(), mode),
                        ));
                    }
                }
            }

            #[cfg(windows)]
            {
                // On Windows, just check that the file exists and flag for review
                findings.push(META.finding(
                    Status::Warn,
                    format!("{} exists, verify ACLs are restricted", path.display()),
                ));
            }
        }

        if findings.is_empty() {
            findings.push(META.finding(Status::Skip, "No OpenClaw config files found"));
        }

        Ok(findings)
    }
}
