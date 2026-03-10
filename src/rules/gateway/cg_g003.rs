use crate::engine::*;
use crate::platform;
use anyhow::Result;

/// CG-G003: Secret provider exec commands with weak path security
pub struct CgG003;

static META: RuleMeta = RuleMeta {
    id: "CG-G003",
    name: "Secret provider exec path security",
    description: "Checks if secrets.providers.*.command paths have secure permissions and are \
                  not using allowInsecurePath or allowSymlinkCommand bypass flags.",
    category: Category::GatewayConfig,
    severity: Severity::High,
    remediation: "Set allowInsecurePath and allowSymlinkCommand to false. \
                  Ensure exec command files are owned by current user with mode 700. \
                  Use trustedDirs to restrict command locations.",
};

impl StaticRule for CgG003 {
    fn meta(&self) -> &RuleMeta {
        &META
    }

    fn evaluate(&self) -> Result<Vec<Finding>> {
        let config_path = platform::home_dir().join(".openclaw/openclaw.json");

        if !config_path.exists() {
            return Ok(vec![META.finding(Status::Skip, "openclaw.json not found")]);
        }

        let content = std::fs::read_to_string(&config_path)?;
        let json: serde_json::Value = serde_json::from_str(&content)?;

        let providers = match json.pointer("/secrets/providers") {
            Some(p) if p.is_object() => p.as_object().unwrap(),
            _ => return Ok(vec![META.finding(Status::Pass, "No secret providers configured")]),
        };

        let mut findings = Vec::new();

        for (name, config) in providers {
            let source = config.get("source").and_then(|v| v.as_str()).unwrap_or("");

            if source == "exec" {
                // Check bypass flags
                if config.get("allowInsecurePath").and_then(|v| v.as_bool()) == Some(true) {
                    findings.push(META.finding_with_evidence(
                        Status::Fail,
                        format!("Provider '{}' has allowInsecurePath=true, disabling permission checks", name),
                        format!("provider={} flag=allowInsecurePath", name),
                    ));
                }

                if config.get("allowSymlinkCommand").and_then(|v| v.as_bool()) == Some(true) {
                    findings.push(META.finding_with_evidence(
                        Status::Fail,
                        format!("Provider '{}' allows symlinked commands, path can be redirected", name),
                        format!("provider={} flag=allowSymlinkCommand", name),
                    ));
                }

                // Check if trustedDirs is configured
                if config.get("trustedDirs").is_none() {
                    findings.push(META.finding_with_evidence(
                        Status::Warn,
                        format!("Provider '{}' has no trustedDirs constraint on exec command", name),
                        format!("provider={}", name),
                    ));
                }

                // Check command path permissions if specified
                if let Some(cmd) = config.get("command").and_then(|v| v.as_str()) {
                    let cmd_path = std::path::Path::new(cmd);
                    if cmd_path.exists() {
                        #[cfg(unix)]
                        {
                            use std::os::unix::fs::MetadataExt;
                            if let Ok(meta) = std::fs::metadata(cmd_path) {
                                let mode = meta.mode() & 0o777;
                                if mode & 0o022 != 0 {
                                    findings.push(META.finding_with_evidence(
                                        Status::Fail,
                                        format!("Provider '{}' command {} is writable by group/others (mode {:o})", name, cmd, mode),
                                        format!("provider={} command={} mode={:o}", name, cmd, mode),
                                    ));
                                }
                            }
                        }
                    }
                }
            }
        }

        if findings.is_empty() {
            findings.push(META.finding(Status::Pass, "Secret providers have secure configuration"));
        }

        Ok(findings)
    }
}
