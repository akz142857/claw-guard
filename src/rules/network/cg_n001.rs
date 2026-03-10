use crate::engine::*;
use anyhow::Result;
use std::process::Command;

/// CG-N001: OpenClaw-related processes listening on all interfaces (0.0.0.0)
pub struct CgN001;

static META: RuleMeta = RuleMeta {
    id: "CG-N001",
    name: "Wildcard network listeners",
    description: "Checks if OpenClaw gateway or related processes are bound to 0.0.0.0 \
                  instead of 127.0.0.1, exposing the gateway to the network.",
    category: Category::Network,
    severity: Severity::High,
    remediation: "Bind gateway to 127.0.0.1 (--bind localhost). Never use --bind lan \
                  in production without strong authentication.",
};

const OPENCLAW_KEYWORDS: &[&str] = &["openclaw", "claw", "node"];

impl Rule for CgN001 {
    fn meta(&self) -> &RuleMeta {
        &META
    }

    fn evaluate(&self) -> Result<Vec<Finding>> {
        let output = if cfg!(target_os = "macos") {
            Command::new("lsof").args(["-iTCP", "-sTCP:LISTEN", "-nP"]).output()
        } else if cfg!(target_os = "windows") {
            Command::new("netstat").args(["-ano", "-p", "TCP"]).output()
        } else {
            Command::new("ss").args(["-tlnp"]).output()
        };

        match output {
            Ok(out) => {
                let stdout = String::from_utf8_lossy(&out.stdout);
                let mut wildcard_lines = Vec::new();

                for line in stdout.lines().skip(1) {
                    let lower = line.to_lowercase();
                    let is_wildcard = lower.contains("0.0.0.0")
                        || lower.contains("*:")
                        || lower.contains("[::]");
                    let is_openclaw = OPENCLAW_KEYWORDS.iter().any(|kw| lower.contains(kw));

                    if is_wildcard && is_openclaw {
                        wildcard_lines.push(line.trim().to_string());
                    }
                }

                if wildcard_lines.is_empty() {
                    Ok(vec![META.finding(
                        Status::Pass,
                        "No OpenClaw processes listening on 0.0.0.0",
                    )])
                } else {
                    Ok(wildcard_lines
                        .iter()
                        .map(|l| {
                            META.finding_with_evidence(
                                Status::Fail,
                                "OpenClaw process bound to all interfaces",
                                l.clone(),
                            )
                        })
                        .collect())
                }
            }
            Err(e) => Ok(vec![META.finding(
                Status::Error,
                format!("Failed to enumerate listeners: {}", e),
            )]),
        }
    }
}
