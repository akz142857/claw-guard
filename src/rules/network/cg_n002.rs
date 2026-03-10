use crate::engine::*;
use anyhow::Result;
use std::process::Command;

/// CG-N002: Unexpected outbound connections from OpenClaw
pub struct CgN002;

static META: RuleMeta = RuleMeta {
    id: "CG-N002",
    name: "Outbound connection audit",
    description: "Detects established outbound connections from OpenClaw processes \
                  that may indicate data exfiltration or C2 communication.",
    category: Category::Network,
    severity: Severity::High,
    remediation: "Review outbound connections. Use network policies or firewall rules \
                  to restrict OpenClaw outbound access to known API endpoints only.",
};

impl StaticRule for CgN002 {
    fn meta(&self) -> &RuleMeta {
        &META
    }

    fn evaluate(&self) -> Result<Vec<Finding>> {
        let output = if cfg!(target_os = "macos") {
            Command::new("lsof")
                .args(["-iTCP", "-sTCP:ESTABLISHED", "-nP"])
                .output()
        } else if cfg!(target_os = "windows") {
            Command::new("netstat").args(["-ano"]).output()
        } else {
            Command::new("ss").args(["-tnp"]).output()
        };

        match output {
            Ok(out) => {
                let stdout = String::from_utf8_lossy(&out.stdout);
                let mut count = 0u32;

                for line in stdout.lines() {
                    let lower = line.to_lowercase();
                    if cfg!(target_os = "windows") && !lower.contains("established") {
                        continue;
                    }
                    if lower.contains("openclaw") || lower.contains("claw") {
                        count += 1;
                    }
                }

                if count == 0 {
                    Ok(vec![META.finding(Status::Pass, "No OpenClaw outbound connections")])
                } else {
                    Ok(vec![META.finding_with_evidence(
                        Status::Warn,
                        format!("{} outbound connection(s) detected, review recommended", count),
                        format!("connection_count={}", count),
                    )])
                }
            }
            Err(e) => Ok(vec![META.finding(
                Status::Error,
                format!("Failed to check connections: {}", e),
            )]),
        }
    }
}
