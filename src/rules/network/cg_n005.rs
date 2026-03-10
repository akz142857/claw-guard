use crate::engine::*;
use anyhow::Result;
use std::process::Command;

/// CG-N005: DNS tunnel / exfiltration detection
pub struct CgN005;

static META: RuleMeta = RuleMeta {
    id: "CG-N005",
    name: "DNS tunnel detection",
    description: "Detects indicators of DNS tunneling: processes using known DNS tunnel \
                  tools (iodine, dnscat2, dns2tcp) or anomalous DNS resolution patterns \
                  that suggest data exfiltration via DNS.",
    category: Category::Network,
    severity: Severity::Medium,
    remediation: "Investigate and terminate DNS tunnel processes. Block outbound DNS \
                  to non-corporate resolvers. Use DNS monitoring/logging. \
                  Consider deploying DNS-over-HTTPS with filtering.",
};

const DNS_TUNNEL_TOOLS: &[&str] = &[
    "iodine",
    "iodined",
    "dnscat",
    "dnscat2",
    "dns2tcp",
    "dns2tcpc",
    "dns2tcpd",
    "dnspot",
    "ozymandns",
    "heyoka",
    "tuns",
    "dnsexfiltrator",
    "dnslivery",
    "godoh",
    "sliver",
];

impl StaticRule for CgN005 {
    fn meta(&self) -> &RuleMeta {
        &META
    }

    fn evaluate(&self) -> Result<Vec<Finding>> {
        let mut findings = Vec::new();

        // Check for known DNS tunneling tools in process list
        let output = if cfg!(unix) {
            Command::new("ps").args(["aux"]).output()
        } else {
            Command::new("tasklist").arg("/v").output()
        };

        match output {
            Ok(out) => {
                let stdout = String::from_utf8_lossy(&out.stdout);
                for line in stdout.lines().skip(1) {
                    let lower = line.to_lowercase();
                    for tool in DNS_TUNNEL_TOOLS {
                        if lower.contains(tool) {
                            findings.push(META.finding_with_evidence(
                                Status::Fail,
                                format!("DNS tunnel tool '{}' detected in process list", tool),
                                truncate(line.trim(), 200),
                            ));
                            break;
                        }
                    }
                }
            }
            Err(e) => {
                findings.push(META.finding(
                    Status::Error,
                    format!("Failed to enumerate processes: {}", e),
                ));
            }
        }

        // Check for processes with high-frequency DNS (port 53) connections
        if cfg!(target_os = "macos") {
            if let Ok(out) = Command::new("lsof").args(["-i", ":53", "-nP"]).output() {
                let stdout = String::from_utf8_lossy(&out.stdout);
                let dns_connections: Vec<&str> = stdout.lines().skip(1).collect();
                // More than 10 concurrent DNS connections is suspicious
                if dns_connections.len() > 10 {
                    findings.push(META.finding_with_evidence(
                        Status::Warn,
                        format!(
                            "{} concurrent DNS connections detected — may indicate DNS tunneling",
                            dns_connections.len()
                        ),
                        dns_connections.iter().take(5).cloned().collect::<Vec<_>>().join("\n"),
                    ));
                }
            }
        } else if cfg!(unix) {
            if let Ok(out) = Command::new("ss").args(["-unp", "sport", "=", "53"]).output() {
                let stdout = String::from_utf8_lossy(&out.stdout);
                let dns_lines: Vec<&str> = stdout.lines().skip(1).collect();
                if dns_lines.len() > 10 {
                    findings.push(META.finding_with_evidence(
                        Status::Warn,
                        format!(
                            "{} DNS socket connections detected — may indicate DNS tunneling",
                            dns_lines.len()
                        ),
                        dns_lines.iter().take(5).cloned().collect::<Vec<_>>().join("\n"),
                    ));
                }
            }
        }

        if findings.is_empty() {
            findings.push(META.finding(
                Status::Pass,
                "No DNS tunneling indicators detected",
            ));
        }

        Ok(findings)
    }
}

fn truncate(s: &str, max: usize) -> String {
    if s.len() > max {
        format!("{}...", &s[..max])
    } else {
        s.to_string()
    }
}
