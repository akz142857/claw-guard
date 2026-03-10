use crate::engine::*;
use anyhow::Result;
use sysinfo::System;

/// CG-P004: Anomalous child processes from agent
pub struct CgP004;

static META: RuleMeta = RuleMeta {
    id: "CG-P004",
    name: "Anomalous child process detection",
    description: "Detects suspicious child processes spawned by AI agent or OpenClaw \
                  processes: cryptocurrency miners, port scanners, proxy tools, \
                  password crackers, and other unexpected binaries.",
    category: Category::Process,
    severity: Severity::High,
    remediation: "Terminate the suspicious process immediately. Investigate how it was \
                  spawned (check agent logs and command history). Enable sandbox mode \
                  to restrict process creation. Rotate any credentials on the host.",
};

/// Agent process names that might spawn children
const AGENT_NAMES: &[&str] = &[
    "openclaw", "claw", "claude", "codex", "opencode", "node", "aider",
];

/// Suspicious binaries that agents should never spawn
const SUSPICIOUS_BINARIES: &[&str] = &[
    // Miners
    "xmrig",
    "minerd",
    "cpuminer",
    "ethminer",
    "bfgminer",
    "cgminer",
    "nbminer",
    "t-rex",
    "phoenixminer",
    "lolminer",
    // Scanners
    "nmap",
    "masscan",
    "zmap",
    "rustscan",
    "sqlmap",
    "nikto",
    "dirb",
    "dirbuster",
    "gobuster",
    "ffuf",
    "wfuzz",
    "hydra",
    "medusa",
    "hashcat",
    "john",
    // Proxy / tunnel / C2
    "frpc",
    "frps",
    "chisel",
    "ligolo",
    "gost",
    "revsocks",
    "pwncat",
    "msfconsole",
    "msfvenom",
    "cobaltstrike",
    // Network tools (unusual for an AI agent)
    "tcpdump",
    "wireshark",
    "tshark",
    "ettercap",
    "arpspoof",
    "bettercap",
];

impl StaticRule for CgP004 {
    fn meta(&self) -> &RuleMeta {
        &META
    }

    fn evaluate(&self) -> Result<Vec<Finding>> {
        let mut findings = Vec::new();
        let mut sys = System::new();
        sys.refresh_processes(sysinfo::ProcessesToUpdate::All, true);

        // Build a map of agent PIDs
        let agent_pids: Vec<sysinfo::Pid> = sys
            .processes()
            .iter()
            .filter(|(_, proc)| {
                let name = proc.name().to_string_lossy().to_lowercase();
                AGENT_NAMES.iter().any(|a| name.contains(a))
            })
            .map(|(pid, _)| *pid)
            .collect();

        // Check all processes for suspicious names
        for (pid, process) in sys.processes() {
            let name = process.name().to_string_lossy().to_lowercase();
            let cmd: String = process
                .cmd()
                .iter()
                .map(|s| s.to_string_lossy().to_string())
                .collect::<Vec<_>>()
                .join(" ")
                .to_lowercase();

            // Check if this is a suspicious process
            let suspicious_match = SUSPICIOUS_BINARIES
                .iter()
                .find(|b| name.contains(*b) || cmd.contains(*b));

            if let Some(matched) = suspicious_match {
                // Extra severity if it's a child of an agent process
                let is_agent_child = process
                    .parent()
                    .map(|ppid| agent_pids.contains(&ppid))
                    .unwrap_or(false);

                let detail = if is_agent_child {
                    format!(
                        "Suspicious process '{}' (pid {}) spawned by AI agent",
                        matched, pid
                    )
                } else {
                    format!(
                        "Suspicious process '{}' (pid {}) running on host",
                        matched, pid
                    )
                };

                findings.push(META.finding_with_evidence(
                    Status::Fail,
                    detail,
                    format!(
                        "pid={} ppid={:?} name={} cmd={}",
                        pid,
                        process.parent(),
                        process.name().to_string_lossy(),
                        truncate(&cmd, 200)
                    ),
                ));
            }
        }

        if findings.is_empty() {
            findings.push(META.finding(
                Status::Pass,
                "No suspicious child processes detected",
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
