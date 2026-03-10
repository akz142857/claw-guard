use crate::engine::*;
use anyhow::Result;
use sysinfo::System;

/// CG-P002: Sub-agents spawned with dangerous permission flags
pub struct CgP002;

static META: RuleMeta = RuleMeta {
    id: "CG-P002",
    name: "Dangerous sub-agent flags",
    description: "Detects AI coding agents (claude, codex, opencode, pi) spawned with \
                  permission-bypass flags like --yolo, --full-auto, bypassPermissions.",
    category: Category::Process,
    severity: Severity::High,
    remediation: "Never use --yolo or bypassPermissions in production. \
                  Use interactive permission mode or a tightly scoped allowlist.",
};

const AGENT_BINARIES: &[&str] = &["claude", "codex", "opencode", "pi", "aider", "cline"];
const DANGEROUS_FLAGS: &[&str] = &[
    "--yolo",
    "--full-auto",
    "bypasspermissions",
    "--dangerously-skip-permissions",
    "--no-verify",
    "--trust-all",
];

impl StaticRule for CgP002 {
    fn meta(&self) -> &RuleMeta {
        &META
    }

    fn evaluate(&self) -> Result<Vec<Finding>> {
        let mut findings = Vec::new();
        let mut sys = System::new();
        sys.refresh_processes(sysinfo::ProcessesToUpdate::All, true);

        for (pid, process) in sys.processes() {
            let name = process.name().to_string_lossy().to_lowercase();
            let cmd: Vec<String> = process
                .cmd()
                .iter()
                .map(|s| s.to_string_lossy().to_lowercase().to_string())
                .collect();
            let cmd_str = cmd.join(" ");

            let is_agent = AGENT_BINARIES.iter().any(|b| name.contains(b) || cmd_str.contains(b));
            if !is_agent {
                continue;
            }

            let dangerous: Vec<&&str> = DANGEROUS_FLAGS
                .iter()
                .filter(|f| cmd_str.contains(&f.to_lowercase()))
                .collect();

            if !dangerous.is_empty() {
                findings.push(META.finding_with_evidence(
                    Status::Fail,
                    format!(
                        "Agent '{}' (pid {}) running with dangerous flags",
                        process.name().to_string_lossy(), pid
                    ),
                    format!(
                        "pid={} flags=[{}]",
                        pid,
                        dangerous.iter().map(|f| f.to_string()).collect::<Vec<_>>().join(", ")
                    ),
                ));
            }
        }

        if findings.is_empty() {
            findings.push(META.finding(
                Status::Pass,
                "No sub-agents with dangerous permission flags detected",
            ));
        }

        Ok(findings)
    }
}
