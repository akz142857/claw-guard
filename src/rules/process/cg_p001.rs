use crate::engine::*;
use anyhow::Result;
use sysinfo::System;

/// CG-P001: OpenClaw running as root/SYSTEM
pub struct CgP001;

static META: RuleMeta = RuleMeta {
    id: "CG-P001",
    name: "Elevated privilege execution",
    description: "Checks if OpenClaw processes are running as root (Unix) or SYSTEM (Windows). \
                  AI agents should run under a dedicated unprivileged user.",
    category: Category::Process,
    severity: Severity::High,
    remediation: "Run OpenClaw as a non-root user. Create a dedicated service account \
                  with minimal file system access.",
};

impl Rule for CgP001 {
    fn meta(&self) -> &RuleMeta {
        &META
    }

    fn evaluate(&self) -> Result<Vec<Finding>> {
        let mut findings = Vec::new();
        let mut sys = System::new();
        sys.refresh_processes(sysinfo::ProcessesToUpdate::All, true);

        let mut found = false;

        for (pid, process) in sys.processes() {
            let name = process.name().to_string_lossy().to_lowercase();
            let cmd_str: String = process
                .cmd()
                .iter()
                .map(|s| s.to_string_lossy().to_lowercase().to_string())
                .collect::<Vec<_>>()
                .join(" ");

            if !name.contains("openclaw") && !cmd_str.contains("openclaw") {
                continue;
            }

            found = true;

            #[cfg(unix)]
            {
                let uid = process.user_id().map(|u| **u);
                if uid == Some(0) {
                    findings.push(META.finding_with_evidence(
                        Status::Fail,
                        format!(
                            "Process '{}' (pid {}) running as root",
                            process.name().to_string_lossy(), pid
                        ),
                        format!("pid={} uid=0", pid),
                    ));
                } else {
                    findings.push(META.finding(
                        Status::Pass,
                        format!(
                            "Process '{}' (pid {}) running as uid {:?}",
                            process.name().to_string_lossy(), pid, uid
                        ),
                    ));
                }
            }

            #[cfg(windows)]
            {
                if let Ok(output) = std::process::Command::new("tasklist")
                    .args(["/FI", &format!("PID eq {}", pid), "/FO", "CSV", "/V"])
                    .output()
                {
                    let stdout = String::from_utf8_lossy(&output.stdout).to_lowercase();
                    if stdout.contains("system") || stdout.contains("administrator") {
                        findings.push(META.finding_with_evidence(
                            Status::Fail,
                            format!("Process (pid {}) running as SYSTEM/Administrator", pid),
                            format!("pid={}", pid),
                        ));
                    } else {
                        findings.push(META.finding(
                            Status::Pass,
                            format!("Process (pid {}) running as standard user", pid),
                        ));
                    }
                }
            }
        }

        if !found {
            findings.push(META.finding(Status::Pass, "No OpenClaw processes running"));
        }

        Ok(findings)
    }
}
