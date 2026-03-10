use anyhow::Result;
use std::process::Command;
use std::time::{Duration, Instant};
use tracing::warn;

use crate::engine::{Finding, RuleMeta, Status};

/// Skill command output protocol
#[derive(serde::Deserialize)]
struct SkillOutput {
    status: String,
    detail: String,
    #[serde(default)]
    evidence: Option<String>,
}

/// Run a skill's evaluate command and convert output to Findings.
/// Enforces a timeout — kills the child process if it exceeds `timeout_secs`.
pub fn run_skill_command(
    meta: &RuleMeta,
    cmd: &str,
    timeout_secs: u64,
) -> Result<Vec<Finding>> {
    let shell = if cfg!(windows) { "cmd" } else { "sh" };
    let flag = if cfg!(windows) { "/C" } else { "-c" };

    let mut child = match Command::new(shell)
        .arg(flag)
        .arg(cmd)
        .env("CLAW_GUARD", "1")
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
    {
        Ok(c) => c,
        Err(e) => {
            return Ok(vec![meta.finding(
                Status::Error,
                format!("Failed to spawn skill command: {}", e),
            )]);
        }
    };

    // Poll-based timeout
    let deadline = Instant::now() + Duration::from_secs(timeout_secs);
    loop {
        match child.try_wait() {
            Ok(Some(_)) => break,
            Ok(None) => {
                if Instant::now() >= deadline {
                    let _ = child.kill();
                    let _ = child.wait();
                    return Ok(vec![meta.finding(
                        Status::Error,
                        format!("Skill command timed out after {}s", timeout_secs),
                    )]);
                }
                std::thread::sleep(Duration::from_millis(50));
            }
            Err(e) => {
                let _ = child.kill();
                return Ok(vec![meta.finding(
                    Status::Error,
                    format!("Error waiting for skill command: {}", e),
                )]);
            }
        }
    }

    let output = match child.wait_with_output() {
        Ok(o) => o,
        Err(e) => {
            return Ok(vec![meta.finding(
                Status::Error,
                format!("Failed to read skill output: {}", e),
            )]);
        }
    };

    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);

    if !output.status.success() && stdout.trim().is_empty() {
        return Ok(vec![Finding {
            rule_id: meta.id.to_string(),
            rule_name: meta.name.to_string(),
            category: meta.category,
            severity: meta.severity,
            status: Status::Error,
            detail: format!(
                "Skill command exited with code {}. stderr: {}",
                output.status.code().unwrap_or(-1),
                stderr.trim()
            ),
            evidence: None,
            remediation: meta.remediation.to_string(),
        }]);
    }

    // Parse each line of stdout as a JSON SkillOutput
    let mut findings = Vec::new();

    for line in stdout.lines() {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }

        match serde_json::from_str::<SkillOutput>(line) {
            Ok(skill_out) => {
                let status = match skill_out.status.as_str() {
                    "pass" => Status::Pass,
                    "fail" => Status::Fail,
                    "warn" => Status::Warn,
                    "skip" => Status::Skip,
                    _ => Status::Warn,
                };

                findings.push(Finding {
                    rule_id: meta.id.to_string(),
                    rule_name: meta.name.to_string(),
                    category: meta.category,
                    severity: meta.severity,
                    status,
                    detail: skill_out.detail,
                    evidence: skill_out.evidence,
                    remediation: meta.remediation.to_string(),
                });
            }
            Err(e) => {
                warn!("Skill {} output not JSON: {}. Line: {}", meta.id, e, line);
                // Only create a finding from non-JSON if it's the only output line
                if stdout.lines().filter(|l| !l.trim().is_empty()).count() == 1 {
                    findings.push(Finding {
                        rule_id: meta.id.to_string(),
                        rule_name: meta.name.to_string(),
                        category: meta.category,
                        severity: meta.severity,
                        status: if output.status.success() {
                            Status::Pass
                        } else {
                            Status::Fail
                        },
                        detail: line.to_string(),
                        evidence: None,
                        remediation: meta.remediation.to_string(),
                    });
                }
            }
        }
    }

    // Fallback: if no findings produced, use exit code
    if findings.is_empty() {
        findings.push(Finding {
            rule_id: meta.id.to_string(),
            rule_name: meta.name.to_string(),
            category: meta.category,
            severity: meta.severity,
            status: if output.status.success() {
                Status::Pass
            } else {
                Status::Fail
            },
            detail: if output.status.success() {
                "Skill check passed".to_string()
            } else {
                format!(
                    "Skill check failed (exit code {})",
                    output.status.code().unwrap_or(-1)
                )
            },
            evidence: if !stderr.trim().is_empty() {
                Some(stderr.trim().to_string())
            } else {
                None
            },
            remediation: meta.remediation.to_string(),
        });
    }

    Ok(findings)
}
