use anyhow::Result;
use std::process::Command;
use std::time::{Duration, Instant};
use tracing::warn;

use crate::engine::{Finding, OwnedRuleMeta, Status};

/// Skill command output protocol
#[derive(serde::Deserialize)]
struct SkillOutput {
    status: String,
    detail: String,
    #[serde(default)]
    evidence: Option<String>,
}

/// Sensitive env var prefixes that should NOT be inherited by skill commands.
const STRIPPED_ENV_PREFIXES: &[&str] = &[
    "AWS_SECRET",
    "AWS_SESSION",
    "ANTHROPIC_API_KEY",
    "OPENAI_API_KEY",
    "CLAW_GUARD_API_KEY",
    "GH_TOKEN",
    "GITHUB_TOKEN",
    "GOOGLE_APPLICATION_CREDENTIALS",
    "AZURE_",
    "DATABASE_URL",
    "DB_PASSWORD",
];

/// Run a skill's evaluate command and convert output to Findings.
/// Enforces a timeout and strips sensitive env vars from the child process.
pub fn run_skill_command(
    meta: &OwnedRuleMeta,
    cmd: &str,
    timeout_secs: u64,
) -> Result<Vec<Finding>> {
    let shell = if cfg!(windows) { "cmd" } else { "sh" };
    let flag = if cfg!(windows) { "/C" } else { "-c" };

    let mut command = Command::new(shell);
    command
        .arg(flag)
        .arg(cmd)
        .env("CLAW_GUARD", "1")
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped());

    // Strip sensitive env vars from child process
    for (key, _) in std::env::vars() {
        if STRIPPED_ENV_PREFIXES
            .iter()
            .any(|prefix| key.starts_with(prefix))
        {
            command.env_remove(&key);
        }
    }

    let mut child = match command.spawn() {
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
            rule_id: meta.id.clone(),
            rule_name: meta.name.clone(),
            category: meta.category,
            severity: meta.severity,
            status: Status::Error,
            detail: format!(
                "Skill command exited with code {}. stderr: {}",
                output.status.code().unwrap_or(-1),
                stderr.trim()
            ),
            evidence: None,
            remediation: meta.remediation.clone(),
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
                    rule_id: meta.id.clone(),
                    rule_name: meta.name.clone(),
                    category: meta.category,
                    severity: meta.severity,
                    status,
                    detail: skill_out.detail,
                    evidence: skill_out.evidence,
                    remediation: meta.remediation.clone(),
                });
            }
            Err(e) => {
                warn!("Skill {} output not JSON: {}. Line: {}", meta.id, e, line);
                if stdout.lines().filter(|l| !l.trim().is_empty()).count() == 1 {
                    findings.push(Finding {
                        rule_id: meta.id.clone(),
                        rule_name: meta.name.clone(),
                        category: meta.category,
                        severity: meta.severity,
                        status: if output.status.success() {
                            Status::Pass
                        } else {
                            Status::Fail
                        },
                        detail: line.to_string(),
                        evidence: None,
                        remediation: meta.remediation.clone(),
                    });
                }
            }
        }
    }

    // Fallback: if no findings produced, use exit code
    if findings.is_empty() {
        findings.push(Finding {
            rule_id: meta.id.clone(),
            rule_name: meta.name.clone(),
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
            remediation: meta.remediation.clone(),
        });
    }

    Ok(findings)
}
