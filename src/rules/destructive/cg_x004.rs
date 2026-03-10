use crate::engine::*;
use crate::platform;
use anyhow::Result;

/// CG-X004: No human-in-the-loop confirmation for dangerous operations
pub struct CgX004;

static META: RuleMeta = RuleMeta {
    id: "CG-X004",
    name: "No human confirmation for dangerous ops",
    description: "Checks if OpenClaw requires human approval for high-risk operations \
                  (file deletion, exec commands, network requests). Without this, an agent \
                  can autonomously perform irreversible actions.",
    category: Category::DestructiveAction,
    severity: Severity::Medium,
    remediation: "Configure permission mode in openclaw.json: \
                  {\"permissions\": {\"mode\": \"interactive\", \
                  \"autoApprove\": [\"read\"], \"requireApproval\": [\"exec\", \"write\", \"delete\"]}}. \
                  Never use 'auto-approve-all' in production.",
};

const APPROVAL_FIELDS: &[&str] = &[
    "/permissions/mode",
    "/permissions/requireApproval",
    "/permissions/autoApprove",
    "/tools/exec/requireConfirmation",
    "/security/humanInTheLoop",
];

const DANGEROUS_MODES: &[&str] = &[
    "auto",
    "auto-approve-all",
    "yolo",
    "full-auto",
    "unattended",
];

impl StaticRule for CgX004 {
    fn meta(&self) -> &RuleMeta {
        &META
    }

    fn evaluate(&self) -> Result<Vec<Finding>> {
        let config_path = platform::home_dir().join(".openclaw/openclaw.json");

        if !config_path.exists() {
            return Ok(vec![META.finding(
                Status::Warn,
                "openclaw.json not found — cannot verify human approval requirements",
            )]);
        }

        let content = std::fs::read_to_string(&config_path)?;
        let json: serde_json::Value = serde_json::from_str(&content)?;

        let mut findings = Vec::new();

        // Check for auto-approve-all or yolo mode
        if let Some(mode) = json.pointer("/permissions/mode").and_then(|v| v.as_str()) {
            let mode_lower = mode.to_lowercase();
            if DANGEROUS_MODES.iter().any(|d| mode_lower == *d) {
                findings.push(META.finding_with_evidence(
                    Status::Fail,
                    format!(
                        "Permission mode '{}' auto-approves all operations without human review",
                        mode
                    ),
                    format!("permissions.mode={}", mode),
                ));
            }
        }

        // Check if any approval config exists at all
        let has_approval_config = APPROVAL_FIELDS
            .iter()
            .any(|path| json.pointer(path).is_some());

        if !has_approval_config {
            findings.push(META.finding(
                Status::Warn,
                "No explicit permission/approval configuration found. \
                 Verify that the agent's default mode requires human confirmation for writes and exec.",
            ));
        }

        if findings.is_empty() {
            findings.push(META.finding(
                Status::Pass,
                "Human-in-the-loop approval configuration found",
            ));
        }

        Ok(findings)
    }
}
