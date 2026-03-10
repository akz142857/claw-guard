use crate::engine::*;
use crate::platform;
use anyhow::Result;

/// CG-X001: No destructive command denylist / allowlist
pub struct CgX001;

static META: RuleMeta = RuleMeta {
    id: "CG-X001",
    name: "No destructive command restrictions",
    description: "Checks if the agent has command denylist/allowlist configured. Without \
                  restrictions, an agent can execute rm -rf /, DROP DATABASE, \
                  git push --force, or other irreversible destructive commands.",
    category: Category::DestructiveAction,
    severity: Severity::Critical,
    remediation: "Configure command restrictions in openclaw.json: \
                  {\"tools\": {\"exec\": {\"denylist\": [\"rm -rf\", \"mkfs\", \"dd if=\", \
                  \":(){ :|:& };:\"], \"allowlist\": [\"cargo\", \"npm\", \"git status\"]}}}. \
                  Or enable sandbox mode (CG-S001) to contain all exec operations.",
};

const RESTRICTION_FIELDS: &[&str] = &[
    "/tools/exec/denylist",
    "/tools/exec/allowlist",
    "/tools/exec/blockedCommands",
    "/tools/exec/allowedCommands",
    "/tools/exec/commandFilter",
    "/security/commandDenylist",
    "/security/commandAllowlist",
];

impl StaticRule for CgX001 {
    fn meta(&self) -> &RuleMeta {
        &META
    }

    fn evaluate(&self) -> Result<Vec<Finding>> {
        let config_path = platform::home_dir().join(".openclaw/openclaw.json");

        if !config_path.exists() {
            return Ok(vec![META.finding(
                Status::Fail,
                "openclaw.json not found — agent has unrestricted command execution",
            )]);
        }

        let content = std::fs::read_to_string(&config_path)?;
        let json: serde_json::Value = serde_json::from_str(&content)?;

        let mut findings = Vec::new();

        let has_restriction = RESTRICTION_FIELDS
            .iter()
            .any(|path| {
                json.pointer(path)
                    .and_then(|v| v.as_array())
                    .map(|a| !a.is_empty())
                    .unwrap_or(false)
            });

        if has_restriction {
            findings.push(META.finding(
                Status::Pass,
                "Command denylist/allowlist configured",
            ));
        } else {
            findings.push(META.finding_with_evidence(
                Status::Fail,
                "No command denylist or allowlist configured. The agent can execute \
                 any shell command including rm -rf /, DROP DATABASE, format, etc.",
                "Dangerous commands include: rm -rf, mkfs, dd, fdisk, \
                 DROP DATABASE, git push --force, chmod -R 777, \
                 iptables -F, systemctl stop, kill -9 1",
            ));
        }

        Ok(findings)
    }
}
