use crate::engine::*;
use crate::platform;
use anyhow::Result;

/// CG-S001: Sandbox mode is disabled — all exec runs directly on host
pub struct CgS001;

static META: RuleMeta = RuleMeta {
    id: "CG-S001",
    name: "Sandbox mode status",
    description: "Checks if OpenClaw sandbox is enabled. Default is 'off', meaning all agent \
                  exec commands run directly on the host with full system access. \
                  This is the single most impactful security setting.",
    category: Category::Sandbox,
    severity: Severity::Critical,
    remediation: "Enable sandbox mode in openclaw.json: \
                  agents.defaults.sandbox.mode = 'all' (recommended) or 'non-main'. \
                  Requires Docker. See OpenClaw docs for sandbox setup.",
};

impl StaticRule for CgS001 {
    fn meta(&self) -> &RuleMeta {
        &META
    }

    fn evaluate(&self) -> Result<Vec<Finding>> {
        let config_path = platform::home_dir().join(".openclaw/openclaw.json");

        if !config_path.exists() {
            return Ok(vec![META.finding(
                Status::Warn,
                "openclaw.json not found — sandbox defaults to 'off' if unconfigured",
            )]);
        }

        let content = std::fs::read_to_string(&config_path)?;
        let json: serde_json::Value = serde_json::from_str(&content)?;

        let mode = json
            .pointer("/agents/defaults/sandbox/mode")
            .and_then(|v| v.as_str())
            .unwrap_or("off");

        match mode {
            "off" => Ok(vec![META.finding_with_evidence(
                Status::Fail,
                "Sandbox mode is 'off' — all agent commands execute directly on host",
                "agents.defaults.sandbox.mode=off",
            )]),
            "non-main" => Ok(vec![META.finding(
                Status::Warn,
                "Sandbox mode is 'non-main' — main agent still runs on host unsandboxed",
            )]),
            "all" => Ok(vec![META.finding(
                Status::Pass,
                "Sandbox mode is 'all' — all agents run in isolated containers",
            )]),
            other => Ok(vec![META.finding(
                Status::Warn,
                format!("Unknown sandbox mode: '{}'", other),
            )]),
        }
    }
}
