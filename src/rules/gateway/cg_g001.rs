use crate::engine::*;
use crate::platform;
use anyhow::Result;

/// CG-G001: Gateway auth mode is "none" — unauthenticated RCE
pub struct CgG001;

static META: RuleMeta = RuleMeta {
    id: "CG-G001",
    name: "Gateway authentication mode",
    description: "Checks if OpenClaw gateway auth mode is set to 'none'. \
                  Combined with network binding to 0.0.0.0, this allows any network-adjacent \
                  attacker to execute arbitrary commands via the gateway.",
    category: Category::GatewayConfig,
    severity: Severity::Critical,
    remediation: "Set gateway.auth.mode to 'token' or 'password' in openclaw.json. \
                  Generate a strong token: openssl rand -hex 24",
};

impl Rule for CgG001 {
    fn meta(&self) -> &RuleMeta {
        &META
    }

    fn evaluate(&self) -> Result<Vec<Finding>> {
        let config_path = platform::home_dir().join(".openclaw/openclaw.json");

        if !config_path.exists() {
            return Ok(vec![META.finding(Status::Skip, "openclaw.json not found")]);
        }

        let content = match std::fs::read_to_string(&config_path) {
            Ok(c) => c,
            Err(e) => return Ok(vec![META.finding(Status::Error, format!("Cannot read config: {}", e))]),
        };

        let json: serde_json::Value = match serde_json::from_str(&content) {
            Ok(v) => v,
            Err(e) => return Ok(vec![META.finding(Status::Error, format!("Invalid JSON: {}", e))]),
        };

        let auth_mode = json
            .pointer("/gateway/auth/mode")
            .and_then(|v| v.as_str())
            .unwrap_or("not_set");

        match auth_mode {
            "none" => Ok(vec![META.finding_with_evidence(
                Status::Fail,
                "Gateway auth mode is 'none' — unauthenticated access to agent execution",
                "gateway.auth.mode=none",
            )]),
            "not_set" => Ok(vec![META.finding(
                Status::Warn,
                "Gateway auth mode not explicitly set, may default to insecure mode",
            )]),
            "token" | "password" | "trusted-proxy" => Ok(vec![META.finding(
                Status::Pass,
                format!("Gateway auth mode is '{}'", auth_mode),
            )]),
            other => Ok(vec![META.finding(
                Status::Warn,
                format!("Unknown auth mode: '{}'", other),
            )]),
        }
    }
}
