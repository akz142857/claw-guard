use crate::engine::*;
use crate::platform;
use anyhow::Result;

/// CG-G004: Gateway auth token strength
pub struct CgG004;

static META: RuleMeta = RuleMeta {
    id: "CG-G004",
    name: "Gateway token strength",
    description: "Checks if the gateway auth token (when mode=token) has sufficient entropy. \
                  OpenClaw auto-generates 48-char hex tokens; shorter/weaker tokens are flagged.",
    category: Category::GatewayConfig,
    severity: Severity::High,
    remediation: "Use a strong random token: openssl rand -hex 24 (produces 48 hex chars). \
                  Never reuse passwords or use short tokens.",
};

impl StaticRule for CgG004 {
    fn meta(&self) -> &RuleMeta {
        &META
    }

    fn evaluate(&self) -> Result<Vec<Finding>> {
        let config_path = platform::home_dir().join(".openclaw/openclaw.json");

        if !config_path.exists() {
            return Ok(vec![META.finding(Status::Skip, "openclaw.json not found")]);
        }

        let content = std::fs::read_to_string(&config_path)?;
        let json: serde_json::Value = serde_json::from_str(&content)?;

        let mode = json.pointer("/gateway/auth/mode")
            .and_then(|v| v.as_str())
            .unwrap_or("");

        if mode != "token" {
            return Ok(vec![META.finding(Status::Skip, format!("Auth mode is '{}', not token", mode))]);
        }

        // Check config token
        let token = json.pointer("/gateway/auth/token")
            .and_then(|v| v.as_str());

        // Also check env var
        let env_token = std::env::var("OPENCLAW_GATEWAY_TOKEN").ok();

        let effective_token = token.map(|s| s.to_string()).or(env_token);

        match effective_token {
            None => Ok(vec![META.finding(
                Status::Warn,
                "Token mode set but no token found in config or env — may auto-generate at runtime",
            )]),
            Some(t) => {
                let len = t.len();
                // Check basic entropy indicators (we never log the actual token)
                if len < 16 {
                    Ok(vec![META.finding_with_evidence(
                        Status::Fail,
                        format!("Gateway token is too short ({} chars), easily brute-forced", len),
                        format!("token_length={}", len),
                    )])
                } else if len < 32 {
                    Ok(vec![META.finding_with_evidence(
                        Status::Warn,
                        format!("Gateway token is moderate length ({} chars), recommend 48+", len),
                        format!("token_length={}", len),
                    )])
                } else {
                    Ok(vec![META.finding(
                        Status::Pass,
                        format!("Gateway token has sufficient length ({} chars)", len),
                    )])
                }
            }
        }
    }
}
