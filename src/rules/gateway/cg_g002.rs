use crate::engine::*;
use crate::platform;
use anyhow::Result;

/// CG-G002: Dangerous configuration flags enabled
pub struct CgG002;

static META: RuleMeta = RuleMeta {
    id: "CG-G002",
    name: "Dangerous configuration flags",
    description: "Detects dangerous flags in openclaw.json that weaken security boundaries: \
                  allowInsecureAuth, dangerouslyDisableDeviceAuth, allowUnsafeExternalContent, \
                  workspaceOnly=false, etc.",
    category: Category::GatewayConfig,
    severity: Severity::Critical,
    remediation: "Remove or set dangerous flags to their safe defaults. These flags are \
                  intended only for development, never for production.",
};

struct DangerousFlag {
    path: &'static str,
    dangerous_value: DangerousValue,
    label: &'static str,
}

enum DangerousValue {
    True,
    False,
}

const FLAGS: &[DangerousFlag] = &[
    DangerousFlag {
        path: "/gateway/controlUi/allowInsecureAuth",
        dangerous_value: DangerousValue::True,
        label: "allowInsecureAuth bypasses auth requirements",
    },
    DangerousFlag {
        path: "/gateway/controlUi/dangerouslyAllowHostHeaderOriginFallback",
        dangerous_value: DangerousValue::True,
        label: "host header fallback enables CSRF attacks",
    },
    DangerousFlag {
        path: "/gateway/controlUi/dangerouslyDisableDeviceAuth",
        dangerous_value: DangerousValue::True,
        label: "device auth disabled, weakens session security",
    },
    DangerousFlag {
        path: "/tools/exec/applyPatch/workspaceOnly",
        dangerous_value: DangerousValue::False,
        label: "applyPatch can write outside workspace boundary",
    },
];

impl StaticRule for CgG002 {
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

        let mut findings = Vec::new();

        for flag in FLAGS {
            if let Some(val) = json.pointer(flag.path) {
                let is_dangerous = match flag.dangerous_value {
                    DangerousValue::True => val.as_bool() == Some(true),
                    DangerousValue::False => val.as_bool() == Some(false),
                };

                if is_dangerous {
                    findings.push(META.finding_with_evidence(
                        Status::Fail,
                        flag.label,
                        format!("{}={}", flag.path, val),
                    ));
                }
            }
        }

        // Check hooks for allowUnsafeExternalContent
        if let Some(hooks) = json.pointer("/hooks/mappings") {
            if let Some(arr) = hooks.as_array() {
                for (i, hook) in arr.iter().enumerate() {
                    if hook.get("allowUnsafeExternalContent").and_then(|v| v.as_bool()) == Some(true) {
                        findings.push(META.finding_with_evidence(
                            Status::Fail,
                            "Hook allows unsafe external content injection",
                            format!("hooks.mappings[{}].allowUnsafeExternalContent=true", i),
                        ));
                    }
                }
            }
        }

        if findings.is_empty() {
            findings.push(META.finding(Status::Pass, "No dangerous configuration flags detected"));
        }

        Ok(findings)
    }
}
