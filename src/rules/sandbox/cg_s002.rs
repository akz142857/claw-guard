use crate::engine::*;
use crate::platform;
use anyhow::Result;

/// CG-S002: Dangerous sandbox Docker security bypasses
pub struct CgS002;

static META: RuleMeta = RuleMeta {
    id: "CG-S002",
    name: "Sandbox security bypasses",
    description: "Detects dangerous sandbox overrides: dangerouslyAllowContainerNamespaceJoin, \
                  dangerouslyAllowReservedContainerTargets, dangerouslyAllowExternalBindSources, \
                  seccomp/apparmor unconfined profiles.",
    category: Category::Sandbox,
    severity: Severity::High,
    remediation: "Remove all 'dangerously*' flags from sandbox configuration. \
                  Never use seccomp=unconfined or apparmor=unconfined in production.",
};

const DANGEROUS_BOOLEANS: &[(&str, &str)] = &[
    (
        "/agents/defaults/sandbox/docker/dangerouslyAllowContainerNamespaceJoin",
        "container namespace join allows sandbox escape",
    ),
    (
        "/agents/defaults/sandbox/docker/dangerouslyAllowReservedContainerTargets",
        "reserved container targets allow overwriting sandbox internals",
    ),
    (
        "/agents/defaults/sandbox/docker/dangerouslyAllowExternalBindSources",
        "external bind sources allow mounting arbitrary host paths",
    ),
];

impl StaticRule for CgS002 {
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

        for (path, label) in DANGEROUS_BOOLEANS {
            if json.pointer(path).and_then(|v| v.as_bool()) == Some(true) {
                findings.push(META.finding_with_evidence(
                    Status::Fail,
                    *label,
                    format!("{}=true", path),
                ));
            }
        }

        // Check for unconfined security profiles
        if let Some(seccomp) = json.pointer("/agents/defaults/sandbox/docker/seccompProfile") {
            if seccomp.as_str() == Some("unconfined") {
                findings.push(META.finding_with_evidence(
                    Status::Fail,
                    "Seccomp profile is 'unconfined' — no syscall filtering",
                    "seccompProfile=unconfined",
                ));
            }
        }

        if let Some(apparmor) = json.pointer("/agents/defaults/sandbox/docker/apparmorProfile") {
            if apparmor.as_str() == Some("unconfined") {
                findings.push(META.finding_with_evidence(
                    Status::Fail,
                    "AppArmor profile is 'unconfined' — no mandatory access control",
                    "apparmorProfile=unconfined",
                ));
            }
        }

        if findings.is_empty() {
            findings.push(META.finding(Status::Pass, "No sandbox security bypasses detected"));
        }

        Ok(findings)
    }
}
