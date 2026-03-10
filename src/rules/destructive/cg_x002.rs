use crate::engine::*;
use crate::platform;
use anyhow::Result;

/// CG-X002: No filesystem write scope restriction
pub struct CgX002;

static META: RuleMeta = RuleMeta {
    id: "CG-X002",
    name: "No filesystem write scope restriction",
    description: "Checks if the agent's file write access is restricted to a specific \
                  workspace directory. Without scope limits, the agent can write or delete \
                  files anywhere the process user has access.",
    category: Category::DestructiveAction,
    severity: Severity::High,
    remediation: "Restrict agent file access in openclaw.json: \
                  {\"tools\": {\"exec\": {\"applyPatch\": {\"workspaceOnly\": true}, \
                  \"allowedPaths\": [\"/home/user/project\"]}}}. \
                  Or use sandbox mode to isolate the filesystem.",
};

const SCOPE_FIELDS: &[&str] = &[
    "/tools/exec/applyPatch/workspaceOnly",
    "/tools/exec/allowedPaths",
    "/tools/exec/rootDir",
    "/tools/exec/sandboxPaths",
    "/tools/writeFile/workspaceOnly",
    "/tools/writeFile/allowedPaths",
    "/security/allowedPaths",
    "/security/workspaceRoot",
];

impl StaticRule for CgX002 {
    fn meta(&self) -> &RuleMeta {
        &META
    }

    fn evaluate(&self) -> Result<Vec<Finding>> {
        let config_path = platform::home_dir().join(".openclaw/openclaw.json");

        if !config_path.exists() {
            return Ok(vec![META.finding(
                Status::Fail,
                "openclaw.json not found — agent has unrestricted filesystem access",
            )]);
        }

        let content = std::fs::read_to_string(&config_path)?;
        let json: serde_json::Value = serde_json::from_str(&content)?;

        let has_scope = SCOPE_FIELDS.iter().any(|path| {
            if let Some(val) = json.pointer(path) {
                match val {
                    serde_json::Value::Bool(b) => *b, // workspaceOnly=true
                    serde_json::Value::Array(a) => !a.is_empty(),
                    serde_json::Value::String(s) => !s.is_empty(),
                    _ => false,
                }
            } else {
                false
            }
        });

        if has_scope {
            Ok(vec![META.finding(
                Status::Pass,
                "Filesystem write scope restriction configured",
            )])
        } else {
            Ok(vec![META.finding(
                Status::Fail,
                "No filesystem write scope configured. The agent can create, modify, \
                 or delete files anywhere the process user can access, including \
                 ~/.ssh, /etc, and other critical paths.",
            )])
        }
    }
}
