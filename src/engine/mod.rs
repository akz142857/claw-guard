pub mod registry;

use anyhow::Result;
use serde::{Deserialize, Serialize};
use std::fmt;

// ---------------------------------------------------------------------------
// Rule ID convention:  CG-XNNN
//   X = category letter:  C=Credential, F=FileSystem, N=Network, P=Process,
//                          G=GatewayConfig, S=Sandbox, K=Plugin, D=DataLeak
//   NNN = sequential number
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum Severity {
    Info,
    Low,
    Medium,
    High,
    Critical,
}

impl fmt::Display for Severity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Severity::Info => write!(f, "INFO"),
            Severity::Low => write!(f, "LOW"),
            Severity::Medium => write!(f, "MEDIUM"),
            Severity::High => write!(f, "HIGH"),
            Severity::Critical => write!(f, "CRITICAL"),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Status {
    Pass,
    Fail,
    Warn,
    Error,
    Skip,
}

impl fmt::Display for Status {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Status::Pass => write!(f, "PASS"),
            Status::Fail => write!(f, "FAIL"),
            Status::Warn => write!(f, "WARN"),
            Status::Error => write!(f, "ERROR"),
            Status::Skip => write!(f, "SKIP"),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Category {
    Credential,
    FileSystem,
    Network,
    Process,
    GatewayConfig,
    Sandbox,
    Plugin,
    DataLeak,
    Docker,
}

impl fmt::Display for Category {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Category::Credential => write!(f, "Credential Exposure"),
            Category::FileSystem => write!(f, "File System Security"),
            Category::Network => write!(f, "Network Exposure"),
            Category::Process => write!(f, "Process Security"),
            Category::GatewayConfig => write!(f, "Gateway Configuration"),
            Category::Sandbox => write!(f, "Sandbox & Isolation"),
            Category::Plugin => write!(f, "Plugin & Extension Security"),
            Category::DataLeak => write!(f, "Data Leak Detection"),
            Category::Docker => write!(f, "Container Security"),
        }
    }
}

/// Metadata describing a detection rule (static, compile-time).
#[derive(Debug, Clone)]
pub struct RuleMeta {
    pub id: &'static str,
    pub name: &'static str,
    pub description: &'static str,
    pub category: Category,
    pub severity: Severity,
    pub remediation: &'static str,
}

/// A single finding produced by a rule execution.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Finding {
    pub rule_id: String,
    pub rule_name: String,
    pub category: Category,
    pub severity: Severity,
    pub status: Status,
    pub detail: String,
    pub evidence: Option<String>,
    pub remediation: String,
}

/// Trait every detection rule must implement.
pub trait Rule: Send + Sync {
    fn meta(&self) -> &RuleMeta;
    fn evaluate(&self) -> Result<Vec<Finding>>;
}

/// Convenience: build a single-finding vec from rule meta + runtime data.
impl RuleMeta {
    pub fn finding(&self, status: Status, detail: impl Into<String>) -> Finding {
        Finding {
            rule_id: self.id.to_string(),
            rule_name: self.name.to_string(),
            category: self.category,
            severity: self.severity,
            status,
            detail: detail.into(),
            evidence: None,
            remediation: self.remediation.to_string(),
        }
    }

    pub fn finding_with_evidence(
        &self,
        status: Status,
        detail: impl Into<String>,
        evidence: impl Into<String>,
    ) -> Finding {
        Finding {
            rule_id: self.id.to_string(),
            rule_name: self.name.to_string(),
            category: self.category,
            severity: self.severity,
            status,
            detail: detail.into(),
            evidence: Some(evidence.into()),
            remediation: self.remediation.to_string(),
        }
    }
}
