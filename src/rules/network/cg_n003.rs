use crate::engine::*;
use anyhow::Result;
use std::net::TcpStream;
use std::time::Duration;

/// CG-N003: OpenClaw known port surface scan
pub struct CgN003;

static META: RuleMeta = RuleMeta {
    id: "CG-N003",
    name: "OpenClaw port surface scan",
    description: "Probes all known OpenClaw ports (gateway 18789, bridge 18790, browser 18791, \
                  canvas 18793, CDP 18800-18810, sandbox VNC 5900/6080, CDP 9222) to map the \
                  exposed attack surface.",
    category: Category::Network,
    severity: Severity::Medium,
    remediation: "Disable unused services. Ensure all open ports require authentication.",
};

const KNOWN_PORTS: &[(&str, u16)] = &[
    ("gateway", 18789),
    ("bridge", 18790),
    ("browser_control", 18791),
    ("canvas", 18793),
    ("cdp_0", 18800),
    ("cdp_1", 18801),
    ("cdp_2", 18802),
    ("cdp_3", 18803),
    ("cdp_4", 18804),
    ("cdp_5", 18805),
    ("sandbox_cdp", 9222),
    ("sandbox_vnc", 5900),
    ("sandbox_novnc", 6080),
];

impl StaticRule for CgN003 {
    fn meta(&self) -> &RuleMeta {
        &META
    }

    fn evaluate(&self) -> Result<Vec<Finding>> {
        let mut findings = Vec::new();
        let mut open_ports = Vec::new();
        let timeout = Duration::from_millis(200);

        for (name, port) in KNOWN_PORTS {
            let addr = format!("127.0.0.1:{}", port);
            if TcpStream::connect_timeout(
                &addr.parse().unwrap(),
                timeout,
            ).is_ok() {
                open_ports.push((*name, *port));
                findings.push(META.finding_with_evidence(
                    Status::Warn,
                    format!("Port {} ({}) is open", port, name),
                    format!("port={} service={}", port, name),
                ));
            }
        }

        if open_ports.is_empty() {
            findings.push(META.finding(Status::Pass, "No OpenClaw ports detected on localhost"));
        }

        Ok(findings)
    }
}
