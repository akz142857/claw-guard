use crate::engine::*;
use anyhow::Result;
use std::process::Command;

/// CG-T001: Docker socket mounted into OpenClaw containers
pub struct CgT001;

static META: RuleMeta = RuleMeta {
    id: "CG-T001",
    name: "Docker socket exposure",
    description: "Checks if /var/run/docker.sock is mounted into any OpenClaw container. \
                  Docker socket access from inside a container is equivalent to root on the host.",
    category: Category::Docker,
    severity: Severity::Critical,
    remediation: "Never mount Docker socket into containers. Use Docker-in-Docker (dind) \
                  or a rootless Docker setup if containers need Docker access.",
};

impl StaticRule for CgT001 {
    fn meta(&self) -> &RuleMeta {
        &META
    }

    fn evaluate(&self) -> Result<Vec<Finding>> {
        // Check if Docker is available
        let docker_check = Command::new("docker").arg("version").output();
        if docker_check.is_err() {
            return Ok(vec![META.finding(Status::Skip, "Docker not available on this system")]);
        }

        // List running containers with their mounts
        let output = Command::new("docker")
            .args(["ps", "--format", "{{.ID}} {{.Names}}"])
            .output();

        let container_list = match output {
            Ok(out) => String::from_utf8_lossy(&out.stdout).to_string(),
            Err(_) => return Ok(vec![META.finding(Status::Skip, "Cannot list Docker containers")]),
        };

        let mut findings = Vec::new();

        for line in container_list.lines() {
            let parts: Vec<&str> = line.split_whitespace().collect();
            if parts.is_empty() {
                continue;
            }
            let container_id = parts[0];
            let container_name = parts.get(1).unwrap_or(&container_id);

            // Only check OpenClaw-related containers
            let name_lower = container_name.to_lowercase();
            if !name_lower.contains("openclaw") && !name_lower.contains("claw") {
                continue;
            }

            // Inspect mounts
            if let Ok(inspect) = Command::new("docker")
                .args(["inspect", "--format", "{{json .Mounts}}", container_id])
                .output()
            {
                let mounts = String::from_utf8_lossy(&inspect.stdout).to_lowercase();
                if mounts.contains("docker.sock") {
                    findings.push(META.finding_with_evidence(
                        Status::Fail,
                        format!(
                            "Container '{}' has Docker socket mounted — equivalent to host root",
                            container_name
                        ),
                        format!("container={} id={}", container_name, container_id),
                    ));
                }
            }
        }

        if findings.is_empty() {
            findings.push(META.finding(
                Status::Pass,
                "No OpenClaw containers with Docker socket mount detected",
            ));
        }

        Ok(findings)
    }
}
