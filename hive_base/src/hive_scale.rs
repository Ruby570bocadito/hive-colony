// HiveScale: auto-scaling — adjusts agent count based on host resources.
// More CPU/RAM → more Workers for faster scanning.
// Low resources → minimum footprint (Worker + Drone only).

use tracing::{info, warn};

/// Current resource state of the host.
pub struct HiveResources {
    pub cpu_cores: usize,
    pub cpu_load_pct: f32,
    pub ram_total_mb: u64,
    pub ram_free_mb: u64,
    pub disk_free_pct: f32,
}

impl HiveResources {
    pub fn measure() -> Self {
        let cpu_cores = num_cpus::get();
        let cpu_load = read_loadavg() / cpu_cores.max(1) as f32 * 100.0;

        let (ram_total, ram_free) = read_meminfo();
        let disk_free = read_disk_free();

        Self {
            cpu_cores,
            cpu_load_pct: cpu_load.min(100.0),
            ram_total_mb: ram_total / 1024,
            ram_free_mb: ram_free / 1024,
            disk_free_pct: disk_free,
        }
    }

    /// Recommend how many additional Worker agents to spawn.
    /// Returns 0 if resources are tight, up to 4 if abundant.
    pub fn recommend_workers(&self) -> usize {
        if self.ram_free_mb < 500 {
            warn!("HIVE_SCALE: low memory ({}MB free), keeping minimum", self.ram_free_mb);
            return 0;
        }
        if self.cpu_load_pct > 80.0 {
            info!("HIVE_SCALE: high CPU ({}%), skipping new workers", self.cpu_load_pct);
            return 0;
        }

        // Scale: 1 worker per 2 free cores, up to 4 max
        let headroom = ((100.0 - self.cpu_load_pct) / 25.0) as usize;
        headroom.min(4)
    }

    /// Check if we should reduce to minimum (Worker + Drone only).
    pub fn should_shrink(&self) -> bool {
        self.ram_free_mb < 200 || self.cpu_load_pct > 95.0
    }

    /// Check if disk is nearly full — Honeybee should prioritize large targets.
    pub fn disk_critical(&self) -> bool {
        self.disk_free_pct < 20.0
    }
}

fn read_loadavg() -> f32 {
    std::fs::read_to_string("/proc/loadavg")
        .ok()
        .and_then(|s| s.split_whitespace().next()?.parse().ok())
        .unwrap_or(0.0)
}

fn read_meminfo() -> (u64, u64) {
    let content = std::fs::read_to_string("/proc/meminfo").unwrap_or_default();
    let mut total = 0u64;
    let mut available = 0u64;
    for line in content.lines() {
        if line.starts_with("MemTotal:") {
            total = line.split_whitespace().nth(1).and_then(|s| s.parse().ok()).unwrap_or(0);
        }
        if line.starts_with("MemAvailable:") {
            available = line.split_whitespace().nth(1).and_then(|s| s.parse().ok()).unwrap_or(0);
        }
    }
    (total, available)
}

fn read_disk_free() -> f32 {
    // Check root partition
    if let Ok(out) = std::process::Command::new("df")
        .args(["-h", "/"])
        .output()
    {
        let text = String::from_utf8_lossy(&out.stdout);
        for line in text.lines().skip(1) {
            let parts: Vec<&str> = line.split_whitespace().collect();
            if let Some(pct) = parts.get(4) {
                return pct.trim_end_matches('%').parse().unwrap_or(100.0);
            }
        }
    }
    100.0
}
