// Pheromone Trails: decaying recon data shared passively.
// Workers leave trails of discovered hosts. Stronger trail = recently verified.
// Trails decay over time. The colony follows the strongest trails.
// Keeps the colony coordinated without active communication overhead.

use std::collections::HashMap;
use uuid::Uuid;

/// A pheromone trail marking a discovered host.
#[derive(Debug, Clone)]
pub struct PheromoneTrail {
    pub host: String,
    pub services: Vec<(u16, String)>,  // (port, service_name)
    pub strength: f32,                 // 0-1, decays over time
    pub last_verified: u64,            // unix timestamp
    pub verified_by: Vec<Uuid>,        // agents that confirmed this host
}

/// The colony's shared pheromone map.
pub struct PheromoneMap {
    pub trails: HashMap<String, PheromoneTrail>,
    pub decay_rate: f32,            // strength lost per second
    pub verification_bonus: f32,    // bonus per verifying agent
}

impl Default for PheromoneMap {
    fn default() -> Self {
        Self::new()
    }
}

impl PheromoneMap {
    pub fn new() -> Self {
        Self {
            trails: HashMap::new(),
            decay_rate: 0.0001,
            verification_bonus: 0.2,
        }
    }

    /// Mark a host with pheromones. Strength increases with each verification.
    pub fn mark(&mut self, host: &str, service: Option<(u16, String)>, now: u64, agent: Uuid) {
        let trail = self.trails.entry(host.to_string()).or_insert_with(|| PheromoneTrail {
            host: host.to_string(),
            services: Vec::new(),
            strength: 0.3,
            last_verified: now,
            verified_by: Vec::new(),
        });

        if !trail.verified_by.contains(&agent) {
            trail.verified_by.push(agent);
            trail.strength = (trail.strength + self.verification_bonus).min(1.0);
        }
        trail.last_verified = now;

        if let Some(svc) = service {
            if !trail.services.contains(&svc) {
                trail.services.push(svc);
            }
        }
    }

    /// Apply decay to all trails based on elapsed time.
    pub fn decay(&mut self, now: u64) {
        for trail in self.trails.values_mut() {
            let elapsed = now.saturating_sub(trail.last_verified) as f32;
            trail.strength = (trail.strength - self.decay_rate * elapsed).max(0.0);
        }
    }

    /// Get hosts sorted by strongest pheromone trail.
    pub fn best_targets(&self, min_strength: f32, max_count: usize) -> Vec<String> {
        let mut sorted: Vec<_> = self.trails.iter()
            .filter(|(_, t)| t.strength >= min_strength)
            .collect();
        sorted.sort_by(|a, b| b.1.strength.partial_cmp(&a.1.strength).unwrap());
        sorted.iter().take(max_count).map(|(h, _)| (*h).clone()).collect()
    }

    /// Check if a host has been verified recently.
    pub fn is_fresh(&self, host: &str, max_age_secs: u64, now: u64) -> bool {
        self.trails.get(host)
            .map(|t| now.saturating_sub(t.last_verified) < max_age_secs)
            .unwrap_or(false)
    }
}
