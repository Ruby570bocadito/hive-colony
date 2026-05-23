// Consensus engine with dynamic reputation-weighted voting.
// Agents accumulate reputation based on belief accuracy.
// Votes are weighted by reputation; consensus threshold is based on
// the accumulated weight of supporting votes vs total.

use crate::ldc::{Decision, Message, Payload};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use uuid::Uuid;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VoteRecord {
    pub proposal_id: Uuid,
    pub action: String,
    pub argument: String,
    pub votes: HashMap<Uuid, (Decision, f32)>,
    pub proposer: Uuid,
    pub timestamp: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConsensusEngine {
    pub proposals: HashMap<Uuid, VoteRecord>,
    reputation: HashMap<Uuid, f32>,
    threshold: f32,
    default_reputation: f32,
    decay_rate: f32,        // points per hour toward 1.0
    last_decay: u64,        // timestamp of last decay application
}

impl ConsensusEngine {
    pub fn new(threshold: f32) -> Self {
        Self {
            proposals: HashMap::new(),
            reputation: HashMap::new(),
            threshold,
            default_reputation: 1.0,
            decay_rate: 0.2, // decay 0.2 per hour toward 1.0
            last_decay: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs(),
        }
    }

    /// Save consensus engine state to a JSON snapshot.
    pub fn save_state(&self, path: &std::path::Path) -> Result<(), String> {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent).map_err(|e| e.to_string())?;
        }
        let data = serde_json::to_vec(self).map_err(|e| e.to_string())?;
        std::fs::write(path, data).map_err(|e| e.to_string())
    }

    /// Load consensus engine state from a JSON snapshot.
    pub fn load_state(path: &std::path::Path) -> Option<Self> {
        let data = std::fs::read(path).ok()?;
        serde_json::from_slice(&data).ok()
    }

    pub fn register_proposal(&mut self, proposal_id: Uuid, action: String, argument: String, proposer: Uuid, timestamp: u64) {
        self.proposals.insert(proposal_id, VoteRecord {
            proposal_id, action, argument,
            votes: HashMap::new(), proposer, timestamp,
        });
    }

    pub fn cast_vote(&mut self, proposal_id: Uuid, voter_id: Uuid, decision: Decision, base_weight: f32) {
        // Weight by reputation
        let rep = self.reputation.get(&voter_id).copied().unwrap_or(self.default_reputation);
        let weighted = base_weight * rep;
        if let Some(record) = self.proposals.get_mut(&proposal_id) {
            record.votes.insert(voter_id, (decision, weighted.max(0.01)));
        }
    }

    /// Check if consensus has been reached on a proposal.
    /// Returns (reached, support_ratio, total_weight).
    pub fn check_consensus(&self, proposal_id: &Uuid) -> Option<(bool, f32, f32)> {
        let record = self.proposals.get(proposal_id)?;
        let mut total_weight = 0.0f32;
        let mut support_weight = 0.0f32;
        for (_voter_id, (decision, weight)) in &record.votes {
            total_weight += weight;
            if matches!(decision, Decision::Support) {
                support_weight += weight;
            }
        }
        if total_weight == 0.0 { return None; }
        let ratio = support_weight / total_weight;
        Some((ratio >= self.threshold, ratio, total_weight))
    }

    pub fn get_pending_proposals(&self, timeout_secs: u64) -> Vec<Uuid> {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        self.proposals.iter()
            .filter(|(_, r)| now - r.timestamp < timeout_secs && self.check_consensus(&r.proposal_id).is_none())
            .map(|(id, _)| *id)
            .collect()
    }

    /// Adjust reputation based on accuracy.
    /// success = true: agent was right, reward +reward_delta.
    /// success = false: agent was wrong, penalize -penalty_delta.
    pub fn adjust_reputation(&mut self, agent_id: Uuid, success: bool, reward_delta: f32, penalty_delta: f32) {
        let rep = self.reputation.entry(agent_id).or_insert(self.default_reputation);
        if success {
            *rep = (*rep + reward_delta).min(5.0);
        } else {
            *rep = (*rep - penalty_delta).max(0.1);
        }
    }

    /// Apply reputation decay over time.
    /// Reputation slowly drifts toward 1.0 (the default).
    /// This allows agents to rehabilitate after bad predictions.
    pub fn apply_decay(&mut self) {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let elapsed_hours = (now.saturating_sub(self.last_decay)) as f32 / 3600.0;

        if elapsed_hours > 0.0 {
            let decay = self.decay_rate * elapsed_hours;
            for rep in self.reputation.values_mut() {
                if *rep > self.default_reputation {
                    *rep = (*rep - decay).max(self.default_reputation);
                } else if *rep < self.default_reputation {
                    *rep = (*rep + decay).min(self.default_reputation);
                }
            }
            self.last_decay = now;
        }
    }

    pub fn get_reputation(&self, agent_id: &Uuid) -> f32 {
        self.reputation.get(agent_id).copied().unwrap_or(self.default_reputation)
    }

    /// Process an incoming LdC message for consensus tracking.
    pub fn process_message(&mut self, msg: &Message) {
        self.apply_decay();

        match &msg.payload {
            Payload::Proposal { action, argument, proposal_id } => {
                self.register_proposal(*proposal_id, action.clone(), argument.clone(), msg.agent_id, msg.timestamp);
            }
            Payload::Vote { proposal_id, decision, weight } => {
                self.cast_vote(*proposal_id, msg.agent_id, decision.clone(), *weight);
            }
            _ => {}
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ldc::Decision;
    use uuid::Uuid;

    #[test]
    fn test_reputation_weighted_voting() {
        let mut engine = ConsensusEngine::new(0.66);

        let agent_a = Uuid::new_v4();
        let agent_b = Uuid::new_v4();
        let proposal_id = Uuid::new_v4();

        // Agent A has high reputation
        engine.adjust_reputation(agent_a, true, 1.0, 0.0);
        assert!(engine.get_reputation(&agent_a) > 1.0);

        engine.register_proposal(proposal_id, "test_action".into(), "test_arg".into(), agent_a, 1000);
        engine.cast_vote(proposal_id, agent_a, Decision::Support, 1.0);
        engine.cast_vote(proposal_id, agent_b, Decision::Reject, 1.0);

        // A's vote should have more weight
        let (reached, ratio, total) = engine.check_consensus(&proposal_id).unwrap();
        assert!(reached, "Weighted vote should reach threshold");
        assert!(ratio > 0.5, "A's weighted vote should dominate");
        assert!(total > 2.0, "Total weight should exceed sum of base weights");
    }

    #[test]
    fn test_reputation_decay() {
        let mut engine = ConsensusEngine::new(0.66);
        let agent = Uuid::new_v4();

        // Boost reputation
        engine.adjust_reputation(agent, true, 2.0, 0.0);
        let boosted = engine.get_reputation(&agent);
        assert!(boosted > 1.0);

        // Force immediate decay by manipulating last_decay
        engine.last_decay = 0; // force decay on next apply
        engine.apply_decay();
        let decayed = engine.get_reputation(&agent);
        assert!(decayed < boosted, "Reputation should decay toward 1.0");
    }

    #[test]
    fn test_penalty_reduces_weight() {
        let mut engine = ConsensusEngine::new(0.66);
        let agent = Uuid::new_v4();
        let proposal_id = Uuid::new_v4();

        // Penalize agent
        engine.adjust_reputation(agent, false, 0.0, 1.0);
        let rep = engine.get_reputation(&agent);
        assert!(rep <= 0.1, "Penalized agent should have minimal reputation");

        engine.register_proposal(proposal_id, "test".into(), "arg".into(), agent, 1000);
        engine.cast_vote(proposal_id, agent, Decision::Support, 1.0);

        let (_, _, total) = engine.check_consensus(&proposal_id).unwrap();
        assert!(total < 1.0, "Low-reputation vote should have minimal weight");
    }

    #[test]
    fn test_consensus_threshold_not_met() {
        let mut engine = ConsensusEngine::new(0.80);
        let proposal_id = Uuid::new_v4();
        let a = Uuid::new_v4();
        let b = Uuid::new_v4();

        engine.register_proposal(proposal_id, "test".into(), "arg".into(), a, 1000);
        engine.cast_vote(proposal_id, a, Decision::Support, 1.0);
        engine.cast_vote(proposal_id, b, Decision::Reject, 1.0);

        let (reached, _, _) = engine.check_consensus(&proposal_id).unwrap();
        assert!(!reached, "50/50 should not reach 0.80 threshold");
    }
}
