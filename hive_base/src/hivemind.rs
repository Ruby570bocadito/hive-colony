use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use uuid::Uuid;
use crate::ldc::{Decision, Message, Role, Value};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HiveDirective {
    pub directive_id: Uuid,
    pub proposer_id: Uuid,
    pub action: String,
    pub params: HashMap<String, String>,
    pub threshold: f32,
    pub approved: bool,
    pub executed: bool,
    pub votes: HashMap<Uuid, Decision>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HiveMind {
    pub enabled: bool,
    pub directives: Vec<HiveDirective>,
    pub consensus_threshold: f32,
}

impl HiveMind {
    pub fn new() -> Self {
        Self {
            enabled: false,
            directives: Vec::new(),
            consensus_threshold: 0.66,
        }
    }

    /// Save HiveMind state to a JSON snapshot.
    pub fn save_state(&self, path: &std::path::Path) -> Result<(), String> {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent).map_err(|e| e.to_string())?;
        }
        let data = serde_json::to_vec(self).map_err(|e| e.to_string())?;
        std::fs::write(path, data).map_err(|e| e.to_string())
    }

    /// Load HiveMind state from a JSON snapshot. Returns None if file missing.
    pub fn load_state(path: &std::path::Path) -> Option<Self> {
        let data = std::fs::read(path).ok()?;
        serde_json::from_slice(&data).ok()
    }

    pub fn propose_directive(&mut self, proposer_id: Uuid, action: String,
                              params: HashMap<String, String>) -> Uuid {
        let directive_id = Uuid::new_v4();
        self.directives.push(HiveDirective {
            directive_id,
            proposer_id,
            action,
            params,
            threshold: self.consensus_threshold,
            approved: false,
            executed: false,
            votes: HashMap::new(),
        });
        directive_id
    }

    pub fn cast_vote(&mut self, directive_id: Uuid, agent_id: Uuid, decision: Decision) -> bool {
        if let Some(directive) = self.directives.iter_mut()
            .find(|d| d.directive_id == directive_id && !d.approved) {
            directive.votes.insert(agent_id, decision);
            true
        } else {
            false
        }
    }

    pub fn tally_votes(&mut self, directive_id: Uuid, reputation_map: &HashMap<Uuid, f32>) -> bool {
        if let Some(directive) = self.directives.iter_mut()
            .find(|d| d.directive_id == directive_id) {
            let total_weight: f32 = directive.votes.keys()
                .filter_map(|id| reputation_map.get(id))
                .sum();
            let support_weight: f32 = directive.votes.iter()
                .filter(|(_, d)| matches!(d, Decision::Support))
                .filter_map(|(id, _)| reputation_map.get(id))
                .sum();

            let approval = if total_weight > 0.0 {
                support_weight / total_weight
            } else {
                0.0
            };

            directive.approved = approval >= directive.threshold;
            directive.approved
        } else {
            false
        }
    }

    pub fn execute_approved(&mut self) -> Vec<Uuid> {
        let mut executed = Vec::new();
        for directive in self.directives.iter_mut() {
            if directive.approved && !directive.executed {
                directive.executed = true;
                executed.push(directive.directive_id);
            }
        }
        executed
    }

    pub fn get_pending_directives(&self) -> Vec<&HiveDirective> {
        self.directives.iter()
            .filter(|d| !d.approved)
            .collect()
    }

    pub fn propose_from_operator(&mut self, operator_id: Uuid, action: String,
                                  params: HashMap<String, String>) -> Uuid {
        self.propose_directive(operator_id, action, params)
    }

    pub fn to_belief(&self, directive: &HiveDirective, agent_id: Uuid) -> Message {
        let params_str: Vec<String> = directive.params.iter()
            .map(|(k, v)| format!("{}={}", k, v))
            .collect();
        let value = Value::String(format!("hivemind:{}:{}:{}",
            directive.action, params_str.join(","), directive.directive_id));

        Message::belief(agent_id, Role::Queen,
            format!("directive:{}", directive.directive_id),
            value, 0.9)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    #[test]
    fn test_propose_and_vote() {
        let mut hive = HiveMind::new();
        hive.enabled = true;

        let op_id = Uuid::new_v4();
        let agent_a = Uuid::new_v4();
        let agent_b = Uuid::new_v4();
        let agent_c = Uuid::new_v4();

        let mut params = HashMap::new();
        params.insert("target".into(), "10.0.0.5".into());
        params.insert("action".into(), "exfiltrate".into());

        let directive_id = hive.propose_from_operator(op_id, "exfiltrate_now".into(), params);
        assert!(hive.cast_vote(directive_id, agent_a, Decision::Support));
        assert!(hive.cast_vote(directive_id, agent_b, Decision::Support));
        assert!(hive.cast_vote(directive_id, agent_c, Decision::Reject));

        let mut rep = HashMap::new();
        rep.insert(agent_a, 1.0);
        rep.insert(agent_b, 1.0);
        rep.insert(agent_c, 1.0);

        let approved = hive.tally_votes(directive_id, &rep);
        assert!(approved, "66% support should pass with 0.66 threshold");

        let executed = hive.execute_approved();
        assert_eq!(executed.len(), 1, "Should execute 1 directive");
    }

    #[test]
    fn test_rejection() {
        let mut hive = HiveMind::new();
        hive.enabled = true;

        let op_id = Uuid::new_v4();
        let agent_a = Uuid::new_v4();
        let agent_b = Uuid::new_v4();

        let directive_id = hive.propose_from_operator(op_id, "risky_action".into(), HashMap::new());
        hive.cast_vote(directive_id, agent_a, Decision::Support);
        hive.cast_vote(directive_id, agent_b, Decision::Reject);

        let mut rep = HashMap::new();
        rep.insert(agent_a, 1.0);
        rep.insert(agent_b, 1.0);

        let approved = hive.tally_votes(directive_id, &rep);
        assert!(!approved, "50% support should fail with 0.66 threshold");
    }

    #[test]
    fn test_pending_directives() {
        let mut hive = HiveMind::new();
        hive.propose_from_operator(Uuid::new_v4(), "test".into(), HashMap::new());
        assert_eq!(hive.get_pending_directives().len(), 1);
    }

    #[test]
    fn test_save_and_load_state() {
        let dir = std::env::temp_dir().join("hive_test_hivemind_snap");
        let _ = std::fs::create_dir_all(&dir);
        let snap_path = dir.join("hivemind.json");

        // Create state, save it
        let mut hive = HiveMind::new();
        hive.enabled = true;
        hive.propose_from_operator(Uuid::new_v4(), "snapshot_test".into(), HashMap::new());
        assert!(hive.save_state(&snap_path).is_ok());

        // Load into a new instance
        let loaded = HiveMind::load_state(&snap_path).expect("Should load snapshot");
        assert!(loaded.enabled, "enabled flag restored");
        assert_eq!(loaded.directives.len(), 1, "directives restored");
        assert!((loaded.consensus_threshold - 0.66).abs() < 0.01);

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_consensus_save_and_load_state() {
        use crate::consensus::ConsensusEngine;
        let dir = std::env::temp_dir().join("hive_test_consensus_snap");
        let _ = std::fs::create_dir_all(&dir);
        let snap_path = dir.join("consensus.json");

        let mut engine = ConsensusEngine::new(0.75);
        let agent = Uuid::new_v4();
        engine.adjust_reputation(agent, true, 2.0, 0.0);
        assert!(engine.get_reputation(&agent) > 2.0);
        assert!(engine.save_state(&snap_path).is_ok());

        let loaded = ConsensusEngine::load_state(&snap_path).expect("Should load snapshot");
        assert!(loaded.get_reputation(&agent) > 2.0);

        let _ = std::fs::remove_dir_all(&dir);
    }
}
