use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use uuid::Uuid;
use crate::ldc::{Decision, Message, Role, Value};
use crate::consensus::ConsensusEngine;

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
}
