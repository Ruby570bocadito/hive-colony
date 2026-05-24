use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use uuid::Uuid;
use crate::ldc::{Decision, Message, Payload, Role, Value};

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

impl Default for HiveMind {
    fn default() -> Self {
        Self::new()
    }
}

impl HiveMind {
    pub fn new() -> Self {
        Self {
            enabled: false,
            directives: Vec::new(),
            consensus_threshold: 0.66,
        }
    }

    pub fn save_state(&self, path: &std::path::Path) -> Result<(), String> {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent).map_err(|e| e.to_string())?;
        }
        let data = serde_json::to_vec(self).map_err(|e| e.to_string())?;
        std::fs::write(path, data).map_err(|e| e.to_string())
    }

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

    /// Execute approved directives and return their IDs.
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

    /// Execute approved directives and produce arena messages for each.
    /// Returns list of (directive_id, action, Message) that can be published.
    pub fn execute_approved_with_messages(&mut self, agent_id: Uuid) -> Vec<(Uuid, String, Message)> {
        let approved_ids: Vec<(Uuid, String)> = self.directives.iter_mut()
            .filter(|d| d.approved && !d.executed)
            .map(|d| { d.executed = true; (d.directive_id, d.action.clone()) })
            .collect();
        let mut results = Vec::new();
        for (id, action) in approved_ids {
            if let Some(d) = self.directives.iter().find(|d| d.directive_id == id) {
                let msg = self.to_directive_message(d, agent_id);
                results.push((id, action, msg));
            }
        }
        results
    }

    /// Convert an approved directive into an arena Message for broadcast.
    pub fn to_directive_message(&self, directive: &HiveDirective, agent_id: Uuid) -> Message {
        let params_json = serde_json::to_string(&directive.params).unwrap_or_default();
        let detail = format!("hivemind:{}:{}:{}:threshold={}:votes={}",
            directive.action, params_json, directive.directive_id,
            directive.threshold, directive.votes.len());
        Message::status_event(agent_id, Role::Queen, "hive_directive_approved",
            directive.directive_id, Role::Queen, &detail)
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

    /// Process an incoming arena Message and update HiveMind state.
    /// Handles Proposal (new directive), Vote (cast vote), StatusEvent (finalize).
    /// Returns (directive_id, action, action_type) if action is needed.
    pub fn process_arena_message(&mut self, msg: &Message, reputation: &HashMap<Uuid, f32>)
        -> Option<(Uuid, String, &'static str)>
    {
        if !self.enabled {
            return None;
        }
        let agent_id = msg.agent_id;
        let payload = msg.payload.clone();
        match payload {
            Payload::Proposal { action, argument, .. } => {
                let did = self.propose_directive(agent_id, action.clone(),
                    [("argument".into(), argument)].into());
                Some((did, action, "proposed"))
            }
            Payload::Vote { proposal_id, decision, .. } => {
                let dec = decision;
                if self.cast_vote(proposal_id, agent_id, dec) {
                    let approved = self.tally_votes(proposal_id, reputation);
                    if approved {
                        Some((proposal_id, "approved".into(), "approved"))
                    } else {
                        Some((proposal_id, "voted".into(), "voted"))
                    }
                } else {
                    None
                }
            }
            Payload::Belief { asset, value, .. } if asset.starts_with("directive:") => {
                let did_str = asset.trim_start_matches("directive:");
                if let Ok(did) = Uuid::parse_str(did_str) {
                    if let Value::String(meta) = value {
                        if meta.contains("approved") {
                            if let Some(d) = self.directives.iter_mut().find(|d| d.directive_id == did) {
                                d.approved = true;
                                return Some((did, d.action.clone(), "belief_approved"));
                            }
                        }
                    }
                }
                None
            }
            _ => None,
        }
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

        let mut hive = HiveMind::new();
        hive.enabled = true;
        hive.propose_from_operator(Uuid::new_v4(), "snapshot_test".into(), HashMap::new());
        assert!(hive.save_state(&snap_path).is_ok());

        let loaded = HiveMind::load_state(&snap_path).expect("Should load snapshot");
        assert!(loaded.enabled, "enabled flag restored");
        assert_eq!(loaded.directives.len(), 1, "directives restored");

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_process_arena_proposal() {
        let mut hive = HiveMind::new();
        hive.enabled = true;
        let rep = HashMap::new();

        let agent = Uuid::new_v4();
        let (proposal_msg, _pid) = Message::proposal(agent, Role::Worker,
            "scan_target".into(), "10.0.0.5".into());

        let result = hive.process_arena_message(&proposal_msg, &rep);
        assert!(result.is_some());
        let (_, action, action_type) = result.unwrap();
        assert_eq!(action, "scan_target");
        assert_eq!(action_type, "proposed");
        assert_eq!(hive.directives.len(), 1);
    }

    #[test]
    fn test_process_arena_vote_triggers_approval() {
        let mut hive = HiveMind::new();
        hive.enabled = true;
        hive.consensus_threshold = 0.5;

        let agent_a = Uuid::new_v4();
        let agent_b = Uuid::new_v4();
        let agent_c = Uuid::new_v4();

        let did = hive.propose_from_operator(agent_a, "exfil".into(), HashMap::new());
        assert_eq!(hive.directives.len(), 1);

        let vote_a = Message::vote(agent_b, Role::Drone, did, Decision::Support, 1.0);
        let vote_b = Message::vote(agent_c, Role::Honeybee, did, Decision::Support, 1.0);

        let mut rep = HashMap::new();
        rep.insert(agent_b, 1.0);
        rep.insert(agent_c, 1.0);

        // First vote: 1.0/1.0 = 100% >= 0.5 so it passes
        let r1 = hive.process_arena_message(&vote_a, &rep);
        assert!(r1.is_some());
        assert!(hive.directives[0].approved);
    }

    #[test]
    fn test_execute_approved_with_messages() {
        let mut hive = HiveMind::new();
        hive.enabled = true;
        hive.consensus_threshold = 0.5;

        let agent_a = Uuid::new_v4();
        let agent_b = Uuid::new_v4();

        let did = hive.propose_from_operator(agent_a, "kill_switch".into(), HashMap::new());
        hive.cast_vote(did, agent_b, Decision::Support);
        let mut rep = HashMap::new();
        rep.insert(agent_b, 1.0);
        hive.tally_votes(did, &rep);

        let msgs = hive.execute_approved_with_messages(agent_a);
        assert_eq!(msgs.len(), 1);
        let (id, action, msg) = &msgs[0];
        assert_eq!(*id, did);
        assert_eq!(action, "kill_switch");
        assert!(matches!(msg.payload, Payload::StatusEvent { .. }));
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
