// IPC Contracts: formal schema validation + agent state machine.
// Every LdC message passing through the shared arena is validated against
// a per-variant schema and the sender's current agent state before processing.
// Invalid messages trigger HTL SecurityTrigger events and can push agents
// to DEGRADED state.

use crate::ldc::{Decision, Message, Payload, Role, Value};
use crate::telemetry::{EventType, TelemetryCollector};
use std::sync::atomic::{AtomicU8, Ordering};
use tracing::info;
use uuid::Uuid;

// ── AgentState ────────────────────────────────────────────────────────────

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AgentState {
    Init = 0,
    Active = 1,
    Degraded = 2,
    Dead = 3,
}

impl AgentState {
    pub fn from_u8(v: u8) -> Self {
        match v {
            0 => AgentState::Init,
            1 => AgentState::Active,
            2 => AgentState::Degraded,
            _ => AgentState::Dead,
        }
    }

    pub fn to_u8(self) -> u8 {
        self as u8
    }

    pub fn label(&self) -> &'static str {
        match self {
            AgentState::Init => "init",
            AgentState::Active => "active",
            AgentState::Degraded => "degraded",
            AgentState::Dead => "dead",
        }
    }
}

// ── StateTransition ───────────────────────────────────────────────────────

#[derive(Clone, Debug)]
pub struct StateTransition {
    pub from: AgentState,
    pub to: AgentState,
    pub reason: String,
    pub timestamp: u64,
}

impl StateTransition {
    fn is_valid(from: AgentState, to: AgentState) -> bool {
        matches!(
            (from, to),
            (AgentState::Init, AgentState::Active)
                | (AgentState::Active, AgentState::Degraded)
                | (AgentState::Active, AgentState::Dead)
                | (AgentState::Degraded, AgentState::Active)
                | (AgentState::Degraded, AgentState::Dead)
        )
    }
}

// ── AgentStateMachine ─────────────────────────────────────────────────────

pub struct AgentStateMachine {
    state: AtomicU8,
    history: Vec<StateTransition>,
    invalid_message_count: u64,
    total_messages_seen: u64,
    degrade_threshold: u64,
    agent_id: Uuid,
}

impl AgentStateMachine {
    pub fn new(agent_id: Uuid) -> Self {
        Self {
            state: AtomicU8::new(AgentState::Init.to_u8()),
            history: Vec::new(),
            invalid_message_count: 0,
            total_messages_seen: 0,
            degrade_threshold: 5,
            agent_id,
        }
    }

    pub fn with_degrade_threshold(mut self, threshold: u64) -> Self {
        self.degrade_threshold = threshold;
        self
    }

    pub fn state(&self) -> AgentState {
        AgentState::from_u8(self.state.load(Ordering::Acquire))
    }

    pub fn transition(&mut self, to: AgentState, reason: impl Into<String>) -> Result<StateTransition, &'static str> {
        let from = self.state();
        if !StateTransition::is_valid(from, to) {
            return Err("Invalid state transition");
        }
        let ts = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos() as u64;
        let t = StateTransition {
            from,
            to,
            reason: reason.into(),
            timestamp: ts,
        };
        info!("Agent {} state: {} → {} ({})", self.agent_id, from.label(), to.label(), t.reason);
        self.state.store(to.to_u8(), Ordering::Release);
        self.history.push(t.clone());
        Ok(t)
    }

    pub fn activate(&mut self) -> Result<StateTransition, &'static str> {
        self.transition(AgentState::Active, "initialization complete")
    }

    pub fn degrade(&mut self, reason: impl Into<String>) -> Result<StateTransition, &'static str> {
        self.transition(AgentState::Degraded, reason)
    }

    pub fn mark_dead(&mut self, reason: impl Into<String>) -> Result<StateTransition, &'static str> {
        self.transition(AgentState::Dead, reason)
    }

    pub fn recover(&mut self) -> Result<StateTransition, &'static str> {
        self.transition(AgentState::Active, "recovered from degraded")
    }

    /// Record a message observation. If invalid, increment counter and
    /// auto-degrade if threshold exceeded.
    pub fn record_message(&mut self, is_valid: bool) -> Option<StateTransition> {
        self.total_messages_seen += 1;
        if !is_valid {
            self.invalid_message_count += 1;
            if self.invalid_message_count >= self.degrade_threshold && self.state() == AgentState::Active {
                if let Ok(t) = self.degrade(format!("{} invalid messages", self.invalid_message_count)) {
                    return Some(t);
                }
            }
        }
        None
    }

    pub fn invalid_message_count(&self) -> u64 {
        self.invalid_message_count
    }

    pub fn total_messages_seen(&self) -> u64 {
        self.total_messages_seen
    }

    pub fn history(&self) -> &[StateTransition] {
        &self.history
    }

    pub fn history_len(&self) -> usize {
        self.history.len()
    }

    /// Reset the machine (e.g. after replay reset)
    pub fn reset(&mut self) {
        self.state.store(AgentState::Init.to_u8(), Ordering::Release);
        self.history.clear();
        self.invalid_message_count = 0;
        self.total_messages_seen = 0;
    }
}

// ── ValidationResult ─────────────────────────────────────────────────────-

#[derive(Clone, Debug)]
pub struct ValidationResult {
    pub valid: bool,
    pub errors: Vec<String>,
    pub warnings: Vec<String>,
}

impl ValidationResult {
    pub fn ok() -> Self {
        Self {
            valid: true,
            errors: vec![],
            warnings: vec![],
        }
    }

    pub fn err(msg: impl Into<String>) -> Self {
        Self {
            valid: false,
            errors: vec![msg.into()],
            warnings: vec![],
        }
    }

    pub fn with_warning(mut self, msg: impl Into<String>) -> Self {
        self.warnings.push(msg.into());
        self
    }
}

// ── SchemaValidator ───────────────────────────────────────────────────────

/// Validate a single Payload variant against its formal schema.
pub fn validate_payload(payload: &Payload) -> ValidationResult {
    match payload {
        Payload::Belief { asset, value, confidence } => {
            let mut r = ValidationResult::ok();
            if asset.trim().is_empty() {
                return ValidationResult::err("Belief.asset must not be empty");
            }
            if asset.len() > 256 {
                r = r.with_warning("Belief.asset exceeds 256 chars");
            }
            if !(0.0..=1.0).contains(confidence) {
                return ValidationResult::err("Belief.confidence must be in [0.0, 1.0]");
            }
            match value {
                Value::Bool(_) => {}
                Value::String(s) => {
                    if s.len() > 4096 {
                        r = r.with_warning("Belief.value.String exceeds 4096 chars");
                    }
                }
                Value::Int(_) => {}
                Value::Float(f) => {
                    if !f.is_finite() {
                        return ValidationResult::err("Belief.value.Float is NaN or Inf");
                    }
                }
            }
            r
        }

        Payload::Desire { action, priority } => {
            if action.trim().is_empty() {
                return ValidationResult::err("Desire.action must not be empty");
            }
            if !(0.0..=1.0).contains(priority) {
                return ValidationResult::err("Desire.priority must be in [0.0, 1.0]");
            }
            ValidationResult::ok()
        }

        Payload::Proposal { action, argument, proposal_id: _ } => {
            if action.trim().is_empty() {
                return ValidationResult::err("Proposal.action must not be empty");
            }
            if argument.trim().is_empty() {
                return ValidationResult::err("Proposal.argument must not be empty");
            }
            ValidationResult::ok()
        }

        Payload::Vote { proposal_id: _, decision, weight } => {
            if !(0.0..=10.0).contains(weight) {
                return ValidationResult::err("Vote.weight must be in [0.0, 10.0]");
            }
            match decision {
                Decision::Support | Decision::Reject | Decision::Abstain => {}
            }
            ValidationResult::ok()
        }

        Payload::Request { service, payload: _ } => {
            if service.trim().is_empty() {
                return ValidationResult::err("Request.service must not be empty");
            }
            ValidationResult::ok()
        }

        Payload::Query { dilemma, context, query_id: _ } => {
            if dilemma.trim().is_empty() {
                return ValidationResult::err("Query.dilemma must not be empty");
            }
            if context.len() > 16384 {
                return ValidationResult::err("Query.context exceeds 16384 chars");
            }
            ValidationResult::ok()
        }

        Payload::Response { query_id: _, answer, confidence } => {
            if answer.trim().is_empty() {
                return ValidationResult::err("Response.answer must not be empty");
            }
            if !(0.0..=1.0).contains(confidence) {
                return ValidationResult::err("Response.confidence must be in [0.0, 1.0]");
            }
            ValidationResult::ok()
        }

        Payload::Heartbeat => ValidationResult::ok(),

        Payload::StatusEvent { event_type, subject_id: _, subject_role: _, detail } => {
            if event_type.trim().is_empty() {
                return ValidationResult::err("StatusEvent.event_type must not be empty");
            }
            if detail.len() > 4096 {
                return ValidationResult::err("StatusEvent.detail exceeds 4096 chars");
            }
            ValidationResult::ok()
        }
    }
}

/// Validate an entire Message (agent_id, role, timestamp + payload).
pub fn validate_message(msg: &Message) -> ValidationResult {
    let mut r = ValidationResult::ok();

    // agent_id should parse as a valid UUID (it already is by type, but check zero)
    if msg.agent_id.is_nil() {
        return ValidationResult::err("Message.agent_id is nil");
    }

    // timestamp should be reasonable (not zero, not in far future)
    if msg.timestamp == 0 {
        return ValidationResult::err("Message.timestamp is zero");
    }
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    if msg.timestamp > now + 3600 {
        r = r.with_warning("Message.timestamp is >1h in the future");
    }
    if now > 0 && msg.timestamp < now - 86400 {
        r = r.with_warning("Message.timestamp is >24h in the past");
    }

    // Validate nested payload
    let pr = validate_payload(&msg.payload);
    if !pr.valid {
        return pr;
    }
    r.errors.extend(pr.errors);
    r.warnings.extend(pr.warnings);

    r
}

// ── MessageValidator (pipeline combining schema + state machine) ──────────

pub struct MessageValidator {
    state_machine: AgentStateMachine,
    collector: Option<Box<TelemetryCollector>>,
    reject_count: u64,
}

impl MessageValidator {
    pub fn new(agent_id: Uuid) -> Self {
        Self {
            state_machine: AgentStateMachine::new(agent_id),
            collector: None,
            reject_count: 0,
        }
    }

    pub fn with_collector(mut self, collector: TelemetryCollector) -> Self {
        self.collector = Some(Box::new(collector));
        self
    }

    pub fn attach_collector(&mut self, collector: TelemetryCollector) {
        self.collector = Some(Box::new(collector));
    }

    pub fn state_machine(&self) -> &AgentStateMachine {
        &self.state_machine
    }

    pub fn state_machine_mut(&mut self) -> &mut AgentStateMachine {
        &mut self.state_machine
    }

    pub fn reject_count(&self) -> u64 {
        self.reject_count
    }

    /// Validate a message against schema + state machine.
    /// Returns Ok if valid, Err with reason if not.
    /// Automatically emits HTL SecurityTrigger on rejection.
    pub fn validate(&mut self, msg: &Message) -> Result<(), Vec<String>> {
        let schema_result = validate_message(msg);

        // Update state machine with validity
        if let Some(transition) = self.state_machine.record_message(schema_result.valid) {
            self.emit_security_trigger(
                "state_transition",
                &format!("{} → {}: {}", transition.from.label(), transition.to.label(), transition.reason),
                msg,
            );
        }

        if !schema_result.valid {
            self.reject_count += 1;
            // Emit HTL SecurityTrigger for each validation failure
            self.emit_security_trigger(
                "schema_violation",
                &schema_result.errors.join("; "),
                msg,
            );
            return Err(schema_result.errors);
        }

        // Extra: state-based filtering
        let state = self.state_machine.state();
        match state {
            AgentState::Dead => {
                let err = "Agent is DEAD — rejecting all messages";
                self.emit_security_trigger("dead_agent_msg", err, msg);
                return Err(vec![err.to_string()]);
            }
            AgentState::Init if !matches!(msg.payload, Payload::Heartbeat) => {
                let err = "Agent is INIT — only Heartbeat allowed";
                self.emit_security_trigger("init_msg_rejected", err, msg);
                return Err(vec![err.to_string()]);
            }
            _ => {}
        }

        // Check for self-messages (shouldn't happen but defensive)
        if !msg.agent_id.is_nil() && self.state_machine.agent_id == msg.agent_id {
            let err = "Self-message rejected (agent_id matches own)";
            self.emit_security_trigger("self_message", err, msg);
            return Err(vec![err.to_string()]);
        }

        Ok(())
    }

    /// Emit an HTL SecurityTrigger event
    fn emit_security_trigger(&self, trigger_type: &str, detail: &str, msg: &Message) {
        if let Some(ref collector) = self.collector {
            let payload = serde_json::json!({
                "trigger": trigger_type,
                "detail": detail,
                "agent_id": msg.agent_id.to_string(),
                "role": format!("{:?}", msg.agent_role),
                "payload_type": format!("{:?}", std::mem::discriminant(&msg.payload)),
            });
            collector.emit(
                EventType::SecurityTrigger,
                vec![],
                Some(serde_json::to_vec(&payload).unwrap_or_default()),
            );
        }
    }
}

// ── Chaos integration: contract-violating faults ──────────────────────────

/// New Fault variants that specifically target contract validation.
/// These are injected via ChaosEngine.add_contract_fault().
#[derive(Clone, Debug, PartialEq)]
pub enum ContractFault {
    /// Inject a message with empty fields (violates schema)
    EmptyFieldMessage,
    /// Inject a message with out-of-range confidence
    BadConfidence,
    /// Inject a self-referencing message (agent_id == sender slot)
    SelfReferencingMessage,
    /// Inject a message with NaN float value
    NanValue,
    /// Flood with enough bad messages to force DEGRADED
    FloodInvalidMessages(usize),
}

impl ContractFault {
    pub fn label(&self) -> &'static str {
        match self {
            ContractFault::EmptyFieldMessage => "empty_field_message",
            ContractFault::BadConfidence => "bad_confidence",
            ContractFault::SelfReferencingMessage => "self_referencing_message",
            ContractFault::NanValue => "nan_value",
            ContractFault::FloodInvalidMessages(_) => "flood_invalid_messages",
        }
    }

    /// Build a Message that violates the corresponding contract.
    pub fn build_message(&self, agent_id: Uuid, role: Role) -> Message {
        match self {
            ContractFault::EmptyFieldMessage => Message {
                agent_id,
                agent_role: role,
                timestamp: 1,
                payload: Payload::Belief {
                    asset: "".into(),
                    value: Value::Bool(true),
                    confidence: 0.5,
                },
            },
            ContractFault::BadConfidence => Message {
                agent_id,
                agent_role: role,
                timestamp: 1,
                payload: Payload::Belief {
                    asset: "test".into(),
                    value: Value::Bool(true),
                    confidence: 99.9,
                },
            },
            ContractFault::SelfReferencingMessage => Message {
                agent_id,
                agent_role: role,
                timestamp: 1,
                payload: Payload::Heartbeat,
            },
            ContractFault::NanValue => Message {
                agent_id,
                agent_role: role,
                timestamp: 1,
                payload: Payload::Belief {
                    asset: "test".into(),
                    value: Value::Float(f64::NAN),
                    confidence: 0.5,
                },
            },
            ContractFault::FloodInvalidMessages(_) => Message {
                agent_id,
                agent_role: role,
                timestamp: 0, // zero timestamp = invalid
                payload: Payload::Heartbeat,
            },
        }
    }
}

// ── Tests ────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ldc::{Decision, Message, Role, Value};
    use uuid::Uuid;

    fn test_id() -> Uuid {
        Uuid::new_v4()
    }

    fn test_msg(payload: Payload) -> Message {
        Message {
            agent_id: test_id(),
            agent_role: Role::Worker,
            timestamp: 1000,
            payload,
        }
    }

    // ── Schema validation tests ──

    #[test]
    fn test_validate_valid_belief() {
        let msg = test_msg(Payload::Belief {
            asset: "edr_present".into(),
            value: Value::Bool(true),
            confidence: 0.95,
        });
        assert!(validate_message(&msg).valid);
    }

    #[test]
    fn test_validate_belief_empty_asset() {
        let msg = test_msg(Payload::Belief {
            asset: "".into(),
            value: Value::Bool(true),
            confidence: 0.5,
        });
        assert!(!validate_message(&msg).valid);
    }

    #[test]
    fn test_validate_belief_confidence_out_of_range() {
        let msg = test_msg(Payload::Belief {
            asset: "test".into(),
            value: Value::Bool(true),
            confidence: 1.5,
        });
        assert!(!validate_message(&msg).valid);
    }

    #[test]
    fn test_validate_belief_nan_value() {
        let msg = test_msg(Payload::Belief {
            asset: "test".into(),
            value: Value::Float(f64::NAN),
            confidence: 0.5,
        });
        assert!(!validate_message(&msg).valid);
    }

    #[test]
    fn test_validate_valid_vote() {
        let msg = test_msg(Payload::Vote {
            proposal_id: test_id(),
            decision: Decision::Support,
            weight: 1.0,
        });
        assert!(validate_message(&msg).valid);
    }

    #[test]
    fn test_validate_vote_weight_out_of_range() {
        let msg = test_msg(Payload::Vote {
            proposal_id: test_id(),
            decision: Decision::Support,
            weight: 99.0,
        });
        assert!(!validate_message(&msg).valid);
    }

    #[test]
    fn test_validate_empty_desire() {
        let msg = test_msg(Payload::Desire {
            action: "".into(),
            priority: 0.5,
        });
        assert!(!validate_message(&msg).valid);
    }

    #[test]
    fn test_validate_empty_proposal() {
        let msg = test_msg(Payload::Proposal {
            action: "".into(),
            argument: "arg".into(),
            proposal_id: test_id(),
        });
        assert!(!validate_message(&msg).valid);
    }

    #[test]
    fn test_validate_empty_status_event() {
        let msg = test_msg(Payload::StatusEvent {
            event_type: "".into(),
            subject_id: test_id(),
            subject_role: Role::Worker,
            detail: "test".into(),
        });
        assert!(!validate_message(&msg).valid);
    }

    #[test]
    fn test_validate_nil_agent_id() {
        let msg = Message {
            agent_id: Uuid::nil(),
            agent_role: Role::Worker,
            timestamp: 1000,
            payload: Payload::Heartbeat,
        };
        assert!(!validate_message(&msg).valid);
    }

    #[test]
    fn test_validate_zero_timestamp() {
        let msg = Message {
            agent_id: test_id(),
            agent_role: Role::Worker,
            timestamp: 0,
            payload: Payload::Heartbeat,
        };
        assert!(!validate_message(&msg).valid);
    }

    // ── State machine tests ──

    #[test]
    fn test_state_machine_starts_init() {
        let sm = AgentStateMachine::new(test_id());
        assert_eq!(sm.state(), AgentState::Init);
    }

    #[test]
    fn test_state_machine_valid_transitions() {
        let mut sm = AgentStateMachine::new(test_id());

        assert!(sm.activate().is_ok());
        assert_eq!(sm.state(), AgentState::Active);

        assert!(sm.degrade("test fault").is_ok());
        assert_eq!(sm.state(), AgentState::Degraded);

        assert!(sm.recover().is_ok());
        assert_eq!(sm.state(), AgentState::Active);

        assert!(sm.mark_dead("kill switch").is_ok());
        assert_eq!(sm.state(), AgentState::Dead);
    }

    #[test]
    fn test_state_machine_invalid_transition() {
        let mut sm = AgentStateMachine::new(test_id());
        // Init -> Dead is invalid (must go through Active)
        assert!(sm.transition(AgentState::Dead, "bypass").is_err());
        assert_eq!(sm.state(), AgentState::Init);
    }

    #[test]
    fn test_state_machine_dead_cannot_transition() {
        let mut sm = AgentStateMachine::new(test_id());
        sm.activate().unwrap();
        sm.mark_dead("crash").unwrap();
        assert!(sm.activate().is_err());
    }

    #[test]
    fn test_state_machine_auto_degrade_on_invalid() {
        let mut sm = AgentStateMachine::new(test_id())
            .with_degrade_threshold(3);
        sm.activate().unwrap();

        assert_eq!(sm.state(), AgentState::Active);
        sm.record_message(false); // 1
        sm.record_message(false); // 2
        let t = sm.record_message(false); // 3 -> threshold hit
        assert!(t.is_some(), "should auto-degrade");
        assert_eq!(sm.state(), AgentState::Degraded);
        assert_eq!(sm.invalid_message_count(), 3);
    }

    #[test]
    fn test_state_machine_no_auto_degrade_below_threshold() {
        let mut sm = AgentStateMachine::new(test_id())
            .with_degrade_threshold(5);
        sm.activate().unwrap();

        for _ in 0..3 {
            sm.record_message(false);
        }
        assert_eq!(sm.state(), AgentState::Active);
    }

    #[test]
    fn test_state_machine_history() {
        let mut sm = AgentStateMachine::new(test_id());
        assert_eq!(sm.history_len(), 0);
        sm.activate().unwrap();
        assert_eq!(sm.history_len(), 1);
        sm.degrade("chaos").unwrap();
        assert_eq!(sm.history_len(), 2);
    }

    #[test]
    fn test_state_machine_reset() {
        let mut sm = AgentStateMachine::new(test_id());
        sm.activate().unwrap();
        sm.degrade("test").unwrap();
        sm.reset();
        assert_eq!(sm.state(), AgentState::Init);
        assert_eq!(sm.history_len(), 0);
        assert_eq!(sm.invalid_message_count(), 0);
    }

    // ── MessageValidator integration tests ──

    #[test]
    fn test_validator_accepts_valid_message() {
        let mut v = MessageValidator::new(test_id());
        let msg = test_msg(Payload::Heartbeat);
        assert!(v.validate(&msg).is_ok());
    }

    #[test]
    fn test_validator_rejects_empty_field() {
        let mut v = MessageValidator::new(test_id());
        let msg = test_msg(Payload::Belief {
            asset: "".into(),
            value: Value::Bool(true),
            confidence: 0.5,
        });
        assert!(v.validate(&msg).is_err());
    }

    #[test]
    fn test_validator_rejects_init_state_payload() {
        let mut v = MessageValidator::new(test_id());
        // State is Init by default
        let msg = test_msg(Payload::Belief {
            asset: "test".into(),
            value: Value::Bool(true),
            confidence: 0.5,
        });
        assert!(v.validate(&msg).is_err(), "Init state should reject non-heartbeat");
    }

    #[test]
    fn test_validator_accepts_heartbeat_in_init() {
        let mut v = MessageValidator::new(test_id());
        let msg = test_msg(Payload::Heartbeat);
        assert!(v.validate(&msg).is_ok(), "Init state should accept heartbeat");
    }

    #[test]
    fn test_validator_rejects_dead_state_all() {
        let mut v = MessageValidator::new(test_id());
        v.state_machine_mut().activate().unwrap();
        v.state_machine_mut().mark_dead("test").unwrap();
        let msg = test_msg(Payload::Heartbeat);
        assert!(v.validate(&msg).is_err(), "Dead state should reject everything");
    }

    #[test]
    fn test_validator_tracks_reject_count() {
        let mut v = MessageValidator::new(test_id());
        v.state_machine_mut().activate().unwrap();
        assert_eq!(v.reject_count(), 0);

        let msg = test_msg(Payload::Belief {
            asset: "".into(),
            value: Value::Bool(true),
            confidence: 0.5,
        });
        let _ = v.validate(&msg);
        assert_eq!(v.reject_count(), 1);
    }

    #[test]
    fn test_validator_self_message_rejected() {
        let agent_id = test_id();
        let mut v = MessageValidator::new(agent_id);
        v.state_machine_mut().activate().unwrap();
        let msg = Message {
            agent_id,
            agent_role: Role::Worker,
            timestamp: 1000,
            payload: Payload::Heartbeat,
        };
        assert!(v.validate(&msg).is_err(), "self-message should be rejected");
    }

    // ── ContractFault tests ──

    #[test]
    fn test_contract_fault_empty_field_fails_validation() {
        let agent_id = test_id();
        let msg = ContractFault::EmptyFieldMessage.build_message(agent_id, Role::Worker);
        assert!(!validate_message(&msg).valid);
    }

    #[test]
    fn test_contract_fault_bad_confidence_fails_validation() {
        let agent_id = test_id();
        let msg = ContractFault::BadConfidence.build_message(agent_id, Role::Worker);
        assert!(!validate_message(&msg).valid);
    }

    #[test]
    fn test_contract_fault_self_ref_fails_validation() {
        let agent_id = test_id();
        let msg = ContractFault::SelfReferencingMessage.build_message(agent_id, Role::Worker);
        let mut v = MessageValidator::new(agent_id);
        v.state_machine_mut().activate().unwrap();
        assert!(v.validate(&msg).is_err());
    }

    #[test]
    fn test_contract_fault_nan_fails_validation() {
        let agent_id = test_id();
        let msg = ContractFault::NanValue.build_message(agent_id, Role::Worker);
        assert!(!validate_message(&msg).valid);
    }

    #[test]
    fn test_contract_fault_flood_forces_degraded() {
        let agent_id = test_id();
        // Use the state machine directly — no arena needed for this test
        let mut sm = AgentStateMachine::new(agent_id)
            .with_degrade_threshold(3);
        sm.activate().unwrap();

        let fault = ContractFault::FloodInvalidMessages(10);
        for _ in 0..5 {
            let bad_msg = fault.build_message(test_id(), Role::Worker);
            let is_valid = validate_message(&bad_msg).valid;
            sm.record_message(is_valid);
        }

        assert_eq!(sm.state(), AgentState::Degraded);
        assert!(sm.invalid_message_count() >= 3);
    }
}
