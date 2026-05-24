use serde::{Deserialize, Serialize};
use uuid::Uuid;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Role {
    Worker,
    Weaver,
    Drone,
    Honeybee,
    Queen,
    Swarm,
}

impl std::fmt::Display for Role {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Role::Worker => write!(f, "worker"),
            Role::Weaver => write!(f, "weaver"),
            Role::Drone => write!(f, "drone"),
            Role::Honeybee => write!(f, "honeybee"),
            Role::Queen => write!(f, "queen"),
            Role::Swarm => write!(f, "swarm"),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum Value {
    Bool(bool),
    String(String),
    Int(i64),
    Float(f64),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum Decision {
    Support,
    Reject,
    Abstain,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum Payload {
    Belief {
        asset: String,
        value: Value,
        confidence: f32,
    },
    Desire {
        action: String,
        priority: f32,
    },
    Proposal {
        action: String,
        argument: String,
        proposal_id: Uuid,
    },
    Vote {
        proposal_id: Uuid,
        decision: Decision,
        weight: f32,
    },
    Request {
        service: String,
        payload: Vec<u8>,
    },
    Query {
        dilemma: String,
        context: String,
        query_id: Uuid,
    },
    Response {
        query_id: Uuid,
        answer: String,
        confidence: f32,
    },
    Heartbeat,
    // Swarm status messages (for dead agent detection, etc.)
    StatusEvent {
        event_type: String,
        subject_id: Uuid,
        subject_role: Role,
        detail: String,
    },
}

/// Signed message for wire transport.
/// The `signature` covers `payload_bytes` (rmp-serialized Message).
#[derive(Debug, Clone)]
pub struct SignedMessage {
    pub agent_id: Uuid,
    pub verifying_key: [u8; 32],
    pub signature: [u8; 64],
    pub payload_bytes: Vec<u8>,
}

/// Unsigned message that gets serialized for signing.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Message {
    pub agent_id: Uuid,
    pub agent_role: Role,
    pub timestamp: u64,
    pub payload: Payload,
}

impl Message {
    pub fn to_signed_bytes(&self) -> Vec<u8> {
        rmp_serde::to_vec(self).unwrap_or_default()
    }

    pub fn from_signed_message(signed: &SignedMessage) -> Option<Self> {
        rmp_serde::from_slice(&signed.payload_bytes).ok()
    }

    pub fn heartbeat(agent_id: Uuid, agent_role: Role) -> Self {
        Self {
            agent_id,
            agent_role,
            timestamp: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs(),
            payload: Payload::Heartbeat,
        }
    }

    pub fn belief(agent_id: Uuid, agent_role: Role, asset: String, value: Value, confidence: f32) -> Self {
        Self {
            agent_id,
            agent_role,
            timestamp: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs(),
            payload: Payload::Belief { asset, value, confidence },
        }
    }

    pub fn proposal(agent_id: Uuid, agent_role: Role, action: String, argument: String) -> (Self, Uuid) {
        let proposal_id = Uuid::new_v4();
        let msg = Self {
            agent_id,
            agent_role,
            timestamp: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs(),
            payload: Payload::Proposal {
                action,
                argument,
                proposal_id,
            },
        };
        (msg, proposal_id)
    }

    pub fn vote(agent_id: Uuid, agent_role: Role, proposal_id: Uuid, decision: Decision, weight: f32) -> Self {
        Self {
            agent_id,
            agent_role,
            timestamp: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs(),
            payload: Payload::Vote {
                proposal_id,
                decision,
                weight,
            },
        }
    }

    pub fn status_event(agent_id: Uuid, agent_role: Role, event_type: &str, subject_id: Uuid, subject_role: Role, detail: &str) -> Self {
        Self {
            agent_id,
            agent_role,
            timestamp: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs(),
            payload: Payload::StatusEvent {
                event_type: event_type.to_string(),
                subject_id,
                subject_role,
                detail: detail.to_string(),
            },
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use uuid::Uuid;

    fn test_agent() -> (Uuid, Role) {
        (Uuid::new_v4(), Role::Worker)
    }

    #[test]
    fn test_heartbeat_message() {
        let (id, role) = test_agent();
        let msg = Message::heartbeat(id, role);
        assert_eq!(msg.agent_id, id);
        assert_eq!(msg.agent_role, role);
        assert!(matches!(msg.payload, Payload::Heartbeat));
        assert!(msg.timestamp > 0);
    }

    #[test]
    fn test_belief_message() {
        let (id, role) = test_agent();
        let msg = Message::belief(id, role, "edr".into(), Value::Bool(true), 0.95);
        assert_eq!(msg.agent_id, id);
        assert_eq!(msg.agent_role, role);
        match &msg.payload {
            Payload::Belief { asset, value, confidence } => {
                assert_eq!(asset, "edr");
                assert!(matches!(value, Value::Bool(true)));
                assert_eq!(*confidence, 0.95);
            }
            _ => panic!("Expected Belief payload"),
        }
    }

    #[test]
    fn test_proposal_message() {
        let (id, role) = test_agent();
        let (msg, proposal_id) = Message::proposal(id, role, "encrypt".into(), "target secured".into());
        assert_eq!(msg.agent_id, id);
        match &msg.payload {
            Payload::Proposal { action, argument, proposal_id: pid } => {
                assert_eq!(action, "encrypt");
                assert_eq!(argument, "target secured");
                assert_eq!(*pid, proposal_id);
            }
            _ => panic!("Expected Proposal payload"),
        }
    }

    #[test]
    fn test_vote_message() {
        let (id, role) = test_agent();
        let proposal_id = Uuid::new_v4();
        let msg = Message::vote(id, role, proposal_id, Decision::Support, 1.5);
        match &msg.payload {
            Payload::Vote { proposal_id: pid, decision, weight } => {
                assert_eq!(*pid, proposal_id);
                assert!(matches!(decision, Decision::Support));
                assert_eq!(*weight, 1.5);
            }
            _ => panic!("Expected Vote payload"),
        }
    }

    #[test]
    fn test_status_event_message() {
        let (id, role) = test_agent();
        let subject = Uuid::new_v4();
        let msg = Message::status_event(id, role, "agent_dead", subject, Role::Worker, "no heartbeat");
        match &msg.payload {
            Payload::StatusEvent { event_type, subject_id, subject_role, detail } => {
                assert_eq!(event_type, "agent_dead");
                assert_eq!(*subject_id, subject);
                assert!(matches!(subject_role, Role::Worker));
                assert_eq!(detail, "no heartbeat");
            }
            _ => panic!("Expected StatusEvent payload"),
        }
    }

    #[test]
    fn test_messagepack_roundtrip() {
        let (id, role) = test_agent();
        let original = Message::belief(id, role, "os_type".into(), Value::String("linux".into()), 1.0);
        
        let bytes = rmp_serde::to_vec(&original).expect("Serialize failed");
        let restored: Message = rmp_serde::from_slice(&bytes).expect("Deserialize failed");
        
        assert_eq!(original.agent_id, restored.agent_id);
        assert_eq!(original.agent_role, restored.agent_role);
        assert_eq!(original.timestamp, restored.timestamp);
        match (&original.payload, &restored.payload) {
            (Payload::Belief { asset: a1, value: v1, confidence: c1 },
             Payload::Belief { asset: a2, value: v2, confidence: c2 }) => {
                assert_eq!(a1, a2);
                assert!(matches!((v1, v2), (Value::String(s1), Value::String(s2)) if s1 == s2));
                assert_eq!(c1, c2);
            }
            _ => panic!("Payload mismatch"),
        }
    }

    #[test]
    fn test_all_belief_value_types() {
        let (id, role) = test_agent();
        
        let msg_bool = Message::belief(id, role, "a".into(), Value::Bool(true), 1.0);
        let msg_str = Message::belief(id, role, "b".into(), Value::String("hi".into()), 1.0);
        let msg_int = Message::belief(id, role, "c".into(), Value::Int(42), 1.0);
        let msg_float = Message::belief(id, role, "d".into(), Value::Float(std::f64::consts::PI), 1.0);

        for msg in &[msg_bool, msg_str, msg_int, msg_float] {
            let bytes = rmp_serde::to_vec(msg).expect("serialize");
            let _: Message = rmp_serde::from_slice(&bytes).expect("deserialize");
        }
    }

    #[test]
    fn test_role_display() {
        assert_eq!(format!("{}", Role::Worker), "worker");
        assert_eq!(format!("{}", Role::Drone), "drone");
        assert_eq!(format!("{}", Role::Honeybee), "honeybee");
        assert_eq!(format!("{}", Role::Weaver), "weaver");
        assert_eq!(format!("{}", Role::Queen), "queen");
        assert_eq!(format!("{}", Role::Swarm), "swarm");
    }

    #[test]
    fn test_multiple_proposals_unique_ids() {
        let (id, role) = test_agent();
        let (_, p1) = Message::proposal(id, role, "a".into(), "arg".into());
        let (_, p2) = Message::proposal(id, role, "b".into(), "arg".into());
        assert_ne!(p1, p2, "Proposal IDs must be unique");
    }
}
