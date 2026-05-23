// Waggle Dance: workers share discovered targets with rich metadata.
// Like bees waggling to communicate flower locations, workers broadcast
// target vectors (IP, service, value, distance) to the colony.
// The stronger the dance, the more valuable the target.

use crate::ldc::{Payload, Message, Role, Value};
use uuid::Uuid;
use std::collections::HashMap;

/// A target discovered by a Worker, shared via waggle dance.
#[derive(Debug, Clone)]
pub struct WaggleTarget {
    pub host: String,
    pub port: u16,
    pub service: String,       // ssh, http, smb, rdp, mysql...
    pub value_score: f32,      // how valuable the target is (0-1)
    pub edr_level: f32,        // EDR presence (0-1, lower = safer)
    pub distance_hops: u32,    // network hops from current host
    pub discovered_by: Uuid,
    pub timestamp: u64,
}

impl WaggleTarget {
    /// Strength of the waggle: higher = more urgent to attack.
    pub fn waggle_strength(&self) -> f32 {
        self.value_score * 0.5 + (1.0 - self.edr_level) * 0.3 + 
         (1.0 / (self.distance_hops as f32 + 1.0)) * 0.2
    }

    pub fn to_belief(&self, worker_id: Uuid) -> Message {
        Message::belief(
            worker_id,
            Role::Worker,
            format!("waggle:{}", self.host),
            Value::String(format!(
                "host:{} port:{} svc:{} value:{:.2} edr:{:.2} hops:{}",
                self.host, self.port, self.service,
                self.value_score, self.edr_level, self.distance_hops
            )),
            self.waggle_strength(),
        )
    }

    /// Parse a waggle dance from a belief.
    pub fn from_belief(belief: &Message) -> Option<Self> {
        if let Payload::Belief { asset, value, confidence: _ } = &belief.payload {
            if asset.starts_with("waggle:") {
                if let Value::String(data) = value {
                    let parts: HashMap<&str, &str> = data.split(' ')
                        .filter_map(|s| s.split_once(':'))
                        .collect();
                    return Some(WaggleTarget {
                        host: belief.agent_id.to_string(),
                        port: parts.get("port").and_then(|p| p.parse().ok()).unwrap_or(0),
                        service: parts.get("svc").unwrap_or(&"unknown").to_string(),
                        value_score: parts.get("value").and_then(|v| v.parse().ok()).unwrap_or(0.5),
                        edr_level: parts.get("edr").and_then(|e| e.parse().ok()).unwrap_or(0.5),
                        distance_hops: parts.get("hops").and_then(|h| h.parse().ok()).unwrap_or(1),
                        discovered_by: belief.agent_id,
                        timestamp: belief.timestamp,
                    });
                }
            }
        }
        None
    }
}
