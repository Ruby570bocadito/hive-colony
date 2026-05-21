// Death Dance: A/B testing of attack variants.
// When an attack fails, the Worker automatically tries an alternative.
// Successful variants are shared via Waggle Dance so the colony learns.
// Failed variants are downgraded. Over time, the colony evolves optimal tactics.

use crate::ldc::{Message, Payload, Role, Value};
use uuid::Uuid;
use std::collections::HashMap;
use tracing::{info, warn};

/// A testable attack variant.
#[derive(Debug, Clone)]
pub struct AttackVariant {
    pub variant_id: Uuid,
    pub technique: AttackTechnique,
    pub params: HashMap<String, String>,
    pub success_count: u32,
    pub failure_count: u32,
    pub last_tested: u64,
    pub score: f32,  // 0-1, calculated from success ratio
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum AttackTechnique {
    SSHBruteForce,
    SSHPassAuth,
    SCPDeploy,
    HTTPExploit,
    DNSExfil,
    SMBRelay,
    KerberosDelegation,
    Custom(String),
}

impl std::fmt::Display for AttackTechnique {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        match self {
            AttackTechnique::SSHBruteForce => write!(f, "ssh_brute"),
            AttackTechnique::SSHPassAuth => write!(f, "ssh_pass"),
            AttackTechnique::SCPDeploy => write!(f, "scp_deploy"),
            AttackTechnique::HTTPExploit => write!(f, "http_exploit"),
            AttackTechnique::DNSExfil => write!(f, "dns_exfil"),
            AttackTechnique::SMBRelay => write!(f, "smb_relay"),
            AttackTechnique::KerberosDelegation => write!(f, "kerberos_del"),
            AttackTechnique::Custom(s) => write!(f, "custom_{}", s),
        }
    }
}

impl AttackVariant {
    pub fn success_rate(&self) -> f32 {
        let total = self.success_count + self.failure_count;
        if total == 0 { 0.5 } else { self.success_count as f32 / total as f32 }
    }

    pub fn update_score(&mut self) {
        let rate = self.success_rate();
        let recency = 1.0; // could weight recent results higher
        self.score = rate * recency;
    }
}

/// Death Dance manager: tracks A/B test results across the colony.
pub struct DeathDance {
    pub variants: HashMap<Uuid, AttackVariant>,
    pub technique_index: HashMap<AttackTechnique, Vec<Uuid>>,
}

impl DeathDance {
    pub fn new() -> Self {
        Self { variants: HashMap::new(), technique_index: HashMap::new() }
    }

    /// Register a new attack variant for testing.
    pub fn register(&mut self, technique: AttackTechnique, params: HashMap<String, String>) -> Uuid {
        let id = Uuid::new_v4();
        let variant = AttackVariant {
            variant_id: id, technique: technique.clone(), params,
            success_count: 0, failure_count: 0, last_tested: 0, score: 0.5,
        };
        self.variants.insert(id, variant);
        self.technique_index.entry(technique).or_default().push(id);
        id
    }

    /// Record a successful attack → boost the variant's score.
    pub fn record_success(&mut self, variant_id: Uuid) {
        if let Some(v) = self.variants.get_mut(&variant_id) {
            v.success_count += 1;
            v.update_score();
            info!("DEATH_DANCE: variant {} score -> {:.2}", variant_id, v.score);
        }
    }

    /// Record a failed attack → try the next variant next time.
    pub fn record_failure(&mut self, variant_id: Uuid) -> Option<Uuid> {
        if let Some(v) = self.variants.get_mut(&variant_id) {
            v.failure_count += 1;
            v.update_score();
            warn!("DEATH_DANCE: variant {} failed, score -> {:.2}", variant_id, v.score);

            // If score drops below 0.2, auto-retire this variant
            if v.score < 0.2 {
                warn!("DEATH_DANCE: retiring variant {}", variant_id);
                let tech = v.technique.clone();
                return self.get_best_variant(&tech);
            }
        }
        None
    }

    /// Get the highest-scoring variant for a technique.
    pub fn get_best_variant(&self, technique: &AttackTechnique) -> Option<Uuid> {
        self.technique_index.get(technique).and_then(|ids| {
            ids.iter().max_by(|a, b| {
                self.variants.get(a).unwrap().score
                    .partial_cmp(&self.variants.get(b).unwrap().score)
                    .unwrap()
            }).copied()
        })
    }

    /// Get all variants sorted by score for a technique.
    pub fn get_ranked_variants(&self, technique: &AttackTechnique) -> Vec<&AttackVariant> {
        let mut variants: Vec<_> = self.technique_index.get(technique)
            .map(|ids| ids.iter().filter_map(|id| self.variants.get(id)).collect())
            .unwrap_or_default();
        variants.sort_by(|a, b| b.score.partial_cmp(&a.score).unwrap());
        variants
    }

    /// Emit a waggle dance with the best variant for colony-wide sharing.
    pub fn emit_best_dance(&self, technique: &AttackTechnique, worker_id: Uuid) -> Option<Message> {
        let best = self.get_best_variant(technique)?;
        let variant = self.variants.get(&best)?;
        let params_str: String = variant.params.iter()
            .map(|(k, v)| format!("{}={}", k, v))
            .collect::<Vec<_>>()
            .join(",");

        Some(Message::belief(
            worker_id, Role::Worker,
            format!("death_dance:{}:{:?}", technique, variant.variant_id),
            Value::String(format!("score:{:.2}|params:{}", variant.score, params_str)),
            variant.score,
        ))
    }
}
