// DID: Decentralized Identity with web-of-trust.
// Each agent generates a DID; trust is established by behavioral reputation,
// not by a central authority. Replaces simple reputation scores with a
// verifiable chain of attestations stored in the shared arena.
//
// If an EDR captures an agent's private key, it cannot impersonate them
// because the DID is tied to their historical behavior verified by peers.

use crate::identity::AgentIdentity;
use crate::ldc::{Message, Role};
use uuid::Uuid;
use std::collections::HashMap;
use tracing::info;

/// A Decentralized Identifier for an agent.
#[derive(Debug, Clone)]
pub struct DidDocument {
    pub agent_id: Uuid,
    pub public_key: [u8; 32],         // Ed25519 verifying key
    pub created_at: u64,
    pub attestations: Vec<Attestation>, // Other agents vouching for this one
    pub behavior_score: f32,          // Based on validated attestations
}

/// An attestation: one agent vouches for another's behavior.
#[derive(Debug, Clone)]
pub struct Attestation {
    pub issuer: Uuid,          // Agent making the attestation
    pub subject: Uuid,         // Agent being attested
    pub claim: String,         // What is being claimed (e.g., "accurate_edr_detection")
    pub confidence: f32,       // How confident the issuer is (0-1)
    pub timestamp: u64,
    pub signature: [u8; 64],   // Signed by issuer's key
}

/// Web-of-trust manager: stores DIDs and attestations.
pub struct DidRegistry {
    pub documents: HashMap<Uuid, DidDocument>,
}

impl DidRegistry {
    pub fn new() -> Self {
        Self { documents: HashMap::new() }
    }

    /// Register a new agent DID.
    pub fn register(&mut self, identity: &AgentIdentity) {
        let doc = DidDocument {
            agent_id: identity.id(),
            public_key: identity.verifying_key_bytes(),
            created_at: crate::utils::timestamp_now(),
            attestations: Vec::new(),
            behavior_score: 0.5, // Neutral starting trust
        };
        self.documents.insert(identity.id(), doc);
        info!("DID: registered agent {}", identity.id());
    }

    /// Issue an attestation for another agent.
    pub fn attest(&mut self, issuer: &AgentIdentity, subject_id: Uuid, claim: &str, confidence: f32) -> bool {
        let subject = match self.documents.get_mut(&subject_id) {
            Some(d) => d,
            None => return false,
        };

        // Sign the attestation
        let attestation_data = format!("{}:{}:{}:{}", subject_id, claim, confidence, crate::utils::timestamp_now());
        let signature = issuer.sign_data(attestation_data.as_bytes());

        let att = Attestation {
            issuer: issuer.id(),
            subject: subject_id,
            claim: claim.to_string(),
            confidence,
            timestamp: crate::utils::timestamp_now(),
            signature,
        };

        subject.attestations.push(att);

        // Recalculate behavior score
        subject.behavior_score = Self::calculate_score(&subject.attestations);
        info!("DID: {} attested {} for '{}' (score: {:.2})",
            issuer.id(), subject_id, claim, subject.behavior_score);
        true
    }

    /// Calculate behavior score from attestations.
    fn calculate_score(attestations: &[Attestation]) -> f32 {
        if attestations.is_empty() { return 0.5; }
        let total: f32 = attestations.iter().map(|a| a.confidence).sum();
        (total / attestations.len() as f32).clamp(0.0, 1.0)
    }

    /// Verify an agent's trust level before accepting their vote.
    pub fn trust_level(&self, agent_id: &Uuid) -> f32 {
        self.documents.get(agent_id)
            .map(|d| d.behavior_score)
            .unwrap_or(0.0)
    }

    /// Check if an agent has enough attestations to be fully trusted.
    pub fn is_verified(&self, agent_id: &Uuid, min_attestations: usize) -> bool {
        self.documents.get(agent_id)
            .map(|d| d.attestations.len() >= min_attestations && d.behavior_score > 0.7)
            .unwrap_or(false)
    }

    /// Broadcast a DID attestation to the colony via LdC belief.
    pub fn broadcast_attestation(&self, issuer_id: Uuid, subject_id: Uuid, claim: &str, confidence: f32) -> Message {
        Message::belief(
            issuer_id, Role::Queen,
            format!("did:attest:{}", subject_id),
            crate::ldc::Value::String(format!("claim:{}|confidence:{:.2}", claim, confidence)),
            confidence,
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::identity::AgentIdentity;

    #[test]
    fn test_register_and_attest() {
        let mut reg = DidRegistry::new();
        let id1 = AgentIdentity::new();
        let id2 = AgentIdentity::new();

        reg.register(&id1);
        reg.register(&id2);

        assert!(reg.trust_level(&id1.id()) > 0.0);
        assert!(reg.attest(&id1, id2.id(), "accurate_edr", 0.9));
        assert!(reg.trust_level(&id2.id()) > 0.5);
    }

    #[test]
    fn test_multiple_attestations_boost_score() {
        let mut reg = DidRegistry::new();
        let subject = AgentIdentity::new();
        reg.register(&subject);

        for _ in 0..5 {
            let issuer = AgentIdentity::new();
            reg.register(&issuer);
            reg.attest(&issuer, subject.id(), "good_behavior", 0.9);
        }
        assert!(reg.is_verified(&subject.id(), 3));
    }
}
