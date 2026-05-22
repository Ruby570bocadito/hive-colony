use ed25519_dalek::{SigningKey, VerifyingKey, Signature, Signer};
use rand::rngs::OsRng;
use uuid::Uuid;

#[derive(Clone)]
pub struct AgentIdentity {
    pub id: Uuid,
    signing_key: SigningKey,
    verifying_key: VerifyingKey,
}

impl AgentIdentity {
    pub fn new() -> Self {
        let signing_key = SigningKey::generate(&mut OsRng);
        let verifying_key = signing_key.verifying_key();
        Self {
            id: Uuid::new_v4(),
            signing_key,
            verifying_key,
        }
    }

    pub fn signing_key(&self) -> &SigningKey {
        &self.signing_key
    }

    pub fn sign_data(&self, data: &[u8]) -> [u8; 64] {
        self.signing_key.sign(data).to_bytes()
    }

    pub fn verify(&self, data: &[u8], signature_bytes: &[u8; 64]) -> bool {
        let sig = Signature::from_bytes(signature_bytes);
        self.verifying_key.verify_strict(data, &sig).is_ok()
    }

    pub fn verify_with_key(
        verifying_key_bytes: &[u8; 32],
        data: &[u8],
        signature_bytes: &[u8; 64],
    ) -> bool {
        let vk = match VerifyingKey::from_bytes(verifying_key_bytes) {
            Ok(k) => k,
            Err(_) => return false,
        };
        let sig = Signature::from_bytes(signature_bytes);
        vk.verify_strict(data, &sig).is_ok()
    }

    pub fn verifying_key_bytes(&self) -> [u8; 32] {
        self.verifying_key.to_bytes()
    }

    pub fn id(&self) -> Uuid {
        self.id
    }
}

impl Default for AgentIdentity {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_identity_creation() {
        let id = AgentIdentity::new();
        assert_ne!(id.id(), Uuid::nil());
        assert_eq!(id.verifying_key_bytes().len(), 32);
    }

    #[test]
    fn test_sign_and_verify() {
        let id = AgentIdentity::new();
        let data = b"swarm test message";
        let sig = id.sign_data(data);
        assert!(id.verify(data, &sig));
    }

    #[test]
    fn test_wrong_signature_fails() {
        let id = AgentIdentity::new();
        let data = b"real message";
        let sig = id.sign_data(data);
        let wrong_data = b"tampered message";
        assert!(!id.verify(wrong_data, &sig));
    }

    #[test]
    fn test_wrong_key_fails() {
        let alice = AgentIdentity::new();
        let bob = AgentIdentity::new();
        let data = b"alice message";
        let sig = alice.sign_data(data);
        assert!(!bob.verify(data, &sig));
    }

    #[test]
    fn test_verify_with_key() {
        let id = AgentIdentity::new();
        let data = b"public verify test";
        let sig = id.sign_data(data);
        let vk = id.verifying_key_bytes();
        assert!(AgentIdentity::verify_with_key(&vk, data, &sig));
    }

    #[test]
    fn test_verify_with_key_invalid_key() {
        let id = AgentIdentity::new();
        let data = b"test";
        let sig = id.sign_data(data);
        let bad_key = [0u8; 32];
        assert!(!AgentIdentity::verify_with_key(&bad_key, data, &sig));
    }

    #[test]
    fn test_unique_ids() {
        let a = AgentIdentity::new();
        let b = AgentIdentity::new();
        assert_ne!(a.id(), b.id());
        assert_ne!(a.verifying_key_bytes(), b.verifying_key_bytes());
    }

    #[test]
    fn test_sign_deterministic() {
        let id = AgentIdentity::new();
        let data = b"same data";
        let sig1 = id.sign_data(data);
        let sig2 = id.sign_data(data);
        assert_eq!(sig1, sig2, "Same data + same key must produce same signature");
    }

    #[test]
    fn test_default() {
        let id = AgentIdentity::default();
        assert_ne!(id.id(), Uuid::nil());
    }

    #[test]
    fn test_clone() {
        let id = AgentIdentity::new();
        let cloned = id.clone();
        assert_eq!(id.id(), cloned.id());
        assert_eq!(id.verifying_key_bytes(), cloned.verifying_key_bytes());
    }
}
