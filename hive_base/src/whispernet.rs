use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use uuid::Uuid;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WhisperMessage {
    pub msg_id: Uuid,
    pub sender_id: Uuid,
    pub seq: u64,
    pub payload: Vec<u8>,
    pub ttl: u8,                      // Time-to-live (hops)
    pub signature: Vec<u8>,
    pub timestamp: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MeshPeer {
    pub peer_id: Uuid,
    pub hostname: String,
    pub endpoint: String,             // IP:Port or path
    pub public_key: Vec<u8>,
    pub last_seen: u64,
    pub hop_count: u8,                // Distance from origin
    pub latency_ms: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WhisperConfig {
    pub node_id: Uuid,
    pub listen_port: u16,
    pub max_peers: usize,
    pub max_hops: u8,
    pub heartbeat_interval_secs: u64,
    pub encryption_enabled: bool,
}

pub struct WhisperNet {
    pub config: WhisperConfig,
    pub peers: Vec<MeshPeer>,
    pub messages: Vec<WhisperMessage>,
    pub routing_table: HashMap<Uuid, Vec<Uuid>>,  // dest -> path of peer IDs
}

impl WhisperNet {
    pub fn new(config: WhisperConfig) -> Self {
        Self {
            config,
            peers: Vec::new(),
            messages: Vec::new(),
            routing_table: HashMap::new(),
        }
    }

    pub fn register_peer(&mut self, peer: MeshPeer) -> bool {
        if self.peers.len() >= self.config.max_peers {
            return false;
        }

        if !self.peers.iter().any(|p| p.peer_id == peer.peer_id) {
            self.peers.push(peer);
            self.rebuild_routing_table();
            return true;
        }
        false
    }

    pub fn remove_peer(&mut self, peer_id: Uuid) -> bool {
        let before = self.peers.len();
        self.peers.retain(|p| p.peer_id != peer_id);
        if self.peers.len() < before {
            self.rebuild_routing_table();
            return true;
        }
        false
    }

    pub fn send_message(&mut self, msg: WhisperMessage) -> Result<(), String> {
        if msg.ttl == 0 {
            return Err("Message TTL expired".into());
        }

        let mut relayed = msg.clone();
        relayed.ttl -= 1;

        // Store locally
        self.messages.push(relayed.clone());

        // Simulate relay to peers
        let nearest = self.find_nearest_peers(&relayed, 3);
        for _peer in &nearest {
            // In a real implementation: encrypt & send via TCP/TLS
            // For now we simulate delivery
            tracing::debug!("WhisperNet: relayed {} to peer {}", relayed.msg_id, _peer.peer_id);
        }

        Ok(())
    }

    pub fn receive_messages(&self, after_seq: u64) -> Vec<&WhisperMessage> {
        self.messages.iter()
            .filter(|m| m.seq > after_seq)
            .collect()
    }

    pub fn build_path(&self, destination: Uuid) -> Option<Vec<Uuid>> {
        // Simple BFS routing
        let mut visited = vec![self.config.node_id];
        let mut queue = vec![vec![self.config.node_id]];

        while !queue.is_empty() {
            let path = queue.remove(0);
            let current = *path.last().unwrap();

            if current == destination {
                return Some(path[1..].to_vec());
            }

            for peer in &self.peers {
                if !visited.contains(&peer.peer_id) {
                    visited.push(peer.peer_id);
                    let mut new_path = path.clone();
                    new_path.push(peer.peer_id);
                    queue.push(new_path);
                }
            }
        }

        None
    }

    pub fn number_of_hops(&self, destination: Uuid) -> Option<u8> {
        self.build_path(destination).map(|p| p.len() as u8)
    }

    fn rebuild_routing_table(&mut self) {
        self.routing_table.clear();
        for peer in &self.peers {
            if let Some(path) = self.build_path(peer.peer_id) {
                self.routing_table.insert(peer.peer_id, path);
            }
        }
    }

    fn find_nearest_peers(&self, msg: &WhisperMessage, max: usize) -> Vec<&MeshPeer> {
        let mut candidates: Vec<&MeshPeer> = self.peers.iter()
            .filter(|p| p.hop_count <= msg.ttl)
            .collect();
        candidates.sort_by_key(|p| p.latency_ms);
        candidates.truncate(max);
        candidates
    }

    pub fn create_message(&self, sender_id: Uuid, payload: Vec<u8>, ttl: u8) -> WhisperMessage {
        let seq = self.messages.len() as u64 + 1;
        WhisperMessage {
            msg_id: Uuid::new_v4(),
            sender_id,
            seq,
            payload,
            ttl,
            signature: vec![],
            timestamp: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_secs())
                .unwrap_or(0),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_config(node_id: Uuid) -> WhisperConfig {
        WhisperConfig {
            node_id,
            listen_port: 0,
            max_peers: 10,
            max_hops: 5,
            heartbeat_interval_secs: 30,
            encryption_enabled: true,
        }
    }

    #[test]
    fn test_peer_registration() {
        let node_id = Uuid::new_v4();
        let mut net = WhisperNet::new(test_config(node_id));

        let peer = MeshPeer {
            peer_id: Uuid::new_v4(),
            hostname: "worker-01".into(),
            endpoint: "10.0.0.1:9000".into(),
            public_key: vec![0; 32],
            last_seen: 1_700_000_000,
            hop_count: 1,
            latency_ms: 5,
        };

        assert!(net.register_peer(peer));
        assert_eq!(net.peers.len(), 1);

        let dup = MeshPeer {
            peer_id: net.peers[0].peer_id,
            hostname: "worker-01".into(),
            endpoint: "10.0.0.1:9000".into(),
            public_key: vec![0; 32],
            last_seen: 1_700_000_000,
            hop_count: 1,
            latency_ms: 5,
        };
        assert!(!net.register_peer(dup), "Duplicate should be rejected");
    }

    #[test]
    fn test_message_relay() {
        let node_id = Uuid::new_v4();
        let mut net = WhisperNet::new(test_config(node_id));

        let msg = net.create_message(node_id, vec![1, 2, 3, 4], 3);
        assert_eq!(msg.ttl, 3);

        let result = net.send_message(msg);
        assert!(result.is_ok());
        assert_eq!(net.messages.len(), 1);
    }

    #[test]
    fn test_routing() {
        let node_a = Uuid::new_v4();
        let mut net = WhisperNet::new(test_config(node_a));

        let node_b = Uuid::new_v4();
        let node_c = Uuid::new_v4();

        net.register_peer(MeshPeer {
            peer_id: node_b,
            hostname: "drone-01".into(),
            endpoint: "10.0.0.2:9000".into(),
            public_key: vec![1; 32],
            last_seen: 1_700_000_000,
            hop_count: 1,
            latency_ms: 10,
        });

        net.register_peer(MeshPeer {
            peer_id: node_c,
            hostname: "honeybee-01".into(),
            endpoint: "10.0.0.3:9000".into(),
            public_key: vec![2; 32],
            last_seen: 1_700_000_000,
            hop_count: 2,
            latency_ms: 20,
        });

        let path = net.build_path(node_c);
        assert!(path.is_some(), "Path to node C should exist");
        assert!(path.unwrap().len() >= 1);
    }

    #[test]
    fn test_max_peers() {
        let node_id = Uuid::new_v4();
        let mut config = test_config(node_id);
        config.max_peers = 2;

        let mut net = WhisperNet::new(config);
        for _ in 0..3 {
            let peer = MeshPeer {
                peer_id: Uuid::new_v4(),
                hostname: "test".into(),
                endpoint: "10.0.0.1:9000".into(),
                public_key: vec![0; 32],
                last_seen: 1_700_000_000,
                hop_count: 1,
                latency_ms: 5,
            };
            net.register_peer(peer);
        }
        assert!(net.peers.len() <= 2, "Should not exceed max_peers");
    }

    #[test]
    fn test_ttl_expiry() {
        let node_id = Uuid::new_v4();
        let mut net = WhisperNet::new(test_config(node_id));

        let msg = net.create_message(node_id, vec![], 0);
        let result = net.send_message(msg);
        assert!(result.is_err(), "TTL 0 should fail");
    }
}
