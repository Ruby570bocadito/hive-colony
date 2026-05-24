use chacha20::ChaCha20;
use chacha20::cipher::{KeyIvInit, StreamCipher};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::sync::Mutex as StdMutex;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tracing::{debug, info, warn};
use uuid::Uuid;

const WHISPER_PROTO_MAGIC: &[u8; 4] = b"WHSP";

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WhisperWirePacket {
    pub magic: [u8; 4],
    pub version: u8,
    pub msg_id: Uuid,
    pub nonce: [u8; 12],
    pub encrypted: Vec<u8>,
}

pub fn derive_whisper_key(node_id: &Uuid, peer_id: &Uuid) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(b"WHISPERNET_V1_KEY_2024");
    hasher.update(node_id.as_bytes());
    hasher.update(peer_id.as_bytes());
    let result = hasher.finalize();
    let mut key = [0u8; 32];
    key.copy_from_slice(&result);
    key
}

pub fn encrypt_message(msg: &WhisperMessage, key: &[u8; 32]) -> Result<Vec<u8>, String> {
    let data = rmp_serde::to_vec(msg).map_err(|e| e.to_string())?;
    let nonce: [u8; 12] = msg.msg_id.as_bytes()[..12].try_into().map_err(|_| "bad nonce")?;
    let mut cipher = ChaCha20::new(key.into(), (&nonce).into());
    let mut encrypted = data.clone();
    cipher.apply_keystream(&mut encrypted);

    let packet = WhisperWirePacket {
        magic: *WHISPER_PROTO_MAGIC,
        version: 1,
        msg_id: msg.msg_id,
        nonce,
        encrypted,
    };
    let wire = rmp_serde::to_vec(&packet).map_err(|e| e.to_string())?;
    let mut frame = Vec::with_capacity(4 + wire.len());
    frame.extend_from_slice(&(wire.len() as u32).to_be_bytes());
    frame.extend_from_slice(&wire);
    Ok(frame)
}

pub fn decrypt_message(data: &[u8], key: &[u8; 32]) -> Result<WhisperMessage, String> {
    let packet: WhisperWirePacket = rmp_serde::from_slice(data).map_err(|e| e.to_string())?;
    if &packet.magic != WHISPER_PROTO_MAGIC {
        return Err("bad magic".into());
    }
    let mut cipher = ChaCha20::new(key.into(), (&packet.nonce).into());
    let mut decrypted = packet.encrypted.clone();
    cipher.apply_keystream(&mut decrypted);
    rmp_serde::from_slice(&decrypted).map_err(|e| e.to_string())
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WhisperMessage {
    pub msg_id: Uuid,
    pub sender_id: Uuid,
    pub seq: u64,
    pub payload: Vec<u8>,
    pub ttl: u8,
    pub signature: Vec<u8>,
    pub timestamp: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MeshPeer {
    pub peer_id: Uuid,
    pub hostname: String,
    pub endpoint: String,
    pub public_key: Vec<u8>,
    pub last_seen: u64,
    pub hop_count: u8,
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

struct WhisperCore {
    config: WhisperConfig,
    peers: Vec<MeshPeer>,
    messages: Vec<WhisperMessage>,
    routing_table: HashMap<Uuid, Vec<Uuid>>,
    seq_counter: AtomicU64,
}

pub struct WhisperNet {
    core: Arc<StdMutex<WhisperCore>>,
}

impl WhisperNet {
    pub fn new(config: WhisperConfig) -> Self {
        Self {
            core: Arc::new(StdMutex::new(WhisperCore {
                config,
                peers: Vec::new(),
                messages: Vec::new(),
                routing_table: HashMap::new(),
                seq_counter: AtomicU64::new(0),
            })),
        }
    }

    /// Start the TCP listener. Spawns an accept loop.
    /// config.listen_port == 0 means OS picks a port; use config().listen_port after.
    pub async fn start_listener(&self) -> Result<(), String> {
        let port = self.core.lock().unwrap().config.listen_port;
        let addr: SocketAddr = format!("0.0.0.0:{}", port)
            .parse()
            .map_err(|e| format!("bad addr: {}", e))?;
        let listener = TcpListener::bind(addr)
            .await
            .map_err(|e| format!("bind: {}", e))?;
        let actual_port = listener.local_addr().map_err(|e| e.to_string())?.port();
        {
            let mut core = self.core.lock().unwrap();
            core.config.listen_port = actual_port;
        }
        info!("WhisperNet listening on port {}", actual_port);

        let core = self.core.clone();
        tokio::spawn(async move {
            loop {
                match listener.accept().await {
                    Ok((stream, addr)) => {
                        debug!("WhisperNet: connection from {}", addr);
                        let c = core.clone();
                        tokio::spawn(async move {
                            if let Err(e) = Self::handle_connection(c, stream).await {
                                debug!("WhisperNet: handler: {}", e);
                            }
                        });
                    }
                    Err(e) => {
                        warn!("WhisperNet: accept: {}", e);
                        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
                    }
                }
            }
        });

        Ok(())
    }

    async fn handle_connection(core: Arc<StdMutex<WhisperCore>>, mut stream: TcpStream) -> Result<(), String> {
        let mut len_buf = [0u8; 4];
        stream.read_exact(&mut len_buf).await.map_err(|e| e.to_string())?;
        let frame_len = u32::from_be_bytes(len_buf) as usize;
        if frame_len > 1024 * 1024 {
            return Err("frame too large".into());
        }
        let mut frame = vec![0u8; frame_len];
        stream.read_exact(&mut frame).await.map_err(|e| e.to_string())?;

        let msg: WhisperWirePacket = rmp_serde::from_slice(&frame).map_err(|e| e.to_string())?;
        if &msg.magic != WHISPER_PROTO_MAGIC {
            return Err("bad magic".into());
        }

        let config = { core.lock().unwrap().config.clone() };
        if !config.encryption_enabled {
            let decrypted: WhisperMessage =
                rmp_serde::from_slice(&msg.encrypted).map_err(|e| e.to_string())?;
            core.lock().unwrap().messages.push(decrypted);
            return Ok(());
        }

        let sender_id = msg.msg_id;
        let key = derive_whisper_key(&config.node_id, &sender_id);
        let decrypted = decrypt_message(&frame, &key)?;
        core.lock().unwrap().messages.push(decrypted);
        Ok(())
    }

    /// Connect to a peer and register them.
    pub async fn connect_to_peer(&self, peer: MeshPeer) -> Result<(), String> {
        let addr: SocketAddr = peer.endpoint.parse().map_err(|e| format!("bad endpoint: {}", e))?;
        let stream = TcpStream::connect(addr).await.map_err(|e| format!("connect: {}", e))?;
        let mut core = self.core.lock().unwrap();
        if core.peers.iter().any(|p| p.peer_id == peer.peer_id) {
            return Err("peer already registered".into());
        }
        if core.peers.len() >= core.config.max_peers {
            return Err("max peers reached".into());
        }
        core.peers.push(peer);
        core.rebuild_routing_table();
        drop(stream);
        info!("WhisperNet: connected to peer at {}", addr);
        Ok(())
    }

    /// Send a message to nearest peers over TCP.
    pub async fn send_message(&self, msg: WhisperMessage) -> Result<(), String> {
        if msg.ttl == 0 {
            return Err("TTL expired".into());
        }
        let mut relayed = msg.clone();
        relayed.ttl -= 1;

        let (encryption, node_id, nearest) = {
            let lock = self.core.lock().unwrap();
            let encryption = lock.config.encryption_enabled;
            let node_id = lock.config.node_id;
            let nearest: Vec<MeshPeer> = lock.find_nearest_peers(&relayed, 3);
            (encryption, node_id, nearest)
        };

        for peer in &nearest {
            let key = encryption.then(|| derive_whisper_key(&node_id, &peer.peer_id));
            let wire_data = if let Some(ref k) = key {
                encrypt_message(&relayed, k)?
            } else {
                let nonce = relayed.msg_id.as_bytes()[..12].try_into().unwrap_or([0u8; 12]);
                let data = rmp_serde::to_vec(&relayed).map_err(|e| e.to_string())?;
                let packet = WhisperWirePacket {
                    magic: *WHISPER_PROTO_MAGIC,
                    version: 1,
                    msg_id: relayed.msg_id,
                    nonce,
                    encrypted: data,
                };
                let wire = rmp_serde::to_vec(&packet).map_err(|e| e.to_string())?;
                let mut f = Vec::with_capacity(4 + wire.len());
                f.extend_from_slice(&(wire.len() as u32).to_be_bytes());
                f.extend_from_slice(&wire);
                f
            };

            match TcpStream::connect(&peer.endpoint).await {
                Ok(mut stream) => {
                    stream.write_all(&wire_data).await.map_err(|e| format!("send: {}", e))?;
                    debug!("WhisperNet: sent {} to {}", relayed.msg_id, peer.endpoint);
                }
                Err(e) => warn!("WhisperNet: failed to {}: {}", peer.endpoint, e),
            }
        }

        self.core.lock().unwrap().messages.push(relayed);
        Ok(())
    }

    /// Receive messages since seq.
    pub async fn receive_messages(&self, after_seq: u64) -> Vec<WhisperMessage> {
        let msgs = self.core.lock().unwrap().messages.clone();
        msgs
            .iter()
            .filter(|m| m.seq > after_seq)
            .cloned()
            .collect()
    }

    /// Create a new message (sync).
    pub fn create_message(&self, sender_id: Uuid, payload: Vec<u8>, ttl: u8) -> WhisperMessage {
        let seq = self.core.lock().unwrap().seq_counter.fetch_add(1, Ordering::Relaxed) + 1;
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

    pub fn register_peer(&self, peer: MeshPeer) -> bool {
        let mut core = self.core.lock().unwrap();
        if core.peers.len() >= core.config.max_peers {
            return false;
        }
        if core.peers.iter().any(|p| p.peer_id == peer.peer_id) {
            return false;
        }
        core.peers.push(peer);
        core.rebuild_routing_table();
        true
    }

    pub fn remove_peer(&self, peer_id: Uuid) -> bool {
        let mut core = self.core.lock().unwrap();
        let before = core.peers.len();
        core.peers.retain(|p| p.peer_id != peer_id);
        if core.peers.len() < before {
            core.rebuild_routing_table();
            return true;
        }
        false
    }

    pub fn build_path(&self, destination: Uuid) -> Option<Vec<Uuid>> {
        let core = self.core.lock().unwrap();
        core.build_path_inner(destination)
    }

    pub fn number_of_hops(&self, destination: Uuid) -> Option<u8> {
        self.build_path(destination).map(|p| p.len() as u8)
    }

    pub fn peers(&self) -> Vec<MeshPeer> {
        self.core.lock().unwrap().peers.clone()
    }

    pub fn messages(&self) -> Vec<WhisperMessage> {
        self.core.lock().unwrap().messages.clone()
    }

    pub fn config(&self) -> WhisperConfig {
        self.core.lock().unwrap().config.clone()
    }

    pub fn peer_count(&self) -> usize {
        self.core.lock().unwrap().peers.len()
    }

    pub fn rebuild_routing_table(&self) {
        self.core.lock().unwrap().rebuild_routing_table();
    }
}

impl WhisperCore {
    fn build_path_inner(&self, destination: Uuid) -> Option<Vec<Uuid>> {
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

    pub fn rebuild_routing_table(&mut self) {
        self.routing_table.clear();
        for peer in &self.peers {
            if let Some(path) = self.build_path_inner(peer.peer_id) {
                self.routing_table.insert(peer.peer_id, path);
            }
        }
    }

    fn find_nearest_peers(&self, msg: &WhisperMessage, max: usize) -> Vec<MeshPeer> {
        let mut candidates: Vec<MeshPeer> = self
            .peers
            .iter()
            .filter(|p| p.hop_count <= msg.ttl)
            .cloned()
            .collect();
        candidates.sort_by_key(|p| p.latency_ms);
        candidates.truncate(max);
        candidates
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
    fn test_encrypt_decrypt_roundtrip() {
        let node = Uuid::new_v4();
        let peer = Uuid::new_v4();
        let key = derive_whisper_key(&node, &peer);

        let msg = WhisperMessage {
            msg_id: Uuid::new_v4(),
            sender_id: node,
            seq: 42,
            payload: b"hello whispernet".to_vec(),
            ttl: 3,
            signature: vec![],
            timestamp: 1_700_000_000,
        };

        let wire = encrypt_message(&msg, &key).unwrap();
        let decrypted = decrypt_message(&wire[4..], &key).unwrap();
        assert_eq!(decrypted.msg_id, msg.msg_id);
        assert_eq!(decrypted.payload, msg.payload);
        assert_eq!(decrypted.seq, 42);
    }

    #[test]
    fn test_peer_registration() {
        let node_id = Uuid::new_v4();
        let net = WhisperNet::new(test_config(node_id));

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
        assert_eq!(net.peer_count(), 1);

        let dup = MeshPeer {
            peer_id: net.peers()[0].peer_id,
            hostname: "worker-01".into(),
            endpoint: "10.0.0.1:9000".into(),
            public_key: vec![0; 32],
            last_seen: 1_700_000_000,
            hop_count: 1,
            latency_ms: 5,
        };
        assert!(!net.register_peer(dup));
    }

    #[test]
    fn test_message_send_local() {
        let node_id = Uuid::new_v4();
        let net = WhisperNet::new(test_config(node_id));

        let msg = net.create_message(node_id, vec![1, 2, 3, 4], 3);
        assert_eq!(msg.ttl, 3);

        let rt = tokio::runtime::Runtime::new().unwrap();
        let result = rt.block_on(async { net.send_message(msg).await });
        assert!(result.is_ok());
        assert_eq!(net.messages().len(), 1);
    }

    #[test]
    fn test_routing() {
        let node_a = Uuid::new_v4();
        let net = WhisperNet::new(test_config(node_a));

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
        assert!(path.is_some());
        assert!(!path.unwrap().is_empty());
    }

    #[test]
    fn test_max_peers() {
        let node_id = Uuid::new_v4();
        let mut config = test_config(node_id);
        config.max_peers = 2;

        let net = WhisperNet::new(config);
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
        assert!(net.peer_count() <= 2);
    }

    #[tokio::test]
    async fn test_start_listener() {
        let node_id = Uuid::new_v4();
        let mut config = test_config(node_id);
        config.listen_port = 0;
        config.encryption_enabled = false;

        let net = WhisperNet::new(config);
        let result = net.start_listener().await;
        assert!(result.is_ok());
        let port = net.config().listen_port;
        assert!(port > 0, "should have assigned port, got {}", port);
    }

    #[tokio::test]
    async fn test_send_receive_tcp() {
        let node_a = Uuid::new_v4();
        let node_b = Uuid::new_v4();
        let mut cfg_a = test_config(node_a);
        let mut cfg_b = test_config(node_b);
        cfg_a.encryption_enabled = false;
        cfg_b.encryption_enabled = false;
        cfg_a.listen_port = 0;
        cfg_b.listen_port = 0;

        let net_a = WhisperNet::new(cfg_a);
        let net_b = WhisperNet::new(cfg_b);

        net_a.start_listener().await.unwrap();
        net_b.start_listener().await.unwrap();

        let port_a = net_a.config().listen_port;
        let port_b = net_b.config().listen_port;

        // Connect A to B
        let peer_b = MeshPeer {
            peer_id: node_b,
            hostname: "node-b".into(),
            endpoint: format!("127.0.0.1:{}", port_b),
            public_key: vec![0; 32],
            last_seen: 1_700_000_000,
            hop_count: 1,
            latency_ms: 5,
        };
        net_a.connect_to_peer(peer_b).await.unwrap();
        assert_eq!(net_a.peer_count(), 1);

        // Send message from A (no encryption)
        let msg = net_a.create_message(node_a, b"ping".to_vec(), 3);
        net_a.send_message(msg).await.unwrap();

        // Let the message arrive
        tokio::time::sleep(std::time::Duration::from_millis(200)).await;

        // B should have received it
        let msgs = net_b.receive_messages(0).await;
        assert!(!msgs.is_empty(), "B should have received messages");
    }
}
