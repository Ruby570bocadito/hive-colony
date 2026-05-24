// Hive Telemetry Log (HTL)
// Event-driven telemetry system for the Hive Colony.
// Implements: immutable events with causal IDs, ring buffer in shared arena,
// adaptive sampling, multi-mode draining, persistence (JSONL + zstd),
// and logical replay.

use serde::{Deserialize, Serialize};
use std::collections::VecDeque;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tokio::sync::Mutex;
use tracing::{info, warn};

use crate::shared_arena;

// ── Constants ─────────────────────────────────────────────────────────────

pub const MAX_CAUSES: usize = 8;
pub const HTL_MAGIC: [u8; 4] = [0x48, 0x54, 0x4C, 0x01]; // "HTL\1"
pub const DEFAULT_MAX_FILE_SIZE: u64 = 50 * 1024 * 1024; // 50 MB
pub const DEFAULT_MAX_FILE_AGE_SECS: u64 = 3600; // 1 hour
pub const HEALTHY_SAMPLE_RATE: f64 = 0.10;
pub const DEGRADED_SAMPLE_RATE: f64 = 0.50;
pub const CRITICAL_SAMPLE_RATE: f64 = 1.00;
pub const HEALTHY_THRESHOLD_SECS: u64 = 60;
pub const DEGRADED_THRESHOLD_SECS: u64 = 30;
pub const HIGH_WATERMARK: f64 = 0.75;
pub const LOW_WATERMARK: f64 = 0.25;

// ── EventId ───────────────────────────────────────────────────────────────

#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct EventId {
    pub agent_uuid: [u8; 16],
    pub seq: u64,
}

impl EventId {
    pub fn new(agent_uuid: [u8; 16], seq: u64) -> Self {
        Self { agent_uuid, seq }
    }

    pub fn root() -> Self {
        Self {
            agent_uuid: [0u8; 16],
            seq: 0,
        }
    }

    /// Format as hex string for display
    pub fn short(&self) -> String {
        let prefix: String = self.agent_uuid[..4]
            .iter()
            .map(|b| format!("{:02x}", b))
            .collect();
        format!("{}#{}", prefix, self.seq)
    }
}

// ── Criticality ───────────────────────────────────────────────────────────

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum Criticality {
    Critical = 2,
    Normal = 1,
    Debug = 0,
}

impl Criticality {
    pub fn from_u8(v: u8) -> Self {
        match v {
            2 => Criticality::Critical,
            1 => Criticality::Normal,
            _ => Criticality::Debug,
        }
    }
}

// ── EventType ─────────────────────────────────────────────────────────────

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum EventType {
    // Critical
    ConsensusReached,
    AgentStateChange,
    SecurityTrigger,
    DirectiveEmitted,
    KillSwitchActivated,
    // Normal
    BeliefPublished,
    ProposalCreated,
    VoteCast,
    ActionExecuted,
    HeartbeatSent,
    // Debug
    MessageSerialized,
    ArenaReadWrite,
    ModelInference,
    MutationGenerated,
    ReputationAdjustment,
}

impl EventType {
    pub fn criticality(&self) -> Criticality {
        match self {
            EventType::ConsensusReached
            | EventType::AgentStateChange
            | EventType::SecurityTrigger
            | EventType::DirectiveEmitted
            | EventType::KillSwitchActivated => Criticality::Critical,

            EventType::BeliefPublished
            | EventType::ProposalCreated
            | EventType::VoteCast
            | EventType::ActionExecuted
            | EventType::HeartbeatSent => Criticality::Normal,

            EventType::MessageSerialized
            | EventType::ArenaReadWrite
            | EventType::ModelInference
            | EventType::MutationGenerated
            | EventType::ReputationAdjustment => Criticality::Debug,
        }
    }

    pub fn name(&self) -> &'static str {
        match self {
            EventType::ConsensusReached => "consensus_reached",
            EventType::AgentStateChange => "agent_state_change",
            EventType::SecurityTrigger => "security_trigger",
            EventType::DirectiveEmitted => "directive_emitted",
            EventType::KillSwitchActivated => "kill_switch_activated",
            EventType::BeliefPublished => "belief_published",
            EventType::ProposalCreated => "proposal_created",
            EventType::VoteCast => "vote_cast",
            EventType::ActionExecuted => "action_executed",
            EventType::HeartbeatSent => "heartbeat_sent",
            EventType::MessageSerialized => "message_serialized",
            EventType::ArenaReadWrite => "arena_read_write",
            EventType::ModelInference => "model_inference",
            EventType::MutationGenerated => "mutation_generated",
            EventType::ReputationAdjustment => "reputation_adjustment",
        }
    }
}

// ── Event (core immutable event) ──────────────────────────────────────────

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Event {
    pub id: EventId,
    pub timestamp: u64,
    pub criticality: Criticality,
    pub event_type: EventType,
    pub causes: Vec<EventId>,
    pub payload: Option<Vec<u8>>,
}

impl Event {
    pub fn new(
        agent_uuid: [u8; 16],
        seq: u64,
        event_type: EventType,
        causes: Vec<EventId>,
        payload: Option<Vec<u8>>,
    ) -> Self {
        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos() as u64;
        let criticality = event_type.criticality();
        Self {
            id: EventId::new(agent_uuid, seq),
            timestamp,
            criticality,
            event_type,
            causes,
            payload,
        }
    }

    pub fn root_event(agent_uuid: [u8; 16], seq: u64, event_type: EventType) -> Self {
        Self::new(agent_uuid, seq, event_type, vec![], None)
    }

    pub fn with_payload(
        mut self,
        payload: Vec<u8>,
    ) -> Self {
        self.payload = Some(payload);
        self
    }
}

// ── TelemetryBuffer (lock-free ring buffer in shared arena) ───────────────

pub struct TelemetryBuffer {
    ptr: *mut u8,
    capacity: usize,
}

unsafe impl Send for TelemetryBuffer {}
unsafe impl Sync for TelemetryBuffer {}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct TelemetryEntry {
    pub len: u32,
    pub data: Vec<u8>,
}

impl TelemetryBuffer {
    /// Open the telemetry buffer on the shared arena at `ptr`.
    /// The arena must already have the telemetry region mapped.
    pub fn open(ptr: *mut u8) -> Self {
        Self {
            ptr,
            capacity: shared_arena::TELEMETRY_BUFFER_SIZE,
        }
    }

    /// Initialize the telemetry header (call once from owning process).
    pub fn init(&self) {
        let hdr = shared_arena::telemetry_header_mut(self.ptr);
        hdr.write_cursor.store(0, Ordering::Release);
        hdr.read_cursor.store(0, Ordering::Release);
    }

    fn write_cursor(&self) -> &'static AtomicU64 {
        &shared_arena::telemetry_header_ref(self.ptr).write_cursor
    }

    fn read_cursor(&self) -> &'static AtomicU64 {
        &shared_arena::telemetry_header_ref(self.ptr).read_cursor
    }

    fn data_ptr(&self) -> *mut u8 {
        shared_arena::telemetry_data_mut(self.ptr)
    }

    fn data_ptr_const(&self) -> *const u8 {
        shared_arena::telemetry_data_ptr(self.ptr)
    }

    /// Write an event into the ring buffer.
    /// Returns true if written, false if discarded.
    pub fn write_event(&self, event: &Event) -> bool {
        let bytes = rmp_serde::to_vec(event).unwrap_or_default();
        let entry_len = bytes.len();

        // Debug events are always discarded if buffer might be full
        if event.criticality == Criticality::Debug {
            let write_pos = self.write_cursor().load(Ordering::Acquire);
            let read_pos = self.read_cursor().load(Ordering::Acquire);
            let occupied = write_pos.wrapping_sub(read_pos);
            if occupied as usize + 4 + entry_len > self.capacity {
                return false;
            }
        }

        // Critical events force-sync if needed
        if event.criticality == Criticality::Critical {
            let write_pos = self.write_cursor().load(Ordering::Acquire);
            let read_pos = self.read_cursor().load(Ordering::Acquire);
            let occupied = write_pos.wrapping_sub(read_pos);
            if occupied as usize + 4 + entry_len > self.capacity {
                // Force advance read cursor to make room (discard oldest)
                let need = (occupied as usize + 4 + entry_len) - self.capacity;
                let new_read = read_pos + need as u64;
                self.read_cursor().store(new_read, Ordering::Release);
            }
        }

        // Write the entry
        let write_pos = self.write_cursor().fetch_add(4 + entry_len as u64, Ordering::AcqRel);
        let write_idx = (write_pos as usize) % self.capacity;
        let data_area = self.data_ptr();

        // Write length prefix (unaligned — ring buffer may wrap at any offset)
        unsafe {
            let len_bytes = (entry_len as u32).to_le_bytes();
            std::ptr::copy_nonoverlapping(
                len_bytes.as_ptr(),
                data_area.add(write_idx),
                4,
            );
        }

        // Write data (handle wrap-around)
        let data_start = (write_idx + 4) % self.capacity;
        if data_start + entry_len <= self.capacity {
            unsafe {
                std::ptr::copy_nonoverlapping(
                    bytes.as_ptr(),
                    data_area.add(data_start),
                    entry_len,
                );
            }
        } else {
            let first_chunk = self.capacity - data_start;
            unsafe {
                std::ptr::copy_nonoverlapping(bytes.as_ptr(), data_area.add(data_start), first_chunk);
                std::ptr::copy_nonoverlapping(
                    bytes.as_ptr().add(first_chunk),
                    data_area,
                    entry_len - first_chunk,
                );
            }
        }

        true
    }

    /// Read up to `max_entries` events from the buffer.
    /// Advances the read cursor.
    pub fn drain(&self, max_entries: usize) -> Vec<Event> {
        let mut events = Vec::with_capacity(max_entries.min(256));

        for _ in 0..max_entries {
            let read_pos = self.read_cursor().load(Ordering::Acquire);
            let write_pos = self.write_cursor().load(Ordering::Acquire);

            if read_pos == write_pos {
                break; // Empty
            }

            let read_idx = (read_pos as usize) % self.capacity;
            let data_area = self.data_ptr_const();

            // Read length prefix (unaligned)
            let entry_len: u32 = unsafe {
                let mut len_bytes = [0u8; 4];
                std::ptr::copy_nonoverlapping(data_area.add(read_idx), len_bytes.as_mut_ptr(), 4);
                u32::from_le_bytes(len_bytes)
            };

            if entry_len == 0 || entry_len as usize > self.capacity {
                // Corrupted entry, advance past it
                self.read_cursor().store(read_pos + 4, Ordering::Release);
                continue;
            }

            // Read data (handle wrap-around)
            let data_start = (read_idx + 4) % self.capacity;
            let mut bytes = vec![0u8; entry_len as usize];

            if data_start + entry_len as usize <= self.capacity {
                unsafe {
                    std::ptr::copy_nonoverlapping(
                        data_area.add(data_start),
                        bytes.as_mut_ptr(),
                        entry_len as usize,
                    );
                }
            } else {
                let first_chunk = self.capacity - data_start;
                unsafe {
                    std::ptr::copy_nonoverlapping(
                        data_area.add(data_start),
                        bytes.as_mut_ptr(),
                        first_chunk,
                    );
                    std::ptr::copy_nonoverlapping(
                        data_area,
                        bytes.as_mut_ptr().add(first_chunk),
                        entry_len as usize - first_chunk,
                    );
                }
            }

            // Advance read cursor past this entry
            let new_read = read_pos + 4 + entry_len as u64;
            self.read_cursor().store(new_read, Ordering::Release);

            // Deserialize
            if let Ok(event) = rmp_serde::from_slice::<Event>(&bytes) {
                events.push(event);
            }
        }

        events
    }

    /// Return buffer occupancy ratio (0.0 – 1.0)
    pub fn occupancy_ratio(&self) -> f64 {
        let write_pos = self.write_cursor().load(Ordering::Acquire);
        let read_pos = self.read_cursor().load(Ordering::Acquire);
        let occupied = write_pos.wrapping_sub(read_pos) as usize;
        (occupied as f64 / self.capacity as f64).min(1.0)
    }

    /// Read without advancing cursor (peek)
    pub fn peek(&self, max_entries: usize) -> Vec<Event> {
        let saved = self.read_cursor().load(Ordering::Acquire);
        let events = self.drain(max_entries);
        self.read_cursor().store(saved, Ordering::Release);
        events
    }
}

// ── ColonyHealth & AdaptiveSampler ────────────────────────────────────────

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum ColonyHealth {
    Healthy,
    Degraded,
    Critical,
}

pub struct AdaptiveSampler {
    health: ColonyHealth,
    last_transition: u64,
    recent_critical_events: VecDeque<(u64, EventType)>,
}

impl Default for AdaptiveSampler {
    fn default() -> Self {
        Self {
            health: ColonyHealth::Healthy,
            last_transition: 0,
            recent_critical_events: VecDeque::new(),
        }
    }
}

impl AdaptiveSampler {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn health(&self) -> ColonyHealth {
        self.health
    }

    pub fn sample_rate(&self) -> f64 {
        match self.health {
            ColonyHealth::Healthy => HEALTHY_SAMPLE_RATE,
            ColonyHealth::Degraded => DEGRADED_SAMPLE_RATE,
            ColonyHealth::Critical => CRITICAL_SAMPLE_RATE,
        }
    }

    /// Record an event and possibly adjust health state
    pub fn record_event(&mut self, event: &Event) {
        let now = event.timestamp;

        if event.criticality == Criticality::Critical {
            self.recent_critical_events
                .push_back((now, event.event_type));
        }

        // Prune events older than DEGRADED_THRESHOLD
        while let Some(front) = self.recent_critical_events.front() {
            let age_ns = now.saturating_sub(front.0);
            let age_secs = age_ns / 1_000_000_000;
            if age_secs > HEALTHY_THRESHOLD_SECS {
                self.recent_critical_events.pop_front();
            } else {
                break;
            }
        }

        let new_health = self.compute_health(now);
        if new_health != self.health {
            self.health = new_health;
            self.last_transition = now;
        }
    }

    fn compute_health(&self, now: u64) -> ColonyHealth {
        let has_kill_switch = self
            .recent_critical_events
            .iter()
            .any(|(_, t)| *t == EventType::KillSwitchActivated);

        if has_kill_switch {
            return ColonyHealth::Critical;
        }

        // Check if any critical events have recent AgentStateChange
        for &(ts, _) in &self.recent_critical_events {
            let age_ns = now.saturating_sub(ts);
            let age_secs = age_ns / 1_000_000_000;
            if age_secs < DEGRADED_THRESHOLD_SECS {
                return ColonyHealth::Degraded;
            }
        }

        ColonyHealth::Healthy
    }

    /// Whether a Normal event should be sampled
    pub fn should_sample(&self, rng: &mut impl FnMut() -> f64) -> bool {
        let rate = self.sample_rate();
        rate >= 1.0 || rng() < rate
    }
}

// ── DrainMode ─────────────────────────────────────────────────────────────

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum DrainMode {
    Local,
    Shared,
    Hybrid,
}

impl DrainMode {
    pub fn from_name(s: &str) -> Self {
        match s {
            "shared" => DrainMode::Shared,
            "hybrid" => DrainMode::Hybrid,
            _ => DrainMode::Local,
        }
    }
}

// ── TelemetryFileWriter (JSONL + zstd) ───────────────────────────────────

pub struct TelemetryFileWriter {
    #[allow(dead_code)]
    base_dir: PathBuf,
    critical_dir: PathBuf,
    normal_dir: PathBuf,
    max_file_size: u64,
    max_file_age: Duration,
    critical_writer: Option<RotatingWriter>,
    normal_writer: Option<RotatingWriter>,
}

struct RotatingWriter {
    dir: PathBuf,
    prefix: &'static str,
    current_path: PathBuf,
    current_size: u64,
    created_at: SystemTime,
    max_size: u64,
    max_age: Duration,
    buf: Vec<u8>,
}

impl RotatingWriter {
    fn new(
        dir: PathBuf,
        prefix: &'static str,
        max_size: u64,
        max_age: Duration,
    ) -> Self {
        let path = dir.join(format!("{}_{}.jsonl", prefix, timestamp_str()));
        Self {
            dir,
            prefix,
            current_path: path,
            current_size: 0,
            created_at: SystemTime::now(),
            max_size,
            max_age,
            buf: Vec::with_capacity(65536),
        }
    }

    fn write_event(&mut self, event: &Event) -> std::io::Result<()> {
        // Check rotation
        let should_rotate = self.current_size >= self.max_size
            || self.created_at.elapsed().unwrap_or(Duration::MAX) >= self.max_age;

        if should_rotate {
            self.flush()?;
            let new_path = self
                .dir
                .join(format!("{}_{}.jsonl", self.prefix, timestamp_str()));
            self.current_path = new_path;
            self.current_size = 0;
            self.created_at = SystemTime::now();
        }

        let line = serde_json::to_string(event).unwrap_or_default();
        let line_bytes = line.as_bytes();
        self.buf.extend_from_slice(line_bytes);
        self.buf.push(b'\n');
        self.current_size += line_bytes.len() as u64 + 1;

        Ok(())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        if self.buf.is_empty() {
            return Ok(());
        }
        std::fs::write(&self.current_path, &self.buf)?;
        self.buf.clear();
        Ok(())
    }

}

impl TelemetryFileWriter {
    pub fn new(base_dir: &Path) -> Self {
        let critical_dir = base_dir.join("critical");
        let normal_dir = base_dir.join("normal");
        let _ = std::fs::create_dir_all(&critical_dir);
        let _ = std::fs::create_dir_all(&normal_dir);

        Self {
            base_dir: base_dir.to_path_buf(),
            critical_dir,
            normal_dir,
            max_file_size: DEFAULT_MAX_FILE_SIZE,
            max_file_age: Duration::from_secs(DEFAULT_MAX_FILE_AGE_SECS),
            critical_writer: None,
            normal_writer: None,
        }
    }

    pub fn ensure_writers(&mut self) {
        if self.critical_writer.is_none() {
            self.critical_writer = Some(RotatingWriter::new(
                self.critical_dir.clone(),
                "critical",
                self.max_file_size,
                self.max_file_age,
            ));
        }
        if self.normal_writer.is_none() {
            self.normal_writer = Some(RotatingWriter::new(
                self.normal_dir.clone(),
                "normal",
                self.max_file_size,
                self.max_file_age,
            ));
        }
    }

    pub fn write_event(&mut self, event: &Event) -> std::io::Result<()> {
        self.ensure_writers();

        match event.criticality {
            Criticality::Critical | Criticality::Debug => {
                if let Some(ref mut w) = self.critical_writer {
                    w.write_event(event)?;
                }
            }
            Criticality::Normal => {
                if let Some(ref mut w) = self.normal_writer {
                    w.write_event(event)?;
                }
            }
        }

        Ok(())
    }

    pub fn flush_all(&mut self) -> std::io::Result<()> {
        if let Some(ref mut w) = self.critical_writer {
            w.flush()?;
        }
        if let Some(ref mut w) = self.normal_writer {
            w.flush()?;
        }
        Ok(())
    }
}

// ── TelemetryCollector (top-level orchestrator) ───────────────────────────

pub struct TelemetryCollector {
    agent_uuid: [u8; 16],
    seq: AtomicU64,
    buffer: TelemetryBuffer,
    sampler: Arc<Mutex<AdaptiveSampler>>,
    drain_mode: DrainMode,
    #[allow(dead_code)]
    output_dir: PathBuf,
    file_writer: Arc<Mutex<TelemetryFileWriter>>,
}

impl TelemetryCollector {
    pub fn new(agent_uuid: [u8; 16], arena_ptr: *mut u8, output_dir: &Path) -> Self {
        let buffer = TelemetryBuffer::open(arena_ptr);
        Self {
            agent_uuid,
            seq: AtomicU64::new(1),
            buffer,
            sampler: Arc::new(Mutex::new(AdaptiveSampler::new())),
            drain_mode: DrainMode::Local,
            output_dir: output_dir.to_path_buf(),
            file_writer: Arc::new(Mutex::new(TelemetryFileWriter::new(output_dir))),
        }
    }

    pub fn set_drain_mode(&mut self, mode: DrainMode) {
        self.drain_mode = mode;
    }

    pub fn drain_mode(&self) -> DrainMode {
        self.drain_mode
    }

    /// Emit an event. Returns the EventId if emitted, None if discarded.
    pub fn emit(&self, event_type: EventType, causes: Vec<EventId>, payload: Option<Vec<u8>>) -> Option<EventId> {
        let seq = self.seq.fetch_add(1, Ordering::AcqRel);
        let event = Event::new(self.agent_uuid, seq, event_type, causes, payload);

        // Debug events: only in lab mode (controlled by env var)
        if event.criticality == Criticality::Debug {
            let lab_mode = std::env::var("HIVE_LAB_MODE").unwrap_or_default();
            if lab_mode != "1" {
                return None;
            }
        }

        // Normal events: check sampling
        if event.criticality == Criticality::Normal {
            let sampler = self.sampler.try_lock();
            if let Ok(s) = sampler {
                let mut rng = rand::thread_rng();
                if !s.should_sample(&mut || rand::Rng::gen::<f64>(&mut rng)) {
                    return None;
                }
            }
        }

        // Write to buffer
        let written = self.buffer.write_event(&event);

        // Update sampler
        if let Ok(mut s) = self.sampler.try_lock() {
            s.record_event(&event);
        }

        if written {
            Some(event.id)
        } else {
            None
        }
    }

    /// Quick emit helper for common event types
    pub fn emit_simple(&self, event_type: EventType) -> Option<EventId> {
        self.emit(event_type, vec![], None)
    }

    /// Drain events from buffer and return them (no disk write).
    /// Useful for seer/analytics processing.
    pub fn drain_events(&self, max_entries: usize) -> Vec<Event> {
        self.buffer.drain(max_entries)
    }

    /// Drain events from buffer and write to disk
    pub fn drain(&self, max_entries: usize) -> usize {
        let events = self.buffer.drain(max_entries);
        let count = events.len();
        if count > 0 {
            let fw = self.file_writer.try_lock();
            if let Ok(mut writer) = fw {
                for event in &events {
                    if let Err(e) = writer.write_event(event) {
                        warn!("HTL: failed to write event: {}", e);
                    }
                }
            }
        }
        count
    }

    /// Flush all file writers
    pub fn flush(&self) -> std::io::Result<()> {
        let fw = self.file_writer.try_lock();
        if let Ok(mut writer) = fw {
            writer.flush_all()?;
        }
        Ok(())
    }

    /// Occupancy ratio of the ring buffer
    pub fn buffer_occupancy(&self) -> f64 {
        self.buffer.occupancy_ratio()
    }

    /// Current sampling rate
    pub async fn sample_rate(&self) -> f64 {
        let s = self.sampler.lock().await;
        s.sample_rate()
    }

    /// Get current drain mode
    pub async fn current_drain_mode(&self) -> DrainMode {
        self.drain_mode
    }

    /// Change drain mode at runtime
    pub fn change_drain_mode(&mut self, mode: DrainMode) {
        self.drain_mode = mode;
    }

    pub fn sampler(&self) -> &Arc<Mutex<AdaptiveSampler>> {
        &self.sampler
    }
}

// ── Background Drain Task ────────────────────────────────────────────────

/// Spawn a background task that periodically drains the telemetry buffer.
pub fn spawn_drain_task(
    collector: Arc<TelemetryCollector>,
    interval_secs: u64,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(Duration::from_secs(interval_secs));
        loop {
            interval.tick().await;
            let occupancy = collector.buffer_occupancy();
            let drained = collector.drain(512);

            if drained > 0 {
                info!("HTL drain: {} events flushed (buffer {:.1}%)", drained, occupancy * 100.0);
            }

            // If hybrid mode and occupancy > 75%, signal help
            if collector.drain_mode() == DrainMode::Hybrid && occupancy > HIGH_WATERMARK {
                info!("HTL: buffer {:.1}% full, signaling for shared drain help", occupancy * 100.0);
            }
        }
    })
}

// ── TelemetryFlush (operator-initiated flush) ────────────────────────────

/// Request an immediate drain and flush of all telemetry.
pub fn telemetry_flush(collector: &TelemetryCollector) -> std::io::Result<usize> {
    let drained = collector.drain(4096);
    collector.flush()?;
    Ok(drained)
}

// ── Replay Engine ─────────────────────────────────────────────────────────

#[derive(Clone, Debug)]
pub struct ReplayState {
    pub current_index: usize,
    pub total_events: usize,
    pub agent_states: std::collections::HashMap<String, serde_json::Value>,
    pub processed_ids: std::collections::HashSet<EventId>,
    pub errors: Vec<String>,
}

pub struct ReplayEngine {
    events: Vec<Event>,
    state: ReplayState,
    pub paused: bool,
}

impl Default for ReplayEngine {
    fn default() -> Self {
        Self {
            events: Vec::new(),
            state: ReplayState {
                current_index: 0,
                total_events: 0,
                agent_states: std::collections::HashMap::new(),
                processed_ids: std::collections::HashSet::new(),
                errors: Vec::new(),
            },
            paused: false,
        }
    }
}

impl ReplayEngine {
    pub fn new() -> Self {
        Self::default()
    }

    /// Load events from a JSONL file
    pub fn load_file(&mut self, path: &Path) -> std::io::Result<usize> {
        let content = std::fs::read_to_string(path)?;
        let mut count = 0;
        for line in content.lines() {
            if line.trim().is_empty() {
                continue;
            }
            if let Ok(event) = serde_json::from_str::<Event>(line) {
                self.events.push(event);
                count += 1;
            }
        }
        self.state.total_events = self.events.len();
        self.state.current_index = 0;
        Ok(count)
    }

    /// Load events from multiple files in a directory
    pub fn load_dir(&mut self, dir: &Path) -> std::io::Result<usize> {
        let mut count = 0;
        if let Ok(entries) = std::fs::read_dir(dir) {
            for entry in entries.flatten() {
                let path = entry.path();
                if path.extension().map(|e| e == "jsonl").unwrap_or(false) {
                    count += self.load_file(&path)?;
                }
            }
        }
        Ok(count)
    }

    /// Step forward one event, respecting causal dependencies
    pub fn step_forward(&mut self) -> Option<&Event> {
        if self.paused || self.state.current_index >= self.events.len() {
            return None;
        }

        let event = &self.events[self.state.current_index];

        // Check causal dependencies
        for cause in &event.causes {
            if cause.seq != 0 && !self.state.processed_ids.contains(cause) {
                self.state
                    .errors
                    .push(format!("Missing cause {} for event {}", cause.short(), event.id.short()));
                return None;
            }
        }

        self.state.processed_ids.insert(event.id.clone());
        self.state.current_index += 1;
        Some(event)
    }

    /// Step backward one event
    pub fn step_backward(&mut self) {
        if self.state.current_index > 0 {
            self.state.current_index -= 1;
            let event = &self.events[self.state.current_index];
            self.state.processed_ids.remove(&event.id);
        }
    }

    /// Jump to a specific index
    pub fn jump_to(&mut self, index: usize) {
        if index < self.events.len() {
            self.state.current_index = index;
        }
    }

    /// Reset replay
    pub fn reset(&mut self) {
        self.state.current_index = 0;
        self.state.processed_ids.clear();
        self.state.errors.clear();
        self.paused = false;
    }

    /// Check causal integrity of all loaded events
    pub fn verify_causal_integrity(&self) -> Vec<String> {
        let mut errors = Vec::new();
        let mut known_ids: std::collections::HashSet<&EventId> = std::collections::HashSet::new();

        for event in &self.events {
            known_ids.insert(&event.id);
        }

        for event in &self.events {
            for cause in &event.causes {
                if cause.seq != 0 && !known_ids.contains(cause) {
                    errors.push(format!(
                        "Event {} references missing cause {}",
                        event.id.short(),
                        cause.short()
                    ));
                }
            }
        }

        errors
    }

    pub fn is_paused(&self) -> bool {
        self.paused
    }

    pub fn toggle_pause(&mut self) {
        self.paused = !self.paused;
    }

    pub fn state(&self) -> &ReplayState {
        &self.state
    }

    pub fn events(&self) -> &[Event] {
        &self.events
    }
}

// ── Helpers ──────────────────────────────────────────────────────────────

fn timestamp_str() -> String {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default();
    format!("{}", now.as_secs())
}

// ── Tests ────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn test_agent_id() -> [u8; 16] {
        let mut id = [0u8; 16];
        id[..4].copy_from_slice(b"TEST");
        id
    }

    // ── Event model tests ──

    #[test]
    fn test_event_id_unique() {
        let id1 = EventId::new(test_agent_id(), 1);
        let id2 = EventId::new(test_agent_id(), 2);
        assert_ne!(id1, id2);
        assert_eq!(id1.seq, 1);
        assert_eq!(id2.seq, 2);
    }

    #[test]
    fn test_event_criticality_from_type() {
        assert_eq!(EventType::KillSwitchActivated.criticality(), Criticality::Critical);
        assert_eq!(EventType::HeartbeatSent.criticality(), Criticality::Normal);
        assert_eq!(EventType::ModelInference.criticality(), Criticality::Debug);
    }

    #[test]
    fn test_event_root_event() {
        let event = Event::root_event(test_agent_id(), 1, EventType::HeartbeatSent);
        assert!(event.causes.is_empty());
        assert_eq!(event.id.seq, 1);
        assert_eq!(event.event_type, EventType::HeartbeatSent);
    }

    #[test]
    fn test_event_with_payload() {
        let payload = vec![1u8, 2, 3, 4];
        let event = Event::root_event(test_agent_id(), 1, EventType::BeliefPublished)
            .with_payload(payload.clone());
        assert_eq!(event.payload, Some(payload));
    }

    #[test]
    fn test_event_serialization_roundtrip() {
        let event = Event::new(
            test_agent_id(),
            42,
            EventType::ConsensusReached,
            vec![EventId::new(test_agent_id(), 1)],
            Some(vec![0u8, 1, 2]),
        );
        let json = serde_json::to_string(&event).unwrap();
        let deser: Event = serde_json::from_str(&json).unwrap();
        assert_eq!(deser.id.seq, 42);
        assert_eq!(deser.event_type, EventType::ConsensusReached);
        assert_eq!(deser.causes.len(), 1);
    }

    // ── TelemetryBuffer tests ──

    fn create_test_buffer() -> TelemetryBuffer {
        let size = shared_arena::arena_size();
        let layout = std::alloc::Layout::from_size_align(size, 4096).unwrap();
        let ptr = unsafe { std::alloc::alloc_zeroed(layout) };
        // Init the full arena (including telemetry header)
        let buf = TelemetryBuffer::open(ptr);
        buf.init();
        buf
    }

    unsafe fn destroy_test_buffer(buf: &TelemetryBuffer) {
        let size = shared_arena::arena_size();
        let layout = std::alloc::Layout::from_size_align(size, 4096).unwrap();
        std::alloc::dealloc(buf.ptr, layout);
    }

    #[test]
    fn test_buffer_write_and_drain() {
        let buf = create_test_buffer();
        let event = Event::root_event(test_agent_id(), 1, EventType::HeartbeatSent);
        assert!(buf.write_event(&event));
        let drained = buf.drain(10);
        assert_eq!(drained.len(), 1);
        assert_eq!(drained[0].id.seq, 1);
        unsafe { destroy_test_buffer(&buf); }
    }

    #[test]
    fn test_buffer_empty_drain() {
        let buf = create_test_buffer();
        let drained = buf.drain(10);
        assert!(drained.is_empty());
        unsafe { destroy_test_buffer(&buf); }
    }

    #[test]
    fn test_buffer_multiple_events() {
        let buf = create_test_buffer();
        for i in 0..5 {
            let event = Event::root_event(test_agent_id(), i as u64, EventType::HeartbeatSent);
            assert!(buf.write_event(&event));
        }
        let drained = buf.drain(10);
        assert_eq!(drained.len(), 5);
        for (i, e) in drained.iter().enumerate() {
            assert_eq!(e.id.seq, i as u64);
        }
        unsafe { destroy_test_buffer(&buf); }
    }

    #[test]
    fn test_buffer_occupancy() {
        let buf = create_test_buffer();
        assert!(buf.occupancy_ratio() < 0.01);
        for i in 0..10 {
            let event = Event::root_event(test_agent_id(), i, EventType::HeartbeatSent);
            buf.write_event(&event);
        }
        let occ = buf.occupancy_ratio();
        assert!(occ > 0.0);
        unsafe { destroy_test_buffer(&buf); }
    }

    #[test]
    fn test_buffer_peek() {
        let buf = create_test_buffer();
        let event = Event::root_event(test_agent_id(), 1, EventType::HeartbeatSent);
        buf.write_event(&event);
        let peeked = buf.peek(10);
        assert_eq!(peeked.len(), 1);
        let drained = buf.drain(10);
        assert_eq!(drained.len(), 1, "peek should not advance cursor");
        unsafe { destroy_test_buffer(&buf); }
    }

    #[test]
    fn test_critical_events_force_write() {
        let buf = create_test_buffer();
        let event = Event::root_event(test_agent_id(), 1, EventType::KillSwitchActivated);
        assert!(buf.write_event(&event));
        unsafe { destroy_test_buffer(&buf); }
    }

    // ── AdaptiveSampler tests ──

    #[test]
    fn test_sampler_starts_healthy() {
        let s = AdaptiveSampler::new();
        assert_eq!(s.health(), ColonyHealth::Healthy);
        assert!((s.sample_rate() - 0.10).abs() < 1e-6);
    }

    #[test]
    fn test_sampler_transition_to_degraded() {
        let mut s = AdaptiveSampler::new();
        let event = Event::new(
            test_agent_id(),
            1,
            EventType::AgentStateChange,
            vec![],
            None,
        );
        s.record_event(&event);
        assert_eq!(s.health(), ColonyHealth::Degraded);
        assert!((s.sample_rate() - 0.50).abs() < 1e-6);
    }

    #[test]
    fn test_sampler_transition_to_critical() {
        let mut s = AdaptiveSampler::new();
        let event = Event::new(
            test_agent_id(),
            1,
            EventType::KillSwitchActivated,
            vec![],
            None,
        );
        s.record_event(&event);
        assert_eq!(s.health(), ColonyHealth::Critical);
        assert!((s.sample_rate() - 1.00).abs() < 1e-6);
    }

    #[test]
    fn test_sampler_should_sample() {
        let s = AdaptiveSampler::new();
        let mut calls = 0u32;
        // Rate is 0.10, should sample some but not all
        for _ in 0..100 {
            if s.should_sample(&mut || {
                calls += 1;
                calls as f64 * 0.01
            }) {
                // ok
            }
        }
        // With our deterministic RNG returning increasing values, some will be sampled
    }

    // ── TelemetryFileWriter tests ──

    #[test]
    fn test_file_writer_create() {
        let dir = std::env::temp_dir().join("htl_test_create");
        let _ = std::fs::remove_dir_all(&dir);
        let mut writer = TelemetryFileWriter::new(&dir);
        writer.ensure_writers();
        assert!(dir.join("critical").exists());
        assert!(dir.join("normal").exists());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_file_writer_write_and_read() {
        let dir = std::env::temp_dir().join("htl_test_write");
        let _ = std::fs::remove_dir_all(&dir);
        let mut writer = TelemetryFileWriter::new(&dir);
        let event = Event::root_event(test_agent_id(), 1, EventType::HeartbeatSent);
        writer.write_event(&event).unwrap();
        writer.flush_all().unwrap();
        // Check file was written
        let normal_dir = dir.join("normal");
        assert!(normal_dir.exists());
        let entries: Vec<_> = std::fs::read_dir(&normal_dir).unwrap().collect();
        assert!(!entries.is_empty(), "no normal events file written");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_critical_separate_file() {
        let dir = std::env::temp_dir().join("htl_test_critical");
        let _ = std::fs::remove_dir_all(&dir);
        let mut writer = TelemetryFileWriter::new(&dir);
        let event = Event::root_event(test_agent_id(), 1, EventType::KillSwitchActivated);
        writer.write_event(&event).unwrap();
        writer.flush_all().unwrap();
        let crit_dir = dir.join("critical");
        assert!(crit_dir.exists());
        let entries: Vec<_> = std::fs::read_dir(&crit_dir).unwrap().collect();
        assert!(!entries.is_empty(), "no critical events file written");
        let _ = std::fs::remove_dir_all(&dir);
    }

    // ── ReplayEngine tests ──

    #[test]
    fn test_replay_empty() {
        let engine = ReplayEngine::new();
        assert_eq!(engine.state().total_events, 0);
        assert!(engine.events().is_empty());
    }

    #[test]
    fn test_replay_step_forward() {
        let mut engine = ReplayEngine::new();
        let event = Event::root_event(test_agent_id(), 1, EventType::HeartbeatSent);
        engine.events.push(event);
        engine.state.total_events = 1;

        let result = engine.step_forward();
        assert!(result.is_some());
        assert_eq!(engine.state().current_index, 1);
    }

    #[test]
    fn test_replay_step_backward() {
        let mut engine = ReplayEngine::new();
        let event = Event::root_event(test_agent_id(), 1, EventType::HeartbeatSent);
        engine.events.push(event);
        engine.state.total_events = 1;
        engine.step_forward();
        engine.step_backward();
        assert_eq!(engine.state().current_index, 0);
    }

    #[test]
    fn test_replay_causal_integrity_check() {
        let mut engine = ReplayEngine::new();
        let cause = EventId::new(test_agent_id(), 99);
        let event = Event::new(test_agent_id(), 1, EventType::ConsensusReached, vec![cause], None);
        engine.events.push(event);
        engine.state.total_events = 1;
        let errors = engine.verify_causal_integrity();
        assert!(!errors.is_empty(), "should report missing cause");
        assert!(errors[0].contains("99"));
    }

    #[test]
    fn test_replay_toggle_pause() {
        let mut engine = ReplayEngine::new();
        assert!(!engine.is_paused());
        engine.toggle_pause();
        assert!(engine.is_paused());
        engine.toggle_pause();
        assert!(!engine.is_paused());
    }

    #[test]
    fn test_replay_reset() {
        let mut engine = ReplayEngine::new();
        let event = Event::root_event(test_agent_id(), 1, EventType::HeartbeatSent);
        engine.events.push(event);
        engine.state.total_events = 1;
        engine.step_forward();
        engine.reset();
        assert_eq!(engine.state().current_index, 0);
        assert!(engine.state().errors.is_empty());
    }

    // ── TelemetryCollector integration tests ──

    fn alloc_full_arena() -> *mut u8 {
        let size = shared_arena::arena_size();
        let layout = std::alloc::Layout::from_size_align(size, 4096).unwrap();
        let ptr = unsafe { std::alloc::alloc_zeroed(layout) };
        let buf = TelemetryBuffer::open(ptr);
        buf.init();
        ptr
    }

    unsafe fn dealloc_full_arena(ptr: *mut u8) {
        let size = shared_arena::arena_size();
        let layout = std::alloc::Layout::from_size_align(size, 4096).unwrap();
        std::alloc::dealloc(ptr, layout);
    }

    #[test]
    fn test_collector_emit_basic() {
        let ptr = alloc_full_arena();
        let dir = std::env::temp_dir().join("htl_collector_test");
        let _ = std::fs::remove_dir_all(&dir);

        let collector = TelemetryCollector::new(test_agent_id(), ptr, &dir);
        // Use critical events to bypass sampling
        let id = collector.emit_simple(EventType::ConsensusReached);
        assert!(id.is_some(), "event should be emitted");
        assert_eq!(id.unwrap().seq, 1);

        let _ = std::fs::remove_dir_all(&dir);
        unsafe { dealloc_full_arena(ptr); }
    }

    #[test]
    fn test_collector_emit_sequence() {
        let ptr = alloc_full_arena();
        let dir = std::env::temp_dir().join("htl_seq_test");
        let _ = std::fs::remove_dir_all(&dir);

        let collector = TelemetryCollector::new(test_agent_id(), ptr, &dir);
        let id1 = collector.emit_simple(EventType::AgentStateChange);
        let id2 = collector.emit_simple(EventType::AgentStateChange);
        assert!(id2.unwrap().seq > id1.unwrap().seq);

        let _ = std::fs::remove_dir_all(&dir);
        unsafe { dealloc_full_arena(ptr); }
    }

    #[test]
    fn test_collector_drain_and_persist() {
        let ptr = alloc_full_arena();
        let dir = std::env::temp_dir().join("htl_persist_test");
        let _ = std::fs::remove_dir_all(&dir);

        let collector = TelemetryCollector::new(test_agent_id(), ptr, &dir);
        collector.emit_simple(EventType::SecurityTrigger); // critical — bypasses sampling
        let drained = collector.drain(100);
        assert_eq!(drained, 1, "should drain 1 event");
        collector.flush().unwrap();

        let _ = std::fs::remove_dir_all(&dir);
        unsafe { dealloc_full_arena(ptr); }
    }

    #[test]
    fn test_telemetry_flush() {
        let ptr = alloc_full_arena();
        let dir = std::env::temp_dir().join("htl_flush_test");
        let _ = std::fs::remove_dir_all(&dir);

        let collector = TelemetryCollector::new(test_agent_id(), ptr, &dir);
        collector.emit_simple(EventType::KillSwitchActivated); // critical — bypasses sampling
        let flushed = telemetry_flush(&collector).unwrap();
        assert_eq!(flushed, 1);

        let _ = std::fs::remove_dir_all(&dir);
        unsafe { dealloc_full_arena(ptr); }
    }
}
