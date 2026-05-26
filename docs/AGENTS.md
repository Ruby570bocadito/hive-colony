# Agent Reference

## Worker ◈ — Reconnaissance

**File:** `agents/worker/src/main.rs`
**Role:** Perception

### Capabilities

- System profiling: OS, architecture, hostname, user, process list
- EDR detection: CrowdStrike (csfalcon/CSAgent), Defender (MsMpEng), SentinelOne, CarbonBlack, Cylance, Symantec, McAfee
- Backup service detection: Veeam, Backup Exec, CommVault, NetBackup
- Network interface enumeration
- ML-based environment classification (ONNX Random Forest) — currently using heuristics due to ort crate incompatibility
- Publishes beliefs to swarm: `edr_present`, `backup_present`, `network_interfaces`, `process_count`, `os_type`, `arch`, `hostname`, `user`
- Responds to `scan` requests from other agents

### Configuration

```toml
[agents]
scout_scan_interval_secs = 15
edr_processes = ["csfalcon", "csagent", "msmpeng", "sentinelone", "carbonblack", "cylancesvc", "symantec", "mcafee"]
```

### MITRE ATT&CK

- T1057 — Process Discovery
- T1082 — System Information Discovery
- T1518.001 — Security Software Discovery
- T1046 — Network Service Discovery
- T1614.001 — System Location Discovery

---

## Drone ◆ — Decision & Lateral Movement

**File:** `agents/drone/src/main.rs`
**Role:** Decision-making, lateral propagation, agent regeneration

### Capabilities

- Receives beliefs from all Scouts
- Makes movement decisions (heuristic + MARL policy)
- Network discovery via nmap/ARP
- Agent regeneration: when a Scout dies, mutates binary (Weaver) and spawns new process
- Colony aggressive mode: attacks all reachable hosts via SSH
- Installs persistence (SSH key deployment)
- Requests obfuscation from Weaver

### Decision Logic

1. **Colony mode**: scan all configured subnets, attack every host not in safe_ips
2. **Heuristic mode**: if EDR detected → wait. If backup present → target backup server. Else → propagate to network segment
3. **MARL mode** (when ONNX works): 62-dim state vector → Q-network → best action

### Configuration

```toml
[agents]
shaper_decision_interval_secs = 30

[colony]
aggressive = true
scan_subnets = ["192.168.1.0/24", "10.0.0.0/24"]
max_concurrent_infections = 5
```

### MITRE ATT&CK

- T1021.004 — SSH Remote Services
- T1570 — Lateral Tool Transfer (SCP)
- T1543.002 — System Process Creation (regeneration)
- T1547.001 — Boot/Logon Autostart (persistence)

---

## Honeybee ◉ — Action Execution

**File:** `agents/honeybee/src/main.rs`
**Role:** Destructive actions, data exfiltration

### Capabilities

- File encryption with **AES-256-GCM** (random key, random nonce per file)
- Secure deletion: 3-pass overwrite with random data + zeros + unlink
- HTTP exfiltration: POST files to C2 endpoint
- Consensus-gated execution (80% threshold)
- Target discovery: Documents, Desktop, Downloads, .ssh, .aws, .config
- Only executes when consensus is reached on encrypt/exfiltrate/destroy proposals

### Encryption Format

```
[12 bytes nonce][AES-256-GCM ciphertext + tag]
```

Files are overwritten in-place with this format. The key exists only in agent memory.

### Configuration

```toml
[c2]
url = "https://192.168.1.100:8443/collect"
api_key = ""
```

### MITRE ATT&CK

- T1485 — Data Destruction
- T1048.002 — Exfiltration Over HTTP
- T1005 — Data from Local System

---

## Weaver ✦ — Polymorphic Mutation

**File:** `agents/weaver/src/main.rs`
**Role:** Binary obfuscation, payload mutation

### Capabilities

4 mutation techniques applied randomly:

1. **XOR mutation**: Random XOR key applied to code sections (skip ELF header)
2. **NOP insertion**: Inserts 1-8 byte NOP sleds at random positions
3. **Section shuffle**: Swaps 64-256 byte chunks of the binary
4. **Junk code**: Inserts dead code blocks every ~50 bytes

- Generates polymorphic variant templates (PowerShell, cmd, WMI)
- Maintains mutation cache (last 50 variants)
- Pre-generates variants on startup and every 120 seconds
- Responds to `obfuscate` requests from Shaper

### MITRE ATT&CK

- T1027.002 — Software Packing
- T1055 — Process Injection

---

## Queen ◇ — Strategic Oracle & C2 Bridge

**File:** `agents/queen/src/main.rs`
**Role:** LLM integration, external C2 bridging

### Capabilities

- Queries Ollama LLM for strategic decisions
- Translates LdC protocol to external C2 formats:
  - **Sliver gRPC**: Belief → session note
  - **Cobalt Strike Beacon**: Belief → callback type 0x21
  - **HTTP REST**: JSON task/response protocol
- Responds to `Query` messages from any agent
- Falls back to "wait" recommendation if LLM unavailable

### C2 Bridge Commands (HTTP)

| Command | LdC Translation |
|---------|----------------|
| `scan` | Request("scan") |
| `exfiltrate` | Desire("exfiltrate", 0.9) |
| `encrypt` | Desire("encrypt", 0.8) |
| `kill` | StatusEvent("kill_switch") |
| `inject_belief` | Belief(asset, value, 1.0) |
| Any other | Query(dilemma, context) |

### MITRE ATT&CK

- T1573.002 — Encrypted Channel
- T1090.004 — Proxy: CDN Fronting

---

## Swarm ⬡ — Autonomous Propagation

**File:** `agents/swarm/src/main.rs`
**Role:** Self-spreading, no-consensus infection

### Capabilities

- **Autonomous**: spreads without waiting for swarm consensus
- **MARL target selection**: prioritizes high-value, low-EDR hosts
- **SSH key auth**: tries all harvested SSH keys
- **SCP deploy**: copies itself to victim and execs
- **Self-limiting**:
  - Max 10 hops then self-destructs
  - Max 2 infections per minute
  - Self-destructs after 1 hour
  - Avoids forbidden network segments
  - Respects `[brain] safe_ips`
- Reads Scout beliefs to avoid EDR-protected hosts

### Configuration

```toml
[agents]
worm_max_hops = 10
worm_max_infections_per_minute = 2
worm_self_destruct_secs = 3600

[brain]
safe_ips = ["192.168.1.100", "192.168.1.1"]
```

### MITRE ATT&CK

- T1021.004 — SSH Remote Services
- T1570 — Lateral Tool Transfer
- T1497.001 — System Checks (avoids EDR hosts)
