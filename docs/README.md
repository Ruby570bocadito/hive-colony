# Hive Colony — Multi-Agent Autonomous Swarm Framework

```
                     .' '.
        _/__)        .   .       .
       (8|)_}}- .      .        .
        `\__)    '. . ' ' .  . '
    H I V E   C O L O N Y
```

> Bee-inspired multi-agent autonomous framework for Red Team operations.
> Agents communicate via shared memory, spread via SSH, and evade EDRs
> through 10-layer defense bypass.

---

## Quick Start

```bash
source build_env.sh

# Operator mode (safe — C2 + dashboard only, no attacks)
./hive.sh brain

# Colony mode (aggressive — attacks all reachable hosts except safe_ips)
./hive.sh colony

# Deploy to remote victim
./hive.sh deploy 192.168.1.50

# Stop everything
./hive.sh stop

# Status
./hive.sh status

# Tests (38)
./hive.sh test
```

**Dashboard:** `http://localhost:8080` | **C2 API:** `http://localhost:8443/health`

---

## Architecture

```
APICULTOR (safe)                    VICTIM NETWORK (hive)
┌──────────────────┐               ┌─────────────────────────────┐
│ C2 Server :8443  │◄──beacon─────│ Host #1 ──SSH──► Host #2   │
│ Dashboard :8080  │               │  ├ Worker ◈  recon         │
│ ./hive.sh brain  │               │  ├ Drone ◆   lateral       │
│                  │               │  ├ Honeybee ◉ encrypt/exfil│
│ SAFE from attack │               │  ├ Weaver ✦  polymorph     │
│ (safe_ips)       │               │  ├ Queen ◇   LLM oracle   │
└──────────────────┘               │  └ Swarm ⬡  autonomous    │
                                   └─────────────────────────────┘
```

---

## 6 Agent Types

| Agent | Icon | Role | Real Capabilities |
|-------|------|------|-------------------|
| **Worker** | ◈ | Reconnaissance | Process scanning, EDR detection (8 vendors), system profiling, network enumeration |
| **Drone** | ◆ | Decision & Spread | Network discovery via nmap/ARP, SSH lateral movement, agent regeneration, colony aggressive mode |
| **Honeybee** | ◉ | Action Execution | AES-256-GCM file encryption, 3-pass secure deletion, HTTP exfiltration to C2, consensus-gated (80%) |
| **Weaver** | ✦ | Obfuscation | 4 mutation techniques (XOR, NOP insertion, section shuffle, junk code), polymorphic variants |
| **Queen** | ◇ | Strategic Oracle | Ollama LLM integration, C2 bridge (Sliver/CS/HTTP REST), Royal Jelly directives |
| **Swarm** | ⬡ | Autonomous Spread | Self-propagating via SSH, MARL target selection, self-limiting (max 10 hops, 2/min, 1h lifetime) |

---

## Communication

All 6 agents communicate via a **lock-free atomic ring buffer in shared memory** (`memfd_create` + `mmap`). Zero TCP ports. Zero sockets. Messages signed with Ed25519.

---

## 10-Layer Evasion Stack

| Layer | Technique | Module |
|-------|-----------|--------|
| 1 | Shared memory IPC (no TCP) | `shared_arena` |
| 2 | Fileless execution (memfd_create) | `fileless` |
| 3 | Direct syscalls in ASM | `syscalls` |
| 4 | Call stack spoofing (synthetic RBP) | `stack_spoof` |
| 5 | XOR-encrypted ONNX models | `crypto` |
| 6 | Anti-debug (ptrace, TracerPid) | `anti_analysis` |
| 7 | Anti-sandbox (uptime, CPU, RAM) | `anti_analysis` |
| 8 | Anti-VM (DMI, CPUID, modules) | `anti_analysis` |
| 9 | String obfuscation at compile time | `obfstr!()` macro |
| 10 | Honey detection (bait files, honeypots, canary tokens) | `guardian` |

---

## Bee Colony Modules

| Module | Bee Concept | Function |
|--------|------------|----------|
| `royal_jelly.rs` | Royal Jelly | Queen issues priority directives to the colony |
| `waggle_dance.rs` | Waggle Dance | Workers share discovered targets with rich vectors |
| `pheromone.rs` | Pheromone Trail | Decaying recon data — colony follows strongest trails |
| `swarming.rs` | Colony Split | >5 agents per host → migrate half to new host |
| `honeycomb.rs` | Honeycomb | Persistence (crontab @reboot, systemd, .bashrc) |
| `hive_scale.rs` | Thermoregulation | Auto-scale agents based on CPU/RAM/disk |
| `guardian.rs` | Guard Bees | Detect honeyfiles, honeypots, canary tokens |
| `panal.rs` | Safe Cells | Protect operator IPs from colony attacks |
| `nectar.rs` | Nectar Flow | Data exfiltration (DNS, HTTP, WebSocket CDN) |
| `wax.rs` | Wax Seal | Payload encryption + mutation per session |

---

## MITRE ATT&CK — 36 Techniques

**Defense Evasion (10):** T1055.012, T1562.001, T1622, T1497.001, T1497.003, T1027.002, T1027.005, T1070.004, T1564.004, T1055
**Discovery (5):** T1082, T1057, T1046, T1518.001, T1614.001
**Credential Access (3):** T1552.001, T1552.004, T1552.002
**Lateral Movement (4):** T1021.004, T1570, T1021.006, T1047
**C2 (4):** T1573.002, T1090.004, T1572, T1571
**Exfiltration (3):** T1048.003, T1048.002, T1029
**Execution (2):** T1204.002, T1106
**Persistence (2):** T1543.002, T1547.001

---

## Configuration

Edit `hive.toml`:

```toml
[brain]
safe_ips = ["192.168.1.100"]      # NEVER attacked

[colony]
aggressive = true                  # Attack all reachable hosts
scan_subnets = ["192.168.1.0/24"]

[exploits]
safe_mode = true                   # DEFAULT: exploits are inert

[c2]
url = "https://your-server:8443/collect"
api_key = "your-api-key"
```

---

## Payloads

Pre-compiled binaries in `payloads/`:

```
stinger     513MB  ← embeds all agents, self-destructs
worker       21MB  ← reconnaissance
drone        22MB  ← decisions & lateral
honeybee     25MB  ← encrypt & exfil
weaver       21MB  ← mutation
queen        25MB  ← LLM oracle
swarm        22MB  ← autonomous spread
```

---

## Requirements

- Rust toolchain (`rustup`, `cargo`)
- OpenSSL dev (`libssl-dev`)
- Python 3 (C2 server + dashboard)
- Linux kernel 3.17+ (memfd_create)
- Optional: Ollama (for Queen LLM), nmap (for host discovery)

---

## Directory Structure

```
hive_base/     # 25 shared modules
agents/
├── worker/    # Reconnaissance agent
├── drone/     # Decision & lateral agent
├── honeybee/  # Action agent
├── weaver/    # Obfuscation agent
├── queen/     # LLM oracle
└── swarm/     # Autonomous spread
stinger/       # Dropper/payload deployer
beekeeper/     # CLI control panel
buzz/          # Integration test launcher
tests/         # 38 tests + monitoring tools
payloads/      # Compiled standalone binaries
docs/          # Full documentation
hive.sh        # Main control script
hive.toml      # Configuration file
```
