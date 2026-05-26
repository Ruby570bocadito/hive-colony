# Agent Reference 🐝

```
╔══════════════════════════════════════════════════════════════════╗
║                    HIVE COLONY — AGENTES                         ║
║                                                                  ║
║  ┌─────────┐                                                     ║
║  │  QUEEN  │ ◀── Overmind: estrategia LLM + bridge C2           ║
║  │  (1)    │                                                     ║
║  └────┬────┘                                                     ║
║       │                                                          ║
║       ▼                                                          ║
║  ┌─────────┐  ┌─────────┐  ┌─────────┐  ┌─────────┐              ║
║  │ WORKER  │  │  DRONE  │  │HONEYBEE │  │ WEAVER │               ║
║  │ Scout   │  │ Shaper  │  │ Hoarder │  │  Morph  │              ║
║  └─────────┘  └─────────┘  └─────────┘  └─────────┘              ║
║       │                                                          ║
║       ▼                                                          ║
║  ┌─────────┐                                                     ║
║  │  SWARM  │  Worm auto-propagante                               ║
║  └─────────┘                                                     ║
║                                                                  ║
║  Todos se comunican vía ARENA (memoria compartida, sin TCP)      ║
╚══════════════════════════════════════════════════════════════════╝
```

## Índice

| Agente | Símbolo | Rol | Archivo |
|--------|---------|-----|---------|
| [Queen](#queen--overmind) | ◇ | Overmind — estrategia LLM + C2 bridge | `agents/queen/` |
| [Worker](#worker--scout) | ◈ | Scout — reconocimiento + EDR detection | `agents/worker/` |
| [Drone](#drone--shaper) | ◆ | Shaper — decisiones + movimiento lateral | `agents/drone/` |
| [Honeybee](#honeybee--hoarder) | ◉ | Hoarder — ejecución final + exfiltración | `agents/honeybee/` |
| [Weaver](#weaver--morph) | ✦ | Morph — ofuscación polimórfica | `agents/weaver/` |
| [Swarm](#swarm--worm) | ⬡ | Worm — auto-propagación autónoma | `agents/swarm/` |

---

## Queen ◇ — Overmind

```
┌─────────────────────────────────────────────────────────────────┐
│  QUEEN                                                          │
│                                                                 │
│  ┌──────────────┐    ┌──────────────┐    ┌──────────────┐       │
│  │ Ollama LLM   │───▶│ HiveMind     │───▶│ C2 Bridge   │       │
│  │ (estratégico)│    │ consensus    │    │ HTTP / DNS   │       │
│  └──────────────┘    └──────────────┘    │ ICMP / Dead  │       │
│                                          └──────────────┘       │
│                                                                 │
│  Receptor de órdenes del operador vía C2                        │
│  Traductor entre LdC (Lenguaje de la Colmena) y C2 externo      │
│  Orquestador: decide QUÉ hacer basado en creencias de Worker    │
└─────────────────────────────────────────────────────────────────┘
```

**Archivo:** `agents/queen/src/main.rs`
**Rol:** Overmind — estrategia LLM, bridge C2, HiveMind consensus

### Capacidades

| Capacidad | Detalle |
|-----------|---------|
| LLM estratégico | Consulta Ollama para decisiones tácticas |
| C2 Bridge | Traduce LdC → HTTP/DNS/ICMP/Dead Drop |
| HiveMind Consensus | Coordina votación entre agentes |
| Seer predictivo | Predice eventos basado en telemetría |
| Failover | Cambia de canal C2 si uno falla |

### Comunicación

```
┌──────────┐     LdC (Arena)      ┌──────────┐
│  Worker  │◀──────────────────▶ │  Queen   │
│  Drone   │                      │          │
│  Honeybee│                      │  C2 🡕    │
│  Weaver  │                      │  HTTP    │
│  Swarm   │                      │  DNS     │
└──────────┘                      │  ICMP    │
                                  │  Dead    │
                                  └──────────┘
```

### C2 Bridge Commands (HTTP)

| Comando | Traducción LdC | Efecto |
|---------|----------------|--------|
| `scan` | `Request("scan")` | Worker escanea |
| `exfiltrate` | `Desire("exfiltrate", 0.9)` | Honeybee exfiltra |
| `encrypt` | `Desire("encrypt", 0.8)` | Honeybee cifra |
| `kill` | `StatusEvent("kill_switch")` | Todos se destruyen |
| `inject_belief` | `Belief(asset, value, 1.0)` | Inyecta creencia |

### MITRE ATT&CK

| Técnica | ID | Descripción |
|---------|----|-------------|
| Encrypted Channel | T1573.002 | Cifrado AES-GCM en comunicaciones C2 |
| Proxy: CDN Fronting | T1090.004 | Dead Drop vía servicios legítimos |

---

## Worker ◈ — Scout

```
┌─────────────────────────────────────────────────────────────────┐
│  WORKER                                                         │
│                                                                 │
│  ┌──────────────┐    ┌──────────────┐    ┌──────────────┐     │
│  │ System       │───▶│ EDR          │───▶│ Publica      │     │
│  │ Profiling    │    │ Detection    │    │ creencias    │     │
│  └──────────────┘    └──────────────┘    │ a la Arena   │     │
│                                          └──────────────┘     │
│  Lee: /proc, /sys, cgroups, hostname, user                     │
│  Detecta: CrowdStrike, Defender, SentinelOne, CarbonBlack...   │
│  Clasifica: ONNX Random Forest (o heurísticas)                 │
└─────────────────────────────────────────────────────────────────┘
```

**Archivo:** `agents/worker/src/main.rs`
**Rol:** Perception — reconocimiento y detección

### Capacidades

| Capacidad | Detalle |
|-----------|---------|
| System profiling | OS, arquitectura, hostname, usuario, procesos |
| EDR detection | 30+ firmas (CrowdStrike, Defender, SentinelOne, etc.) |
| Backup detection | Veeam, Backup Exec, CommVault, NetBackup |
| Network enum | Interfaces, IPs, MACs, gateway |
| ML classification | ONNX Random Forest (fallback a heurísticas) |

### EDRs detectados

```
┌─────────────────────────────────────────────────────────────────┐
│  FIRMAS EDR DETECTADAS                                          │
│                                                                 │
│  CrowdStrike    │ csfalcon, CSAgent                             │
│  Microsoft      │ MsMpEng (Defender)                            │
│  SentinelOne    │ SentinelService, SentinelAgent               │
│  Carbon Black   │ carbonblack                                   │
│  Cylance        │ CylanceSvc                                    │
│  Symantec       │ Symantec, Norton                              │
│  McAfee         │ mcafee, MfeTDI                                │
│  Sophos         │ sesvc, sophos                                  │
│  Tanium         │ taniumclient                                   │
│  Elastic        │ elastic-endpoint                               │
│  Palo Alto      │ trap, trapcord                                 │
│  Trend Micro    │ tmlisten, amsp                                 │
│  Kaspersky      │ kavfs, avp                                     │
│  ESET           │ ekrn, eset                                     │
│  BitDefender    │ bdredline, bdagent                             │
│  ... y 15+ más                                                  │
└─────────────────────────────────────────────────────────────────┘
```

### Creencias publicadas

| Creencia | Tipo | Significado |
|----------|------|-------------|
| `edr_present` | bool | Hay EDR corriendo |
| `backup_present` | bool | Hay backup software |
| `network_interfaces` | vec | IPs y MACs del host |
| `process_count` | int | Número de procesos |
| `os_type` | string | Linux / Windows |
| `arch` | string | x86_64 / aarch64 |
| `hostname` | string | Nombre del host |
| `user` | string | Usuario actual |

### Configuración

```toml
[agents]
worker_scan_interval_secs = 15
edr_processes = ["csfalcon", "csagent", "msmpeng", "sentinelone",
                 "carbonblack", "cylancesvc", "symantec", "mcafee"]
```

### MITRE ATT&CK

| Técnica | ID | Descripción |
|---------|----|-------------|
| Process Discovery | T1057 | Lista procesos |
| System Info Discovery | T1082 | OS, hostname, arch |
| Security Software Discovery | T1518.001 | 30+ firmas EDR |
| Network Service Discovery | T1046 | Interfaces de red |
| System Location Discovery | T1614.001 | Geo-localización |

---

## Drone ◆ — Shaper

```
┌─────────────────────────────────────────────────────────────────┐
│  DRONE                                                          │
│                                                                 │
│  ┌──────────────┐    ┌──────────────┐    ┌──────────────┐       │
│  │ Lee          │───▶│ Decide      │───▶│ Ejecuta      │       │
│  │ creencias    │    │ acción       │    │ movimiento   │       │
│  │ de Worker    │    │ óptima       │    │ lateral      │       │
│  └──────────────┘    └──────────────┘    └──────────────┘       │
│                                                                 │
│  Estrategias:                                                   │
│    • Colony mode → atacar TODO lo alcanzable                    │
│    • Heuristic  → EDR? esperar. Backup? atacar backup.          │
│    • MARL       → 62-dim state → Q-network                      │
│                                                                 │
│  Si un Worker muere, Drone lo regenera via Weaver               │
└─────────────────────────────────────────────────────────────────┘
```

**Archivo:** `agents/drone/src/main.rs`
**Rol:** Decision-making, lateral propagation, agent regeneration

### Capacidades

| Capacidad | Detalle |
|-----------|---------|
| Toma decisiones | Basado en creencias de Worker |
| Network discovery | nmap / ARP scan de subredes |
| Movimiento lateral | SSH con claves cosechadas |
| Regeneración | Cuando un Worker muere, Weaver muta y spawn |
| Persistencia | Instala claves SSH autorizadas |
| Ofuscación | Solicita variantes polimórficas a Weaver |

### Decision Logic

```
                           ┌──────────────┐
                           │  Creencias   │
                           │  de Worker   │
                           └──────┬───────┘
                                  ▼
                    ┌─────────────────────────┐
                    │   ¿EDR presente?        │
                    │   ┌───┐    ┌───┐        │
                    │   │ SI│    │ NO│        │
                    │   └─┬─┘    └─┬─┘        │
                    │     ▼        ▼          │
                    │  Esperar   ¿Backup?     │
                    │           ┌───┐ ┌───┐   │
                    │           │ SI│ │ NO│   │
                    │           └─┬─┘ └─┬─┘   │
                    │             ▼     ▼     │
                    │        Atacar  Propaga  │
                    │        backup  a red    │
                    └─────────────────────────┘
```

### Configuración

```toml
[agents]
drone_decision_interval_secs = 30

[colony]
aggressive = true
scan_subnets = ["192.168.1.0/24", "10.0.0.0/24"]
max_concurrent_infections = 5
```

### MITRE ATT&CK

| Técnica | ID | Descripción |
|---------|----|-------------|
| SSH Remote Services | T1021.004 | Movimiento lateral |
| Lateral Tool Transfer | T1570 | SCP de bins |
| System Process Creation | T1543.002 | Regeneración de workers |
| Boot/Logon Autostart | T1547.001 | Persistencia SSH |

---

## Honeybee ◉ — Hoarder

```
┌─────────────────────────────────────────────────────────────────┐
│  HONEYBEE                                                       │
│                                                                 │
│  ┌──────────────┐    ┌──────────────┐    ┌──────────────┐       │
│  │ Busca        │───▶│ Cifra        │───▶│ Exfiltra     │      │
│  │ targets:     │    │ AES-256-GCM  │    │ vía HTTP C2  │       │
│  │ Documentos   │    │ 3-pass wipe  │    │ ┌──────────┐ │       │
│  │ .ssh, .aws   │    │              │    │ │ C2 Queue │ │       │
│  │ .config      │    │              │    │ └──────────┘ │       │
│  └──────────────┘    └──────────────┘    └──────────────┘       │
│                                                                 │
│  Solo ejecuta con consenso ≥80% (HiveMind)                      │
│  Soporta: privesc (SUID, sudo, Docker, PwnKit)                  │
│           cloud pivot (AWS, GCP, Azure)                         │
└─────────────────────────────────────────────────────────────────┘
```

**Archivo:** `agents/honeybee/src/main.rs`
**Rol:** Action execution, encryption, exfiltration

### Capacidades

| Capacidad | Detalle |
|-----------|---------|
| File encryption | AES-256-GCM con key/nonce aleatorio por archivo |
| Secure deletion | 3-pass overwrite (random + zeros + unlink) |
| HTTP exfiltration | POST chunks a C2 endpoint |
| Consensus-gated | Requiere 80% de aprobación HiveMind |
| Target discovery | Documents, Desktop, Downloads, .ssh, .aws, .config |
| Privesc | SUID, sudo, LD_PRELOAD, Docker, PwnKit, DirtyPipe |
| Cloud pivot | AWS STS/EC2/S3, GCP Compute/IAM, Azure VM/KeyVault |

### Encryption Format

```
┌─────────────────────────────────────────────────────────────────┐
│  ARCHIVO CIFRADO                                                │
│                                                                 │
│  ┌──────────────────────────────┬────────────────────────────┐  │
│  │  Nonce (12 bytes)            │  AES-256-GCM ciphertext    │  │
│  │  (aleatorio por archivo)     │  + authentication tag      │  │
│  └──────────────────────────────┴────────────────────────────┘  │
│                                                                 │
│  La key existe SOLO en memoria del agente.                      │
│  Sin key → datos irrecuperables.                                │
└─────────────────────────────────────────────────────────────────┘
```

### Configuración

```toml
[c2]
url = "https://tu-c2.com:8444/collect"
api_key = "supersecreto"

[consensus]
threshold = 0.8
```

### MITRE ATT&CK

| Técnica | ID | Descripción |
|---------|----|-------------|
| Data Destruction | T1485 | 3-pass wipe |
| Exfiltration Over HTTP | T1048.002 | POST a C2 |
| Data from Local System | T1005 | Documentos, .ssh, .aws |

---

## Weaver ✦ — Morph

```
┌─────────────────────────────────────────────────────────────────┐
│  WEAVER                                                         │
│                                                                 │
│  ┌──────────────┐    ┌──────────────┐    ┌──────────────┐     │
│  │ 4 técnicas   │───▶│ Cache de     │───▶│ Responde a   │     │
│  │ de mutación  │    │ 50 variantes │    │ obfuscate    │     │
│  └──────────────┘    └──────────────┘    └───┬──────────┘     │
│                                              │                  │
│  Técnicas:                                    ▼                  │
│  1. XOR mutation ──── key aleatoria          Drone solicita    │
│  2. NOP insertion ─── 1-8 bytes             variante para     │
│  3. Section shuffle ─ chunks swap           regenerar Worker  │
│  4. Junk code ─────── dead code blocks                         │
│                                                                 │
│  También genera: PowerShell, cmd, WMI stagers                 │
└─────────────────────────────────────────────────────────────────┘
```

**Archivo:** `agents/weaver/src/main.rs`
**Rol:** Binary obfuscation, payload mutation

### Las 4 técnicas de mutación

```
Técnica 1: XOR MUTATION
┌────────────────────┐     ┌────────────────────┐
│ ELF header (skip)  │     │ ELF header (skip)  │
│ .text              │────▶│ .text XOR 0xA3     │
│ .data              │     │ .data XOR 0xA3     │
│ ...                │     │ ...                │
└────────────────────┘     └────────────────────┘

Técnica 2: NOP INSERTION
┌────────────────────┐     ┌──────────────────────────┐
│ mov eax, 1         │     │ mov eax, 1               │
│ add eax, 2         │────▶│ nop; nop; nop; nop       │
│ ret                │     │ add eax, 2               │
│                    │     │ nop; nop                  │
│                    │     │ ret                       │
└────────────────────┘     └──────────────────────────┘

Técnica 3: SECTION SHUFFLE
┌──────┬──────┬──────┐     ┌──────┬──────┬──────┐
│ .text│.data │.rdata│────▶│.rdata│.text │.data │
└──────┴──────┴──────┘     └──────┴──────┴──────┘
  (chunks de 64-256 bytes intercambiados)

Técnica 4: JUNK CODE
┌────────────────────┐     ┌────────────────────────────────────┐
│ mov eax, 1         │     │ mov eax, 1                         │
│ add eax, 2         │────▶│ push rbp; mov rbp, rsp; pop rbp   │
│ ret                │     │ add eax, 2                         │
│                    │     │ xor rbx, rbx; inc rbx; dec rbx    │
│                    │     │ ret                                │
└────────────────────┘     └────────────────────────────────────┘
```

### MITRE ATT&CK

| Técnica | ID | Descripción |
|---------|----|-------------|
| Software Packing | T1027.002 | Mutación binaria |
| Process Injection | T1055 | Nuevos procesos mutados |

---

## Swarm ⬡ — Worm

```
┌─────────────────────────────────────────────────────────────────┐
│  SWARM                                                          │
│                                                                 │
│  ┌──────────────┐    ┌──────────────┐    ┌──────────────┐     │
│  │ Lee          │───▶│ Selecciona   │───▶│ Se propaga   │     │
│  │ creencias    │    │ targets via  │    │ vía SSH + SCP│     │
│  │ de Worker   │    │ MARL policy  │    │              │     │
│  └──────────────┘    └──────────────┘    └──────────────┘     │
│                                                                 │
│  Auto-limitante:                                                │
│    • Max 10 hops → self-destruct                                │
│    • Max 2 infecciones/min                                      │
│    • Self-destruct después de 1h                                │
│    • Evita hosts con EDR (lee creencias de Worker)             │
│    • No requiere consenso — propaga autónomamente              │
└─────────────────────────────────────────────────────────────────┘
```

**Archivo:** `agents/swarm/src/main.rs`
**Rol:** Autonomous propagation, no-consensus spreading

### Capacidades

| Capacidad | Detalle |
|-----------|---------|
| Autónomo | Propaga sin esperar consenso HiveMind |
| MARL target selection | Prioriza hosts de alto valor y bajo EDR |
| SSH key auth | Prueba todas las claves cosechadas |
| SCP deploy | Copia binario y ejecuta remoto |
| Auto-limitante | 10 hops, 2/min, 1h de vida |
| EDR avoidance | Lee creencias de Worker |

### Ciclo de vida

```
NACE ────────────────────────────────────────────────────────── MUERE
  │                                                              │
  ▼                                                              ▼
┌──────────┐    ┌──────────┐    ┌──────────┐    ┌──────────┐
│ Spawnea  │───▶│ Escanea  │───▶│ Infecta  │───▶│ Salta a  │
│ target 1  │    │ target 2 │    │ target 3 │    │ target 4 │
└──────────┘    └──────────┘    └──────────┘    └──────────┘
                                                     │
                                                     ▼    (hop ≥ 10
                                                  ┌──────────┐  o 1h
                                                  │ SELF-    │  pasado)
                                                  │ DESTRUCT │
                                                  └──────────┘
```

### Configuración

```toml
[agents]
swarm_max_hops = 10
swarm_max_infections_per_minute = 2
swarm_self_destruct_secs = 3600

[brain]
safe_ips = ["192.168.1.100", "192.168.1.1"]
```

### MITRE ATT&CK

| Técnica | ID | Descripción |
|---------|----|-------------|
| SSH Remote Services | T1021.004 | Propagación |
| Lateral Tool Transfer | T1570 | SCP de binarios |
| System Checks | T1497.001 | Evita hosts con EDR |

---

## Comunicación entre agentes (Arena)

```
┌─────────────────────────────────────────────────────────────────┐
│  ARENA — Memoria compartida (shm_open / mmap)                  │
│                                                                 │
│  ┌────────────┐                                                 │
│  │ Arena      │  /dev/shm/hive_arena                           │
│  │ Header     │  Magic: 0x48495645 ("HIVE")                    │
│  ├────────────┤  Slots: 16                                     │
│  │ Slot 0     │  Tamaño: 8KB por slot                         │
│  │ Slot 1     │                                                 │
│  │ Slot 2     │  Lock-free: seq counters + atomic flags        │
│  │ ...        │                                                 │
│  │ Slot 15    │  Serialización: MessagePack (rmp-serde)        │
│  └────────────┘                                                 │
│                                                                 │
│  ┌──────────┐  ┌──────────┐  ┌──────────┐  ┌──────────┐       │
│  │  QUEEN   │  │ WORKER   │  │  DRONE   │  │HONEYBEE  │       │
│  │  Slot 0  │  │  Slot 1  │  │  Slot 2  │  │  Slot 3  │       │
│  └──────────┘  └──────────┘  └──────────┘  └──────────┘       │
│                                                                 │
│  Ventajas:                                                      │
│    • Sin TCP → sin puertos abiertos                             │
│    • Sin sockets → invisible a netstat                         │
│    • Velocidad de RAM → ~50ns por mensaje                      │
│    • Fileless → no hay archivos de socket                       │
└─────────────────────────────────────────────────────────────────┘
```

### Protocolo LdC (Lenguaje de la Colmena)

| Tipo de mensaje | Campos | Ejemplo |
|-----------------|--------|---------|
| `Belief` | asset, value, confidence | `("edr_present", true, 0.95)` |
| `Desire` | action, priority | `("encrypt", 0.8)` |
| `Request` | command, args | `("scan", "192.168.1.0/24")` |
| `Query` | dilemma, context | `("should_move?", {...})` |
| `StatusEvent` | event_type, detail | `("kill_switch", "")` |

---

## Resumen de arquitectura

| Aspecto | Detalle |
|---------|---------|
| Lenguaje | Rust 1.70+ |
| IPC | Memoria compartida (shm_open / mmap) |
| Serialización | MessagePack (rmp-serde) |
| C2 | HTTP(S), DNS Tunnel, ICMP Tunnel, Dead Drop |
| Failover | Priority → Race → RoundRobin |
| Consenso | HiveMind (voting, 66% threshold) |
| ML | ONNX Random Forest + DQN (MARL) |
| Evasión | 10 capas (IPC fileless, syscalls, anti-debug, ...) |
| Target | Linux x86_64, Windows x86_64 (cross-compile) |
