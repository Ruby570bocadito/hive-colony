# Hive Colony

```
                          .' '.
        _/__)           .       .
       (8|)_}}- .      .        .
        `\__)    '. . ' ' .  . '
    H I V E   C O L O N Y
```

**Multi-agent autonomous security assessment framework.**
Bee-inspired swarm architecture con agentes especializados, evasión por capas y C2 diverso.

[Documentation](docs/README.md) | [Operator Guide](docs/OPERATOR_GUIDE.md) | [MITRE Coverage](docs/MITRE_MAPPING.md) | [Evasion](docs/EVASION.md)

---

## Quick Start (3 pasos)

```bash
# 1. Entorno
source build_env.sh
pip install -r requirements.txt

# 2. Compilar
./hive.sh build

# 3. Ejecutar
./hive.sh dev      # Agentes en terminal (desarrollo)
./hive.sh all      # Stack completo (C2 + dashboard + agentes)
./hive.sh test     # Tests unitarios (+ integración)
./hive.sh e2e      # Test de integración end-to-end
./hive.sh status   # Ver agentes vivos
./hive.sh stop     # Matar todo
```

## Comandos

| Comando | Qué hace |
|---------|----------|
| `./hive.sh dev` | Lanza 6 agentes en terminal (Queen+Worker+Drone+Honeybee+Weaver+Swarm) |
| `./hive.sh all` | Stack completo: C2 + dashboard + 6 agentes |
| `./hive.sh docker` | Despliegue Docker Compose (colonia completa) |
| `./hive.sh test` | Ejecuta tests unitarios (319+) |
| `./hive.sh e2e` | Test end-to-end cross-agent |
| `./hive.sh status` | Muestra PIDs y memoria de agentes vivos |
| `./hive.sh stop` | Mata todos los procesos |
| `./hive.sh build` | Compila workspace completo |
| `./hive.sh build-win` | Cross-compile a Windows x86_64 |
| `./hive.sh build-android` | Cross-compile a Android aarch64 |
| `./hive.sh clean` | Limpia procesos + `cargo clean` |

## 6 Agent Types

| Agent | Rol | Capacidad |
|-------|-----|-----------|
| **Queen** | Overmind | Estrategia LLM (Ollama), bridge C2, HiveMind consensus, Seer predictivo |
| **Worker** | Scout | Reconocimiento, EDR detection (30+ firmas), ONNX classifier, Leech harvesting |
| **Drone** | Shaper | Movimiento lateral SSH, descubrimiento de red, regeneración fileless |
| **Honeybee** | Hoarder | Ejecución final: cifrado AES-256-GCM, wipe 3-pasada, exfiltración C2, privesc, cloud pivot |
| **Weaver** | Morph | Ofuscación polimórfica, 4 técnicas de mutación |
| **Swarm** | Worm | Auto-propagación SSH, selección de targets via MARL |

## Comunicación

### Interna (Arena)
```
Worker ──┐
Drone  ──┤── Arena compartida (shm_open / mmap) ── sin red, sin puertos
Honeybee─┤   16 slots lock-free, MessagePack, 8KB mensajes
Weaver ──┘
```

### Externa (C2)
```
Queen ─── HTTP(S) ─── C2 Server
       ─── DNS Tunnel ─── (txt records)
       ─── ICMP Tunnel ─── (raw socket)
       ─── Dead Drop ─── Gist / Pastebin / S3
Failover: Priority → Race → RoundRobin con backoff exponencial
```

## Evasion por Capas

| Capa | Técnica | Estado |
|------|---------|--------|
| 1 | IPC por memoria compartida (sin TCP) | ✅ |
| 2 | Fileless `memfd_create` / NtCreateSection | ✅ Linux + Windows |
| 3 | ASM syscalls directas (Hell's Gate / Halo's Gate) | ✅ Linux + Windows |
| 4 | Stack spoofing (ret-spoofing / RBP chain) | ✅ Linux + Windows |
| 5 | Anti-debug (PEB BeingDebugged, ptrace) | ✅ Linux + Windows |
| 6 | Anti-sandbox (USER/CPU/tiempo de actividad) | ✅ Linux + Windows |
| 7 | EDR detection (30+ firmas: Defender, CrowdStrike, SentinelOne...) | ✅ Windows |
| 8 | String obfuscation | ✅ |
| 9 | OPSEC: Jitter, DecoyProfile, ActivitySchedule, TrafficMimic | ✅ |
| 10 | Hibernación adaptativa + channel rotation | ✅ |

## Windows Support (D-2)

El framework cross-compila a Windows x86_64 con todos los módulos de evasión:

| Módulo | Capacidad |
|--------|-----------|
| `syscalls` | Hell's Gate + Halo's Gate + Hades Gate + indirect syscall |
| `hades_gate` | Resolución dinámica de SSN desde ntdll.dll en memoria |
| `stack_spoof` | Ret-spoofing con stack swap + RBP chain sintética |
| `fileless` | NtCreateSection + NtMapViewOfSection |
| `leech` | LSASS (syscalls directas), SAM, DPAPI |
| `anti_analysis` | PEB BeingDebugged, sandbox por USER/CPU |
| `system_info` | Toolhelp32Snapshot, GetAdaptersAddresses, GetSystemTimes |
| `runtime` | EDR detection (30+ firmas) |
| `phoenix` | Persistencia: Registry Run, Startup, SchTasks, WMI |
| `remote_shell` | Shell interactiva vía WebSocket (WS) |
| `cloud_worker` | Pivot a AWS / GCP / Azure / K8s |

```bash
./hive.sh build-win   # Cross-compile
# Requiere: mingw-w64 (apt install mingw-w64)
```

## MITRE ATT&CK

36+ técnicas en 10+ tácticas. [Ver mapeo completo](docs/MITRE_MAPPING.md).

## Arquitectura del proyecto

```
├── hive_base/            # Core: 65+ módulos Rust
│   ├── comms.rs          # HiveChamber (arena + opsec + failover + privesc + cloud + exec)
│   ├── c2_channels.rs    # HTTP/DNS/ICMP/DeadDrop + FailoverDirector
│   ├── opsec.rs          # Jitter, DecoyProfile, ActivitySchedule, TrafficMimic
│   ├── privesc.rs        # SUID, sudo, LD_PRELOAD, Docker, PwnKit, DirtyPipe, cron
│   ├── cloud_worker.rs   # AWS STS/EC2/S3/Lambda, GCP Compute/IAM/Functions, Azure VM/KeyVault
│   ├── remote_shell.rs   # Command-exec + WebSocket interactive shell
│   ├── syscalls.rs       # Hell's Gate + Halo's Gate (Windows) / raw asm (Linux)
│   ├── hades_gate.rs     # SSN desde ntdll.dll en memoria
│   ├── stack_spoof.rs    # Ret-spoofing (Windows) / RBP chain (Linux)
│   ├── fileless.rs       # memfd_create (Linux) / NtCreateSection (Windows)
│   ├── leech.rs          # Credential harvester (shadow, proc/mem, cloud, LSASS, SAM)
│   ├── anti_analysis.rs  # Debug/sandbox/VM detection
│   ├── phoenix.rs        # Persistencia Windows (4 métodos)
│   └── ...
├── agents/
│   ├── queen/            # Overmind: LLM + C2 bridge + HiveMind
│   ├── worker/           # Scout: percepción + ONNX
│   ├── drone/            # Shaper: decisiones + regeneración
│   ├── honeybee/         # Hoarder: ejecutor final + privesc + cloud
│   ├── weaver/           # Morph: mutación polimórfica
│   └── swarm/            # Worm auto-propagante
├── stinger/              # Dropper/payload inicial
├── beekeeper/            # Consola del operador
├── tests/                # C2 server + dashboard (Python) + EDR gauntlet
├── training/             # ML: datasets, RandomForest, DQN
├── docker-compose.yml    # Despliegue Docker (C2 + dashboard + 6 agentes + victim + monitor)
└── hive.sh               # CLI principal
```

## Docker Compose

```bash
docker compose up -d          # Iniciar colonia completa
docker compose logs -f        # Ver logs
docker compose down           # Detener todo

# Servicios:
#   c2-server  :8444 ─── C2 HTTP endpoint
#   dashboard  :8080 ─── Web dashboard
#   queen/worker/drone/honeybee/weaver/swarm ─── agentes
#   victim    ─── simulated target data
#   monitor   ─── detection watch
#   ollama    ─── LLM (perfil: llm, docker compose --profile llm up)
```

## Variables de Entorno

| Variable | Propósito | Default |
|----------|-----------|---------|
| `__HIVE_ARENA` | Ruta del archivo de arena IPC | `/dev/shm/hive_arena` |
| `HIVE_C2_URL` | Endpoint HTTP C2 | `https://c2:8444/collect` |
| `HIVE_C2_DNS_DOMAIN` | Dominio para DNS tunnel | `tunnel.example.com` |
| `HIVE_C2_ICMP_TARGET` | Target para ICMP tunnel | `8.8.8.8` |
| `HIVE_C2_DEAD_DROP_TOKEN` | Token para Dead Drop (Gist) | — |
| `HIVE_LAB_MODE` | Modo laboratorio (1=simulado) | `0` |
| `HIVE_TELEMETRY_DIR` | Directorio de telemetría | `/tmp/hive_telemetry` |
| `HIVE_EXEC_TIMEOUT` | Timeout por defecto para comandos (s) | `30` |
| `RUST_LOG` | Nivel de logging | `info` |

## Feature Flags

```bash
cargo build                           # Con ONNX (default)
cargo build --no-default-features     # Sin ONNX, compilación rápida
cargo build --target x86_64-pc-windows-gnu  # Windows cross-compile
```

## Requirements

- **Rust** 1.70+ (`rustup default stable`)
- **OpenSSL** dev (`apt install libssl-dev pkg-config`)
- **Python** 3.10+ con `flask`, `scikit-learn` (ver `requirements.txt`)
- **Linux** 3.17+ (kernel con `shm_open`)
- **Docker** (opcional, para colonia containerizada)
- **Opcional:** Ollama, nmap, mingw-w64

## Research Use

Este proyecto es exclusivamente para **investigación y educación** en ciberseguridad defensiva. No usar en sistemas sin autorización explícita por escrito.

## License

Research & educational use only.
