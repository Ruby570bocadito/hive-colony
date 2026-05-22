# Hive Colony v3.0

```
                          .' '.
        _/__)           .       .
       (8|)_}}- .      .        .
        `\__)    '. . ' ' .  . '
    H I V E   C O L O N Y
```

**Bee-inspired multi-agent autonomous Red Team framework.**

[Documentation](docs/README.md) | [Naming Map](docs/NAMING.md) | [Operator Guide](docs/OPERATOR_GUIDE.md) | [MITRE Coverage](docs/MITRE_MAPPING.md)

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
./hive.sh test     # 80 tests unitarios
./hive.sh e2e      # Test de integración end-to-end
./hive.sh status   # Ver agentes vivos
./hive.sh stop     # Matar todo
```

## Comandos

| Comando | Qué hace |
|---------|----------|
| `./hive.sh dev` | Lanza 4 agentes en la terminal (Worker+Drone+Honeybee+Weaver) |
| `./hive.sh all` | Stack completo: C2 + dashboard + 4 agentes |
| `./hive.sh test` | Ejecuta todos los tests (80 unitarios + integración) |
| `./hive.sh e2e` | Test end-to-end con verificación cross-agent |
| `./hive.sh status` | Muestra PIDs y memoria de agentes vivos |
| `./hive.sh stop` | Mata todos los procesos |
| `./hive.sh build` | Compila el workspace completo |
| `./hive.sh clean` | Limpia procesos + `cargo clean` |

## 6 Agent Types

| Agent | Rol | Capacidad |
|-------|-----|-----------|
| **Worker** | Reconocimiento | Detección de EDR (8 vendors), escaneo de procesos, ONNX classifier |
| **Drone** | Decisión | Movimiento lateral SSH, descubrimiento de red, regeneración fileless |
| **Honeybee** | Ejecución | Cifrado AES-256-GCM, wipe 3 pasadas, exfiltración C2 |
| **Weaver** | Ofuscación | 4 técnicas de mutación, variantes polimórficas |
| **Queen** | Estrategia | LLM local (Ollama), bridge C2, directivas Royal Jelly |
| **Swarm** | Autónomo | Auto-propagación SSH, selección de targets via MARL |

## Comunicación

```
Worker ──┐
Drone  ──┤── Arena compartida (shm_open/mmap) ── sin red, sin puertos
Honeybee─┤   16 slots lock-free, MessagePack, 8KB mensajes
Weaver ──┘
```

## 10-Layer Evasion

1. IPC por memoria compartida (sin TCP) · 2. Fileless `memfd_create` / `/dev/shm` · 3. ASM syscalls directas · 4. Stack spoofing · 5. Modelos ONNX cifrados · 6. Anti-debug · 7. Anti-sandbox · 8. Anti-VM · 9. String obfuscation · 10. Honey detection

## MITRE ATT&CK

36 técnicas en 10 tácticas. [Ver mapeo completo](docs/MITRE_MAPPING.md).

## Arquitectura del proyecto

```
├── hive_base/          # Core: 45 módulos Rust (comms, crypto, evasión, ML)
├── agents/
│   ├── worker/         # Scout: percepción + ONNX
│   ├── drone/          # Shaper: decisiones + regeneración
│   ├── honeybee/       # Hoarder: ejecutor final
│   ├── weaver/         # Weaver: mutación polimórfica
│   ├── queen/          # Overmind: LLM + C2 bridge
│   └── swarm/          # Worm auto-propagante
├── stinger/            # Dropper/payload inicial
├── beekeeper/          # Consola del operador
├── buzz/               # Despliegue rápido
├── tests/              # C2 server + dashboard (Python) + EDR gauntlet
├── training/           # ML: datasets, RandomForest, DQN, fine-tuning
├── docs/               # Documentación de diseño + naming map
├── hive.sh             # CLI principal
└── hive_test.sh        # Test harness end-to-end
```

## Feature Flags

```bash
cargo build                    # Con ONNX (default)
cargo build --no-default-features  # Sin ONNX, compilación rápida
```

## Requirements

- **Rust** 1.70+ (`rustup default stable`)
- **OpenSSL** dev (`apt install libssl-dev pkg-config`)
- **Python** 3.10+ con `flask`, `scikit-learn` (ver `requirements.txt`)
- **Linux** 3.17+ (kernel con `shm_open`)
- **Opcional:** Ollama para LLM local, nmap para escaneo

## Research Use

Este proyecto es exclusivamente para **investigación y educación** en ciberseguridad defensiva. No usar en sistemas sin autorización explícita por escrito.

## License

Research & educational use only. See `docs/` for full documentation.
