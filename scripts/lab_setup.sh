#!/usr/bin/env bash
# Hive Colony v3.0 — Laboratorio de verificación
# Prepara infraestructura: targets SSH, Ollama, claves, red
set -euo pipefail

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; CYAN='\033[0;36m'; NC='\033[0m'
info()  { echo -e "${CYAN}[*]${NC} $*"; }
ok()    { echo -e "  ${GREEN}✓${NC} $*"; }
warn()  { echo -e "  ${YELLOW}⚠${NC} $*"; }
fail()  { echo -e "  ${RED}✗${NC} $*"; }

LAB_DIR="$(dirname "$0")/../docker/lab"
HIVE_BIN="target/release"
COMPOSE="docker compose -f ${LAB_DIR}/docker-compose.lab.yml"

# Verificar Docker
if ! command -v docker &>/dev/null; then
    fail "Docker no instalado"
    exit 1
fi

# 1. Generar claves SSH para el laboratorio
info "Paso 1: Generando claves SSH para propagación..."
mkdir -p /tmp/hive_lab_keys
if [ ! -f /tmp/hive_lab_keys/id_ed25519 ]; then
    ssh-keygen -t ed25519 -f /tmp/hive_lab_keys/id_ed25519 -N "" -q
    ok "Clave SSH generada: /tmp/hive_lab_keys/id_ed25519"
else
    ok "Clave SSH ya existe"
fi

# 2. Configurar authorized_keys en los targets
info "Paso 2: Preparando authorized_keys..."
PUBKEY=$(cat /tmp/hive_lab_keys/id_ed25519.pub)
# Inyectar public key en el Dockerfile temporalmente
sed "s|lab-test-key|${PUBKEY}|g" "${LAB_DIR}/Dockerfile.ssh-target" > /tmp/hive_lab_keys/Dockerfile.ssh-target.patched
ok "Public key inyectada en Dockerfile"

# 3. Construir imágenes
info "Paso 3: Construyendo imágenes Docker..."
# Build base image first (hive agents)
if ! docker image inspect hive-colony:latest &>/dev/null; then
    info "  Construyendo imagen base hive-colony..."
    docker build -t hive-colony:latest -f Dockerfile .
    ok "Imagen hive-colony construida"
else
    ok "Imagen hive-colony ya existe"
fi

# Build SSH target images
for target in target-web target-db target-backup; do
    info "  Construyendo ${target}..."
    docker build -t "hive-${target}:latest" -f /tmp/hive_lab_keys/Dockerfile.ssh-target.patched .
    ok "Imagen hive-${target} construida"
done

# 4. Verificar binarios compilados
info "Paso 4: Verificando binarios..."
for bin in c2-server queen worker drone honeybee weaver swarm; do
    if [ ! -f "${HIVE_BIN}/${bin}" ]; then
        fail "Binario faltante: ${HIVE_BIN}/${bin}"
        info "Ejecutá: cargo build --release --workspace --exclude stinger"
        exit 1
    fi
done
ok "Todos los binarios listos"

# 5. Copiar clave privada donde los agentes puedan harvestearla
info "Paso 5: Instalando clave SSH para harvesting..."
mkdir -p ~/.ssh
cp /tmp/hive_lab_keys/id_ed25519 ~/.ssh/id_ed25519 2>/dev/null || true
cp /tmp/hive_lab_keys/id_ed25519.pub ~/.ssh/id_ed25519.pub 2>/dev/null || true
chmod 600 ~/.ssh/id_ed25519 2>/dev/null || true

# También ponerla en /root/.ssh para que Leech la encuentre
sudo mkdir -p /root/.ssh 2>/dev/null || true
sudo cp /tmp/hive_lab_keys/id_ed25519 /root/.ssh/ 2>/dev/null || true
sudo chmod 600 /root/.ssh/id_ed25519 2>/dev/null || true
ok "Clave instalada para harvesting (~/.ssh/ y /root/.ssh/)"

# 6. Iniciar la red de laboratorio
info "Paso 6: Iniciando laboratorio..."
${COMPOSE} up -d target-web target-db target-backup c2-server arena ollama 2>&1 | tail -3
ok "Servicios de laboratorio iniciados"

# 7. Esperar a que los targets SSH estén listos
info "Paso 7: Esperando targets SSH..."
for target in hive-target-web hive-target-db hive-target-backup; do
    for i in $(seq 1 15); do
        if docker exec "$target" nc -z 127.0.0.1 22 2>/dev/null; then
            ok "${target} SSH listo"
            break
        fi
        if [ "$i" -eq 15 ]; then
            fail "${target} no responde"
        fi
        sleep 1
    done
done

# 8. Verificar conectividad SSH
info "Paso 8: Verificando SSH desde el host..."
for target in hive-target-web hive-target-db hive-target-backup; do
    IP=$(docker inspect -f '{{range.NetworkSettings.Networks}}{{.IPAddress}}{{end}}' "$target" 2>/dev/null)
    if ssh -o StrictHostKeyChecking=no -o ConnectTimeout=3 -o BatchMode=yes \
           -i /tmp/hive_lab_keys/id_ed25519 "root@${IP}" "hostname" 2>/dev/null; then
        ok "SSH a ${target} (${IP}) funciona"
    else
        warn "SSH a ${target} (${IP}) falló — puede requerir password"
        # Fallback: intentar con password
        if sshpass -p toor ssh -o StrictHostKeyChecking=no -o ConnectTimeout=3 \
                   "root@${IP}" "hostname" 2>/dev/null; then
            ok "SSH password a ${target} (${IP}) funciona"
        fi
    fi
done

# 9. Verificar Ollama
info "Paso 9: Verificando Ollama..."
OLLAMA_IP=$(docker inspect -f '{{range.NetworkSettings.Networks}}{{.IPAddress}}{{end}}' hive-ollama 2>/dev/null)
for i in $(seq 1 20); do
    if curl -sf "http://${OLLAMA_IP}:11434/api/tags" > /dev/null 2>&1; then
        ok "Ollama listo en ${OLLAMA_IP}:11434"
        # Pull tinyllama
        docker exec hive-ollama ollama pull tinyllama 2>/dev/null &
        ok "Descargando modelo tinyllama (background)..."
        break
    fi
    sleep 3
done

# 10. Resumen
echo ""
echo "╔══════════════════════════════════════════════╗"
echo "║   LABORATORIO LISTO                          ║"
echo "╠══════════════════════════════════════════════╣"
echo "║  Targets SSH:                               ║"
for target in hive-target-web hive-target-db hive-target-backup; do
    IP=$(docker inspect -f '{{range.NetworkSettings.Networks}}{{.IPAddress}}{{end}}' "$target" 2>/dev/null)
    echo "║    ${target}: ${IP}:22"
done
echo "║                                              ║"
echo "║  Ollama:   http://${OLLAMA_IP}:11434         ║"
echo "║  C2:       http://localhost:8444             ║"
echo "║  Arena:    hive_arena:/dev/shm               ║"
echo "║                                              ║"
echo "║  Para desplegar colonia:                     ║"
echo "║    docker compose -f ${LAB_DIR}/docker-compose.lab.yml up -d   ║"
echo "║                                              ║"
echo "║  Para probar propagación:                    ║"
echo "║    ./scripts/test_ssh_propagation.sh          ║"
echo "╚══════════════════════════════════════════════╝"
