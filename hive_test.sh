#!/bin/bash
# Hive Colony Test Harness — automated deploy + bug detection
# Usage: bash hive_test.sh

set -euo pipefail
cd "$(dirname "$0")"

GREEN='\033[0;32m' RED='\033[0;31m' CYAN='\033[0;36m' YELLOW='\033[1;33m' NC='\033[0m'
BUGS=0 FIXES=0

# ── Cleanup ───────────────────────────────────────────────────────────
cleanup() {
    echo -e "\n${CYAN}[cleanup] Stopping hive...${NC}"
    kill $WORKER_PID $DRONE_PID $HONEYBEE_PID $WEAVER_PID $C2_PID $DASH_PID 2>/dev/null
    fuser -k 8080/tcp 2>/dev/null || true; fuser -k 8445/tcp 2>/dev/null || true
    echo -e "${GREEN}Bugs found: $BUGS | Fixed: $FIXES${NC}"
    exit 0
}
trap cleanup INT TERM

# ── Clean ports ────────────────────────────────────────────────────────
fuser -k 8080/tcp 2>/dev/null || true; fuser -k 8445/tcp 2>/dev/null || true; sleep 1

# ── Generate shared arena ──────────────────────────────────────────────
ARENA_NAME="/hive_$(date +%s)_$(shuf -i 1000-9999 -n 1)"
export __HIVE_ARENA="$ARENA_NAME"

echo -e "${CYAN}╔══════════════════════════════════════════╗${NC}"
echo -e "${CYAN}║   HIVE COLONY TEST HARNESS v1.1         ║${NC}"
echo -e "${CYAN}║   Arena: $ARENA_NAME${NC}"
echo -e "${CYAN}╚══════════════════════════════════════════╝${NC}"
echo ""

# ── Phase 1: Launch infrastructure ─────────────────────────────────────
echo -e "${GREEN}[Phase 1] Infrastructure${NC}"

echo -n "  C2 Server :8445... "
python3 tests/c2_server.py --port 8445 --no-tls > /dev/null 2>&1 &
C2_PID=$!
sleep 2
if curl -s http://127.0.0.1:8445/health > /dev/null 2>&1; then
    echo -e "${GREEN}OK${NC}"
else
    echo -e "${RED}FAIL${NC}"; ((BUGS++))
fi

echo -n "  Dashboard :8080... "
python3 tests/dashboard.py --port 8080 > /dev/null 2>&1 &
DASH_PID=$!
sleep 2
if curl -s -o /dev/null -w "%{http_code}" http://127.0.0.1:8080/ | grep -q 200; then
    echo -e "${GREEN}OK${NC}"
else
    echo -e "${RED}FAIL${NC}"; ((BUGS++))
fi

# ── Phase 2: Launch colony agents ──────────────────────────────────────
echo -e "\n${GREEN}[Phase 2] Colony Agents${NC}"

echo -n "  Worker (arena creator)... "
target/debug/worker > /tmp/hive_worker.log 2>&1 &
WORKER_PID=$!
sleep 3
if kill -0 $WORKER_PID 2>/dev/null; then
    echo -e "${GREEN}OK (PID: $WORKER_PID)${NC}"
else
    echo -e "${RED}CRASHED${NC}"; ((BUGS++))
    tail -5 /tmp/hive_worker.log
fi

echo -n "  Drone (decision maker)... "
target/debug/drone > /tmp/hive_drone.log 2>&1 &
DRONE_PID=$!
sleep 2
if kill -0 $DRONE_PID 2>/dev/null; then
    echo -e "${GREEN}OK (PID: $DRONE_PID)${NC}"
else
    echo -e "${RED}CRASHED${NC}"; ((BUGS++))
    tail -5 /tmp/hive_drone.log
fi

echo -n "  Honeybee (executor)... "
target/debug/honeybee > /tmp/hive_honeybee.log 2>&1 &
HONEYBEE_PID=$!
sleep 2
if kill -0 $HONEYBEE_PID 2>/dev/null; then
    echo -e "${GREEN}OK (PID: $HONEYBEE_PID)${NC}"
else
    echo -e "${RED}CRASHED${NC}"; ((BUGS++))
    tail -5 /tmp/hive_honeybee.log
fi

echo -n "  Weaver (mutator)... "
target/debug/weaver > /tmp/hive_weaver.log 2>&1 &
WEAVER_PID=$!
sleep 2
if kill -0 $WEAVER_PID 2>/dev/null; then
    echo -e "${GREEN}OK (PID: $WEAVER_PID)${NC}"
else
    echo -e "${RED}CRASHED${NC}"; ((BUGS++))
    tail -5 /tmp/hive_weaver.log
fi

# ── Phase 3: Wait for communication ────────────────────────────────────
echo -e "\n${CYAN}[Phase 3] Waiting 20s for colony communication...${NC}"
sleep 20
echo -e "${GREEN}  Done — analyzing logs${NC}"

# ── Phase 4: Arena Verification ────────────────────────────────────────
echo -e "\n${GREEN}[Phase 4] Arena & Communication${NC}"

echo -n "  Agents connected to arena... "
ARENA_CONNS=$(grep -l "connected to shared-memory arena\|Hive.*active\|Hive.*starting" /tmp/hive_*.log 2>/dev/null | wc -l)
echo -e "${GREEN}${ARENA_CONNS}/4 agents${NC}"

echo -n "  Worker published beliefs... "
WORKER_BELIEFS=$(grep -c "Belief:" /tmp/hive_worker.log 2>/dev/null || echo 0)
echo -e "${GREEN}${WORKER_BELIEFS} published${NC}"

echo -n "  Honeybee received beliefs... "
HB_BELIEFS=$(grep -c "Belief:" /tmp/hive_honeybee.log 2>/dev/null || echo 0)
echo -e "${GREEN}${HB_BELIEFS} received${NC}"

echo -n "  Weaver received beliefs... "
WV_BELIEFS=$(grep -c "Belief:" /tmp/hive_weaver.log 2>/dev/null || echo 0)
echo -e "${GREEN}${WV_BELIEFS} received${NC}"

echo -n "  Drone received beliefs... "
DR_BELIEFS=$(grep -c "Belief" /tmp/hive_drone.log 2>/dev/null || echo 0)
echo -e "${GREEN}${DR_BELIEFS} received${NC}"

echo -n "  Weaver mutations... "
MUTATIONS=$(grep -c "Variant:" /tmp/hive_weaver.log 2>/dev/null || echo 0)
echo -e "${GREEN}${MUTATIONS} variants${NC}"

echo -n "  Drone regeneration activity... "
REGENS=$(grep -c "regenerat\|Fileless spawn" /tmp/hive_drone.log 2>/dev/null || echo 0)
echo -e "${GREEN}${REGENS} attempts${NC}"

# ── Phase 5: Dashboard & C2 Check ──────────────────────────────────────
echo -e "\n${GREEN}[Phase 5] External Interfaces${NC}"

echo -n "  Agent count in dashboard... "
AGENTS=$(curl -s http://127.0.0.1:8080/api/state 2>/dev/null | python3 -c "import json,sys; print(len(json.load(sys.stdin).get('agents',[])))" 2>/dev/null || echo "0")
echo -e "${GREEN}${AGENTS} agents visible${NC}"

echo -n "  C2 beacons received... "
BEACONS=$(curl -s http://127.0.0.1:8445/logs 2>/dev/null | python3 -c "import json,sys; print(len(json.load(sys.stdin).get('beacons',[])))" 2>/dev/null || echo "0")
echo -e "${GREEN}${BEACONS} beacons${NC}"

# ── Phase 6: Bug Summary ───────────────────────────────────────────────
echo -e "\n${CYAN}══════════════════════════════════════════${NC}"
echo -e "${CYAN}   BUG REPORT${NC}"
echo -e "${CYAN}══════════════════════════════════════════${NC}"

for agent in worker drone honeybee weaver; do
    log="/tmp/hive_${agent}.log"
    if grep -q "panicked\|SIGSEGV\|SIGABRT\|stack overflow" "$log" 2>/dev/null; then
        echo -e "${RED}  CRASH: $agent — $(grep 'panicked\|Error' $log | tail -1)${NC}"
        ((BUGS++))
    fi
done

# Check arena sharing (multiple agents on different slots)
SLOTS=$(grep -o "slot [0-9]\+" /tmp/hive_*.log 2>/dev/null | sort -u | wc -l)
if [ "$SLOTS" -ge 2 ]; then
    echo -e "${GREEN}  PASS: Multi-slot arena ($SLOTS slots, agents sharing)${NC}"
elif [ "$ARENA_CONNS" -ge 2 ]; then
    echo -e "${GREEN}  PASS: Agents sharing arena${NC}"
else
    echo -e "${YELLOW}  WARN: Only $ARENA_CONNS agent(s) connected${NC}"
fi

# Check cross-agent belief reception
if [ "$HB_BELIEFS" -gt 0 ] || [ "$WV_BELIEFS" -gt 0 ]; then
    echo -e "${GREEN}  PASS: Cross-agent belief propagation working${NC}"
elif [ "$WORKER_BELIEFS" -gt 0 ]; then
    echo -e "${YELLOW}  WARN: Worker published but others didn't receive${NC}"
    ((BUGS++))
fi

# Check fileless execution
if grep -q "Fileless spawn" /tmp/hive_drone.log 2>/dev/null; then
    echo -e "${GREEN}  PASS: Fileless regeneration working${NC}"
fi

# Final status
echo -e "\n${GREEN}Bugs: $BUGS | Agents alive: $(jobs -p | wc -l)${NC}"
echo -e "${CYAN}══════════════════════════════════════════${NC}"
echo ""
echo "Logs: /tmp/hive_*.log"
echo "Dashboard: http://localhost:8080"
echo "C2: http://localhost:8445/health"

# Keep running briefly for data collection
sleep 5
cleanup
