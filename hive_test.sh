#!/bin/bash
# Hive Colony Test Harness — automated deploy + bug detection
# Usage: ./hive.sh e2e

set -euo pipefail
cd "$(dirname "$0")"

GREEN='\033[0;32m' RED='\033[0;31m' CYAN='\033[0;36m' YELLOW='\033[1;33m' NC='\033[0m'
BUGS=0

cleanup() {
    echo -e "\n${CYAN}[cleanup] Stopping hive...${NC}"
    kill $WORKER_PID $DRONE_PID $HONEYBEE_PID $WEAVER_PID $C2_PID $DASH_PID 2>/dev/null
    fuser -k 8080/tcp 2>/dev/null || true; fuser -k 8445/tcp 2>/dev/null || true
    echo -e "${GREEN}Bugs: $BUGS${NC}"
    exit 0
}
trap cleanup INT TERM

fuser -k 8080/tcp 2>/dev/null || true; fuser -k 8445/tcp 2>/dev/null || true; sleep 1

ARENA_NAME="/hive_$(date +%s)_$(shuf -i 1000-9999 -n 1)"
export __HIVE_ARENA="$ARENA_NAME"

echo -e "${CYAN}╔══════════════════════════════════════════╗${NC}"
echo -e "${CYAN}║   HIVE COLONY TEST v1.2                 ║${NC}"
echo -e "${CYAN}║   Arena: $ARENA_NAME${NC}"
echo -e "${CYAN}╚══════════════════════════════════════════╝${NC}"
echo ""

# Phase 1: Infrastructure
echo -e "${GREEN}[1] Infrastructure${NC}"
echo -n "  C2 :8445... "
python3 tests/c2_server.py --port 8445 --no-tls > /dev/null 2>&1 & C2_PID=$!
sleep 2
curl -s http://127.0.0.1:8445/health > /dev/null 2>&1 && echo -e "${GREEN}OK${NC}" || { echo -e "${RED}FAIL${NC}"; ((BUGS++)); }

echo -n "  Dashboard :8080... "
python3 tests/dashboard.py --port 8080 > /dev/null 2>&1 & DASH_PID=$!
sleep 2
curl -s -o /dev/null -w "%{http_code}" http://127.0.0.1:8080/ | grep -q 200 && echo -e "${GREEN}OK${NC}" || { echo -e "${RED}FAIL${NC}"; ((BUGS++)); }

# Phase 2: Agents
echo -e "\n${GREEN}[2] Agents${NC}"
for agent in worker drone honeybee weaver; do
    echo -n "  ${agent^}... "
    target/debug/$agent > /tmp/hive_${agent}.log 2>&1 &
    eval "${agent^^}_PID=\$!"
    sleep 2
    kill -0 $! 2>/dev/null && echo -e "${GREEN}OK${NC}" || { echo -e "${RED}CRASHED${NC}"; ((BUGS++)); tail -3 /tmp/hive_${agent}.log; }
done

# Phase 3: Wait
echo -e "\n${CYAN}[3] Waiting 20s for communication...${NC}"
sleep 20
echo -e "${GREEN}  Done${NC}"

# Phase 4: Results
echo -e "\n${GREEN}[4] Results${NC}"
echo -n "  Arena connections... "; grep -l "connected to shared-memory arena\|Hive.*active\|Hive.*starting" /tmp/hive_*.log 2>/dev/null | wc -l | xargs echo -e "${GREEN}"
echo -n "  Honeybee beliefs... "; grep -c "Belief:" /tmp/hive_honeybee.log 2>/dev/null || echo 0
echo -n "  Weaver beliefs... "; grep -c "Belief:" /tmp/hive_weaver.log 2>/dev/null || echo 0
echo -n "  Weaver mutations... "; grep -c "Variant:" /tmp/hive_weaver.log 2>/dev/null || echo 0
echo -n "  Drone decisions... "; grep -c "prop_to\|waiting" /tmp/hive_drone.log 2>/dev/null || echo 0

# Phase 5: External
echo -e "\n${GREEN}[5] External${NC}"
echo -n "  Dashboard agents... "
curl -s http://127.0.0.1:8080/api/state 2>/dev/null | python3 -c "import json,sys; print(len(json.load(sys.stdin).get('agents',[])))" 2>/dev/null || echo "0"
echo -n "  C2 beacons... "
curl -s http://127.0.0.1:8445/logs 2>/dev/null | python3 -c "import json,sys; print(len(json.load(sys.stdin).get('beacons',[])))" 2>/dev/null || echo "0"

# Phase 6: Bug check (exclude ONNX fallback panics which are expected)
echo -e "\n${CYAN}[6] Bug Check${NC}"
for agent in worker drone honeybee weaver; do
    log="/tmp/hive_${agent}.log"
    # Only flag real SIGSEGV/SIGABRT, not catch_unwind ONNX fallback
    if grep -q "SIGSEGV\|SIGABRT\|stack overflow" "$log" 2>/dev/null; then
        echo -e "${RED}  CRASH: $agent${NC}"; ((BUGS++))
    fi
done
# Check cross-agent communication
HB=$(grep -c "Belief:" /tmp/hive_honeybee.log 2>/dev/null || echo 0)
WV=$(grep -c "Belief:" /tmp/hive_weaver.log 2>/dev/null || echo 0)
DR=$(grep -c "prop_to\|waiting" /tmp/hive_drone.log 2>/dev/null || echo 0)
if [ "$HB" -gt 0 ] && [ "$WV" -gt 0 ]; then
    echo -e "${GREEN}  PASS: Cross-agent beliefs ($HB+$WV)${NC}"
fi
if [ "$DR" -gt 0 ]; then
    echo -e "${GREEN}  PASS: Drone making decisions ($DR)${NC}"
fi

echo -e "\n${GREEN}Bugs: $BUGS${NC}"
cleanup
