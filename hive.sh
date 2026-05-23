#!/bin/bash
# Hive Colony Control CLI
# Commands: dev | all | test | stop | status | build | clean
set -euo pipefail

# ── Paths ─────────────────────────────────────────────────────────────
export OPENSSL_DIR="${OPENSSL_DIR:-/usr}"
export OPENSSL_LIB_DIR="${OPENSSL_LIB_DIR:-/usr/lib/x86_64-linux-gnu}"
export OPENSSL_INCLUDE_DIR="${OPENSSL_INCLUDE_DIR:-/usr/include}"
cd "$(dirname "$0")"

ARENA_NAME="/hive_$(date +%s)_$$"
GREEN='\033[0;32m' CYAN='\033[0;36m' RED='\033[0;31m' YELLOW='\033[1;33m' NC='\033[0m' BOLD='\033[1m'

# ── Helpers ───────────────────────────────────────────────────────────
_clean() {
    pkill -f "dashboard.py\|c2_server.py" 2>/dev/null || true
    pkill -f "target/debug/" 2>/dev/null || true
    sleep 1
    rm -f /dev/shm/hive_*
}

_build() {
    echo -e "${GREEN}[build] Compiling...${NC}"
    cargo build "$@" 2>&1 | grep -E "Compiling|Finished|error" || true
}

_agents() {
    export __HIVE_ARENA="$ARENA_NAME"
    target/debug/worker > /tmp/hive_worker.log 2>&1 &
    target/debug/drone > /tmp/hive_drone.log 2>&1 &
    target/debug/honeybee > /tmp/hive_honeybee.log 2>&1 &
    target/debug/weaver > /tmp/hive_weaver.log 2>&1 &
}

# ── Commands ──────────────────────────────────────────────────────────
case "${1:-}" in
    # ── dev: solo agentes, sin C2, directo a terminal ─────────────────
    dev)
        _clean
        _build -p worker -p drone -p honeybee -p weaver
        echo -e "${CYAN}╔══════════════════════════╗${NC}"
        echo -e "${CYAN}║   HIVE DEV MODE          ║${NC}"
        echo -e "${CYAN}╚══════════════════════════╝${NC}"
        echo ""
        export __HIVE_ARENA="$ARENA_NAME"
        echo -e "${GREEN}Worker${NC}" && target/debug/worker 2>&1 &
        sleep 2
        echo -e "${GREEN}Drone${NC}"  && target/debug/drone 2>&1 &
        sleep 1
        echo -e "${GREEN}Honeybee${NC}" && target/debug/honeybee 2>&1 &
        sleep 1
        echo -e "${GREEN}Weaver${NC}" && target/debug/weaver 2>&1 &
        echo ""
        echo -e "${YELLOW}Agents running. Ctrl+C to stop.${NC}"
        wait
        ;;

    # ── all: stack completo (C2 + dashboard + agentes) ────────────────
    all)
        _clean
        _build
        echo -e "${CYAN}╔══════════════════════════════════════╗${NC}"
        echo -e "${CYAN}║   HIVE FULL STACK                    ║${NC}"
        echo -e "${CYAN}║   Dashboard: http://localhost:8080   ║${NC}"
        echo -e "${CYAN}║   C2 API:    http://localhost:8443   ║${NC}"
        echo -e "${CYAN}╚══════════════════════════════════════╝${NC}"
        echo ""
        python3 tests/c2_server.py --port 8445 --no-tls > /tmp/hive_c2.log 2>&1 &
        python3 tests/dashboard.py --port 8080 > /tmp/hive_dash.log 2>&1 &
        sleep 2
        export __HIVE_ARENA="$ARENA_NAME"
        _agents
        sleep 3
        echo -e "${GREEN}4 agents + C2 + dashboard running.${NC}"
        echo -e "${YELLOW}Ctrl+C to stop. ./hive.sh stop${NC}"
        wait
        ;;

    # ── test: ejecutar todos los tests ────────────────────────────────
    test)
        echo -e "${CYAN}Running tests...${NC}"
        export PATH="/tmp/pkgconf/usr/bin:${PATH:-}"
        export LD_LIBRARY_PATH="/tmp/pkgconf/usr/lib/x86_64-linux-gnu:${LD_LIBRARY_PATH:-}"
        cargo test --workspace 2>&1 | grep -E "test result|FAILED|running"
        echo -e "${GREEN}Done.${NC}"
        ;;

    # ── e2e: test end-to-end ──────────────────────────────────────────
    e2e)
        export PATH="/tmp/pkgconf/usr/bin:${PATH:-}"
        export LD_LIBRARY_PATH="/tmp/pkgconf/usr/lib/x86_64-linux-gnu:${LD_LIBRARY_PATH:-}"
        bash hive_test.sh
        ;;

    # ── stop: matar todo ──────────────────────────────────────────────
    stop)
        _clean
        echo -e "${GREEN}Hive stopped.${NC}"
        ;;

    # ── status: ver agentes vivos ─────────────────────────────────────
    status)
        printf "%-10s %-8s %s\n" "AGENT" "PID" "MEM"
        printf "%-10s %-8s %s\n" "----------" "--------" "----"
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
        ;;

    # ── build: compilar ───────────────────────────────────────────────
    build)
        _build "$@"
        ;;
    build-win)
        echo -e "${GREEN}[build] Cross-compiling for Windows x86_64...${NC}"
        echo -e "${YELLOW}NOTE: Requires mingw-w64 (run: bash setup_cross.sh win)${NC}"
        export CARGO_BUILD_TARGET="x86_64-pc-windows-gnu"
        cargo build --target x86_64-pc-windows-gnu --release 2>&1 | grep -E "Compiling|Finished|error" || true
        ls -lh target/x86_64-pc-windows-gnu/release/*.exe 2>/dev/null || echo "No Windows binaries built"
        unset CARGO_BUILD_TARGET
        ;;
    build-android)
        echo -e "${GREEN}[build] Cross-compiling for Android aarch64...${NC}"
        echo -e "${YELLOW}NOTE: Requires Android NDK (run: bash setup_cross.sh android)${NC}"
        export CARGO_BUILD_TARGET="aarch64-linux-android"
        cargo build --target aarch64-linux-android --release 2>&1 | grep -E "Compiling|Finished|error" || true
        ls -lh target/aarch64-linux-android/release/* 2>/dev/null || echo "No Android binaries built"
        unset CARGO_BUILD_TARGET
        ;;

    # ── clean: limpiar ────────────────────────────────────────────────
    clean)
        _clean
        cargo clean
        echo -e "${GREEN}Cleaned.${NC}"
        ;;

    # ── help ──────────────────────────────────────────────────────────
    *)
        echo -e "${CYAN}╔══════════════════════════════════════╗${NC}"
        echo -e "${CYAN}║   HIVE COLONY v3.0                   ║${NC}"
        echo -e "${CYAN}╚══════════════════════════════════════╝${NC}"
        echo ""
        echo -e "${BOLD}Quick Start:${NC}"
        echo "  source build_env.sh          # Set up environment"
        echo "  pip install -r requirements.txt  # Python deps"
        echo "  ./hive.sh build              # Compile"
        echo "  ./hive.sh dev                # Dev mode: agents only"
        echo "  ./hive.sh all                # Full stack: C2 + dashboard + agents"
        echo ""
        echo -e "${BOLD}Build commands:${NC}"
        echo "  ./hive.sh build              # Compile for Linux (native)"
        echo "  ./hive.sh build --release    # Release build (optimized, stripped)"
        echo "  ./hive.sh build-win          # Cross-compile for Windows x86_64"
        echo "  ./hive.sh build-android      # Cross-compile for Android aarch64"
        echo ""
        echo -e "${BOLD}Setup:${NC}"
        echo "  bash setup_cross.sh          # Install cross-compilation toolchains"
        echo ""
        echo -e "${BOLD}Commands:${NC}"
        echo "  dev     Launch 4 agents in terminal (safest)"
        echo "  all     Full stack: C2 + dashboard + agents"
        echo "  test    Run all tests"
        echo "  e2e     End-to-end integration test"
        echo "  stop    Kill all hive processes"
        echo "  status  Show running agents"
        echo "  clean   Kill processes + cargo clean"
        echo ""
        echo -e "${BOLD}After launching:${NC}"
        echo "  Dashboard: http://localhost:8080"
        echo "  C2 Health: http://localhost:8445/health"
        ;;
esac
