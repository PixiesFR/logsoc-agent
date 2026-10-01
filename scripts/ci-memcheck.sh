#!/usr/bin/env bash
# scripts/ci-memcheck.sh — T4.8.12 — Memory safety CI gate
#
# Runs ASan + valgrind on test_memcheck_sustained.
# Exits non-zero on ANY leak, UAF, buffer overrun, or UB.
#
# Usage:
#   bash scripts/ci-memcheck.sh                 # run all (default)
#   bash scripts/ci-memcheck.sh --asan-only      # skip valgrind (faster)
#   bash scripts/ci-memcheck.sh --valgrind-only  # skip ASan
#
# Pre-requisites:
#   - g++ >= 7 (C++17 support, -fsanitize=address)
#   - valgrind >= 3.16 (--show-leak-kinds=all)
#   - Run from src/ or with $SRCDIR pointing at it
#
# CI integration (Gitea Actions, GitLab CI, Jenkins):
#   steps:
#     - name: Memory safety
#       run: bash scripts/ci-memcheck.sh
#       working-directory: src

set -euo pipefail

# Repo root: one level up from this script (scripts/ is at the root).
REPOROOT="${REPOROOT:-$(cd "$(dirname "$0")/.." && pwd)}"
cd "$REPOROOT"

# Parse args
RUN_ASAN=1
RUN_VALGRIND=1
for arg in "$@"; do
    case "$arg" in
        --asan-only)     RUN_VALGRIND=0 ;;
        --valgrind-only) RUN_ASAN=0 ;;
        -h|--help)
            grep '^#' "$0" | sed 's/^# \?//'
            exit 0
            ;;
        *) echo "Unknown arg: $arg" >&2; exit 2 ;;
    esac
done

# Sanity checks
command -v g++ >/dev/null 2>&1 || { echo "g++ not found" >&2; exit 2; }
if [ "$RUN_VALGRIND" = "1" ]; then
    command -v valgrind >/dev/null 2>&1 || { echo "valgrind not found (apt-get install -y valgrind)" >&2; exit 2; }
fi

GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
NC='\033[0m'

PASS=0
FAIL=0

run_step() {
    local name="$1"
    local cmd="$2"
    echo -e "${YELLOW}--- $name ---${NC}"
    echo "+ $cmd"
    if eval "$cmd"; then
        echo -e "${GREEN}PASS: $name${NC}"
        PASS=$((PASS+1))
    else
        echo -e "${RED}FAIL: $name${NC}"
        FAIL=$((FAIL+1))
    fi
    echo
}

if [ "$RUN_ASAN" = "1" ]; then
    run_step "ASan (AddressSanitizer)" \
        "g++ -std=c++17 -O0 -g -Wall -pthread -Isrc/agent -fsanitize=address -fno-omit-frame-pointer -o /tmp/test_asan_sustained tests/test_memcheck_sustained.cpp src/agent/circuit_breaker.cpp src/agent/mitre_mapping.cpp src/agent/fd_resolver.cpp src/agent/fim_collector.cpp src/agent/fim_metrics.cpp && ASAN_OPTIONS=detect_leaks=1:abort_on_error=1 /tmp/test_asan_sustained"
fi

if [ "$RUN_VALGRIND" = "1" ]; then
    run_step "valgrind (leak + UB detection)" \
        "g++ -std=c++17 -O0 -g -Wall -pthread -Isrc/agent -o /tmp/test_memcheck_sustained tests/test_memcheck_sustained.cpp src/agent/circuit_breaker.cpp src/agent/mitre_mapping.cpp src/agent/fd_resolver.cpp src/agent/fim_collector.cpp src/agent/fim_metrics.cpp && valgrind --leak-check=full --show-leak-kinds=all --error-exitcode=1 --suppressions=tests/valgrind.supp /tmp/test_memcheck_sustained 2>&1 | tail -20"
fi

echo "============================================"
echo "Memory safety CI: $PASS passed, $FAIL failed"
echo "============================================"

[ "$FAIL" = "0" ] || exit 1
