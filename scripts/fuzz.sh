#!/usr/bin/env bash
# scripts/fuzz.sh — T4.8.11 — libFuzzer harness runner
#
# Builds and runs the 2 libFuzzer harnesses added in T4.8.11:
#   - fuzz_yara_load_blob    : exercises YaraEngine::load_compiled_blob
#   - fuzz_policy_validation : exercises the policy JSON parser
#
# Usage:
#   bash scripts/fuzz.sh build       # compile both (clang++ required)
#   bash scripts/fuzz.sh yara        # 60s run on YARA blob fuzzer
#   bash scripts/fuzz.sh policy      # 60s run on policy JSON fuzzer
#   bash scripts/fuzz.sh all         # 60s run on both
#   bash scripts/fuzz.sh smoke       # 10s quick check (default 60s)
#
# Pre-requisites:
#   - clang++ (libFuzzer is a clang feature; g++ does NOT support -fsanitize=fuzzer)
#   - libyara, libpcap, libbpf, openssl headers installed
#   - Run from repo root

set -euo pipefail

REPOROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$REPOROOT"

# Args
TARGET="${1:-build}"
DURATION="${DURATION:-60}"
if [ "${2:-}" = "smoke" ]; then
    DURATION=10
fi

YARA_BIN=/tmp/fuzz_yara_load_blob
POLICY_BIN=/tmp/fuzz_policy_validation
YARA_CORPUS=/tmp/fuzz_yara_corpus
POLICY_CORPUS=/tmp/fuzz_policy_corpus

CXX=clang++
COMMON_FLAGS="-std=c++17 -O1 -g -Wall -fno-omit-frame-pointer -Isrc -Isrc/agent -Isrc/yara -fsanitize=address,fuzzer"
COMMON_LIBS="$(curl-config --libs 2>/dev/null) -lcrypto -lssl -lpcap -lbpf -lelf -lz -ldl -lsystemd -lyara"

# Sanity
command -v clang++ >/dev/null 2>&1 || { echo "clang++ not found (apt-get install -y clang)" >&2; exit 2; }
command -v pkg-config >/dev/null 2>&1 || true

build_yara() {
    echo "=== Building $YARA_BIN (clang++ -fsanitize=address,fuzzer) ==="
    $CXX $COMMON_FLAGS \
        tests/fuzz_yara_load_blob.cpp \
        src/yara/yara_engine.cpp src/agent_auth.cpp src/crypto.cpp \
        $COMMON_LIBS \
        -o "$YARA_BIN"
    ls -la "$YARA_BIN"
}

build_policy() {
    echo "=== Building $POLICY_BIN (clang++ -fsanitize=address,fuzzer) ==="
    $CXX $COMMON_FLAGS \
        tests/fuzz_policy_validation.cpp \
        $COMMON_LIBS \
        -o "$POLICY_BIN"
    ls -la "$POLICY_BIN"
}

run_yara() {
    mkdir -p "$YARA_CORPUS"
    echo "=== Running $YARA_BIN for ${DURATION}s (corpus: $YARA_CORPUS) ==="
    timeout $((DURATION + 5)) "$YARA_BIN" "$YARA_CORPUS" \
        -max_total_time="$DURATION" -max_len=1048576 -rss_limit_mb=2048 \
        2>&1 | tail -20
    echo ""
    echo "Corpus entries: $(ls "$YARA_CORPUS" | wc -l)"
    echo "Crashes: $(ls "$YARA_CORPUS" 2>/dev/null | grep -c '^crash-' || echo 0)"
    echo "Leaks: $(ls "$YARA_CORPUS" 2>/dev/null | grep -c '^leak-' || echo 0)"
}

run_policy() {
    mkdir -p "$POLICY_CORPUS"
    # Seed with 3 real-world policy responses
    cat > "$POLICY_CORPUS/wrapped.json" <<'EOF'
{"policy":{"metrics_bind_address":"0.0.0.0","fim_watch_paths":["/etc/passwd"],"ship_heuristic_threshold":3}}
EOF
    cat > "$POLICY_CORPUS/flat.json" <<'EOF'
{"metrics_bind_address":"127.0.0.1","fim_watch_paths":["/etc/ssh"],"ship_heuristic_threshold":5}}
EOF
    cat > "$POLICY_CORPUS/evil.json" <<'EOF'
{"metrics_bind_address":"not-an-ip","fim_watch_paths":["../../etc/passwd","","/a/../b"]}
EOF
    echo "=== Running $POLICY_BIN for ${DURATION}s (corpus: $POLICY_CORPUS) ==="
    timeout $((DURATION + 5)) "$POLICY_BIN" "$POLICY_CORPUS" \
        -max_total_time="$DURATION" -max_len=4096 -rss_limit_mb=1024 \
        2>&1 | tail -20
    echo ""
    echo "Corpus entries: $(ls "$POLICY_CORPUS" | wc -l)"
    echo "Crashes: $(ls "$POLICY_CORPUS" 2>/dev/null | grep -c '^crash-' || echo 0)"
    echo "Leaks: $(ls "$POLICY_CORPUS" 2>/dev/null | grep -c '^leak-' || echo 0)"
}

case "$TARGET" in
    build)   build_yara; build_policy ;;
    yara)    [ -x "$YARA_BIN" ] || build_yara; run_yara ;;
    policy)  [ -x "$POLICY_BIN" ] || build_policy; run_policy ;;
    all)     [ -x "$YARA_BIN" ] || build_yara; [ -x "$POLICY_BIN" ] || build_policy
             run_yara; echo "---"; run_policy ;;
    smoke)   DURATION=10; "${0}" all ;;
    *)       echo "Usage: $0 {build|yara|policy|all|smoke} [DURATION_SECONDS]" >&2
             exit 1 ;;
esac
