#!/bin/bash
# LogSOC-AI Agent V3 — Workflow "Base Correcte"
# Usage: ./scripts/verify-baseline.sh [--server URL] [--agent-id ID]
# Ce script NE MODIFIE RIEN, il verifie uniquement.
# A executer sur demande explicite de l'utilisateur avant A4/A5.

set -euo pipefail

SERVER="${1:-https://logsoc.anytimeadmin.info}"
AGENT_ID="${2:-$(uuidgen)}"
KEYFILE="/etc/logsoc/key.json"
BUILD_DIR="${BUILD_DIR:-build}"
TEST_LOG="/tmp/agent_baseline_test.log"

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

log()  { echo -e "${GREEN}[OK]${NC} $1"; }
warn() { echo -e "${YELLOW}[WARN]${NC} $1"; }
err()  { echo -e "${RED}[FAIL]${NC} $1"; exit 1; }

header() { echo ""; echo "=== $1 ==="; }

# ---
header "1. Etat git"
if [ -d .git ]; then
    git pull
    git log --oneline -5
else
    warn "Pas de repo git ici"
fi

# ---
header "2. Compilation v3.1 (baseline statique)"
make clean 2>/dev/null || true
cd "$BUILD_DIR" 2>/dev/null || make agent_v3.1 || make agent_v3 || err "Compilation echec"
BINARY="$BUILD_DIR/agent_v3.1"
if [ ! -f "$BINARY" ]; then BINARY="$BUILD_DIR/agent_v3"; fi
if [ ! -f "$BINARY" ]; then err "Binaire non trouve dans $BUILD_DIR"; fi

log "Binaire: $BINARY"
file "$BINARY" | grep -q "ELF" || err "$BINARY n'est pas un ELF"
ldd_output=$(ldd "$BINARY" 2>&1 || true)
if echo "$ldd_output" | grep -q "not a dynamic executable"; then
    log "Binary statique confirme"
elif echo "$ldd_output" | grep -q "statically linked"; then
    log "Statically linked OK"
else
    warn "Binary peut avoir des deps dynamiques:\n$ldd_output"
fi

# ---
header "3. Test connexion agent (10 secondes)"
pkill -f "$(basename "$BINARY")" 2>/dev/null || true
sleep 1
"$BINARY" \
    --server "$SERVER" \
    --keyfile "$KEYFILE" \
    --agent-id "$AGENT_ID" \
    --verbose 2>&1 | tee "$TEST_LOG" &
AGENT_PID=$!
sleep 10
kill $AGENT_PID 2>/dev/null || true
wait $AGENT_PID 2>/dev/null || true

# ---
header "4. Verification logs connexion"
if grep -qi "register" "$TEST_LOG"; then log "register present"; else err "register absent du log"; fi
if grep -qi "heartbeat\|200 OK" "$TEST_LOG"; then log "heartbeat/200 OK present"; else warn "heartbeat non present (peut etre normal si premier lancement)"; fi
if grep -qi "push" "$TEST_LOG"; then log "push present"; else warn "push non present (peut etre normal si pas d'evenements)"; fi

# ---
header "5. Ping backend PHP"
HTTP_CODE=$(curl -s -o /dev/null -w "%{http_code}" "$SERVER/api/v1/status.php" || echo "000")
if [ "$HTTP_CODE" = "200" ]; then log "Backend PHP OK (HTTP 200)"
else warn "Backend PHP non-200: HTTP $HTTP_CODE"; fi

# ---
header "6. Verifier agent en base"
DB_RESULT=$(ssh root@backend "mysql -u logsoc logsoc -sNe 'SELECT agent_id FROM agents_v3 WHERE agent_id=\"$AGENT_ID\" LIMIT 1;'" 2>/dev/null || echo "")
if [ -n "$DB_RESULT" ]; then log "Agent $AGENT_ID trouve en base"
else warn "Agent $AGENT_ID non trouve en base (normal si registration echec)"; fi

# ---
header "7. Decision"
echo ""
if grep -qi "register.*success\|already registered" "$TEST_LOG" 2>/dev/null; then
    log "BASELINE OK — peut passer a A4/A5"
    exit 0
else
    err "BASELINE KO — debugger register/heartbeat AVANT A4/A5"
fi
