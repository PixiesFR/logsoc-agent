#!/bin/bash
# deploy_t29.sh — T29 (ML triage / MITRE / Sigma) deploy on Hestia
set -euo pipefail

HESTIA_IP="127.0.0.1"
SSH_USER="root"
PKG_LOCAL="$(pwd)/packaging/logsoc-agent_3.10.0-T29_amd64.deb"
PKG_REMOTE="/tmp/logsoc-agent_3.10.0-T29_amd64.deb"
B64_REMOTE="/tmp/d_t29.b64"

echo "=== T29 deploy ==="

# 1. Upload via base64 chunks
echo "=== 1. Upload .deb ==="
B64=$(base64 -w0 "$PKG_LOCAL")
CHUNK_SIZE=60000
CHUNKS=()
for ((i=0; i<${#B64}; i+=CHUNK_SIZE)); do
    CHUNKS+=("${B64:i:CHUNK_SIZE}")
done
echo "  b64 size: ${#B64} chars, ${#CHUNKS[@]} chunks"

ssh "$SSH_USER@$HESTIA_IP" "rm -f $B64_REMOTE && touch $B64_REMOTE"
for i in "${!CHUNKS[@]}"; do
    ssh "$SSH_USER@$HESTIA_IP" "printf '%s' $(printf '%q' "${CHUNKS[$i]}") >> $B64_REMOTE"
    if [ $((i % 50)) -eq 0 ]; then
        echo "  sent chunk $((i+1))/${#CHUNKS[@]}"
    fi
done
ssh "$SSH_USER@$HESTIA_IP" "base64 -d $B64_REMOTE > $PKG_REMOTE && md5sum $PKG_REMOTE && ls -la $PKG_REMOTE"

# 2. Stop + install + start
echo "=== 2. Stop agent ==="
ssh "$SSH_USER@$HESTIA_IP" "systemctl is-active logsoc-agent && systemctl stop logsoc-agent || true"

echo "=== 3. dpkg -i ==="
ssh "$SSH_USER@$HESTIA_IP" "dpkg -i $PKG_REMOTE 2>&1 | tail -5"

echo "=== 4. Start agent ==="
ssh "$SSH_USER@$HESTIA_IP" "systemctl start logsoc-agent && sleep 4 && systemctl status logsoc-agent --no-pager | head -15"

echo "=== 5. Sanity ==="
ssh "$SSH_USER@$HESTIA_IP" "journalctl -u logsoc-agent --since '15 seconds ago' --no-pager | grep -E 'T29|MITRE|sigma|severity|ERROR|error|FATAL' | head -15"

echo "=== DONE ==="
echo "E2E check (run from any host):"
echo "  echo \"Q | curl -s 'http://127.0.0.1:8123/' --data-binary @-\""
echo "  Q = SELECT count(), severity FROM logsoc.siem_logs WHERE ts > now() - INTERVAL 5 MINUTE GROUP BY severity"
