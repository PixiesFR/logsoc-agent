#!/bin/bash
# deploy_t30.sh — T30 (eBPF hardening: ringbuf loss, hot-reload, integrity) deploy
set -euo pipefail

HESTIA_IP="127.0.0.1"
SSH_USER="root"
PKG_LOCAL="$(pwd)/packaging/logsoc-agent_3.11.1-T30.1_amd64.deb"
PKG_REMOTE="/tmp/logsoc-agent_3.11.1-T30.1_amd64.deb"
B64_REMOTE="/tmp/d_t30.b64"

echo "=== T30 deploy ==="

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
ssh "$SSH_USER@$HESTIA_IP" "systemctl start logsoc-agent && sleep 4 && systemctl status logsoc-agent --no-pager | head -10"

echo "=== 5. T30.5 verify integrity file ==="
ssh "$SSH_USER@$HESTIA_IP" "ls -la /var/lib/logsoc-agent/install.sha256; cat /var/lib/logsoc-agent/install.sha256; echo; sha256sum /usr/bin/logsoc-agent | head -1" 2>&1

echo "=== 6. Verify heartbeat now reports ringbuf_lost/total/enabled_probes ==="
sleep 30
ssh "$SSH_USER@$HESTIA_IP" "Q=\"SELECT agent_id, JSONExtractString(raw_message, 'agent_id') as rid, JSONExtractString(raw_message, 'ringbuf_lost_events') as lost, JSONExtractString(raw_message, 'ringbuf_total_events') as total, JSONExtractString(raw_message, 'enabled_probes') as probes FROM logsoc.siem_logs WHERE event = 'agent_metrics' AND received_at > now() - INTERVAL 1 MINUTE ORDER BY received_at DESC LIMIT 2 FORMAT Vertical\"; echo \"\$Q\" | curl -s 'http://127.0.0.1:8123/' --data-binary @-" 2>&1 | head -20

echo "=== DONE ==="
