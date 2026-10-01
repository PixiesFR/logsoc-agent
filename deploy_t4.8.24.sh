#!/bin/bash
# deploy_t4.8.24.sh — T4.8.24 deploy on Hestia (127.0.0.1)
#
# Usage: bash deploy_t4.8.24.sh
# Run from /home/hermes/log-soc-ai/repo-agent/

set -euo pipefail

HESTIA_IP="127.0.0.1"
SSH_USER="${SSH_USER:-anytimeadmin}"
PKG_LOCAL="$(pwd)/releases/logsoc-agent_4.8.0-t4.8.24_amd64.deb"
PKG_REMOTE="/tmp/logsoc-agent_4.8.0-t4.8.24_amd64.deb"

echo "=== T4.8.24 deploy ==="
echo "  Local: $PKG_LOCAL"
echo "  Remote: $SSH_USER@$HESTIA_IP:$PKG_REMOTE"

if [ ! -f "$PKG_LOCAL" ]; then
    echo "ERROR: $PKG_LOCAL not found. Build with:"
    echo "  VERSION=4.8.0-t4.8.24 bash packaging/scripts/build-deb.sh"
    exit 1
fi

# 1. Upload via base64 (Hestia has no scp/sftp exposed in our session)
echo "=== 1. Upload .deb (base64 chunks) ==="
B64=$(base64 -w0 "$PKG_LOCAL")
CHUNK_SIZE=60000
CHUNKS=()
for ((i=0; i<${#B64}; i+=CHUNK_SIZE)); do
    CHUNKS+=("${B64:i:CHUNK_SIZE}")
done
echo "  b64 size: ${#B64} chars, ${#CHUNKS[@]} chunks"

ssh "$SSH_USER@$HESTIA_IP" "rm -f /tmp/d.b64 && touch /tmp/d.b64"
for i in "${!CHUNKS[@]}"; do
    # shlex.quote ne marche pas en bash pur, mais printf %s échappe le b64
    ssh "$SSH_USER@$HESTIA_IP" "printf '%s' $(printf '%q' "${CHUNKS[$i]}") >> /tmp/d.b64"
    if [ $((i % 50)) -eq 0 ]; then
        echo "  sent chunk $((i+1))/${#CHUNKS[@]}"
    fi
done

ssh "$SSH_USER@$HESTIA_IP" "base64 -d /tmp/d.b64 > $PKG_REMOTE && md5sum $PKG_REMOTE && ls -la $PKG_REMOTE"

# 2. Stop agent
echo "=== 2. Stop logsoc-agent ==="
ssh "$SSH_USER@$HESTIA_IP" "systemctl is-active logsoc-agent && systemctl stop logsoc-agent || true"

# 3. Install
echo "=== 3. Install .deb ==="
ssh "$SSH_USER@$HESTIA_IP" "dpkg -i $PKG_REMOTE"

# 4. Enable module_network in config
echo "=== 4. Enable module_network: true in /etc/logsoc-agent/config.json ==="
ssh "$SSH_USER@$HESTIA_IP" "python3 -c '
import json
with open(\"/etc/logsoc-agent/config.json\") as f:
    cfg = json.load(f)
cfg[\"module_network\"] = True
if \"network\" not in cfg:
    cfg[\"network\"] = {
        \"interfaces\": [\"eth0\"],
        \"bpf_filter\": \"\",
        \"snaplen\": 65535,
        \"buffer_mb\": 8,
        \"batch_interval_ms\": 5000,
        \"batch_max_events\": 1000,
        \"payload_preview_bytes\": 256
    }
with open(\"/etc/logsoc-agent/config.json\", \"w\") as f:
    json.dump(cfg, f, indent=2)
print(\"module_network:\", cfg[\"module_network\"])
'"

# 5. Start agent
echo "=== 5. Start logsoc-agent ==="
ssh "$SSH_USER@$HESTIA_IP" "systemctl start logsoc-agent && sleep 3 && systemctl status logsoc-agent --no-pager | head -15"

# 6. Quick sanity check
echo "=== 6. Verify network module is running ==="
ssh "$SSH_USER@$HESTIA_IP" "journalctl -u logsoc-agent --since '1 minute ago' --no-pager | grep -E 'NET|Detector|is_alert' | tail -10"

echo "=== DONE ==="
echo "Next: trigger an attack from another host and check ClickHouse:"
echo "  nmap -sS 127.0.0.1 -p 1-100"
echo "  echo 'password=hunter2' | nc 127.0.0.1 80"
echo "  echo 'curl -H \"Authorization: Bearer x\" http://127.0.0.1' && curl -H 'Authorization: Bearer x' http://127.0.0.1/"
