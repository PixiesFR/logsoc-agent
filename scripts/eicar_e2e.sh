#!/bin/bash
# eicar_e2e.sh — T4.8.26 — One-command EICAR E2E test for LogSOC Agent
#
# Validates the full prod pipeline: write EICAR → eBPF/Fanotify capture →
# YARA match → ship → ClickHouse row. Takes ~60s.
#
# What it does (in order):
#   1. Backup current /etc/logsoc-agent/config.json + agent_policy row
#   2. Patch CENTRAL POLICY (agent_policy table in MariaDB):
#        - add /tmp/eicar_test/ to fim_watch_paths
#      (agent pulls the central policy every 5min, or we restart to force)
#   3. Patch LOCAL CONFIG:
#        - remove /tmp/ from ebpf.open.ignore_paths
#        - remove /tmp/ from ebpf.unlink.ignore_paths
#      (the eBPF probe fires BEFORE the central watch_paths check, so we
#       need to remove the /tmp/ filter locally)
#   4. Restart logsoc-agent (forces central policy re-pull + new config)
#   5. Wait 15s for boot
#   6. mkdir + echo -n $EICAR > /tmp/eicar_test/eicar.com
#      (NOTE: `touch` does NOT trigger vfs_write kprobe; we need `echo -n`)
#   7. Wait 45s for: eBPF kprobe + FimPoller poll + YARA scan + ship + CH insert
#   8. Query ClickHouse for the match
#   9. ALWAYS restore (config + DB row) on exit (trap)
#
# Run as root on Hestia: bash eicar_e2e.sh
#
# Exit codes:
#   0 = EICAR found in ClickHouse (PASS)
#   1 = EICAR NOT found (FAIL)
#   2 = script error (cannot reach backend / clickhouse / mariadb)
#
# REQUIREMENTS:
#   - root access (systemctl + config write)
#   - python3 with pymysql on Hestia (for the DB push)
#   - MariaDB credentials in /etc/logsoc/api.env (MYSQL_PASSWORD=...)
#   - ClickHouse accessible on 127.0.0.1:8123

set -uo pipefail

HESTIA_IP="127.0.0.1"
AGENT_ID="48048de6-e542-43cb-b30b-c274fc1f7804"
CONFIG="/etc/logsoc-agent/config.json"
BACKUP_CFG="/tmp/config.json.eicar-backup-$$"
BACKUP_POL="/tmp/agent_policy.eicar-backup-$$"
EICAR='X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*'
TEST_DIR="/tmp/eicar_test"
TEST_FILE="$TEST_DIR/eicar.com"
EICAR_PATH_FOR_POLICY="/tmp/eicar_test/"

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

cleanup() {
    echo ""
    echo -e "${YELLOW}=== Restoring (config + central policy) ===${NC}"
    # Restore DB row
    if [ -f "$BACKUP_POL" ]; then
        python3 - "$BACKUP_POL" <<'PYEOF'
import sys, json, pymysql
backup = json.load(open(sys.argv[1]))
# Read pwd from api.env
env = open("/etc/logsoc/api.env").read()
pwd_line = [l for l in env.splitlines() if l.startswith("MYSQL_PASSWORD=")][0]
pwd = pwd_line.split("=", 1)[1]
conn = pymysql.connect(host="127.0.0.1", port=3306, user="anytimeadmin_logsoc",
                       password=pwd, database="anytimeadmin_logsoc", connect_timeout=5)
cur = conn.cursor()
cur.execute("UPDATE agent_policy SET fim_watch_paths=%s, updated_at=NOW() WHERE agent_id=%s",
            (backup["fim_watch_paths"], backup["agent_id"]))
conn.commit()
conn.close()
print(f"  agent_policy row restored (agent_id={backup['agent_id']})")
PYEOF
        rm -f "$BACKUP_POL"
    fi
    # Restore config
    if [ -f "$BACKUP_CFG" ]; then
        cp "$BACKUP_CFG" "$CONFIG"
        rm -f "$BACKUP_CFG"
        systemctl start logsoc-agent 2>/dev/null || true
        echo "  config restored"
    fi
    # Clean up test artifacts
    rm -rf "$TEST_DIR" 2>/dev/null || true
}
trap cleanup EXIT INT TERM

echo "=== T4.8.26 EICAR E2E test ==="
echo ""

# 1. Pre-flight
if [ "$(id -u)" -ne 0 ]; then
    echo -e "${RED}Must run as root (need systemctl + config write)${NC}"
    exit 2
fi
if [ ! -f "$CONFIG" ]; then
    echo -e "${RED}Config not found: $CONFIG${NC}"
    exit 2
fi
if ! python3 -c "import pymysql" 2>/dev/null; then
    echo -e "${RED}python3-pymysql not installed. Run: apt-get install -y python3-pymysql${NC}"
    exit 2
fi

# 2. Backup local config
echo "[1/8] Backing up local config to $BACKUP_CFG"
cp "$CONFIG" "$BACKUP_CFG"

# 3. Backup + patch CENTRAL POLICY (DB)
echo "[2/8] Pushing /tmp/eicar_test/ to central agent_policy table"
python3 - "$AGENT_ID" "$BACKUP_POL" "$EICAR_PATH_FOR_POLICY" <<'PYEOF'
import sys, json, pymysql
agent_id, backup_path, new_path = sys.argv[1], sys.argv[2], sys.argv[3]
env = open("/etc/logsoc/api.env").read()
pwd_line = [l for l in env.splitlines() if l.startswith("MYSQL_PASSWORD=")][0]
pwd = pwd_line.split("=", 1)[1]
conn = pymysql.connect(host="127.0.0.1", port=3306, user="anytimeadmin_logsoc",
                       password=pwd, database="anytimeadmin_logsoc", connect_timeout=5)
cur = conn.cursor()
cur.execute("SELECT fim_watch_paths FROM agent_policy WHERE agent_id=%s", (agent_id,))
row = cur.fetchone()
if not row:
    print(f"  ERROR: no agent_policy row for agent_id={agent_id}")
    sys.exit(1)
original = row[0]
with open(backup_path, "w") as f:
    json.dump({"agent_id": agent_id, "fim_watch_paths": original}, f)
paths = [p.strip() for p in original.split("\n") if p.strip()]
if new_path not in paths:
    paths.append(new_path)
new_value = "\n".join(paths)
cur.execute("UPDATE agent_policy SET fim_watch_paths=%s, updated_at=NOW() WHERE agent_id=%s",
            (new_value, agent_id))
conn.commit()
print(f"  fim_watch_paths: {len(paths)} paths (added {new_path})")
conn.close()
PYEOF

# 4. Patch LOCAL CONFIG: remove /tmp/ from open/unlink ignore_paths
echo "[3/8] Patching local config (remove /tmp/ from open/unlink ignore_paths)"
python3 <<EOF
import json
with open("$CONFIG") as f:
    cfg = json.load(f)
eb = cfg.setdefault("ebpf", {})
for kind in ("open", "unlink"):
    sub = eb.setdefault(kind, {})
    ig = sub.get("ignore_paths", [])
    new_ig = [p for p in ig if p not in ("/tmp/", "/tmp")]
    if len(new_ig) != len(ig):
        sub["ignore_paths"] = new_ig
        print(f"  ebpf.{kind}.ignore_paths: {ig} -> {new_ig}")
with open("$CONFIG", "w") as f:
    json.dump(cfg, f, indent=2)
EOF

# 5. Restart agent (forces central re-pull + new config)
echo "[4/8] Restarting logsoc-agent"
pkill -9 -f 'logsoc-agent /etc' 2>/dev/null
sleep 2
systemctl start logsoc-agent
# Agent takes 8-15s to fully boot (YARA load, Fanotify init, eBPF attach, central pull)
sleep 15

# 6. Verify
echo "[5/8] Verifying agent is up + watching /tmp/eicar_test"
PID=$(pgrep -f 'logsoc-agent /etc' | head -1)
if [ -z "$PID" ]; then
    echo -e "${RED}Agent failed to start! Last journal lines:${NC}"
    journalctl -u logsoc-agent --since '30 seconds ago' --no-pager 2>&1 | tail -20
    exit 2
fi
echo "  agent PID: $PID"
journalctl -u logsoc-agent --since '20 seconds ago' --no-pager 2>&1 | \
    grep -iE 'FimPoller|watch_paths|polic.*pull|/tmp/eicar' | head -8

# 7. Write EICAR
echo "[6/8] Writing EICAR to $TEST_FILE (echo -n, NOT touch)"
mkdir -p "$TEST_DIR"
echo -n "$EICAR" > "$TEST_FILE"
ls -la "$TEST_FILE"

# 8. Wait for full pipeline
echo "[7/8] Waiting 45s for pipeline (eBPF → FIM → YARA → ship → ClickHouse)"
sleep 45

# 9. Query ClickHouse (only events from THIS run, i.e. after $BACKUP_CFG mtime)
# Use the backup file's mtime as the "since" timestamp to avoid false positives
# from historical EICAR tests in the DB.
echo "[8/8] Querying ClickHouse for EICAR match (since script start)"
SINCE_TS=$(date -u -d "@$(stat -c %Y "$BACKUP_CFG")" '+%Y-%m-%d %H:%M:%S')
echo "  since: $SINCE_TS"
QUERY="SELECT count(), min(received_at), max(received_at) FROM logsoc.siem_logs WHERE event='fim' AND filename LIKE '%eicar%' AND received_at >= toDateTime('$SINCE_TS') FORMAT TabSeparated"
RESULT=$(echo "$QUERY" | curl -s --max-time 10 --data-binary @- "http://$HESTIA_IP:8123/" 2>&1)
echo "  ClickHouse response: $RESULT"

# 10. Verdict
if echo "$RESULT" | grep -qE '^[0-9]+\s'; then
    COUNT=$(echo "$RESULT" | awk '{print $1}')
    if [ "$COUNT" -gt 0 ]; then
        echo ""
        echo -e "${GREEN}=== PASS: Found $COUNT EICAR fim event(s) in ClickHouse ===${NC}"
        echo "  Query the full event:"
        echo '    echo "SELECT received_at, severity, filename, ebpf_match, raw_message FROM logsoc.siem_logs WHERE filename LIKE '"'"'%eicar%'"'"' ORDER BY received_at DESC LIMIT 1 FORMAT Vertical" | curl -s --data-binary @- http://127.0.0.1:8123/'
        EXIT=0
    else
        echo ""
        echo -e "${RED}=== FAIL: No EICAR fim event in ClickHouse ===${NC}"
        echo "  Possible causes:"
        echo "    1. eBPF not attached (check journalctl for kprobe attach errors)"
        echo "    2. FimPoller not polling (check journalctl)"
        echo "    3. YARA rule for EICAR not loaded (check 'YARA rules' count in boot log)"
        echo "    4. /tmp/ still in ignore_paths (script patch may have failed)"
        EXIT=1
    fi
else
    echo -e "${RED}=== ERROR: ClickHouse query failed ===${NC}"
    echo "$RESULT"
    EXIT=2
fi

exit $EXIT
