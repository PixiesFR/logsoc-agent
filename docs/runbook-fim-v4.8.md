# FIM Pipeline Runbook (V4.8)

> **Last updated**: 2026-06-13 (T4.8.10 + T4.8.13 + T4.8.15 ship)
> **Owner**: LogSOC team
> **Severity**: P1 (FIM is a core SOC signal)

## Quick health check

```bash
# 1. Is the agent running?
systemctl status logsoc-agent

# 2. FIM metrics (T4.8.10 — port 9011, FIM-specific)
#    (YaraShipper metrics on port 9010 — different surface, different scope)
curl -s http://localhost:9011/metrics | grep logsoc_fim

# 3. Are events arriving at the backend?
curl -s 'http://localhost:9011/metrics' | grep -E '(shipped|dropped|timeout)'

# 4. Liveness + agent version
curl -s http://localhost:9011/liveness | jq
# Sample: {"status":"ok","uptime_seconds":3600,"version":"4.8.0-t4.8.15"}
# The version comes from config.json (T4.8.15) — verify with:
grep '"version"' /etc/logsoc-agent/config.json

# 5. BPF ringbuf drops (T4.8.13 finding)
# The ringbuf is 16MB. Drops appear in the BPF drop_stats map, NOT
# in the FimMetrics /metrics endpoint. To check:
bpftool -j map dump id 1000 2>/dev/null | python3 -m json.tool
# key 3 = type 4 (fim) drops. key 7 = type 8 (write_fd) drops.
# If either is climbing fast (>1000/s sustained), the ringbuf is
# saturating and most events are dropped at the kernel level.
```

## Common failure modes

### Symptom: `logsoc_fim_fd_timeout_total` is climbing

**Cause**: `/proc/<pid>/fd/<n>` lookups are slow (10ms timeout exceeded).

**Investigation**:
```bash
# Are you under high process churn?
ps -e | wc -l
# Are you on a kernel that has a slow /proc?
uname -r
# Is the FdResolver worker pool saturated?
curl -s http://localhost:9010/metrics | grep logsoc_fim_resolver_queue_depth
```

**Mitigation**:
- Reduce `fim.fd.worker_count` to 2 if CPU-bound
- Increase `fim.fd.per_resolve_timeout` to 20ms
- If `/proc` is the bottleneck, restart the agent (will reset CB state)

### Symptom: `logsoc_fim_circuit_breaker_trips_total` is non-zero

**Cause**: The CircuitBreaker has tripped from repeated /proc failures.

**Investigation**:
```bash
# Check the persisted state
cat /var/lib/logsoc-agent/fim_cb_state.json
# Should contain "state":"OPEN" if currently tripped
```

**Mitigation**:
- Wait 30s for automatic recovery (HALF_OPEN probe)
- Manual reset:
  ```bash
  echo '{"state":"CLOSED","trips":0}' > /var/lib/logsoc-agent/fim_cb_state.json
  systemctl restart logsoc-agent
  ```

### Symptom: `logsoc_fim_rate_limited_total` is high

**Cause**: A specific PID is generating too many FIM events (token bucket).

**Investigation**:
```bash
# Find the offending process (requires prometheus labels — V4.9)
# For V4.8: check fim_collector logs
journalctl -u logsoc-agent | grep "rate_limited"
```

**Mitigation**:
- Increase `fim.rate_limit_per_pid_per_sec` in agent config.json
- Add the path to `local_filters.fim.ignore_paths`

### Symptom: `logsoc_fim_dropped_total` is high

**Cause**: The ship queue (cap 8192) is overflowing.

**Investigation**:
```bash
# Is the ship thread alive?
curl -s http://localhost:9010/livez
# Are the backend URLs reachable?
curl -I https://logsoc-web/api/v1/events/
```

**Mitigation**:
- Increase `fim.ship_queue_capacity` to 16384
- Check if the backend is rate-limiting the agent (HTTP 429)

## Rollback procedure

If V4.8 has a critical regression, roll back to V4.7 (v3.23.1):

```bash
# 1. Stop the agent
systemctl stop logsoc-agent

# 2. Install the V4.7 .deb (cached at /var/cache/logsoc-agent/)
dpkg -i /var/cache/logsoc-agent/logsoc-agent_3.23.1_amd64.deb

# 3. Restore the V4.7 config
cp /var/lib/logsoc-agent/config.json.backup-pre-v4.8 /var/lib/logsoc-agent/config.json

# 4. Restart
systemctl start logsoc-agent

# 5. Verify
curl -s http://localhost:9010/metrics | head
journalctl -u logsoc-agent -n 20
```

## Performance tuning

For high-throughput environments (>1000 FIM events/s):

| Setting | Default | High-throughput | Notes |
|---|---|---|---|
| `fim.fd.worker_count` | 4 | 8 | More workers = more CPU |
| `fim.ship_queue_capacity` | 8192 | 16384 | More queue = more RAM (~256B/event) |
| `fim.rate_limit_per_pid_per_sec` | 100 | 500 | Per-pid burst budget |
| `fim.watchdog_period` | 30s | 60s | Less overhead |

### Capacity ceiling (T4.8.13 finding)

The **BPF ringbuf is 16MB** (configured in `src/ebpf/skel_soc.c`).
At ~200B per event, this fits ~80,000 events in flight. When the
input rate exceeds what userspace can drain (~50k eps sustained),
**events are dropped at the kernel level** — they never reach
FimCollector, so `logsoc_fim_dropped_total` stays at 0 even though
massive droppage is happening.

**Symptoms of ringbuf saturation (silent loss):**
- `bpftool -j map dump id 1000` shows `key=3` (type 4 fim) or
  `key=7` (type 8 write_fd) growing fast (>1000/s sustained)
- `logsoc_fim_shipped_total` plateaus while input rate grows
- `logsoc_fim_dropped_total` stays at 0 (the metric only counts
  userspace drops, not kernel-level ringbuf drops)

**To bench on Hestia (T4.8.13 harness):**
```bash
mkdir -p /etc/bench_fim
python3 /opt/logsoc-agent/tools/bench_fim_capacity.py \
  --writers 4 --duration 20 --write-size 1024 \
  --path-prefix /etc/bench_fim --output /tmp/bench.json
bpftool -j map dump id 1000 | python3 -m json.tool
```

**Recommended fixes (out of scope for the bench card):**
1. Ringbuf 16MB → 64MB (30 min, 4x ceiling). Edit
   `src/ebpf/skel_soc.c` `.maps` declaration, rebuild, redeploy.
2. Path filter in kprobe (4-6h, only emit for `watch_paths`).
3. Batch 8 events per ringbuf entry (1 day, 8x ceiling).

Full report: `docs/bench-fim-v4.8.md`.

## Memory safety CI (T4.8.12)

The FIM pipeline code (FimCollector, FdResolver, CircuitBreaker,
MitreMapping, FimMetrics) is covered by an in-tree memory safety
test. Run it locally before pushing:

```bash
# From repo root:
make -C tests ci-memcheck       # ASan + valgrind
# Or individually:
make -C tests test-asan         # ASan only (~2s)
make -C tests test-valgrind     # valgrind (~10s)
bash scripts/ci-memcheck.sh     # full CI script
```

**Expected result (2026-06-14)**:
- ASan: 0 errors, 0 warnings
- valgrind: 6,759 allocs / 6,759 frees, 0 bytes lost

**Suppressions** (`tests/valgrind.supp`) cover 3 confirmed
third-party false-positives (glibc getdelim EOF, libstdc++
__cxa_finalize, libcurl global init). All documented in-file.

**CI integration** (T4.8.14 will wire this into Gitea Actions):

```yaml
- name: Memory safety
  run: bash scripts/ci-memcheck.sh
```

Any non-zero exit fails the PR.

## Health check Prometheus alerts

Recommended alerts (add to your Prometheus rules):

```yaml
groups:
- name: logsoc_fim
  rules:
  - alert: LogsocFimDroppingEvents
    expr: rate(logsoc_fim_dropped_total[5m]) > 1
    for: 5m
    annotations:
      summary: "LogSOC FIM is dropping events"
      runbook: "https://internal/runbooks/logsoc-fim.html#dropping"

  - alert: LogsocFimCircuitBreakerOpen
    expr: logsoc_fim_circuit_breaker_trips_total > 0
    annotations:
      summary: "LogSOC FIM CircuitBreaker has tripped"

  - alert: LogsocFimNoEvents
    expr: rate(logsoc_fim_shipped_total[10m]) == 0
    for: 10m
    annotations:
      summary: "LogSOC FIM shipped 0 events in 10 minutes (silent failure)"
```

## Support

- Logs: `journalctl -u logsoc-agent`
- Metrics: `http://localhost:9010/metrics`
- Liveness: `http://localhost:9010/livez`
- GitHub: https://git.anytimeadmin.info/pixies/SOC-AGENT/issues
- Runbook owner: @logsoc-team
