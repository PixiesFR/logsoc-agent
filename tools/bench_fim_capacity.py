#!/usr/bin/env python3
"""bench_fim_capacity.py — T4.8.13 — FIM pipeline capacity benchmark.

Hammers the LogSOC agent (C++ on Hestia) with a configurable rate of
synthetic FIM events, then measures how many make it to ClickHouse.

What it measures:
  - End-to-end throughput: events/sec landing in logsoc.siem_logs (fim_v4_8)
  - Pipeline losses: FimMetrics counters (shipped/dropped/rate_limited) via
    the /metrics HTTP endpoint (T4.8.10)
  - Backend ingestion latency: time between event generation and ClickHouse row

What it does NOT measure (out of scope for capacity planning):
  - BPF kprobe miss rate (covered by T4.8.8 E2E with `python3 os.write()`)
  - ClickHouse insert ceiling (separate CH bench, see infra team)
  - Per-event CPU/mem inside the agent (use perf + flamegraph)

Usage:
  # On Hestia, with agent running and FimMetricsServer enabled on :9011
  python3 tools/bench_fim_capacity.py --writers 16 --duration 30
  python3 tools/bench_fim_capacity.py --writers 64 --duration 60 --path-prefix /tmp/bench

Outputs:
  - Console: live throughput every 5s + summary
  - JSON:    /tmp/bench_fim_results.json (for later aggregation)

The benchmark WRITES real files (creates + writes + deletes them in a
loop). It uses /tmp by default to avoid touching the real filesystem.
"""

import argparse
import base64
import json
import multiprocessing
import os
import subprocess
import sys
import time
import urllib.request
import urllib.error
from datetime import datetime, timezone


def worker(idx: int, duration: int, path_prefix: str, write_size: int) -> dict:
    """One writer process. Generates `write_size`-byte writes for `duration`s."""
    import os as _os
    file_path = f"{path_prefix}/bench_{idx}_{_os.getpid()}.bin"
    end_at = time.monotonic() + duration
    writes_attempted = 0
    writes_completed = 0
    bytes_written = 0
    pid = _os.getpid()
    payload = b"X" * write_size
    # Open the file once; rewrite the same offset (cheap, valid write() syscall)
    fd = _os.open(file_path, _os.O_WRONLY | _os.O_CREAT | _os.O_TRUNC, 0o644)
    try:
        while time.monotonic() < end_at:
            _os.lseek(fd, 0, _os.SEEK_SET)
            try:
                n = _os.write(fd, payload)
                writes_attempted += 1
                if n == write_size:
                    writes_completed += 1
                    bytes_written += n
            except OSError:
                # EBUSY/EAGAIN on the file — fine, skip this tick
                pass
    finally:
        _os.close(fd)
        try:
            _os.unlink(file_path)
        except OSError:
            pass
    return {
        "idx": idx,
        "pid": pid,
        "writes_attempted": writes_attempted,
        "writes_completed": writes_completed,
        "bytes_written": bytes_written,
        "duration_s": duration,
    }


def fetch_metrics(agent_host: str, port: int) -> dict:
    """Scrape the FimMetricsServer /metrics endpoint and parse the
    counters we care about. Returns dict {metric_name: float}."""
    url = f"http://{agent_host}:{port}/metrics"
    try:
        with urllib.request.urlopen(url, timeout=2) as r:
            body = r.read().decode("utf-8", errors="replace")
    except (urllib.error.URLError, ConnectionError) as e:
        return {"error": str(e)}
    out = {}
    for line in body.splitlines():
        if line.startswith("#") or "{" in line and not line.startswith("logsoc_fim_"):
            # HELP/TYPE comments skipped, labeled metrics ignored (we want plain counters)
            continue
        if line.startswith("logsoc_fim_") and " " in line and "_total " in line:
            try:
                name, val = line.rsplit(" ", 1)
                # Strip _total suffix for brevity
                out[name] = float(val)
            except (ValueError, IndexError):
                pass
    return out


def ch_query(sql: str, host: str = "127.0.0.1", port: int = 8123) -> str:
    """Run a ClickHouse query via local HTTP. Returns tab-separated result body."""
    cmd = [
        "curl", "-s",
        f"http://{host}:{port}/",
        "--data-binary", f"={sql}",
    ]
    r = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
    return r.stdout.strip()


def ch_count_fim_v4_8() -> int:
    """Returns the number of fim_v4_8 events in the last 5 minutes."""
    out = ch_query(
        "SELECT count() FROM logsoc.siem_logs "
        "WHERE event = 'fim_v4_8' "
        "AND received_at > now() - INTERVAL 5 MINUTE"
    )
    try:
        return int(out)
    except ValueError:
        return -1


def main() -> int:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--writers", type=int, default=8,
                   help="Number of parallel writer processes (default 8)")
    p.add_argument("--duration", type=int, default=30,
                   help="Duration in seconds (default 30)")
    p.add_argument("--write-size", type=int, default=4096,
                   help="Bytes per write() syscall (default 4096)")
    p.add_argument("--path-prefix", default="/tmp/bench_fim",
                   help="Where to write the bench files (default /tmp/bench_fim)")
    p.add_argument("--agent-host", default="127.0.0.1",
                   help="Agent host (default 127.0.0.1)")
    p.add_argument("--metrics-port", type=int, default=9011,
                   help="Agent FimMetricsServer port (default 9011)")
    p.add_argument("--output", default="/tmp/bench_fim_results.json",
                   help="JSON output path (default /tmp/bench_fim_results.json)")
    args = p.parse_args()

    # Sanity: ensure the path prefix exists
    os.makedirs(args.path_prefix, exist_ok=True)

    print(f"=== LogSOC FIM Capacity Benchmark (T4.8.13) ===")
    print(f"  writers      = {args.writers}")
    print(f"  duration     = {args.duration}s")
    print(f"  write_size   = {args.write_size} bytes")
    print(f"  path_prefix  = {args.path_prefix}")
    print(f"  metrics_url  = http://{args.agent_host}:{args.metrics_port}/metrics")
    print()

    # Baseline metrics + CH count
    print(">>> Baseline...")
    metrics_before = fetch_metrics(args.agent_host, args.metrics_port)
    ch_before = ch_count_fim_v4_8()
    print(f"    FimMetrics counters (sample): {list(metrics_before.items())[:3]}")
    print(f"    ClickHouse fim_v4_8 (last 5min): {ch_before}")
    print()

    # Spawn writers
    print(f">>> Starting {args.writers} writer processes for {args.duration}s...")
    t_start = time.monotonic()
    with multiprocessing.Pool(args.writers) as pool:
        async_results = [
            pool.apply_async(worker, (i, args.duration, args.path_prefix, args.write_size))
            for i in range(args.writers)
        ]
        # Live ticker
        ticker_end = t_start + args.duration
        sample_idx = 0
        while time.monotonic() < ticker_end:
            time.sleep(min(5.0, ticker_end - time.monotonic()))
            elapsed = time.monotonic() - t_start
            remaining = max(0.0, ticker_end - time.monotonic())
            m = fetch_metrics(args.agent_host, args.metrics_port)
            ch_now = ch_count_fim_v4_8()
            ch_delta = (ch_now - ch_before) if ch_before >= 0 and ch_now >= 0 else -1
            print(f"  [t+{elapsed:5.1f}s  -{remaining:4.1f}s left]  "
                  f"shipped={m.get('logsoc_fim_shipped_total', 'n/a'):>7}  "
                  f"dropped={m.get('logsoc_fim_dropped_total', 'n/a'):>5}  "
                  f"rate_lim={m.get('logsoc_fim_rate_limited_total', 'n/a'):>5}  "
                  f"watchdog={m.get('logsoc_fim_watchdog_pings_total', 'n/a'):>3}  "
                  f"ch_delta_5min={ch_delta}")
            sample_idx += 1

        # Drain results
        worker_results = [r.get(timeout=5) for r in async_results]
    t_end = time.monotonic()
    actual_duration = t_end - t_start

    # Final metrics
    metrics_after = fetch_metrics(args.agent_host, args.metrics_port)
    ch_after = ch_count_fim_v4_8()
    print()
    print(">>> Final metrics...")
    for k in sorted(metrics_after.keys()):
        before = metrics_before.get(k, 0)
        after = metrics_after.get(k, 0)
        delta = after - before
        print(f"    {k:50s}  before={before:>10.0f}  after={after:>10.0f}  delta={delta:>10.0f}")

    # Aggregate
    total_attempted = sum(r["writes_attempted"] for r in worker_results)
    total_completed = sum(r["writes_completed"] for r in worker_results)
    total_bytes = sum(r["bytes_written"] for r in worker_results)
    attempted_eps = total_attempted / actual_duration
    completed_eps = total_completed / actual_duration
    shipped_delta = metrics_after.get("logsoc_fim_shipped_total", 0) - \
                    metrics_before.get("logsoc_fim_shipped_total", 0)
    dropped_delta = metrics_after.get("logsoc_fim_dropped_total", 0) - \
                    metrics_before.get("logsoc_fim_dropped_total", 0)
    rate_lim_delta = metrics_after.get("logsoc_fim_rate_limited_total", 0) - \
                     metrics_before.get("logsoc_fim_rate_limited_total", 0)
    ch_delta = ch_after - ch_before if ch_after >= 0 and ch_before >= 0 else -1

    summary = {
        "config": vars(args),
        "actual_duration_s": actual_duration,
        "writers": args.writers,
        "worker_results": worker_results,
        "total_attempted": total_attempted,
        "total_completed": total_completed,
        "total_bytes": total_bytes,
        "attempted_eps": attempted_eps,
        "completed_eps": completed_eps,
        "shipped_delta": shipped_delta,
        "dropped_delta": dropped_delta,
        "rate_limited_delta": rate_lim_delta,
        "ch_delta_5min": ch_delta,
        "metrics_before": metrics_before,
        "metrics_after": metrics_after,
        "ts": datetime.now(timezone.utc).isoformat(),
    }

    print()
    print(f"=== Summary ===")
    print(f"  writers          : {args.writers} parallel processes")
    print(f"  actual duration  : {actual_duration:.1f}s")
    print(f"  write() syscalls : {total_attempted} attempted, {total_completed} completed")
    print(f"  bytes written    : {total_bytes:,} ({total_bytes/actual_duration/1024:.1f} KB/s)")
    print(f"  attempted eps    : {attempted_eps:,.0f} events/sec")
    print(f"  completed eps    : {completed_eps:,.0f} events/sec")
    print(f"  agent shipped    : {shipped_delta:,.0f} events ({shipped_delta/actual_duration:,.0f} eps)")
    print(f"  agent dropped    : {dropped_delta:,.0f} events ({dropped_delta/actual_duration:,.0f} eps)")
    print(f"  agent rate_lim   : {rate_lim_delta:,.0f} events ({rate_lim_delta/actual_duration:,.0f} eps)")
    print(f"  ClickHouse 5min  : {ch_delta:,.0f} new fim_v4_8 events")
    if ch_delta > 0:
        print(f"  end-to-end ratio : {shipped_delta/ch_delta*100:.0f}% of agent-shipped "
              f"events visible in CH (latency may delay visibility past 5min window)")
    # Verdict
    print()
    if dropped_delta > shipped_delta * 0.05:  # >5% dropped
        print(f"  >>> VERDICT: agent dropped {dropped_delta/shipped_delta*100:.0f}% of events. "
              f"Increase ship_queue_capacity or ship_batch_size.")
    if rate_lim_delta > 0:
        print(f"  >>> VERDICT: rate limiter tripped {rate_lim_delta} times. "
              f"Either too many distinct PIDs (expected with this bench) or "
              f"raise fim_rate_limit_per_pid_per_sec.")
    if completed_eps > 0 and shipped_delta < completed_eps * 0.5 * actual_duration:
        print(f"  >>> VERDICT: agent undercount: shipped {shipped_delta} but "
              f"writers did {total_completed} write()s. "
              f"Check BPF kprobe attachment (bpftool prog list) "
              f"and local_filters.open.ignore_paths.")
    if completed_eps > 0 and shipped_delta >= total_completed * 0.9 * actual_duration:
        print(f"  >>> VERDICT: agent kept up with {completed_eps:,.0f} eps generated. "
              f"Good.")

    with open(args.output, "w") as f:
        json.dump(summary, f, indent=2)
    print(f"\n  Full results saved to {args.output}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
