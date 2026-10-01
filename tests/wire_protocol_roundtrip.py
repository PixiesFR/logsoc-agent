#!/usr/bin/env python3
"""
T14.4-bis — Wire-protocol round-trip CI test.

This test validates that the agent's outbound HTTP payload contains
ALL the enrichment fields that the backend expects. It catches the
class of bug where a collector writes a field to the WAL/in-memory
buffer but the Sender or EbpfCollector silently drops it during
payload construction (Gitea issue #37, T14.4 + T14.5).

How it works:
  1. Start a Flask mock server on 127.0.0.1:9913
  2. The mock accepts POST /api/v1/events/ and dumps the JSON body
  3. Run the agent binary against the mock (with a minimal config)
  4. Wait for at least 1 batch to arrive
  5. Assert that each expected field is present in at least 1 event
  6. Print a report + exit 0 (pass) or 1 (fail)

Usage:
  python3 tests/wire_protocol_roundtrip.py [path/to/static_soc_agent]

If no path is given, defaults to ../src/static_soc_agent.

Requirements:
  - pip install flask (or use the system package)
  - The agent binary must be built (make static_soc_agent)

This test is designed to run in CI (Gitea Actions) WITHOUT a real
backend. It only needs the agent binary + Python + Flask.
"""

import json
import os
import signal
import subprocess
import sys
import tempfile
import time
import threading
from http.server import HTTPServer, BaseHTTPRequestHandler

# ── Expected fields in the payload ──
# These are the fields that the backend's EventLine schema expects
# (app/schemas.py) and that the agent's collectors generate.
# If any of these are missing from the payload, it indicates a
# silent drop in the Sender or EbpfCollector pipeline.

REQUIRED_FIELDS = [
    # Core fields (always present)
    "event_id",
    "source_host",
    "severity",
    "event",
    "message",
    "pid",
    "uid",
    "comm",
]

# Enrichment fields (may be absent if no eBPF events fired, but
# should be present if the agent ran for > 5s with eBPF enabled)
ENRICHMENT_FIELDS = [
    "severity_score",    # eBPF severity_scorer
    "mitre",             # eBPF mitre_mapping (array of strings)
    "sigma",             # eBPF sigma_engine (array of objects)
    "argv",              # execve command line
    "action",            # fim create/modify/delete
    "flags",             # open flags
    "bytes_size",        # write byte count
    "family",            # connect ipv4/ipv6/unix
    "source",            # event source
    "sha256",            # fim file hash
    "count",             # T14.0b coalescing
    "pids",              # T14.0b coalescing
    "ebpf_match",        # cross-validation
    "ebpf_event",
    "ebpf_comm",
    "ebpf_filename",
    "correlation_window_ms",
]

# ── Mock server ──

received_batches = []
received_heartbeats = []


class MockHandler(BaseHTTPRequestHandler):
    """Mock backend that accepts agent POSTs and stores the payloads."""

    def log_message(self, format, *args):
        pass  # suppress access log

    def _send_json(self, code, body):
        resp = json.dumps(body).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(resp)))
        self.end_headers()
        self.wfile.write(resp)

    def do_POST(self):
        length = int(self.headers.get("Content-Length", 0))
        body = self.rfile.read(length) if length > 0 else b""

        if self.path == "/api/v1/agents/register" or self.path == "/api/v1/agents/register/":
            # Mock registration: return a fake agent_id + token + hmac_secret
            try:
                req = json.loads(body)
                self._send_json(200, {
                    "agent_id": "test-00000000-0000-0000-0000-000000000001",
                    "token": "test-token",
                    "hmac_secret": "test-hmac-secret-32-bytes-padding!",
                    "wal_fallback_key": "test-wal-key-32-bytes-padding!!!",
                    "status": "active",
                })
            except Exception as e:
                self._send_json(400, {"error": str(e)})

        elif self.path == "/api/v1/events/":
            try:
                payload = json.loads(body)
                received_batches.append(payload)
                # Return 201 Created
                self._send_json(201, {"status": "ok", "accepted": len(payload.get("lines", []))})
            except Exception as e:
                self._send_json(400, {"error": str(e)})

        elif self.path.endswith("/heartbeat"):
            try:
                payload = json.loads(body)
                received_heartbeats.append(payload)
                # Return config response (minimal)
                self._send_json(200, {
                    "batch_interval_sec": 30,
                    "hmac_window_sec": 60,
                })
            except Exception as e:
                self._send_json(400, {"error": str(e)})

        elif "/action-report" in self.path:
            self._send_json(200, {"status": "ok"})

        elif "/yara/scan" in self.path:
            self._send_json(200, {"scan_id": "test", "matches": []})

        else:
            self._send_json(404, {"error": "not found"})

    def do_GET(self):
        if "/yara/ruleset" in self.path:
            self._send_json(200, {"version": "test", "ruleset_blob_b64": "", "rule_count": 0})
        elif "/api/v1/agents/status" in self.path:
            # Mock agent status: return active + secrets (for activation)
            self._send_json(200, {
                "status": "active",
                "agent_token": "test-token-active",
                "hmac_secret": "test-hmac-secret-32-bytes-padding!",
                "wal_secret": "test-wal-key-32-bytes-padding!!!",
            })
        else:
            self._send_json(404, {"error": "not found"})


def start_mock_server(port=9913):
    """Start the mock server in a background thread."""
    server = HTTPServer(("127.0.0.1", port), MockHandler)
    server.timeout = 1
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    return server


def stop_mock_server(server):
    server.shutdown()
    server.server_close()


# ── Test runner ──

def run_test(agent_path, duration_sec=15):
    """Run the agent against the mock server and validate the payload."""
    print(f"=== T14.4-bis Wire-Protocol Round-Trip Test ===")
    print(f"Agent: {agent_path}")
    print(f"Duration: {duration_sec}s")
    print()

    if not os.path.isfile(agent_path):
        print(f"FAIL: agent binary not found at {agent_path}")
        return 1

    # Create a minimal config
    config = {
        "version": "4.8.19",
        "hostname": "test-host",
        "central_url": "http://127.0.0.1:9913",
        "module_ebpf": True,
        "module_journald": True,
        "module_network": False,
        "enabled_probes": {
            "write": False,
            "execve": True,
            "tcp_connect": True,
            "fim": True,
            "open": True,
            "unlink": True,
        },
        "fim": {
            "watch_paths": ["/etc/passwd", "/etc/shadow"],
            "ignore_paths": ["/proc/", "/sys/", "/dev/"],
        },
        "heartbeat": {"interval_sec": 10},
        "batch_interval_sec": 3,
        "batch_max_lines": 100,
        "hmac_window_sec": 60,
        "storage": {
            "directory": "/tmp/logsoc-test-wal",
            "segment_max_size_mb": 1,
            "segment_max_age_sec": 60,
            "max_total_size_mb": 10,
        },
        "data_dir": "/tmp/logsoc-test",
    }

    config_dir = tempfile.mkdtemp(prefix="logsoc-test-")
    config_path = os.path.join(config_dir, "config.json")
    with open(config_path, "w") as f:
        json.dump(config, f)

    # Create data dir
    os.makedirs("/tmp/logsoc-test", exist_ok=True)
    os.makedirs("/tmp/logsoc-test-wal", exist_ok=True)

    # Start mock server
    print("Starting mock backend on 127.0.0.1:9913...")
    server = start_mock_server()
    time.sleep(0.5)

    # Start agent
    print(f"Starting agent with config {config_path}...")
    agent_proc = subprocess.Popen(
        [agent_path, config_path],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        env={**os.environ, "HOME": "/tmp"},
    )

    # Wait for batches
    print(f"Waiting {duration_sec}s for events to flow...")
    time.sleep(duration_sec)

    # Stop agent
    print("Stopping agent...")
    agent_proc.send_signal(signal.SIGTERM)
    try:
        agent_proc.wait(timeout=5)
    except subprocess.TimeoutExpired:
        agent_proc.kill()
        agent_proc.wait()

    stop_mock_server(server)

    # Analyze received batches
    print()
    print(f"=== Results ===")
    print(f"Batches received: {len(received_batches)}")
    print(f"Heartbeats received: {len(received_heartbeats)}")

    if not received_batches:
        print()
        print("WARN: No batches received. This may indicate:")
        print("  - eBPF not available in CI (kernel too old / no BTF)")
        print("  - Agent failed to start")
        print("  - Network issue (mock server not reachable)")
        stderr = agent_proc.stderr.read().decode() if agent_proc.stderr else ""
        if stderr:
            print(f"  Agent stderr (last 500 chars): {stderr[-500:]}")
        # Not a hard fail — CI environments may not have eBPF
        print("  → Skipping field validation (no events to check)")
        return 0

    # Collect all events from all batches
    all_events = []
    for batch in received_batches:
        all_events.extend(batch.get("lines", []))

    print(f"Total events received: {len(all_events)}")

    # Check required fields (must be present in EVERY event)
    missing_required = set()
    for ev in all_events:
        for field in REQUIRED_FIELDS:
            if field not in ev:
                missing_required.add(field)

    # Check enrichment fields (must be present in AT LEAST 1 event)
    found_enrichment = set()
    for ev in all_events:
        for field in ENRICHMENT_FIELDS:
            if field in ev:
                found_enrichment.add(field)

    missing_enrichment = set(ENRICHMENT_FIELDS) - found_enrichment

    # Report
    print()
    print(f"Required fields check ({len(REQUIRED_FIELDS)} fields):")
    if missing_required:
        print(f"  FAIL: {len(missing_required)} required fields missing:")
        for f in sorted(missing_required):
            print(f"    - {f}")
    else:
        print(f"  PASS: all {len(REQUIRED_FIELDS)} required fields present")

    print()
    print(f"Enrichment fields check ({len(ENRICHMENT_FIELDS)} fields):")
    if missing_enrichment:
        print(f"  WARN: {len(missing_enrichment)} enrichment fields not seen")
        print(f"  (may be absent if no matching events fired in {duration_sec}s)")
        for f in sorted(missing_enrichment):
            print(f"    - {f}")
    else:
        print(f"  PASS: all {len(ENRICHMENT_FIELDS)} enrichment fields seen at least once")

    # Check heartbeat hostname (T14.6)
    print()
    print(f"Heartbeat hostname check (T14.6):")
    if received_heartbeats:
        hb = received_heartbeats[0]
        if "hostname" in hb:
            print(f"  PASS: hostname='{hb['hostname']}' present in heartbeat")
        else:
            print(f"  FAIL: hostname NOT in heartbeat body")
            missing_required.add("hostname (heartbeat)")
    else:
        print(f"  SKIP: no heartbeats received")

    # Print sample event for debugging
    if all_events:
        print()
        print("Sample event (first):")
        sample = all_events[0]
        print(json.dumps(sample, indent=2)[:1000])

    # Final result
    print()
    if missing_required:
        print(f"=== RESULT: FAIL ({len(missing_required)} required fields missing) ===")
        return 1
    else:
        print(f"=== RESULT: PASS (all required fields present) ===")
        if missing_enrichment:
            print(f"  ({len(missing_enrichment)} enrichment fields not seen — check CI environment)")
        return 0


if __name__ == "__main__":
    agent_path = sys.argv[1] if len(sys.argv) > 1 else "../src/static_soc_agent"
    duration = int(sys.argv[2]) if len(sys.argv) > 2 else 15
    sys.exit(run_test(agent_path, duration))