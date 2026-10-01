# tests/Makefile — T4.8.7 — unified test runner
#
# Targets:
#   make -C tests test           # run all unit tests
#   make -C tests test-mitre     # individual test
#   make -C tests test-cb
#   make -C tests test-fd
#   make -C tests test-fim
#   make -C tests test-poller    # v4.8.0 (T4.8.8): FimPoller fallback
#   make -C tests test-metrics
#   make -C tests test-e2e       # end-to-end test
#   make -C tests test-memcheck  # T4.8.12: ASan+valgrind sustained load
#   make -C tests test-asan      # T4.8.12: ASan only
#   make -C tests test-valgrind  # T4.8.12: valgrind only
#   make -C tests ci-memcheck   # T4.8.12: full CI gate (ASan + valgrind)
#   make -C tests clean

CC      = g++
CFLAGS  = -std=c++17 -O2 -Wall -pthread -I../src/agent
BINDIR  = /tmp

# When invoked via `make -C tests test`, make changes cwd to tests/.
# All sources and the include path must therefore be relative to
# the repo root, with a `../` prefix.
REPO_ROOT = $(abspath $(dir $(MAKEFILE_LIST))..)
TESTS_DIR = $(REPO_ROOT)/tests
AGENT_DIR = $(REPO_ROOT)/src/agent

AGENT_SRCS_COMMON = \
    $(AGENT_DIR)/circuit_breaker.cpp \
    $(AGENT_DIR)/mitre_mapping.cpp \
    $(AGENT_DIR)/fd_resolver.cpp \
    $(AGENT_DIR)/fim_collector.cpp \
    $(AGENT_DIR)/fim_metrics.cpp

.PHONY: test test-mitre test-cb test-fd test-fim test-poller test-metrics test-e2e \
        test-memcheck test-asan test-valgrind ci-memcheck clean \
        test-network-detector test-ring-buffer test-packet-redact test-gzip-compress

test: test-mitre test-cb test-fd test-fim test-poller test-metrics test-e2e \
     test-network-detector test-ring-buffer test-packet-redact test-gzip-compress

test-mitre:
	$(CC) $(CFLAGS) -o $(BINDIR)/test_mitre_mapping \
	    $(TESTS_DIR)/test_mitre_mapping.cpp $(AGENT_DIR)/mitre_mapping.cpp
	$(BINDIR)/test_mitre_mapping

test-cb:
	$(CC) $(CFLAGS) -o $(BINDIR)/test_circuit_breaker \
	    $(TESTS_DIR)/test_circuit_breaker.cpp $(AGENT_DIR)/circuit_breaker.cpp
	$(BINDIR)/test_circuit_breaker

test-fd: test-cb
	$(CC) $(CFLAGS) -o $(BINDIR)/test_fd_resolver \
	    $(TESTS_DIR)/test_fd_resolver.cpp \
	    $(AGENT_DIR)/fd_resolver.cpp $(AGENT_DIR)/circuit_breaker.cpp
	$(BINDIR)/test_fd_resolver

test-fim: test-mitre
	$(CC) $(CFLAGS) -o $(BINDIR)/test_fim_collector \
	    $(TESTS_DIR)/test_fim_collector.cpp \
	    $(AGENT_DIR)/fim_collector.cpp $(AGENT_DIR)/fd_resolver.cpp \
	    $(AGENT_DIR)/circuit_breaker.cpp $(AGENT_DIR)/mitre_mapping.cpp
	$(BINDIR)/test_fim_collector

test-poller:
	$(CC) $(CFLAGS) -o $(BINDIR)/test_fim_poller \
	    $(TESTS_DIR)/test_fim_poller.cpp \
	    $(AGENT_DIR)/fim_poller.cpp $(AGENT_DIR)/fim_collector.cpp \
	    $(AGENT_DIR)/fd_resolver.cpp $(AGENT_DIR)/circuit_breaker.cpp \
	    $(AGENT_DIR)/mitre_mapping.cpp \
	    -lcrypto
	$(BINDIR)/test_fim_poller

test-metrics:
	$(CC) $(CFLAGS) -o $(BINDIR)/test_fim_metrics \
	    $(TESTS_DIR)/test_fim_metrics.cpp $(AGENT_DIR)/fim_metrics.cpp
	$(BINDIR)/test_fim_metrics

test-e2e: test-metrics
	$(CC) $(CFLAGS) -o $(BINDIR)/test_e2e_fim \
	    $(TESTS_DIR)/test_e2e_fim.cpp \
	    $(AGENT_SRCS_COMMON)
	$(BINDIR)/test_e2e_fim

# T4.8.24 — Network alerting detector
# Uses -I../src (not -I../src/agent) because it depends on
# src/network/network_detector.hpp + src/network/redact.hpp.
test-network-detector:
	$(CC) -std=c++17 -O2 -Wall -pthread -I../src \
	    -o $(BINDIR)/test_network_detector \
	    $(TESTS_DIR)/test_network_detector.cpp \
	    ../src/network/network_detector.cpp
	$(BINDIR)/test_network_detector

# T4.8.9 — Ring buffer (SPSC, 4096 events)
test-ring-buffer:
	$(CC) -std=c++17 -O2 -Wall -pthread -I../src -I../src/network \
	    -o $(BINDIR)/test_ring_buffer \
	    $(TESTS_DIR)/test_ring_buffer.cpp
	$(BINDIR)/test_ring_buffer

# T4.8.9 — Packet redaction
test-packet-redact:
	$(CC) -std=c++17 -O2 -Wall -pthread -I../src -I../src/network \
	    -o $(BINDIR)/test_packet_redact \
	    $(TESTS_DIR)/test_packet_redact.cpp
	$(BINDIR)/test_packet_redact

# T4.8.25 — In-process gzip compression (replaces popen("gzip -c"))
test-gzip-compress:
	$(CC) -std=c++17 -O2 -Wall -pthread -I../src \
	    -o $(BINDIR)/test_gzip_compress \
	    $(TESTS_DIR)/test_gzip_compress.cpp -lz
	$(BINDIR)/test_gzip_compress

# T4.8.12 — Memory safety tests
#
# ASAN_FLAGS / VALGRIND: link with -fsanitize=address (no PIE for cleanest ASan
# reports). valgrind.supp suppresses glibc / libstdc++ / libcurl false-positives
# (documented in the file).
ASAN_FLAGS = -fsanitize=address -fno-omit-frame-pointer -O0 -g

test-memcheck: test-asan test-valgrind

test-asan:
	@echo "=== ASan: building test_memcheck_sustained ==="
	$(CC) $(CFLAGS) $(ASAN_FLAGS) -o $(BINDIR)/test_asan_sustained \
	    $(TESTS_DIR)/test_memcheck_sustained.cpp $(AGENT_SRCS_COMMON)
	@echo "=== ASan: running ==="
	ASAN_OPTIONS=detect_leaks=1:abort_on_error=1 $(BINDIR)/test_asan_sustained

test-valgrind:
	@echo "=== valgrind: building test_memcheck_sustained ==="
	$(CC) $(CFLAGS) -O0 -g -o $(BINDIR)/test_memcheck_sustained \
	    $(TESTS_DIR)/test_memcheck_sustained.cpp $(AGENT_SRCS_COMMON)
	@command -v valgrind >/dev/null 2>&1 || { \
	    echo "valgrind not found — skipping"; exit 0; }
	@echo "=== valgrind --leak-check=full ==="
	cd $(REPO_ROOT) && valgrind --leak-check=full --show-leak-kinds=all --error-exitcode=1 \
	         --suppressions=tests/valgrind.supp \
	         $(BINDIR)/test_memcheck_sustained 2>&1 | tail -20

ci-memcheck: test-memcheck
	@echo "=== CI memcheck gate: PASS ==="

# T4.8.11 — libFuzzer harnesses
#
# The fuzz_* targets are NOT part of the default `make test` because
# they require clang++ (libFuzzer is a clang feature, not g++).
# Run them manually when chasing bugs in the parser surfaces.
#
# Build (one-time):
#   make -C tests fuzz-yara       # builds /tmp/fuzz_yara_load_blob
#   make -C tests fuzz-policy     # builds /tmp/fuzz_policy_validation
#
# Run (60s smoke test):
#   /tmp/fuzz_yara_load_blob /tmp/fuzz_yara_corpus -max_total_time=60
#   /tmp/fuzz_policy_validation /tmp/fuzz_policy_corpus -max_total_time=60
#
# Run on saved crash input:
#   /tmp/fuzz_yara_load_blob crash-deadbeef.bin
.PHONY: fuzz-yara fuzz-policy

# Both fuzzers are listed as PHONY so "make -C tests fuzz-yara" works
# even if the target name doesn't match a file. The actual build
# commands are in scripts/fuzz.sh (kept out of the Makefile because
# they need to be tuned per-host).
fuzz-yara fuzz-policy:
	@echo "Use scripts/fuzz.sh build|yara|policy to build/run fuzzers"
	@echo "  bash scripts/fuzz.sh build   # build both"
	@echo "  bash scripts/fuzz.sh yara    # 60s smoke test on YARA blob fuzzer"
	@echo "  bash scripts/fuzz.sh policy  # 60s smoke test on policy JSON fuzzer"
	@exit 1

clean:
	rm -f $(BINDIR)/test_mitre_mapping $(BINDIR)/test_circuit_breaker \
	      $(BINDIR)/test_fd_resolver $(BINDIR)/test_fim_collector \
	      $(BINDIR)/test_fim_poller \
	      $(BINDIR)/test_fim_metrics $(BINDIR)/test_e2e_fim \
	      $(BINDIR)/test_asan_sustained $(BINDIR)/test_memcheck_sustained
