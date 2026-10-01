CXX      ?= g++

# T38: Agent version baked at compile time. Override with: make VERSION=4.8.19
# This ensures the heartbeat sends the compiled version, not config.json's version.
AGENT_VERSION ?= 4.8.26

# T13.6 hardening flags (production binary):
#   -fvisibility=hidden        : hide all symbols by default; only explicitly
#                                exported (or extern "C" declared) symbols are
#                                in the dynamic symbol table. Reduces PLT/GOT
#                                attack surface and trims binary size.
#   -Werror=format-security    : turn format-non-literal warnings into errors.
#                                Defends against CVE-style printf(buf) mistakes.
#   -fcf-protection=full       : x86_64 Control-flow Integrity (Intel CET).
#                                Mitigates ROP/JOP via endbr64 + shadow stack.
#                                Requires binutils >= 2.29 + kernel >= 5.18.
#   -fstack-protector-strong   : stack canary for any function with >8 bytes
#                                of stack arrays (vs -fstack-protector only
#                                protects functions with char arrays).
#   -D_FORTIFY_SOURCE=3        : runtime buffer-overflow checks on libc/glibc
#                                functions (strncpy, memcpy, sprintf, etc.).
#                                3 = aggressive (overrides), 2 = runtime check.
#   -D_GLIBCXX_ASSERTIONS      : STL runtime bounds/contract assertions.
#                                Negligible perf cost, catches std::vector OOB.
#   -fno-omit-frame-pointer    : keep %rbp for profiling + backtraces
#                                (perf impact ~1-2% on hot paths).
HARDENING_CXXFLAGS = -fvisibility=hidden -Werror=format-security -fcf-protection=full -fno-omit-frame-pointer -D_GLIBCXX_ASSERTIONS

# T13.7 -Werror: any warning becomes a build error. Forces all new code to
# be warning-clean. Existing 3 warnings were fixed in T13.7 (see CHANGELOG).
# Adding -Werror later is hard (locks you out of shipping until everything
# is clean). Better to fail loud now than to discover latent issues months
# later via valgrind or a production crash.
CXXFLAGS  = -std=c++17 -O2 -Wall -Wextra -Werror -fPIC -fstack-protector-strong $(shell if [ $(shell g++ -dumpversion | cut -d. -f1) -ge 12 ]; then echo "-D_FORTIFY_SOURCE=3"; else echo "-D_FORTIFY_SOURCE=2"; fi) $(HARDENING_CXXFLAGS) -I. -I./network $(shell curl-config --cflags 2>/dev/null) $(shell pkg-config --cflags openssl 2>/dev/null) $(shell pkg-config --cflags yara 2>/dev/null) -DAGENT_VERSION=\"$(AGENT_VERSION)\"

# T12.12: libmnl + libnftnl are linked STATICALLY (vendor libs that the agent
# embeds). Justification: these libs are used to talk netlink/nftables
# directly from the agent (no /bin/sh, no /usr/sbin/nft, no iptables binary).
# Static linking is safe because:
#   - libmnl is a stable low-level netlink wrapper (last ABI change in 2012)
#   - libnftnl has a stable soname (libnftnl.so.11) and is feature-frozen
# If the host's libnftnl ever has a security issue, the .deb is rebuilt
# + redeployed (R2 pipeline) — this is preferable to depending on whatever
# .so is installed on the prod host.
#
# NOTE: requires `apt install libmnl-dev libnftnl-dev` on the build sandbox
# (sandbox only — Hestia/prod hosts do not need these dev packages because
# the .a is baked into the .deb binary).
NFTABLES_LDFLAGS = $(shell if [ -f /usr/lib/x86_64-linux-gnu/libmnl.a ] || [ -f /usr/lib64/libmnl.a ]; then echo "-l:libmnl.a -l:libnftnl.a"; else echo "-lmnl -lnftnl"; fi)
LDFLAGS   = -Wl,-z,relro,-z,now -lcurl -lcrypto -lssl $(shell pkg-config --libs openssl 2>/dev/null) -lpcap -lbpf -lelf -lz -ldl -lsystemd $(shell pkg-config --libs yara 2>/dev/null) $(NFTABLES_LDFLAGS)

# T13.6 hardening linker flags (production binary):
#   -Wl,-z,relro,-z,now         : RELRO (full GOT read-only after dynamic linking).
#   -Wl,-z,noexecstack          : NX stack (no exec on stack).
#   -Wl,--gc-sections           : drop unused sections (smaller binary).
#   -fcf-protection=full        : CET at link time too (encodes endbr64 in PLT).
HARDENING_LDFLAGS = -Wl,-z,noexecstack -Wl,--gc-sections -fcf-protection=full

# Mode universel: static link de libstdc++ et libgcc pour compatibilite ABI
# Usage: make static_agent_v3
STATIC_LDFLAGS = -static-libgcc -static-libstdc++ -Wl,-z,relro,-z,now $(LDFLAGS) $(HARDENING_LDFLAGS) -Wl,--as-needed

TARGET    = soc_agent
SRCS      = agent.cpp agent_auth.cpp crypto.cpp fallback_wal.cpp runtime_credentials.cpp \
            network/pcap_collector.cpp \
            network/network_detector.cpp \
            ebpf/loader.cpp \
            ebpf/t13_4_xdp_loader.cpp \
            yara/yara_engine.cpp \
            yara_shipper.cpp \
            encryption_detect.cpp \
            agent/circuit_breaker.cpp \
            agent/severity_scorer.cpp \
            agent/fd_resolver.cpp \
            agent/fim_collector.cpp \
            agent/fim_poller.cpp \
            agent/fim_metrics.cpp \
            agent/t12_10c_commands.cpp \
            action_executor.cpp \
            wal_writer_process.cpp \
            fim_scanner_process.cpp \
            action_recommender_process.cpp \
            action_validator.cpp

$(TARGET): $(SRCS)
	$(CXX) $(CXXFLAGS) -o $@ $(SRCS) $(LDFLAGS) $(HARDENING_LDFLAGS)

# Binaire avec libs C++ statiques — compatible Ubuntu 20.04 -> 25.04
static_$(TARGET): $(SRCS)
	$(CXX) $(CXXFLAGS) -o $@ $(SRCS) $(STATIC_LDFLAGS)


# Build Docker multi-distro (glibc 2.31, gcc 10 sur Ubuntu 20.04)
# Usage: make docker_build
docker_build:
	@echo "Building in Docker (ubuntu:20.04) for universal .deb/.rpm..."
	cd .. && docker build -f packaging/Dockerfile.build -t logsoc-agent-builder:latest . \
		&& docker run --rm -v "$(PWD)/../packaging:/out" logsoc-agent-builder:latest

clean:
	$(RM) $(TARGET) static_$(TARGET)

# Unit tests (T66/T77)
# Usage: make tests
TEST_SRCS = test_yara_blob_load.cpp
tests: $(TEST_SRCS) yara/yara_engine.cpp agent_auth.cpp crypto.cpp
	$(CXX) $(CXXFLAGS) -O0 -g -o test_yara_blob_load $(TEST_SRCS) yara/yara_engine.cpp agent_auth.cpp crypto.cpp $(LDFLAGS)
	./test_yara_blob_load
