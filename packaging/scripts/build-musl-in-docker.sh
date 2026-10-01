#!/bin/bash
set -euo pipefail
REPO=/home/hermes/log-soc-ai/repo-agent
SRC=$REPO/src
OUT=$REPO/src/static_soc_agent

# Run Alpine container with musl toolchain and static libs
docker run --rm -v "$REPO:/src" alpine:3.19 sh -c '
  apk add --no-cache build-base curl-dev openssl-dev libpcap-dev libbpf-dev elfutils-dev zlib-dev linux-headers git g++ make > /dev/null 2>&1
  cd /src/src
  CXX="g++ -std=c++17 -O2 -Wall -Wextra -I. -I./network"
  STATIC="-static -no-pie"
  LIBS="$(curl-config --libs 2>/dev/null || echo -lcurl) -lcrypto -lssl -lpcap -lbpf -lelf -lz"
  # Link everything statically
  $CXX $STATIC -o static_soc_agent agent_v3.cpp agent_auth.cpp crypto.cpp wal.cpp network/pcap_collector.cpp ebpf/loader.cpp $LIBS
  echo "[OK] musl static build done"
  file static_soc_agent
'
