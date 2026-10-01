# T77_eicar E2E test tools
#
# Build:
#   make -f src/tools/Makefile
#
# This produces two helper binaries (gitignored, source lives in this dir):
#   - compile_yara_rule: takes a .yar source, emits a .yarac compiled blob
#   - load_and_scan: loads a .yarac blob and scans a file, prints MATCH
#
# Both are used by the T77_eicar end-to-end test (see logsoc-web
# CHANGELOG entry [0.31.0-t77-eicar] for the full reproduction recipe).
#
# Requires: libyara (pkg-config name "yara"), g++ with C++17.

CXX      ?= g++
CXXFLAGS ?= -std=c++17 -O2 -Wall
YARA_CFLAGS := $(shell pkg-config --cflags yara)
# libyara 4.x pulls in OpenSSL for hashing (MD5/SHA1/SHA256); pkg-config
# does not always export -lcrypto on every distro — add it explicitly.
YARA_LIBS   := $(shell pkg-config --libs yara) -lcrypto

BIN_DIR := $(dir $(abspath $(firstword $(MAKEFILE_LIST))))../

.PHONY: all clean
all: $(BIN_DIR)compile_yara_rule $(BIN_DIR)load_and_scan

$(BIN_DIR)compile_yara_rule: compile_yara_rule.cpp
	$(CXX) $(CXXFLAGS) $(YARA_CFLAGS) -o $@ $< $(YARA_LIBS)

$(BIN_DIR)load_and_scan: load_and_scan.cpp
	$(CXX) $(CXXFLAGS) $(YARA_CFLAGS) -o $@ $< $(YARA_LIBS)

clean:
	rm -f $(BIN_DIR)compile_yara_rule $(BIN_DIR)load_and_scan
