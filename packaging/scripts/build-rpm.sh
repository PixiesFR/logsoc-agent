#!/bin/bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_DIR="$(cd "$SCRIPT_DIR/../.." && pwd)"
cd "$REPO_DIR"

VERSION="${VERSION:-3.3.10}"
RELEASE="${RELEASE:-1}"
ARCH="${ARCH:-x86_64}"
TOPDIR="$REPO_DIR/packaging/rpm"

echo "REPO=$REPO_DIR"
echo "=== Compilation (static_agent_v3) ==="
cd "$REPO_DIR/src" && make clean && make AGENT_VERSION="$VERSION" static_soc_agent
cd "$REPO_DIR"

echo "=== Preparation RPM ==="
mkdir -p "$TOPDIR/SOURCES"
mkdir -p "$TOPDIR/BUILD"
mkdir -p "$TOPDIR/RPMS"
mkdir -p "$TOPDIR/SRPMS"

# Sources: binaire statique, config, service, readme
install -m 755 "$REPO_DIR/src/static_soc_agent" "$TOPDIR/SOURCES/logsoc-agent"
install -m 644 "$REPO_DIR/packaging/debian/etc/logsoc-agent/config.json" "$TOPDIR/SOURCES/"
install -m 644 "$REPO_DIR/packaging/debian/lib/systemd/system/logsoc-agent.service" "$TOPDIR/SOURCES/"
install -m 644 "$REPO_DIR/packaging/debian/usr/share/doc/logsoc-agent/README" "$TOPDIR/SOURCES/"
install -m 644 "$REPO_DIR/packaging/debian/etc/sysctl.d/99-logsoc.conf" "$TOPDIR/SOURCES/"

echo "=== Construction RPM ==="

# Substitute version in spec file
sed -i "s/^Version: .*/Version: $VERSION/" "$TOPDIR/SPECS/logsoc-agent.spec"

# Substitute version in config.json
sed -i "s/__AGENT_VERSION__/$VERSION/g" "$TOPDIR/SOURCES/config.json"

rpmbuild --define "_topdir $TOPDIR" \
         --define "_rpmdir $TOPDIR/RPMS" \
         --define "_sourcedir $TOPDIR/SOURCES" \
         --define "_specdir $TOPDIR/SPECS" \
         -ba "$TOPDIR/SPECS/logsoc-agent.spec" 2>&1

echo "=== OK ==="
find "$TOPDIR/RPMS" -name '*.rpm' 2>/dev/null | head -5
