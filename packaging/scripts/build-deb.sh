#!/bin/bash
set -euo pipefail

# build-deb.sh — Packager LogSOC Agent v3.1 pour Debian/Ubuntu

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_DIR="$(cd "$SCRIPT_DIR/../.." && pwd)"
cd "$REPO_DIR"
echo "REPO=$REPO_DIR"

VERSION="${VERSION:-3.9.8}"
ARCH="${ARCH:-amd64}"
PKG="logsoc-agent_${VERSION}_${ARCH}"
BUILD="$REPO_DIR/packaging/build-deb"

echo "=== Nettoyage ==="
rm -rf "$BUILD"

echo "=== Compilation (static_soc_agent, AGENT_VERSION=$VERSION) ==="
cd "$REPO_DIR/src" && make clean && make AGENT_VERSION="$VERSION" static_soc_agent
cd "$REPO_DIR"

echo "=== Preparation ==="
mkdir -p "$BUILD/$PKG/DEBIAN"
mkdir -p "$BUILD/$PKG/usr/bin"
mkdir -p "$BUILD/$PKG/etc/logsoc-agent"
mkdir -p "$BUILD/$PKG/etc/apparmor.d"
mkdir -p "$BUILD/$PKG/etc/sysctl.d"
mkdir -p "$BUILD/$PKG/lib/systemd/system"
mkdir -p "$BUILD/$PKG/usr/share/doc/logsoc-agent"
mkdir -p "$BUILD/$PKG/var/lib/logsoc-agent/wal"
mkdir -p "$BUILD/$PKG/var/log/logsoc-agent"
# T14.2 — C-03: ship the AppArmor local fragment generator alongside
# the main binary. The postinst calls it to build the local include
# from the live config.json at install time.
mkdir -p "$BUILD/$PKG/usr/share/logsoc-agent"

cp "$REPO_DIR/src/static_soc_agent" "$BUILD/$PKG/usr/bin/logsoc-agent"
chmod 755 "$BUILD/$PKG/usr/bin/logsoc-agent"

install -m 644 "$REPO_DIR/packaging/debian/DEBIAN/control"    "$BUILD/$PKG/DEBIAN/"
# Substitute $VERSION in control file
sed -i "s/^Version: .*/Version: $VERSION/" "$BUILD/$PKG/DEBIAN/control"
chmod 755 "$REPO_DIR/packaging/debian/DEBIAN/postinst" "$REPO_DIR/packaging/debian/DEBIAN/prerm"
install -m 755 "$REPO_DIR/packaging/debian/DEBIAN/postinst"   "$BUILD/$PKG/DEBIAN/"
install -m 755 "$REPO_DIR/packaging/debian/DEBIAN/prerm"      "$BUILD/$PKG/DEBIAN/"

cp "$REPO_DIR/packaging/debian/etc/logsoc-agent/config.json" "$BUILD/$PKG/etc/logsoc-agent/"
sed -i "s/__AGENT_VERSION__/$VERSION/g" "$BUILD/$PKG/etc/logsoc-agent/config.json"
# T13.3': ship the 3 allowlist config files for ActionValidator
install -m 644 "$REPO_DIR/packaging/debian/etc/logsoc-agent/rules_allowlist.json"   "$BUILD/$PKG/etc/logsoc-agent/"
install -m 644 "$REPO_DIR/packaging/debian/etc/logsoc-agent/pid_exclusions.json"   "$BUILD/$PKG/etc/logsoc-agent/"
install -m 644 "$REPO_DIR/packaging/debian/etc/logsoc-agent/action_allowlist.json" "$BUILD/$PKG/etc/logsoc-agent/"
cp "$REPO_DIR/packaging/debian/lib/systemd/system/logsoc-agent.service" "$BUILD/$PKG/lib/systemd/system/"
cp "$REPO_DIR/packaging/debian/usr/share/doc/logsoc-agent/README" "$BUILD/$PKG/usr/share/doc/logsoc-agent/"
cp "$REPO_DIR/packaging/debian/etc/apparmor.d/usr.bin.logsoc-agent" "$BUILD/$PKG/etc/apparmor.d/"
# T14.2 — C-03: install the AppArmor local fragment generator
install -m 755 "$REPO_DIR/packaging/debian/usr/share/logsoc-agent/generate_apparmor_local.py" "$BUILD/$PKG/usr/share/logsoc-agent/"
cp "$REPO_DIR/packaging/debian/etc/sysctl.d/99-logsoc.conf" "$BUILD/$PKG/etc/sysctl.d/"

echo "=== Construction .deb ==="
fakeroot dpkg-deb --build "$BUILD/$PKG" "$REPO_DIR/packaging/${PKG}.deb"

echo "=== OK ==="
ls -lh "$REPO_DIR/packaging/${PKG}.deb"
