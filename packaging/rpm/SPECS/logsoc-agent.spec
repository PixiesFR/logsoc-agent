Name:           logsoc-agent
Version: 4.8.26
Release:        1%{?dist}
Summary:        LogSOC-AI SIEM Agent C++ — privilege-separated WAL writer
License:        Proprietary
URL:            https://logsoc.anytimeadmin.info
AutoReqProv:    yes
Requires:       systemd, libcurl >= 7.76, openssl-libs >= 3.0, libpcap >= 1.9, libbpf >= 1.0, yara >= 4.5, libmnl, libnftnl, elfutils-libelf, zlib

%description
Agent C++ pour collecte de logs systeme, capture reseau (libpcap),
ingestion chiffree (WAL AES-GCM + HMAC) vers le central LogSOC,
et sondes eBPF V4.2 via libbpf (kernel >= 5.x requis).
6 sondes unifiees (write, execve, connect, fim, open, unlink),
ringbuf 4MB, self-exclusion PID, masquage args, rate-limit.

Packaged with sysctl.d drop-in (perf_event_paranoid=2 for BPF),
systemd service (User=root, privilege-separated WAL child setuid logsoc).

%prep
# Binaire pre-compile — pas de compilation

%install
mkdir -p %{buildroot}%{_bindir}
mkdir -p %{buildroot}%{_sysconfdir}/logsoc-agent
mkdir -p %{buildroot}/usr/lib/systemd/system
mkdir -p %{buildroot}%{_localstatedir}/lib/logsoc-agent/wal
mkdir -p %{buildroot}%{_localstatedir}/lib/logsoc/quarantine
mkdir -p %{buildroot}%{_localstatedir}/log/logsoc-agent
mkdir -p %{buildroot}%{_docdir}/logsoc-agent
mkdir -p %{buildroot}%{_sysconfdir}/sysctl.d

install -m 755 %{_sourcedir}/logsoc-agent %{buildroot}%{_bindir}/logsoc-agent
install -m 644 %{_sourcedir}/config.json %{buildroot}%{_sysconfdir}/logsoc-agent/config.json
install -Dm644 %{_sourcedir}/logsoc-agent.service %{buildroot}/usr/lib/systemd/system/logsoc-agent.service
install -m 644 %{_sourcedir}/README %{buildroot}%{_docdir}/logsoc-agent/README
install -m 644 %{_sourcedir}/99-logsoc.conf %{buildroot}%{_sysconfdir}/sysctl.d/99-logsoc.conf

%files
%license %{_docdir}/logsoc-agent/README
%config(noreplace) %{_sysconfdir}/logsoc-agent/config.json
%{_bindir}/logsoc-agent
/usr/lib/systemd/system/logsoc-agent.service
%{_sysconfdir}/sysctl.d/99-logsoc.conf
%attr(775,logsoc,logsoc) %{_localstatedir}/lib/logsoc-agent
%attr(775,logsoc,logsoc) %{_localstatedir}/lib/logsoc-agent/wal
%attr(775,logsoc,logsoc) %{_localstatedir}/lib/logsoc
%attr(775,logsoc,logsoc) %{_localstatedir}/lib/logsoc/quarantine
%attr(750,logsoc,logsoc) %{_localstatedir}/log/logsoc-agent

%pre
getent group logsoc > /dev/null || groupadd -r logsoc
getent passwd logsoc > /dev/null || useradd -r -g logsoc -d %{_localstatedir}/lib/logsoc-agent -s /sbin/nologin logsoc
if getent group adm >/dev/null 2>&1; then
    usermod -a -G adm logsoc 2>/dev/null || true
fi

%post
# WAL directory owned by logsoc (privilege-separated child writes as logsoc)
chown -R logsoc:logsoc %{_localstatedir}/lib/logsoc-agent
chown -R logsoc:logsoc %{_localstatedir}/lib/logsoc
chown -R logsoc:logsoc %{_localstatedir}/log/logsoc-agent
chmod 775 %{_localstatedir}/lib/logsoc-agent
chmod 775 %{_localstatedir}/lib/logsoc-agent/wal
chmod 775 %{_localstatedir}/lib/logsoc
chmod 775 %{_localstatedir}/lib/logsoc/quarantine
chmod 750 %{_localstatedir}/log/logsoc-agent
# BUGFIX #42: config.json doit etre writable par le group logsoc (thread hot-reload en UID logsoc)
if [ -d %{_sysconfdir}/logsoc-agent ]; then
    chown root:logsoc %{_sysconfdir}/logsoc-agent
    chmod 775 %{_sysconfdir}/logsoc-agent
    if [ -f %{_sysconfdir}/logsoc-agent/config.json ]; then
        chown root:logsoc %{_sysconfdir}/logsoc-agent/config.json
        chmod 664 %{_sysconfdir}/logsoc-agent/config.json
    fi
fi
# Fix agent.identity ownership if present (must be root:root)
if [ -f %{_localstatedir}/lib/logsoc-agent/agent.identity ]; then
    chown root:root %{_localstatedir}/lib/logsoc-agent/agent.identity
    chmod 600 %{_localstatedir}/lib/logsoc-agent/agent.identity
fi
# Apply sysctl for eBPF perf_event (quiet — only logsoc conf)
sysctl -p %{_sysconfdir}/sysctl.d/99-logsoc.conf >/dev/null 2>&1 || true
systemctl daemon-reload 2>/dev/null || true
systemctl enable logsoc-agent 2>/dev/null || true
systemctl restart logsoc-agent 2>/dev/null || true

%preun
if [ $1 -eq 0 ]; then
    systemctl stop logsoc-agent 2>/dev/null || true
    systemctl disable logsoc-agent 2>/dev/null || true
fi

%postun
if [ $1 -eq 0 ]; then
    systemctl daemon-reload 2>/dev/null || true
    rm -f %{_sysconfdir}/sysctl.d/99-logsoc.conf
    sysctl --system 2>/dev/null || true
    if getent passwd logsoc >/dev/null 2>&1; then
        userdel logsoc 2>/dev/null || true
    fi
    if getent group logsoc >/dev/null 2>&1; then
        groupdel logsoc 2>/dev/null || true
    fi
fi

%changelog
* Tue Jun 30 2026 Hermes Agent <hermes@anytimeadmin.info> - 4.8.22-1
- Fix postinst: chown root:root agent.identity after upgrade
- Fix agent C++: no crash on unexpected status (wait 60s and retry)
- Fix agent C++: HTTP 404 on activate -> re-register
- Fix backend: re-registration returns 'pending' not 'inactive'
- Fix backend: reactivate inactive agents on heartbeat
- Logs JournaldCollector + FimShipper reduced to DEBUG level
- Service file: no more hardcoded v3.5
- config.json: version is now dynamic from build
- AutoReqProv: no — suppresses false dependency detection on static binary
- Removed unnecessary Requires (libcurl, libpcap, libyara, etc.) — binary is static
- Added /var/lib/logsoc/quarantine directory
- Quiet sysctl in post script