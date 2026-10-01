# LogSOC Agent

> **LogSOC** = **L**ibre · **O**pen · **G**ouvernance · **S**écurité · **O**pérations · **C**onformité

> **Status: stable v4.8.x** — voir [CHANGELOG.md](CHANGELOG.md) pour l'historique complet.
>
> Agent de collecte d'événements système (EDR/XDR) pour la plateforme
> **LogSOC-AI** (SIEM/SOC local enterprise-grade). C++17 statique,
> compatible Linux amd64. Capture process exec, file write/open/unlink,
> FIM (eBPF + fanotify opt-in), trafic réseau (libpcap / XDP opt-in),
> journald, et YARA HQ. Ingeste vers le central via HTTPS (AES-256-GCM
> + HMAC-SHA256), avec WAL chiffré local et recovery au démarrage.

---

## Table des matières

1. [Utilité de l'agent](#utilité-de-lagent)
2. [Fonctions principales](#fonctions-principales)
3. [Architecture](#architecture)
4. [Prérequis](#prérequis)
5. [Installation](#installation)
   - 5.1 [Build par compilation](#51-build-par-compilation)
   - 5.2 [Package .deb](#52-package-deb)
6. [Configuration minimale](#configuration-minimale)
7. [Démarrage du service](#démarrage-du-service)
8. [Documentation complémentaire](#documentation-complémentaire)
9. [Bibliothèques tierces et licences](#bibliothèques-tierces-et-licences)

---

## Utilité de l'agent

LogSOC Agent est un **collecteur d'événements bas-niveau** qui s'installe
sur chaque machine surveillée (serveur Linux, poste admin, conteneur
privilégié, IoT industriel) et alimente en temps réel une plateforme
**SIEM/SOC centralisée** (LogSOC-AI). Il sert de couche d'observabilité
unifiée entre le noyau Linux et la console d'analyse du SOC.

Concrètement, l'agent :

- **Voit tout ce qui se passe** au niveau syscall, sans instrumentation
  applicative (eBPF kprobes/tracepoints sur `sys_execve`, `sys_openat`,
  `vfs_write`, `sys_unlink`, `tcp_connect`).
- **Détecte les modifications de fichiers critiques** (FIM : `/etc/passwd`,
  `/etc/shadow`, `/etc/sudoers`, `/etc/ssh/*`, `/etc/cron*`, `/root/.ssh/*`,
  `/home/*` — voir `fim.watch_paths`) en temps réel (latence < 1µs par
  événement en eBPF).
- **Capture le trafic réseau sortant suspect** (connexions TCP, DNS,
  payloads) avec une latence négligeable (< 0.5% CPU idle, < 3% sous
  charge).
- **Lit journald** (auth.log, syslog, services systemd) avec des
  filtres d'exclusion pour éviter les boucles.
- **Scanne les fichiers** (YARA HQ) en background avec un bitmask de
  4 modes : `file`, `memory`, `network`, `log`. Le matching est posté
  au central avec un payload préview de 256 octets par défaut.
- **Signe et chiffre chaque batch** (AES-256-GCM + HMAC-SHA256) avant
  envoi HTTPS, avec un nonce d'authentification dérivé d'un secret
  partagé (rotation de clé 60s, fenêtre anti-replay 60s).
- **Survit aux coupures réseau** via un WAL chiffré sur disque
  (rotation automatique, quota configurable, recovery au boot).
- **Sépare les privilèges** (T13 privilege separation) : un process
  principal root drop ses privilèges vers un user `logsoc` non-privilégié
  pour les opérations WAL, et ne les récupère que via un helper setuid
  pour les opérations qui le nécessitent (boot BPF, FIM scan,
  journald open).

L'agent **ne décide pas** ce qui est une alerte. Il se contente de
collecter, signer, chiffrer, et pousser. La logique de corrélation,
scoring de sévérité, et notification est dans le **central** (LogSOC-Web).

## Fonctions principales

| Fonction                       | Description                                                                                             | Activation par défaut |
|--------------------------------|---------------------------------------------------------------------------------------------------------|-----------------------|
| **eBPF execve**                | Capture de chaque exécution de binaire (chemin + argv) avec kprobe `sys_execve`                        | ON (`execve: true`)   |
| **eBPF openat**                | Capture de chaque ouverture de fichier (basename + flags) avec kprobe `sys_enter_openat`                | ON (`open: true`)     |
| **eBPF vfs_write**             | Capture de chaque écriture de fichier (basename + bytes) avec kprobe `vfs_write`                        | OFF (`write: false`)  |
| **eBPF unlink**                | Capture de chaque suppression de fichier (basename) avec kprobe `sys_unlink`                            | ON (`unlink: true`)   |
| **eBPF tcp_connect**           | Capture de chaque connexion TCP sortante (dst_ip:dst_port + comm) avec kprobe `tcp_connect`             | ON (`tcp_connect: true`) |
| **eBPF FIM**                   | File Integrity Monitoring kernel-level : `vfs_write` + `openat` + cache `open_path_cache`              | ON (`fim: true`)      |
| **XDP SYN scan** (T13.4)       | Détection in-kernel de SYN scan via programme XDP attaché à l'interface réseau                         | OFF (`enable_xdp_scan: false`) |
| **Fanotify FIM** (opt-in)      | FIM userspace via `fanotify(7)` API, chemins absolus livrés par le noyau (incompatible AppArmor)      | OFF (`fanotify_enabled: false`) |
| **YARA HQ scan** (opt-in)      | Scan YARA (libyara 4.5+) sur fichiers, mémoire, réseau, logs. 5 modes bitmask                          | OFF (`yara_enabled: false`) |
| **YARA ship to central**       | Quand un fichier est suspect, ship le contenu (max 4MB) au central pour scan profond                    | OFF (`yara_ship_content: false`) |
| **Journald collector**         | Lecture de journald (`sd-journal` API) avec filtres par `_SYSTEMD_UNIT` / `MESSAGE` / `SYSLOG_IDENTIFIER` | ON                    |
| **App collector** (opt-in)     | Lecture de fichiers de log (auth.log, syslog) avec rotation                                           | OFF (`app_collector_enabled: false`) |
| **Network collector** (opt-in) | Capture libpcap des interfaces, avec BPF filter configurable                                           | OFF (`module_network: false`) |
| **AES-256-GCM encryption**     | Chiffrement symétrique du payload avant envoi (clé 256 bits dérivée via PBKDF2 600k iterations)        | ALWAYS                |
| **HMAC-SHA256 signing**        | Signature de chaque requête (header `X-Signature`), anti-replay 60s, rotation clé périodique          | ALWAYS                |
| **WAL fallback**               | Write-ahead log chiffré sur disque, activé quand le buffer in-memory est plein ou que le central est down | ALWAYS                |
| **Sender batcher (T14.0)**     | Drain batch en 1 lock, dedup 60s, adaptive batch size (100-1000 events selon latence), priority reorder (opt-in), coalesce (opt-in), 207 partial-success (opt-in) | ALWAYS (sauf opt-ins) |
| **HMAC nonce** (T14.1, opt-in) | Ajout d'un `X-Nonce` header pour replay defense côté central (Redis SET)                              | OFF (`hmac_nonce_enabled: false`) |
| **Heartbeat**                  | Envoi périodique d'un heartbeat (intervalle configurable) avec stats FIM/eBPF/YARA                     | ON (`heartbeat.interval_sec: 60`) |
| **AppArmor confinement**       | Profil AppArmor dédié (généré dynamiquement à partir de `fim.watch_paths` et `scan_paths` à l'install) | ALWAYS                |
| **Privilege separation** (T13) | Process principal root → fork setuid `logsoc` user pour WAL + helper setuid pour BPF/FIM/journald   | ALWAYS                |
| **Hot-reload config**          | Rechargement à chaud de `log_level`, `heartbeat_interval_sec`, `scan_paths`, `watch_paths`, `journald_exclude_ids` (envoi SIGHUP) | ALWAYS                |

## Architecture

```
                 ┌─────────────────────┐
                 │  Noyau Linux        │
                 │  (kprobes, XDP)     │
                 └──────────┬──────────┘
                            │ events (ring buffer)
                 ┌──────────▼──────────┐
                 │  Process root       │ ← setuid helper for BPF/FIM/journald open
                 │  (full privilege)   │
                 └──────────┬──────────┘
                            │ fork+setuid (T13)
                 ┌──────────▼──────────┐
                 │  Process logsoc     │ ← WAL writer, FIM poller, network detector
                 │  (unprivileged)     │
                 └──────────┬──────────┘
                            │ shared buffer + FIM queue
                 ┌──────────▼──────────┐
                 │  Sender (single     │ ← InMemoryBuffer + FallbackWAL
                 │  thread)            │   dedup 60s, adaptive batch, priority, coalesce
                 └──────────┬──────────┘       ↓ HMAC + AES-256-GCM
                            │ HTTPS POST /api/v1/events/
                 ┌──────────▼──────────┐
                 │  Central (log-web)  │ ← correlate, score, alert, persist
                 └─────────────────────┘
```

**Points clés** :
- **Single-threaded sender** : pas de race conditions, ordonnancement déterministe
- **Lock-free collectors** : chaque collector pousse dans un ring buffer SPSC
- **WAL en privilege separation** : le process unprivileged écrit, le process root lit
- **Aucune dépendance à un orchestrateur** : systemd unit seulement

## Prérequis

### OS supportés

- **Debian 11+ (bullseye+)**
- **Ubuntu 20.04+ (focal+)**
- **RHEL 8+ / Rocky Linux 8+** (build .rpm)
- **Kernel Linux 5.4+** (eBPF kprobes + ring buffer)

### Outils de build

```bash
# Debian / Ubuntu
sudo apt install -y \
    build-essential g++ make cmake \
    libpcap-dev libssl-dev libcurl4-openssl-dev \
    libsystemd-dev libelf-dev zlib1g-dev \
    libbpf-dev libyara-dev \
    libmnl-dev libnftnl-dev \
    dpkg-dev fakeroot
```

```bash
# RHEL / Rocky
sudo dnf install -y \
    gcc gcc-c++ make cmake \
    libpcap-devel openssl-devel libcurl-devel \
    systemd-devel elfutils-libelf-devel zlib-devel \
    libbpf-devel yara-devel \
    libmnl-devel libnftnl-devel \
    rpm-build fakeroot
```

### Dépendances runtime (paquet .deb)

```
libc6 (>= 2.31), libcurl4 (>= 7.68), libssl3 (>= 3.0) | libssl1.1 (>= 1.1.1),
libpcap0.8 (>= 1.9), libbpf1 (>= 1.3.0), libyara10 (>= 4.5), systemd
```

Recommandés : `libcap2-bin` (setuid), `apparmor` (confinement).
Suggérés : `logrotate` (rotation WAL).

## Installation

### 5.1 Build par compilation

#### Build local (binaire dynamique)

```bash
git clone <repo>  # ou tarball source
cd <repo>/src
make
# Sortie : ./soc_agent (dynamique, ~2.4 MB)
```

#### Build statique (compatibilité maximale)

```bash
cd src
make static_soc_agent
# Sortie : ./static_soc_agent (statique glibc+stdc++, 2.7 MB)
```

Le binaire statique est lié avec `-static-libgcc -static-libstdc++` et
**toujours** `-Wl,-z,relro,-z,now` (Full RELRO). Compatible Ubuntu 20.04+
et Debian 11+ sans dépendance GCC runtime.

#### Options de build (Makefile)

| Variable     | Défaut       | Effet                                                                  |
|--------------|--------------|------------------------------------------------------------------------|
| `CXX`        | `g++`        | Compilateur (clang++ accepté)                                          |
| `CXXFLAGS`   | `-O2 -Wall -Wextra -Werror` | Flags C++. `-Werror` obligatoire en CI                  |
| `LDFLAGS`    | (auto)       | Flags de link (Full RELRO, BIND_NOW, gc-sections)                      |
| `STATIC`     | (auto)       | Link statique (libgcc+libstdc++)                                       |
| `DOCKER_BUILD` | 0          | Cross-compile glibc 2.31 (Ubuntu 20.04 base) pour .deb multi-distro  |

#### Test après build

```bash
# Test unitaire (~10s)
cd tests
make test

# Memory safety (valgrind + ASan, ~3-5 min)
cd ..
bash scripts/ci-memcheck.sh

# Fuzzing smoke (clang requis, ~10s)
bash scripts/fuzz.sh smoke
```

#### Build Docker universel

```bash
cd src
make docker_build
# Produit .deb et .rpm dans ../packaging/ (compatibles Ubuntu 20.04+,
# Debian 11+, RHEL 8+)
```

### 5.2 Package .deb

#### Build du .deb (sans Docker)

```bash
cd <repo>
VERSION=4.8.17 bash packaging/scripts/build-deb.sh
# Sortie : packaging/logsoc-agent_4.8.17_amd64.deb
```

Le script :
1. Compile `static_soc_agent` (cible `static_soc_agent` du Makefile)
2. Assemble l'arborescence `packaging/debian/`
3. Exécute `dpkg-deb --build`
4. Vérifie la présence des artefacts obligatoires (`/usr/bin/logsoc-agent`,
   `/etc/logsoc-agent/config.json`, profil AppArmor)

#### Contenu du .deb

```
/usr/bin/logsoc-agent                         # binaire statique, mode 0755
/usr/bin/logsoc-agent-helper                  # setuid root helper (T13)
/usr/share/logsoc-agent/generate_apparmor_local.py  # générateur profil AppArmor dynamique
/etc/logsoc-agent/config.json                 # config par défaut
/etc/logsoc-agent/config.json.example         # config commentée
/etc/logsoc-agent/pid_exclusions.json         # PIDs à ignorer (cron, systemd)
/etc/logsoc-agent/action_allowlist.json       # actions autorisées (T12)
/etc/logsoc-agent/rules_allowlist.json        # règles YARA pré-approuvées
/etc/apparmor.d/usr.bin.logsoc-agent          # profil AppArmor (généré à l'install)
/etc/sysctl.d/99-logsoc.conf                  # perf_event_paranoid=2, etc.
/etc/logrotate.d/logsoc-agent                 # rotation WAL
/lib/systemd/system/logsoc-agent.service      # unit systemd
/var/lib/logsoc-agent/                        # data dir (créé au postinst)
```

#### Install du .deb

```bash
# Install (NEEDRESTART vars pour éviter hang postinst)
sudo NEEDRESTART_SUSPEND=1 NEEDRESTART_MODE=l \
     DEBIAN_FRONTEND=noninteractive \
     apt install ./logsoc-agent_4.8.17_amd64.deb

# Le postinst :
#   1. Crée le user `logsoc` (système) si manquant
#   2. setuid le helper → /usr/bin/logsoc-agent-helper
#   3. Génère le profil AppArmor local (à partir de fim.watch_paths)
#   4. Recharge le profil en complain mode
#   5. Écrit /var/lib/logsoc-agent/install.sha256 (intégrité)
```

#### Pitfalls d'install

- **`agent.identity` ownership** : dpkg peut reset le owner à
  `logsoc:logsoc`. Toujours faire `sudo chown root:root
  /var/lib/logsoc-agent/agent.identity` après install.
- **`NEEDRESTART_*` env vars** : sans elles, le postinst peut hang
  sur demande de restart de service (systemd `needrestart` hook).
- **dpkg lock** : si un autre process tient le lock, attendre ou
  `sudo kill -9 <dpkg_pid>` puis réessayer.

#### Désinstall

```bash
sudo apt remove logsoc-agent
# Garde /var/lib/logsoc-agent/ (WAL) par défaut — purge explicite nécessaire :
sudo apt purge logsoc-agent
```

## Configuration minimale

Éditer `/etc/logsoc-agent/config.json` avant de démarrer :

```json
{
  "central_url": "https://central.example.com",
  "module_ebpf": true,
  "module_journald": true,
  "enabled_probes": {
    "execve": true,
    "open": true,
    "unlink": true,
    "fim": true,
    "tcp_connect": true,
    "write": false
  },
  "fim": {
    "watch_paths": [
      "/etc/passwd", "/etc/shadow", "/etc/sudoers",
      "/etc/ssh/", "/etc/cron*", "/root/.ssh/"
    ]
  }
}
```

Documentation complète : [doc/configuration.md](doc/configuration.md).

## Démarrage du service

```bash
# Start + enable au boot
sudo systemctl enable --now logsoc-agent

# Status
systemctl status logsoc-agent

# Logs en temps réel
sudo journalctl -u logsoc-agent -f

# Vérification rapide (events flow → central)
sudo journalctl -u logsoc-agent -n 50 | grep SENDER
# Attendu : "[SENDER] POST https://central.example.com/api/v1/events/ => HTTP 201"
```

## Documentation complémentaire

| Document                                                | Contenu                                                                |
|---------------------------------------------------------|------------------------------------------------------------------------|
| [doc/configuration.md](doc/configuration.md)            | Référence exhaustive de chaque option de `config.json`                 |
| [doc/developer-backend.md](doc/developer-backend.md)    | Contrat wire-protocol agent ↔ central (pour dev backend)              |
| [CHANGELOG.md](CHANGELOG.md)                            | Historique des versions (breaking changes, fixes, features)            |
| [docs/adr/](docs/adr/)                                  | Architecture Decision Records (FIM backend, privilege separation, etc.) |
| [docs/decisions/](docs/decisions/)                      | Décisions techniques (AppArmor FIM, XDP, YARA HQ)                       |
| [docs/runbook-fim-v4.8.md](docs/runbook-fim-v4.8.md)   | Runbook opérationnel FIM (debug, perf, cas de panne)                   |

## Bibliothèques tierces et licences

L'agent est **propriétaire** (voir [LICENSE](#license) ci-dessous). Les
bibliothèques tierces utilisées sont sous leurs licences open-source
respectives :

| Bibliothèque                     | Version min | Rôle                                              | Licence                  | URL                                                                                       |
|----------------------------------|-------------|---------------------------------------------------|--------------------------|-------------------------------------------------------------------------------------------|
| **libcurl**                      | 7.68        | Client HTTPS (envoi batches au central)           | MIT (curl license)       | https://curl.se/docs/copyright.html                                                       |
| **OpenSSL** (libssl + libcrypto) | 1.1.1 / 3.0 | AES-256-GCM, HMAC-SHA256, PBKDF2, SHA-256, base64 | Apache License 2.0       | https://www.openssl.org/source/license.html                                               |
| **libpcap**                      | 1.9         | Capture réseau userspace                          | BSD 3-Clause             | https://github.com/the-tcpdump-group/libpcap/blob/master/LICENSE                           |
| **libbpf**                       | 1.3         | Loader eBPF (sondes kernel)                       | LGPL-2.1 OR BSD-2-Clause | https://github.com/libbpf/libbpf/blob/master/LICENSE                                       |
| **libelf** (elfutils)            | (system)    | Parsing BPF ELF objects (transitive via libbpf)   | LGPL-2.1+                | https://sourceware.org/elfutils/                                                          |
| **zlib**                         | (system)    | Compression BPF objects (transitive via libbpf)    | zlib License             | https://www.zlib.net/zlib_license.html                                                    |
| **libsystemd** (sd-journal)      | 245         | Lecture journald                                  | LGPL-2.1+                | https://github.com/systemd/systemd/blob/main/LICENSE.LGPL2.1                              |
| **libyara**                      | 4.5         | Moteur YARA (scan fichiers/mémoire/réseau/logs)   | BSD 3-Clause             | https://github.com/VirusTotal/yara/blob/master/LICENSE                                     |
| **libmnl**                       | (system)    | Netlink userspace (transitive via libbpf)         | LGPL-2.1+                | https://netfilter.org/projects/libmnl/                                                    |
| **libnftnl**                     | (system)    | nftables netlink (transitive via libbpf)          | GPL-2.0+                 | https://netfilter.org/projects/libnftnl/                                                  |
| **libcap2**                      | 2.x         | setuid privilege separation (T13)                 | BSD 3-Clause OR GPL-2    | https://sites.google.com/site/fullycapable/                                               |
| **libc / glibc**                 | 2.31+       | C runtime                                         | LGPL-2.1+                | https://www.gnu.org/software/libc/                                                        |
| **libstdc++ (GCC runtime)**      | 7+          | C++ runtime                                       | GPL-3+ with GCC Runtime Library Exception | https://gcc.gnu.org/onlinedocs/libstdc++/manual/license.html            |

### Note sur le linking (LGPL compliance)

L'agent est lié dynamiquement à **libbpf**, **libsystemd** et **libc** (LGPL-2.1+).
La LGPL impose que l'utilisateur puisse **re-lier** avec une version modifiée
de ces bibliothèques. C'est garanti par le link dynamique standard du
paquet `.deb` par défaut (cible `soc_agent` du Makefile, pas
`static_soc_agent`).

Le binaire **statique** `static_soc_agent` (cible alternative du Makefile)
est destiné aux environnements Docker/CI sans dépendance système, ou aux
paquets `.deb` avec `LDFLAGS+=-static` (Docker build). Pour distribuer
un binaire statique en LGPL compliance, il faut livrer les sources de
ces libs LGPL ou un mécanisme de re-linking équivalent (script
`ld`-wrapper fourni dans `packaging/scripts/`).

### Note sur AppArmor / seccomp

Les profils **AppArmor** (`/etc/apparmor.d/usr.bin.logsoc-agent`) et les
règles **seccomp** ne sont **pas des dépendances linkées** : ce sont des
artefacts de configuration policy-based livrés dans le paquet. Ils
n'affectent pas la licence de l'agent.

## License

**Propriétaire** — © 2026 LogSOC-AI. Tous droits réservés.

Code source non publié. Distribution binaire uniquement (paquets `.deb` /
`.rpm`). Pour les termes complets de redistribution, contacter
l'éditeur.

---

**Mainteneur** : LogSOC-AI Engineering
**Repo** : voir `git remote -v` dans votre clone
**Issues** : voir le tracker de votre plateforme (Gitea / GitLab / GitHub)
