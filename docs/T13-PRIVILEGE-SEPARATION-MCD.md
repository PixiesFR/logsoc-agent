# T13 — Privilege Separation (MCD)

**Date** : 2026-06-16
**Statut** : PROPOSITION — attend GO user avant code
**Cible** : `4.8.0-t13.0` (breaking change — version bump à 5.0.0 envisagé)

---

## 1. Problème

L'agent actuel (`4.8.0-t12.15`) tourne **100% en root** avec toutes les capabilities Linux nécessaires (eBPF, perfmon, net_raw, net_admin, sys_admin, dac_override, dac_read_search). Le profil AppArmor est `/** r` (lecture totale du FS). Conséquences :

- Un bug dans n'importe quel module = root compromise
- Une RCE dans le code YARA scanner = root + accès à tout le FS
- L'audit Nova 2026-06-16 C-03 (AppArmor permissif) et C-05 (serveur HTTP YARA) sont bloquants

## 2. Cible (1 binaire, multi-process)

L'agent reste **1 seul binaire** (`/usr/bin/logsoc-agent`) mais se **décompose en 4 processus** au démarrage via `fork()` :

```
                  logsoc-agent (master / root temporaire)
                              |
            +-----------------+-----------------+----------+
            |                 |                 |          |
            v                 v                 v          v
       [P1: root]        [P2: logsoc]      [P3: logsoc]  [P4: root]
       COLLECTOR_ROOT    SENDER            FIM_YARA      ACTION
       (capabilités      (aucune)          (dac_read)    (cap net_admin,
        eBPF+pcap)                                          kill, sys_module)
            |                 ^                 ^            |
            +--socket unix-->+<--socket unix--+<-----------+
            |   FIM events   |   YARA results |   actions
            |   via FIFO/SHM via FIFO/SHM    |   via FIFO
            v
       [buf partagé WAL — owned by logsoc]
```

### 2.1. Process 1 : `COLLECTOR_ROOT` (root temporaire)
- **Durée de vie** : permanente
- **Capabilities après fork** : `CAP_BPF CAP_PERFMON CAP_NET_RAW CAP_SYS_ADMIN CAP_DAC_OVERRIDE CAP_DAC_READ_SEARCH`
- **Role** :
  - Charge les programmes eBPF dans le kernel
  - Ouvre la socket pcap (libpcap)
  - Init fanotify (cap SYS_ADMIN, absolu paths)
  - Lit les events du ringbuf kernel
  - **Filtre** les events (rate limit, severity, ignore list)
  - Sérialise en JSON et **envoie** via socket unix au P2 (SENDER) ou P3 (FIM_YARA)
- **Capabilities dropped après init** : peut dropper `CAP_SYS_ADMIN` après `fanotify_init` réussi (mais on garde pour rmmod via P4)
- **PAS de** : filesystem write (sauf SHM/FIFO), `open()` direct de fichiers user, exécution de commandes

### 2.2. Process 2 : `SENDER` (logsoc user)
- **Durée de vie** : permanente
- **UID/GID** : `logsoc:logsoc` (drop avant init)
- **Capabilities** : AUCUNE (`CapabilityBoundingSet=`)
- **Role** :
  - Reçoit les events JSON depuis P1 + P3 + P4 via socket unix
  - Écrit dans le WAL (AES-256-GCM) — `/var/lib/logsoc-agent/wal/`
  - Flush périodique vers le central via HTTPS (libcurl, TLS pinning)
  - Heartbeat vers le central
  - Reçoit les pending_actions du central, **dispatche** vers P4 (action executor) via FIFO
- **PAS de** : raw socket, eBPF, accès /proc/<pid>/mem, pcap

### 2.3. Process 3 : `FIM_YARA` (logsoc user, cap dac_read_search)
- **Durée de vie** : permanente
- **UID/GID** : `logsoc:logsoc`
- **Capabilities** : `CAP_DAC_READ_SEARCH` (seule)
- **Role** :
  - Reçoit les events FIM (open/unlink) depuis P1
  - Résout les chemins via `/proc/<pid>/fd/*` et `readlinkat`
  - **Lit le contenu des fichiers** surveillés (FIM scan complet)
  - Exécute YARA sur le contenu
  - Sérialise les résultats et envoie à P2 (SENDER)
- **PAS de** : écriture filesystem (sauf tmp), exécution, eBPF, pcap

### 2.4. Process 4 : `ACTION` (root temporaire, drop après chaque action)
- **Durée de vie** : permanente (idle)
- **UID/GID** : root au boot, drop à logsoc après init
- **Capabilities au moment de l'action** : remonte temporairement `CAP_NET_ADMIN CAP_KILL CAP_SYS_MODULE`
- **Role** :
  - Reçoit les pending_actions via FIFO depuis P2
  - Acquiert les caps nécessaires, exécute (kill / nft add / rmmod / etc.)
  - **Drop les caps** immédiatement après
  - Envoie le résultat (status + stdout + duration) à P2
- **PAS de** : capture réseau, eBPF, lecture fichier user

### 2.5. Process 0 : `MASTER` (parent de tous)
- **UID** : root au boot
- **Role** :
  - Parse la config
  - `fork()` × 4 enfants
  - Setuid/setgid chaque enfant
  - Set capabilities chaque enfant
  - **Devient un watchdog** : si un enfant meurt, restart, si crash répété → stop all et exit
  - Gère SIGHUP → SIGHUP aux enfants → reload config
  - Reçoit SIGTERM → forward aux enfants, attend exit propre, exit

## 3. Communication inter-process

| Sens | Mécanisme | Justification |
|------|-----------|---------------|
| P1 → P2 (events normaux) | Unix domain socket `SOCK_SEQPACKET` | Fiable, message-oriented, bas overhead |
| P1 → P3 (FIM events) | Unix domain socket dédié | Sépare le trafic FIM (haut volume) du trafic normal |
| P3 → P2 (YARA results) | Unix domain socket | idem |
| P2 → P4 (pending_actions) | FIFO nommé | Sens unique, faible volume, simple |
| P4 → P2 (action results) | Unix domain socket | idem P3→P2 |
| P0 ↔ enfants (control) | Pipe par enfant + signal (SIGHUP reload) | Pas de polling |

**Sockets dans** `/run/logsoc-agent/` (tmpfs, owned by root) avec perms 0660 + group `logsoc`. **PAS** dans `/tmp` (attaquable par users locaux).

## 4. Capabilities par processus (matrice)

| Cap | P1 (collector) | P2 (sender) | P3 (fim_yara) | P4 (action) |
|-----|----------------|-------------|---------------|-------------|
| `CAP_BPF` | ✓ (eBPF load) | ✗ | ✗ | ✗ |
| `CAP_PERFMON` | ✓ (perf events) | ✗ | ✗ | ✗ |
| `CAP_NET_RAW` | ✓ (pcap) | ✗ | ✗ | ✗ |
| `CAP_NET_ADMIN` | ✗ | ✗ | ✗ | ✓ (block_ip nft) |
| `CAP_KILL` (= CAP_SYS_PTRACE ?) | ✗ | ✗ | ✗ | ✓ (kill_pid) |
| `CAP_SYS_MODULE` | ✗ | ✗ | ✗ | ✓ (rmmod) |
| `CAP_SYS_ADMIN` | ✓ (fanotify_init) | ✗ | ✗ | ✗ |
| `CAP_DAC_OVERRIDE` | ✓ (bypass file perms en walk) | ✗ | ✗ | ✗ |
| `CAP_DAC_READ_SEARCH` | ✓ | ✗ | ✓ (YARA read) | ✗ |
| `CAP_SETUID/SETGID` | init only | init only | init only | init only |

`AmbientCapabilities=` et `CapabilityBoundingSet=` seront réécrites en conséquence. `NoNewPrivileges=true` partout (P2/P3 impératif, P1/P4 désactivé pendant init puis réactivé).

## 5. AppArmor dynamique

Le profil est **généré au démarrage** par P0 (root) à partir de `config.json` :

```
/usr/bin/logsoc-agent-collector { ... }     # capabilities bpf/perfmon/raw, /** r limité aux scan_paths
/usr/bin/logsoc-agent-fim { ... }           # dac_read_search, lecture scan_paths uniquement
/usr/bin/logsoc-agent-sender { ... }        # AUCUNE capability, write /var/lib/logsoc-agent/ seulement
/usr/bin/logsoc-agent-action { ... }        # cap net_admin/kill/sys_module, ** r
```

**Mais** : on a 1 seul binaire `/usr/bin/logsoc-agent`. Solution : **4 hardlinks** ou **4 symlinks** vers le même binaire, et AppArmor utilise le **basename** du binaire (`/usr/bin/logsoc-agent-collector`). Le programme inspecte `argv[0]` (ou un `--role=collector` flag) pour savoir quel rôle tenir.

Alternative plus simple : **1 binaire, 4 profils AppArmor, switch via `execve()`** au démarrage de chaque enfant. Chaque enfant s'exécute via `execve("/proc/self/exe", {"logsoc-agent", "--role=collector", ...}, envp)`. Le **binaire reste 1 fichier** mais le **process image change** (chaque rôle a son propre exec). AppArmor distingue par `execve()` et applique le profil correspondant au basename.

Reload config (SIGHUP) :
1. P0 reçoit SIGHUP
2. P0 relit config.json
3. P0 régénère les profils AppArmor
4. P0 reload via `apparmor_parser -r`
5. P0 SIGHUP aux enfants
6. Chaque enfant re-init son rôle

## 6. Plan d'implémentation (sprints T13.x)

### T13.0 — MCD (ce document, 30 min)
Validation user sur l'arch.

### T13.1 — PoC mono-zone (2-3h)
- Fork simple : P0 → P1 (collector) et P0 → P2 (sender) uniquement
- Communication via 1 socket unix
- FIM et YARA restent dans P1 pour le PoC
- **But** : valider le pattern fork + setuid + capability drop
- **Test** : `strings /proc/<pid>/status | grep -E 'Cap|Uid'` doit montrer Uid=65534 (nobody) pour P2

### T13.2 — Généralisation 4 zones (1-2 jours)
- Ajout P3 (FIM_YARA séparé) et P4 (ACTION séparé)
- 4 sockets unix + 1 FIFO
- Capabilities matrix complète
- Watchdog dans P0

### T13.3 — AppArmor dynamique (1 jour)
- Script `apparmor-gen.sh` (ou code dans P0) qui lit config.json + écrit les 4 profils
- `apparmor_parser -r` au boot
- SIGHUP → regen + reload

### T13.4 — Service unit + packaging (2-3h)
- `logsoc-agent.service` : `User=root` (toujours, pour P0), mais `ExecStart=` lance en mode multi-process
- Suppression des capabilities globales : `CapabilityBoundingSet=` vide, chaque enfant drop explicitement
- `NoNewPrivileges=true` sur P2/P3
- Hardlinks `/usr/bin/logsoc-agent-{collector,fim,sender,action}` → même binaire

### T13.5 — Tests E2E par zone (1 jour)
- Test 1 : P2 (sender) compromis ne peut PAS lire /etc/shadow (AppArmor deny)
- Test 2 : P3 (fim_yara) compromis ne peut PAS écrire dans /var/lib/logsoc-agent/
- Test 3 : P4 (action) idle ne tient PAS les capabilities (vérifier `/proc/<pid>/status` CapEff)
- Test 4 : P0 crash → tous les enfants s'arrêtent proprement (watchdog)

### T13.6 — Deploy Hestia + R5 (1h)
- `dpkg -i` upgrade (breaking change → version bump 5.0.0)
- R5 retro-validate : `ps -ef` montre 5 processus, `CapEff` correct par process, `/var/log/syslog` propre
- Backout plan : downgrade en `4.8.0-t12.15`

## 7. Risques

| Risque | Impact | Mitigation |
|--------|--------|-----------|
| Fork casse un état partagé (file descriptors, threads) | Crash au boot | P0 ferme tout FD sauf stdin/stdout/stderr avant fork ; les enfants réouvrent ce dont ils ont besoin |
| Socket unix permissions | Local attacker spoof | `0660` + group `logsoc`, owner `root` ; vérifier via `stat()` à l'ouverture (pattern R3) |
| SIGHUP reload ne propage pas aux enfants | Config pas rechargée | P0 SIGHUP aux 4 PIDs enfants + waitpid loop |
| Watchdog P0 peut lui-même crasher | Tout meurt | systemd `Restart=always` sur P0 ; enfants = orphans, systemd les adopte via cgroup |
| Breaking change : users qui appellent `logsoc-agent --flag` | API change | Garder les anciens flags en mode "single-process" (legacy), nouveau mode = `--role=<auto-detected>` |
| Performance overhead (4 procs au lieu de 1) | -2% à -5% | Sockets SOCK_SEQPACKET sont ~3x plus rapides que TCP loopback ; zéro copy possible |
| Complexité debugging (5 PIDs dans les logs) | Ops friction | SyslogIdentifier par rôle : `logsoc-agent-collector`, etc. |

## 8. Critères d'acceptance

- [ ] `ps -ef | grep logsoc-agent` montre 5 processus (P0 + 4 enfants)
- [ ] `cat /proc/<pid>/status | grep -E 'Uid|CapEff'` montre :
  - P0 : `Uid: 0 0 0 0`, `CapEff: 00000000a80425fb` (full root caps)
  - P1 : `Uid: 0 0 0 0`, `CapEff: <subset bpf+perfmon+raw+sysadmin+dac>`
  - P2 : `Uid: 65534 65534 65534 65534` (nobody), `CapEff: 0000000000000000`
  - P3 : `Uid: 65534 65534 65534 65534`, `CapEff: 0000000000000002` (dac_read_search)
  - P4 : `Uid: 0 0 0 0` mais `CapEff: 0000000000000000` (idle, drop après init)
- [ ] `aa-status` montre 4 profils `logsoc-agent-*` loaded
- [ ] `strings /usr/bin/logsoc-agent | grep T13` retourne du texte (build marker)
- [ ] Le test de régression YARA fonctionne (file scan, rule pull, match post)
- [ ] Le test de régression FIM fonctionne (open, unlink, file read, ship)
- [ ] Le test de régression action fonctionne (kill, block_ip, rmmod, dry_run)
- [ ] `dpkg -i` upgrade depuis 4.8.0-t12.15 → 5.0.0 sans perte de config

## 9. Rollback

Si T13 casse en prod Hestia :
1. `sudo systemctl stop logsoc-agent`
2. `sudo dpkg -i /var/cache/logsoc-agent_4.8.0-t12.15_amd64.deb` (downgrade)
3. `sudo systemctl start logsoc-agent`
4. Investiguer offline

Le downgrade doit être **testé en pre-prod** avant le deploy (T13.5).

---

## 10. Décision requise

**Q1** — Tu valides l'arch (4 zones, multi-process fork) ?
**Q2** — On bump à `5.0.0` (breaking) ou on garde `4.8.0-t13.x` (experimental) ?
**Q3** — T13.1 (PoC 2 zones) d'abord, ou tu veux qu'on attaque T13.2 (4 zones) direct ?
**Q4** — Le critère d'acceptance des tests (T13.5) est suffisant ou tu veux ajouter d'autres checks ?

Pas de code touché tant que Q1 n'est pas validé. Le MCD est dans `docs/T13-PRIVILEGE-SEPARATION-MCD.md` pour relecture.
