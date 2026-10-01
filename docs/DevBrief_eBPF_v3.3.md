# Dev Brief — eBPF v3.3 : Zero-Loss + Security + YARA

> Soumission courte pour l'équipe dev C++ / backend PHP  
> Basé sur l'audit complet : `docs/EBPF_YARA_Security_Proposal.md`

---

## 1. PROBLÈMES CONFIRMÉS (code source v3.2.5-fix6)

| # | Problème | Où | Gravité |
|---|----------|-----|---------|
| 1 | Ringbuf 256KB × 4 = perte events sous burst I/O | `skel_*.c` | **CRITIQUE** |
| 2 | Poll sleep(100ms) = milliers d'events dropés | `agent.cpp:379` | **CRITIQUE** |
| 3 | Pas de compteurs drops = on ne sait pas combien on perd | Absent | **CRITIQUE** |
| 4 | Queue userspace `deque<string>` illimitée = risque OOM | `loader.cpp:54` | **HAUTE** |
| 5 | Args execve en clair (password CLI visible) | `loader.cpp:86-96` | **HAUTE** |
| 6 | Self-capture agent (boucle feedback WAL) | Absent | **MOYENNE** |
| 7 | Pas de rate-limit PID (fork-bomb DoS ringbuf) | Absent | **MOYENNE** |

---

## 2. FEUILLE DE ROUTE 3 PHASES

### Phase 1 — Zero Loss (2-3 jours)
**Objectif** : < 0.1% perte, comptabilisée

- **Ringbuf fusionné** : 1 seul ringbuf 8-32MB (configurable), remplace les 4×256KB
- **Poll bloquant** : Thread dédié `ring_buffer__poll(rb, -1)`, pas de sleep
- **Queue bornée** : `deque<RawEvent>` max 10k, drop oldest si overflow
- **Compteurs drops** : `BPF_MAP_TYPE_ARRAY` lu toutes les 5s, reporté dans heartbeat

### Phase 2 — Security Hardening (2 jours)
**Objectif** : Pas de fuite, pas de DoS

- **Self-exclusion PID** : bpf map `agent_pid`, skip si current PID == agent PID
- **Rate-limit** : LRU hash `(pid, type)` → max 100 evt/sec par process
- **Redaction args** : Pattern-match `--password`, `-p`, etc. → `[REDACTED]` avant JSON
- **bpf_core_read()** : Remplace `bpf_probe_read_kernel` direct pour bounds-check CO-RE

### Phase 3 — Nouvelles probes + YARA HQ (7-9 jours)
**Objectif** : Couverture maximale, threat intel enrichi

**Nouvelles probes (kernel)** :
| Probe | Données | Risque perte |
|-------|---------|--------------|
| `tcp_close` | Durée, bytes RX/TX | Faible |
| `tcp_drop` | Scan/DoS détection | Très faible |
| `udp_sendmsg` | DNS exfiltration | Moyen |
| `security_socket_bind` | Nouveaux services | Très faible |
| `security_file_open` | Read+write (pas juste write) | Moyen |
| `do_fork` | Création processus | Faible |

> **Full packet capture** (`tc`/`XDP`) : Nécessite sampling (1:N) — à discuter si besoin réel.

**YARA HQ côté CENTRAL** :
- Worker PHP `yara_sync.php` pull depuis https://yarahq.github.io/ régulièrement
- Stockage rules dans `/var/lib/logsoc/yara-rules/`
- Scan temps réel des `execve.args` + `file_open.filename` via `libyara`
- Corrélation → table `alerts` ClickHouse avec score 0-100
- Config agent : `yara.enabled`, `scan_execve_args`, `auto_update_interval_hours`

---

## 3. FICHIERS À MODIFIER / CRÉER

| Fichier | Action |
|---------|--------|
| `src/ebpf/loader.cpp` | Refonte complète |
| `src/ebpf/loader.hpp` | API `get_drop_stats()`, `set_agent_pid()` |
| `src/ebpf/skel_merged.c` | **NOUVEAU** : 1 objet BPF, toutes probes |
| `src/ebpf/skel_*.c` (4 legacy) | Suppression après validation |
| `src/ebpf/event.h` | `drop_stats`, `agent_pid` maps |
| `src/agent.cpp` | Config YARA, heartbeat drop stats |
| `src/api/agents/heartbeat.php` | Recevoir + stocker drop stats |
| `src/workers/yara_sync.php` | **NOUVEAU** pull YARA HQ |
| `packaging/scripts/build-deb.sh` | Ajout `libyara-dev` si P3 inclus |

---

## 4. QUESTIONS POUR PRIORISATION

1. **RAM agent** : Quelle taille ringbuf par défaut ? (8MB / 32MB ?)
2. **Rate-limit** : 100 evt/sec/PID — OK ou trop strict pour CI/CD ?
3. **tc/XDP** : Besoin de capture 100% paquets ou tcp_connect/close suffisent ?
4. **YARA** : Toutes les rules HQ (~5000) ou subset ciblé (malware, apt, ransomware) ?
5. **Redaction** : Liste de mots-clés sensibles à valider côté compliance ?

---

## 5. DÉCISION ATTENDUE

| Option | Charge | Gain |
|--------|--------|------|
| A. P1 seule (zero-loss) | 2-3j | Fiabilité eBPF |
| B. P1 + P2 (zero-loss + security) | 4-5j | Fiabilité + sécurité |
| C. P1 + P2 + P3-I (nouvelles probes) | 7-9j | Couverture complète |
| D. Full (P1+P2+P3-I+P3-J YARA) | 11-14j | SOC enterprise-grade |

**Recommandation** : Option B minimum (P1+P2). Option D si timeline le permet.

---

*Répondre par option choisie (A/B/C/D) + réponses aux 5 questions. On découpe en tickets ensuite.*
