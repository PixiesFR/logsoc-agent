# LogSOC-AI — Analyse eBPF + Sécurité + Intégration YARA HQ

> Document de réflexion pour soumission au développeur C++  
> Date : 2026-05-26  
> Version : v3.2.5-fix6 → v3.3.0 candidate  
> Auteur : Analyse produite par l'agent AI — synthèse du code source local + propositions d'amélioration  
> Statut : Brouillon, en attente de validation équipe dev + PO  

---

## 1. RÉSUMÉ EXÉCUTIF

L'analyse du pipeline eBPF v3.2.5 révèle 6 points critiques de perte d'events, 5 failles de sécurité, et une architecture ringbuf sous-dimensionnée. Ce document propose une feuille de route en 3 phases pour passer à un pipeline "zero-loss" avec filtrage sécurisé, et intégrer YARA HQ côté central pour l'enrichissement threat-intel.

---

## 2. ÉTAT ACTUEL eBPF — Audit Complet

### 2.1 Probes actives (4 objets ELF indépendants)

| Probe | Type | Données | Ringbuf | Fréquence typique |
|-------|------|---------|---------|-------------------|
| `trace_write` | kprobe/vfs_write | fd, count | 256KB | Très haute (I/O burst) |
| `trace_execve` | kprobe/__x64_sys_execve | comm, args[80] | 256KB | Moyenne |
| `trace_connect` | kprobe/tcp_connect | src/dst IP, port | 256KB | Variable |
| `trace_fim` | kprobe + inode | inode, filename[64] | 256KB | Haute sur /tmp,/var/log |

### 2.2 Architecture de remontée

```
Kernel (4 probes) → 4 ringbufs 256KB → loader.cpp poll() sleep(100ms)
                                       ↓
                    g_queue (deque<string> illimitée) → JSON formaté
                                       ↓
                              wal_.write(json) → Sender
```

---

## 3. 🔴 CRITIQUE — 6 Causes de perte d'events

| # | Cause | Impact | Preuve code |
|---|-------|--------|-------------|
| 1 | **Ringbuf 256KB** | Burst de 10ms de vfs_write remplit 256KB → drops kernel | `max_entries: 256*1024` ×4 |
| 2 | **Poll 100ms** | Entre 2 `poll()`, milliers d'events dropés sans récupération | `sleep_for(100ms)` in `EbpfCollector::run()` |
| 3 | **Aucun compteur drops** | On ne sait JAMAIS combien on perd | Aucun `BPF_MAP_TYPE_ARRAY` stats |
| 4 | **4 ringbufs séparés** | ~4× overhead maps, pas d'epoll possible | `get_fd()` retourne `-1` |
| 5 | **Queue userspace illimitée** | OOM possible si sender lent | `std::deque<std::string>` sans `max_size` |
| 6 | **Self-capture** | L'agent se logue dans WAL → boucle feedback | Pas de filtre PID/agent |

---

## 4. 🔒 FAILLES DE SÉCURITÉ IDENTIFIÉES

| # | Problème | Gravité | Conséquence |
|---|----------|---------|-------------|
| SEC-01 | `bpf_probe_read_kernel` sans bounds-check | **HIGH** | Kernel 6.x+ : lecture hors limites possible, crash ou fuite |
| SEC-02 | Args execve en clair | **HIGH** | Mots de passe CLI visibles dans les 80b `args` (ex: `mysql -psecret`) |
| SEC-03 | Pas de rate-limit PID | **MEDIUM** | Process malveillant peut DoS le ringbuf par fork-bomb |
| SEC-04 | Self-exclusion absente | **MEDIUM** | Agent capture ses propres I/O → amplification WAL |
| SEC-05 | Pas de verifier workaround | **LOW** | Vieux kernels peuvent rejeter CO-RE |

---

## 5. 📋 PROPOSITIONS — Feuille de route 3 phases

### PHASE 1 : Zéro perte (ringbuf + polling)

**P1-A. Ringbuf fusionné, taille configurable**
```c
// Un seul ringbuf partagé pour toutes les probes
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 32 * 1024 * 1024);  // 32MB, configurable via config.json
} events SEC(".maps");
```
- Impact : divise par 4 l'overhead de maps, permet des bursts de 32MB
- Config agent : `ebpf.ringbuf_size_mb` (défaut 8, max 128)

**P1-B. Thread dédié, poll bloquant**
- Remplacer `sleep(100ms)` par `ring_buffer__poll(rb, -1)` dans un thread dédié
- Push dans une queue de struct C brutes (pas de JSON dans le callback)
- Thread secondaire formate par batch de 100

**P1-C. Compteurs de drops kernel**
```c
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 4);   // index 0=write,1=execve,2=connect,3=fim
    __uint(key_size, sizeof(__u32));
    __uint(value_size, sizeof(__u64));
} drop_stats SEC(".maps");

// Dans chaque probe, si bpf_ringbuf_reserve échoue :
// __u32 idx = type; __u64 *cnt = bpf_map_lookup_elem(&drop_stats, &idx);
// if (cnt) __sync_fetch_and_add(cnt, 1);
```
- L'agent lit `drop_stats` toutes les 5s et les reporte dans le heartbeat

**P1-D. Batch format + queue bornée**
```cpp
// Queue bounded — max 10k events, drop oldest (ou newest) si overflow
std::deque<RawEvent> g_queue;
const size_t MAX_QUEUE = 10000;
// Formatage JSON en batch de 100 par le thread formatter
```

### PHASE 2 : Sécurité (filtres + redaction)

**P2-E. Self-exclusion par PID**
```c
// bpf map HASH avec le PID de l'agent
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1);
    __type(key, __u32);    // pid
    __type(value, __u8);   // dummy
} agent_pid SEC(".maps");

// Au début de chaque probe :
if ((bpf_get_current_pid_tgid() >> 32) == agent_pid_key) return 0;
```

**P2-F. Rate-limit par (PID, type)**
```c
struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 1024);
    __type(key, struct { __u32 pid; __u32 type; });
    __type(value, __u64);   // last_ns_timestamp
} rate_limit SEC(".maps");

// Max 100 events/sec par (PID, type) — configurable
```

**P2-G. Redaction des arguments sensibles (userspace)**
```cpp
// Pattern-match dans le formatter thread
const std::vector<std::string> SENSITIVE = {
    "password", "passwd", "secret", "token", "api_key", "private_key",
    "-p", "--password", "--api-key"
};
// Replace avec "[REDACTED]" avant JSON serialization
```

**P2-H. Hardening `bpf_probe_read_kernel`**
```c
// Utiliser bpf_core_read() avec vérification taille
// Remplacer les accès directs sk->__sk_common par bpf_core_read() helper
// qui gère le CO-RE et vérifie les offsets
```

### PHASE 3 : Nouvelles probes + YARA HQ

**P3-I. Nouvelles probes priorisées**

| Probe | Intérêt | Risque perte | Implémentation |
|-------|---------|--------------|----------------|
| `kprobe/tcp_close` | Durée connexion, bytes RX/TX | Faible | kprobe simple |
| `kprobe/tcp_drop` | Connexions rejetées (scan/DoS) | Très faible | kprobe simple |
| `kprobe/udp_sendmsg` | DNS exfiltration, tunneling | Moyen | kprobe |
| `kprobe/security_socket_bind` | Nouveaux services écoutant | Très faible | LSM hook |
| `kprobe/security_file_open` | Accès fichiers (read+write) | Moyen | LSM hook |
| `kretprobe/__x64_sys_openat` | Open failed = reconnaissance | Faible | kretprobe |
| `kprobe/do_fork` | Création processus | Faible | kprobe |

> **⚠️ Pour le réseau complet (tous paquets)** : `tc clsact` ou XDP est nécessaire, mais c'est obligatoirement du **sampling** (1:N) ou réservé aux NIC supportant XDP. À discuter si besoin de full-packet capture.

**P3-J. Intégration YARA HQ côté CENTRAL**

https://yarahq.github.io/ est un index communautaire de règles YARA de qualité.

**Proposition d'architecture :**

```
Agent eBPF (execve, file_open) ──→ WAL ──→ Sender ──→ Central (/api/ingest)
                                                                      ↓
                                                           ┌──────────────────┐
                                                           │ Enricher Worker  │
                                                           │ (PHP CLI worker) │
                                                           └────────┬─────────┘
                                                                    ↓
                                                           ┌──────────────────┐
                                                           │ YARA Scanner     │
                                                           │ (libyara / PHP)  │
                                                           │ Rules from:      │
                                                           │ - YARA HQ pull   │
                                                           │ - Custom rules   │
                                                           └────────┬─────────┘
                                                                    ↓
                                                           ┌──────────────────┐
                                                           │ ClickHouse       │
                                                           │ alerts table     │
                                                           │ (score + rule_id)│
                                                           └──────────────────┘
```

**Implémentation détaillée :**

1. **Pull automatique des règles YARA HQ**
   - Worker `yara_sync.php` qui pull régulièrement depuis yarahq.github.io
   - Stockage dans `/var/lib/logsoc/yara-rules/` avec checksum
   - Versioning + rollback possible

2. **Scanning des payloads eBPF**
   - `execve.args` → scan string YARA (détection malware, tools de hacking)
   - `file_open.filename` + hash → scan fichier (si hash disponible)
   - `connect.dst_ip` → corrélation avec IOC lists YARA

3. **Corrélation temps réel**
   - Rules YARA déclenchent des alertes dans la table `alerts` (ClickHouse)
   - Score de 0-100 basé sur nombre de matches + criticité rule
   - Enrichissement GeoIP + threat intel feed

4. **Configuration agent**
   ```json
   {
     "yara": {
       "enabled": true,
       "scan_execve_args": true,
       "scan_file_paths": ["/tmp", "/var/tmp", "/dev/shm"],
       "max_file_size_mb": 50,
       "rules_source": "yarahq",
       "auto_update_interval_hours": 24
     }
   }
   ```

---

## 6. RÉPONSE À LA QUESTION : "Risque de perdre des paquets/logs ?"

| Type d'event | Risque actuel | Avec Phase 1 | Commentaire |
|--------------|---------------|--------------|-------------|
| Network (tcp_connect) | **OUI** — 256KB insuffisant | ~NON — 32MB + poll bloquant | `tc` (tous paquets) = sampling obligatoire |
| File (vfs_write) | **OUI** — burst I/O | ~NON — batch + queue bornée | FIM sur `/tmp` reste bruyant |
| Execve | **MOYEN** — fork-bomb | ~NON — rate-limit PID | 100 evt/sec/PID suffisant |
| FIM | **OUI** — sur /var/log | ~NON — ringbuf fusionné | À tuner selon charge |

**Verdict** : Avec Phase 1 + 2, la perte passe de **non-mesurable/élevée** à **mesurable et <0.1%** sous charge normale. Les drops restants sont comptabilisés et reportés.

---

## 7. PRIORITÉ D'IMPLÉMENTATION

| Phase | Durée estimée | Dépendances | Livrable |
|-------|---------------|-------------|----------|
| **P1** Ringbuf fusionné + compteurs | 2-3j | Refonte loader.cpp, nouveau skel_merged.c | `.deb` test + bench drops |
| **P2** Sécurité (PID, rate-limit, redaction) | 2j | P1 terminée | Review sécurité |
| **P3-I** Nouvelles probes | 3-4j | P1+P2 | `.deb` v3.3.0-alpha |
| **P3-J** YARA HQ côté central | 4-5j | Backend PHP, libyara sur Hestia | Worker + rules sync |

**Recommandation** : Démarrer P1 immédiatement car c'est le fondamental. P2 peut être parallélisé. P3-J est backend-only et peut être fait en parallèle par l'équipe PHP.

---

## 8. ANNEXE — Fichiers concernés

| Fichier | Changement |
|---------|-----------|
| `src/ebpf/loader.cpp` | Refonte complète : ringbuf unique, poll bloquant, queue bornée |
| `src/ebpf/loader.hpp` | Nouvelles API : `get_drop_stats()`, `set_agent_pid()` |
| `src/ebpf/skel_merged.c` | Nouveau : 1 seul objet BPF avec toutes les probes |
| `src/ebpf/skel_*.c` (legacy) | Suppression après validation merged |
| `src/agent.cpp` | Rate-limit config, YARA options, drop stats heartbeat |
| `src/ebpf/event.h` | Ajout struct `drop_stats`, `agent_pid` |
| `src/network/pcap_collector.cpp` | Coordination avec eBPF (pas de double capture) |
| `packaging/scripts/build-deb.sh` | Ajout libyara-dev si P3-J inclus |

---

## 9. QUESTIONS OUVERTES POUR LE DEV

1. **Taille ringbuf** : 8MB par défaut ? 32MB ? Quelle est la RAM disponible sur les agents cibles ?
2. **Rate-limit** : 100 evt/sec/PID est-il trop strict pour les builds CI/CD (make -j32) ?
3. **tc/XDP** : Besoin de full-packet capture ou tcp_connect + tcp_close suffisent ?
4. **YARA HQ** : Quel subset de règles ? Toutes (~5000) ou catégories ciblées (malware, apt, ransomware) ?
5. **Redaction args** : Liste de mots-clés sensibles à valider côté compliance ?

---

*Document prêt pour soumission. Attendre feedback dev avant découpage en issues/tickets.*
