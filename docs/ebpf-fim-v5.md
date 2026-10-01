# Spec ebpf-fim-v5 — FIM eBPF simplified (V4.8.0)

**Repo** : `SOC-AGENT` (`git.anytimeadmin.info/pixies/SOC-AGENT`)
**Tag release** : `v4.8.0`
**Flag interne** : `fim.engine = "v5_simplified" | "v4_duplex"` (défaut V4.8 = `v5_simplified`, rollback V4 = `v4_duplex`)
**Spec status** : APPROVED 2026-06-13, implémentation en cours
**Issue tracker** : [Gitea #6](https://git.anytimeadmin.info/pixies/SOC-AGENT/issues/6) (T77_eicar-prod follow-up)

---

## 1. Objectif

Détecter toute modification de fichier surveillé, **1 event par modif**, avec **path complet** + **tag MITRE ATT&CK** + **scan YARA**, **indéboulonnable** (no crash, no kernel panic, graceful degradation).

**Pourquoi** : le pipeline FIM actuel (V4.7 = `sys_enter_openat` + `kprobe/vfs_write` + BPF `open_path_cache` map) souffre d'un bug où les shell `echo > file` ne génèrent aucun event (cf. issue #6). L'architecture duplex openat+vfs_write + cache est fragile et double-comptable.

**Comment** : on supprime `sys_enter_openat` et le `open_path_cache` map, on garde `kprobe/vfs_write` seul. La résolution path complet se fait **userspace** via `/proc/<pid>/fd/<fd>` dans un **worker pool** dédié, avec **timeout strict** (10ms par event) et **circuit breaker** anti-stampede.

---

## 2. Architecture cible

```
┌─────────────────────────────────────────────────────────────────┐
│  KERNEL                                                         │
│                                                                 │
│  kprobe/vfs_write (type 4)                                      │
│    ↓                                                            │
│    payload: {pid, tid, uid, fd, basename(63), comm(16), flags}  │
│    ↓                                                            │
│  ringbuf "events" (256 KB)                                      │
└─────────────────────────────────────────────────────────────────┘
                              ↓
┌─────────────────────────────────────────────────────────────────┐
│  USERSpace — FimCollector (src/agent/fim_collector.cpp)         │
│                                                                 │
│  [1] Consomme ringbuf                                           │
│      ↓                                                          │
│  [2] Rate limit per-PID (100 ev/s/PID, token bucket)            │
│      ↓ (drop → fim_queue_drops_total{reason="rate_limit_pid"})  │
│  [3] Push dans queue bornée (100k)                              │
│      ↓ (drop → fim_queue_drops_total{reason="full"})            │
│  [4] Worker pool (4 threads × 10ms timeout par event)           │
│      ├─→ [4a] CircuitBreaker.check()                            │
│      │      - CLOSED : fd_resolver.resolve()                    │
│      │      - OPEN   : skip resolve, publish basename direct    │
│      ↓                                                          │
│  [5] FdResolver.resolve(pid, fd) → /proc/<pid>/fd/<fd>          │
│      ├─ OK      → resolution='ok'                               │
│      ├─ ENOENT  → resolution='enoent' (process mort)            │
│      ├─ EACCES  → resolution='eperm'                            │
│      └─ timeout → resolution='timeout'                          │
│      ↓                                                          │
│  [6] MitreMapping::tag(full_path) → ['T1098', ...]              │
│      ↓                                                          │
│  [7] YaraEngine::scan_file(full_path, "fim")  [opt-in]          │
│      ↓                                                          │
│  [8] Publie JSON event → buffer SENDER (HTTP POST backend)      │
└─────────────────────────────────────────────────────────────────┘
                              ↓
                ┌──────────────────────────────────────┐
                │  Backend POST /api/v1/events/         │
                │  → ClickHouse table `fim_events` (NEW)│
                └──────────────────────────────────────┘
```

---

## 3. Spécifications détaillées

### 3.1 BPF (kernel-side)

**Fichier** : `src/ebpf/skel_soc.c`

- **Supprimer** : section `SEC("tp/syscalls/sys_enter_openat")` (type 5, fonction `trace_open`).
- **Supprimer** : la BPF map `open_path_cache` (struct `bpf_map_def`).
- **Garder** : section `SEC("kprobe/vfs_write")` (type 4, fonction `trace_fim`).
- **Garder** : sections `sys_enter_write` (type 1), `sys_enter_execve` (type 2), `tcp_v4_connect` (type 3), `sys_enter_unlinkat` (type 6).
- **Modifier `trace_fim`** : émettre le `basename` (déjà fait via `d_path` du `struct file*`) + le **fd** (nouveau, via `bpf_get_current_fd()` ou récupéré depuis le kprobe `vfs_write` arg2 = `struct file*` → `f_pos` non, c'est la position. Le fd doit être récupéré autrement, voir 3.1.1).

#### 3.1.1 Récupération du `fd` dans `kprobe/vfs_write`

Le kprobe `vfs_write` reçoit `(struct file *file, const char __user *buf, size_t count, loff_t *pos)`. Le `fd` n'est pas directement accessible depuis le kprobe. Deux options :

- **Option X** : ajouter un 2e kprobe sur `__x64_sys_write` (syscall entry) qui capture le `fd` depuis les registers (`PT_REGS_PARM1` = fd int). Le `struct file*` est lié au fd via le process `fdtable`, mais pour l'event fim on n'a besoin que du `fd` (pour `/proc/<pid>/fd/<fd>`). C'est l'option choisie.
- **Option Y** : ne pas avoir le fd, juste `basename` + `pid`. La résolution passe par scan de tous les `fd/*` de `/proc/<pid>/fd/` et match par basename. Plus lent, plus fragile. Rejeté.

**Décision** : **Option X** — on garde `kprobe/vfs_write` pour le `basename` (déjà dispo) ET on ajoute `kprobe/__x64_sys_write` pour le `fd`. Les deux events sont fusionnés userspace via `(pid, ktime_ns)` matching avec fenêtre 1ms. Si pas de match → on ship quand même avec `fd=0` et le resolver skip la résolution, ship en `resolution='enoent'`.

### 3.2 FdResolver (userspace)

**Fichiers** : `src/agent/fd_resolver.{hpp,cpp}`

```cpp
class FdResolver {
public:
    enum class Outcome { OK, TIMEOUT, ENOENT, EPERM };
    struct Result {
        Outcome outcome;
        std::string full_path;  // empty si != OK
    };
    Result resolve(uint32_t pid, int32_t fd);
};
```

- **Lecture** : `readlinkat(AT_FDCWD, "/proc/<pid>/fd/<fd>", buf, sizeof(buf))`
- **Timeout** : 10ms strict par appel. Implémentation : `poll()` sur le fd du `readlinkat` n'est pas applicable (readlink est synchrone). Solution : un **worker thread dédié par event**, avec `pthread_cond_timedwait` côté orchestrateur. Si le worker n'a pas fini en 10ms → outcome=TIMEOUT, on ship avec basename.
- **Pool** : 4 workers fixes. Backlog dans une `std::deque<Result>` protégée par mutex. Si backlog > 10000 → reject (publish direct avec `cb_open`).
- **Validation** : le path résolu doit commencer par `/`, sinon considéré ENOENT (path bizarre → no trust).

### 3.3 MitreMapping (userspace)

**Fichiers** : `src/agent/mitre_mapping.{hpp,cpp}`

- Table **constexpr** de 24 règles (paths courants → techniques MITRE ATT&CK).
- Format : `fnmatch(FNM_PATHNAME)` pour matcher `/etc/passwd*`, `/etc/cron.*`, etc.
- Source des 20-30 paths : `docs/MITRE-ATTACK-LOGSOC-MAPPING.md` (à créer en T4.8.3).
- **API** : `static const std::vector<std::string>& tag(const std::string& path)`
- **Coût** : évaluation compile-time, pas de runtime overhead.

### 3.4 CircuitBreaker (userspace)

**Fichiers** : `src/agent/circuit_breaker.{hpp,cpp}`

```cpp
class CircuitBreaker {
public:
    enum class State { CLOSED, OPEN, HALF_OPEN };
    State state() const;
    bool allow();  // true si call autorisé
    void on_success();
    void on_failure();  // compte timeout + eperm (PAS enoent)
    void trip();  // force OPEN (admin)
};
```

- **Trigger** : seuil de failures sur fenêtre glissante (5 failures / 100 calls).
- **Recovery** : OPEN pendant 30s, puis HALF_OPEN (1 call test), si OK → CLOSED.
- **Métriques** : `fim_circuit_breaker_state` (gauge 0/1/2), `fim_circuit_breaker_trips_total` (counter).

### 3.5 FimCollector (userspace)

**Fichiers** : `src/agent/fim_collector.{hpp,cpp}`

- Orchestrateur. Possède le ring buffer consumer thread, le rate limiter, la queue, le FdResolver, le CircuitBreaker, et publie vers le SENDER.
- **Rate limit per-PID** : token bucket, 100 tokens/s/PID, burst 100. Refill via timer thread (1ms granularity).
- **Queue bornée** : 100 000 events. Si plein → drop newest + `fim_queue_drops_total{reason="full"}++`.

### 3.6 Metrics (userspace)

**Fichiers** : `src/agent/metrics.{hpp,cpp}`

- Endpoint HTTP `GET /metrics` (port dédié, à fixer — proposition : 9011 pour ne pas collisionner avec YaraShipper 9010).
- Format Prometheus text (standard).
- **10 métriques obligatoires** (cf. brief) + **2 bonus** si temps :
  1. `fim_events_total{status="ok|dropped|error"}` counter
  2. `fim_resolution_total{outcome="ok|timeout|enoent|eperm|cb_open"}` counter
  3. `fim_resolution_duration_seconds` histogram (buckets 0.001, 0.005, 0.01, 0.05, 0.1)
  4. `fim_resolution_failures_total{reason="timeout|enomem|other"}` counter
  5. `fim_circuit_breaker_state` gauge (0/1/2)
  6. `fim_circuit_breaker_trips_total` counter
  7. `fim_yara_scan_duration_seconds` histogram
  8. `fim_yara_matches_total{threat="..."}` counter
  9. `fim_queue_depth` gauge
  10. `fim_queue_drops_total{reason="full|rate_limit_pid"}` counter
  11. `fim_ebpf_probes_loaded{probe="vfs_write"}` gauge (0/1)
  12. (bonus) `fim_event_processing_duration_seconds` histogram bout-en-bout
  13. (bonus) `fim_workers_active` gauge

### 3.7 ClickHouse schema (backend)

**Nouvelle table** : `logsoc.fim_events`

```sql
CREATE TABLE IF NOT EXISTS logsoc.fim_events (
    ts              DateTime64(9),
    event_id        UUID DEFAULT generateUUIDv4(),
    agent_id        String,
    pid             UInt32,
    tid             UInt32,
    uid             UInt32,
    comm            LowCardinality(String),
    fd              Int32,
    filename        String,           -- path résolu OU basename
    filename_raw    String,           -- basename brut du kprobe
    resolution      Enum8('ok'='ok','timeout'='timeout','enoent'='enoent','eperm'='eperm','cb_open'='cb_open'),
    mitre           Array(String),
    yara_match      UInt8,
    yara_threat     String,
    source          Enum8('kprobe_vfs_write'='kprobe'),
    raw_flags       UInt32
) ENGINE = MergeTree()
  PARTITION BY toYYYYMM(ts)
  ORDER BY (agent_id, ts)
  TTL ts + INTERVAL 90 DAY;
```

**Rétro-compat** : V4.7 `fim` events continuent dans `siem_logs` jusqu'au cutover. Après V4.8.0 deploy, on garde les 2 (dual-write pendant 1 release, puis arrêt V4.7 dans V4.9).

### 3.8 Config (config.json + agent_policy)

**config.json** (local, override-able) :

```json
{
  "fim": {
    "engine": "v5_simplified",
    "worker_threads": 4,
    "resolution_timeout_ms": 10,
    "queue_capacity": 100000,
    "rate_limit_per_pid_per_sec": 100,
    "rate_limit_burst": 100,
    "watch_paths": [
      "/etc/ssh/sshd_config",
      "/etc/passwd",
      "/etc/shadow",
      "/etc/sudoers",
      "/etc/crontab"
    ],
    "ignore_paths": [
      "/proc/", "/sys/", "/dev/"
    ],
    "mitre_mapping_version": "v4.8.0"
  }
}
```

**agent_policy** (central T64) — ajout d'un champ `fim_engine` (string) + `fim_watch_paths` (array). Priorité : central > local. Si central absent → fallback local.

**Behavior** :
- Si `agent_policy.fim_engine` défini → applique (force)
- Sinon → fallback `config.json.fim.engine`
- `watch_paths` = union (deduplicated), central prioritaire en cas de conflit.

### 3.9 Feature flag (rollback V4)

Le flag `fim.engine` accepte 2 valeurs :
- `"v5_simplified"` (défaut V4.8) — nouveau pipeline
- `"v4_duplex"` (legacy) — V4.7 pipeline (openat + vfs_write + cache)

**Rollback** : changer `fim.engine` dans `config.json` (ou via `agent_policy.fim_engine`) + restart agent. Pas de migration data.

---

## 4. Livrables obligatoires

| # | Livrable | Type | Statut |
|---|---|---|---|
| 1 | Spec `ebpf-fim-v5.md` (ce doc) | doc | ✅ |
| 2 | 1 carte Workboard par sous-tâche | org | T4.8.1 à T4.8.7 |
| 3 | Tests unitaires (FdResolver, CircuitBreaker, MitreMapping) | code | T4.8.2, T4.8.3, T4.8.4 |
| 4 | Test E2E EICAR bout-en-bout | e2e | T4.8.7 |
| 5 | Test kill -9 → fallback basename | e2e | T4.8.7 |
| 6 | Test stress 10k/s (100 PIDs × 100 ev) → 0 drop | e2e | T4.8.7 |
| 7 | Test stress 1 PID × 10k → ~9900 drops (rate limit) | e2e | T4.8.7 |
| 8 | Test AppArmor aa-enforce → event toujours capturé | e2e | T4.8.7 |
| 9 | `/metrics` expose 10+ métriques | e2e | T4.8.6 |
| 10 | Rollback V4 via flag vérifié | e2e | T4.8.7 |
| 11 | Test chaos no-crash (30s SIGKILL random, fork bomb, OOM, mount/unmount /proc) | e2e | T4.8.7 |
| 12 | CHANGELOG V4.8.0 | doc | final |

---

## 5. Critères d'acceptation

### 5.1 Fonctionnels

- [ ] 1 event fim par modification de fichier surveillé
- [ ] Path complet résolu dans > 70% des cas (cible 95% sur process long-lived)
- [ ] Tag MITRE correct sur les 20-30 paths du mapping
- [ ] Scan YARA déclenché sur path résolu (cf. T77_eicar pipeline)
- [ ] ClickHouse `fim_events` reçoit les events avec tous les champs

### 5.2 Non-fonctionnels (le "indéboulonnable")

- [ ] Agent ne crashe JAMAIS, même sous chaos (test #11)
- [ ] Queue depth bornée, drops instrumentés
- [ ] Circuit breaker s'ouvre après 5 failures, récupère après 30s
- [ ] `/metrics` répond 200 OK avec 10+ métriques
- [ ] Latence P99 résolution path < 10ms
- [ ] CPU agent < 5% en idle, < 30% sous stress 10k ev/s
- [ ] Memory RSS < 100 MB en idle, < 500 MB sous stress 10k ev/s
- [ ] Graceful shutdown : drain queue (timeout 30s), close fd proprement, detach BPF programs, flush metrics

### 5.3 Rétro-compat

- [ ] V4.7 events continuent à être shippés (dual-write)
- [ ] Flag `v4_duplex` permet rollback en < 30s (config + restart)
- [ ] `siem_logs.fim` events non perdus pendant la transition

---

## 5B. Exigences enterprise-grade (complément au brief original)

### 5B.1 Observabilité

- **Structured logging** : TOUS les logs en JSON, pas de format libre. Champs : `ts`, `level`, `component`, `event_id`, `pid`, `tid`, `comm`, `msg`, `context{...}`. Pas de PII dans les logs (path resolu = OK, content = JAMAIS).
- **Correlation IDs** : chaque event kprobe reçoit un `event_id` (UUID v4) au moment de l'émission. Cet ID est propagé à travers TOUS les stages : ring buffer → FimCollector → FdResolver → MitreMapping → YARA scan → SENDER → ClickHouse row. Permet de tracer un event de bout en bout via `grep event_id=<uuid>`.
- **Prometheus `/metrics`** : 10 métriques obligatoires (cf. §3.6) + 2 bonus.
- **OpenTelemetry-ready** : exporter les spans pour `event.consume`, `fd_resolver.resolve`, `yara.scan`. Format OTLP. Pas obligatoire pour V4.8.0 (P3) mais les hooks doivent être en place (T4.8.6).
- **Health endpoint** : `GET /healthz` (port metrics) → 200 OK si UP, 503 si degraded. Permet à k8s/Consul/etc. de monitorer.

### 5B.2 Sécurité

- **Path validation post-resolution** : le path résolu par `/proc/<pid>/fd/<fd>` est validé avant utilisation :
  - Doit commencer par `/`
  - Ne doit pas contenir `..` (rejeter si présent, return EPERM)
  - Ne doit pas pointer vers `/proc/`, `/sys/`, `/dev/` (return EPERM, log warn)
  - Doit exister (sinon ENOENT)
  - Si size > 4096 → return EPERM (path anormalement long)
- **YARA scan sandboxing** :
  - YARA scan timeout = `cfg.yara.scan_timeout_ms` (default 5000ms, hard cap 30000ms)
  - Si YARA hang > timeout → SIGKILL du thread de scan, event ship avec `yara_match=0, yara_threat=""`, metric `fim_yara_scan_timeouts_total++`
  - Pas d'eval de path en shell (jamais de `system()`, `popen()`, `execve()` sur le path)
- **HMAC signing** : tous les events sortants sont signés HMAC-SHA256 (T79, déjà en place). Le `event_id` fait partie du payload signé, pas du HMAC.
- **No root requirement beyond BPF** : tout le pipeline userspace tourne en user non-root (logsoc user, uid 113). Seul le chargement BPF nécessite CAP_BPF + CAP_SYS_ADMIN (déjà géré par systemd unit).

### 5B.3 Robustesse

- **Worker pool self-healing** : si un worker thread crash (uncaught exception, segfault catché via signal handler), il est automatiquement redémarré avec backoff exponentiel (1s, 2s, 4s, 8s, max 30s). Le compteur `fim_workers_active` reflète le nombre réel de workers UP. Si restart échoue 5× → l'agent passe en mode dégradé (publish direct, skip resolve) et log CRITICAL.
- **State persistence** : le compteur de failures du CircuitBreaker est persisté dans `/var/lib/logsoc-agent/fim_state.json` (atomic write via rename) à chaque transition CLOSED↔OPEN↔HALF_OPEN. Au restart, l'agent recharge l'état. Si fichier corrompu → reset à CLOSED, log warn.
- **Graceful shutdown** : SIGTERM → drain la queue (timeout 30s) → close ring buffer → detach BPF programs → flush metrics → exit 0. SIGKILL (depuis l'extérieur) → exit brutal, la queue est perdue (acceptable, bornée à 100k events = ~1s de données max).
- **Memory limits** : cgroup `MemoryMax=512M` dans la systemd unit. Si OOM → kernel OOM killer, l'agent meurt, systemd le restart, state rechargé.
- **Watchdog** : un thread watchdog vérifie toutes les 5s que : (a) le ring buffer consumer est vivant, (b) au moins 1 worker est UP, (c) la queue depth < 80% capacity. Si l'un fail → log ERROR + restart du composant.

### 5B.4 Tests (au-delà du brief)

- **Fuzzing** : `tests/fuzz_fd_resolver.cpp` (libFuzzer ou AFL) — input random `{pid, fd}` (uint32, int32), vérifier que le resolver ne crash jamais et que le path résolu est validé. Run 1M iterations en CI.
- **Property-based testing** : `tests/test_circuit_breaker_properties.cpp` — utiliser rapidcheck ou libquickcheck pour générer des séquences de {success, failure} et vérifier les invariants CB :
  - "Si 5 failures sur 100 calls consécutives → state=OPEN"
  - "OPEN pendant ≥30s"
  - "HALF_OPEN : 1 success → CLOSED"
- **Mutation testing** : `make mutate` injecte des fautes (changer `<` en `<=`, supprimer une boundary check) et vérifie que les tests existants détectent ≥80% des mutations. Mutation score cible : 80%.
- **Code coverage** : `gcov` ou `llvm-cov`, cible ≥85% lines sur les nouveaux modules.
- **Static analysis** : `clang-tidy --checks=*` (security, performance, readability) — 0 warning bloquant.
- **Sanitizers** : `make test-asan` (AddressSanitizer) et `make test-tsan` (ThreadSanitizer) en CI, 0 leak / 0 race.

### 5B.5 Documentation

- **Runbook opérationnel** : `docs/runbooks/fim.md`
  - Que faire si `fim_circuit_breaker_state=1` persistent
  - Que faire si `fim_queue_drops_total` > 0 régulièrement
  - Comment interpréter un `resolution='enoent'` massif
  - Procédure de rollback V4 (3 étapes, < 5min)
  - Procédure de debug "1 path qui ne trigger jamais"
- **Diagrammes de séquence** (mermaid dans le doc) :
  - Scénario nominal : write → event → resolve → mitre → yara → ship → DB
  - Scénario résolution timeout : write → event → resolve timeout → ship avec `resolution='timeout'`
  - Scénario circuit breaker open : write → event → CB check (OPEN) → ship avec `resolution='cb_open'`
  - Scénario chaos : SIGKILL aléatoire → watchdog détecte → restart worker
- **Matrice de compatibilité** : tableau `kernel version × libbpf version × agent version` avec statut (testé / community-reported / unsupported).
- **ADRs** (Architecture Decision Records) pour les choix non-évidents :
  - ADR-001 : pourquoi supprimer `open_path_cache` (bug issue #6)
  - ADR-002 : pourquoi résolution userspace plutôt que `bpf_get_current_fd()` + `bpf_d_path` (verifier complexity)
  - ADR-003 : pourquoi table MITRE constexpr (vs JSON)
  - ADR-004 : pourquoi 4 workers × 10ms (vs 1 worker × 40ms, vs 8 workers × 5ms)

### 5B.6 Performance (mesurable, pas "subjective")

- **Benchmark reproductible** : `bench/fim_bench.cpp` + script `bench/run_bench.sh`
  - Génère 1M events synthétiques (paths random dans watch_paths)
  - Mesure : throughput (events/s), P50/P95/P99 latence, CPU%, memory RSS
  - Cibles : throughput > 50k events/s, P99 < 10ms, CPU < 30% à 10k ev/s
- **Profiling** : `perf record -g` + `flamegraph.pl` sur le benchmark, identifier le hotspot (probable : `readlinkat` syscall, ou `fnmatch` MITRE). Objectif : < 5% du CPU passé dans les 3 top hotspots.
- **Memory budget documenté** :
  - FimCollector : ~5 MB (queue 100k events × ~50 bytes avg)
  - FdResolver pool : ~1 MB (4 threads × stack 256KB)
  - BPF maps : ~2 MB (ringbuf 256KB + autres)
  - Metrics : ~100 KB
  - Total : < 10 MB hors YARA engine (partagé)

### 5B.7 CI/CD

- **GitHub Actions / Gitea Actions** (par repo) :
  - PR : build, unit tests, fuzzing 1min, sanitizer, coverage, static analysis, lint
  - Merge sur main : build .deb + .rpm, publish artifacts
  - Tag : smoke test (build + start agent dans container + write 1 fichier + check event capturé), publish release avec changelog auto
- **Conventional commits** : `feat:`, `fix:`, `perf:`, `refactor:`, `test:`, `docs:`, `chore:`. Le CHANGELOG est auto-généré par `git-cliff` ou `conventional-changelog`.
- **Signed commits** : GPG signing obligatoire pour les merges sur main (config git global `commit.gpgsign=true`).
- **Signed tags** : GPG signed tags, vérifiables via `git verify-tag v4.8.0`.
- **Pre-commit hooks** : `pre-commit` framework avec hooks `clang-format`, `shellcheck`, `markdownlint`, `gitleaks` (secret scan), `trailing-whitespace`.

### 5B.8 Release process

- **Cutover plan** documenté dans `docs/releases/v4.8.0.md` :
  1. Build + sign .deb
  2. Deploy sur 1 hôte canary (ex: hermes-test, pas hestia prod)
  3. Smoke test (cf. test #4 EICAR)
  4. Monitoring 24h : vérifier `/metrics`, logs JSON, alertes SLO
  5. Si OK → roll progressif sur 10%, 50%, 100% des hôtes
  6. Tag `v4.8.0` sur le commit du cutover
  7. Annonce (channel #soc-releases, email SOC team)
- **SLO post-release** (24h) :
  - `fim_events_total` > 0 (= on capture bien)
  - `fim_resolution_total{outcome="ok"}` / `fim_resolution_total` > 70% (taux de résolution OK)
  - `fim_queue_drops_total` ≈ 0 (pas de saturation)
  - `fim_circuit_breaker_trips_total` = 0 ou très faible (< 10)
  - 0 alert critique dans le dashboard SOC
- **Rollback plan** : si SLO violé dans les 24h post-release :
  1. `agent_policy.fim_engine = "v4_duplex"` via PUT central
  2. Attendre 5min (tick PolicyPuller)
  3. `systemctl restart logsoc-agent` sur tous les hôtes
  4. Vérifier `/metrics` V4.7 reprend (compteurs `fim` dans `siem_logs` recommencent à monter)

---

## 5C. Quality gates (bloquants pour ship)

- ✅ **0 warning clang-tidy** sur les nouveaux fichiers
- ✅ **0 leak AddressSanitizer** sur `make test-asan`
- ✅ **0 race ThreadSanitizer** sur `make test-tsan`
- ✅ **Coverage ≥ 85%** sur les nouveaux modules
- ✅ **Mutation score ≥ 80%** sur `make mutate`
- ✅ **Benchmark pass** : throughput > 50k ev/s, P99 < 10ms
- ✅ **All 11 tests E2E pass** (cf. §4)
- ✅ **Fuzzing 1M iterations** : 0 crash
- ✅ **CHANGELOG V4.8.0** généré
- ✅ **Runbook** + **4 diagrammes de séquence** + **4 ADRs** + **matrice compat** publiés
- ✅ **Tag signed v4.8.0** sur commit du cutover
- ✅ **Smoke test post-deploy** OK
- ✅ **SLO 24h** respecté

---

## 6. Fichiers à créer / modifier

**Nouveaux** (7) :
- `src/agent/fd_resolver.hpp`
- `src/agent/fd_resolver.cpp`
- `src/agent/mitre_mapping.hpp`
- `src/agent/mitre_mapping.cpp`
- `src/agent/circuit_breaker.hpp`
- `src/agent/circuit_breaker.cpp`
- `src/agent/fim_collector.hpp`
- `src/agent/fim_collector.cpp`
- `src/agent/metrics.hpp`
- `src/agent/metrics.cpp`
- `tests/test_fd_resolver.cpp`
- `tests/test_circuit_breaker.cpp`
- `tests/test_mitre_mapping.cpp`
- `tests/test_fim_e2e.sh`
- `tests/test_fim_chaos.sh`
- `docs/MITRE-ATTACK-LOGSOC-MAPPING.md`
- `docs/ebpf-fim-v5.md` (ce doc)

**Modifiés** (4) :
- `src/ebpf/skel_soc.c` — suppr `trace_open` + `open_path_cache`
- `src/agent.cpp` — branchement FimCollector + feature flag
- `config.json` — section `fim` étendue
- `CHANGELOG.md` — entrée `[4.8.0]`
- `docs/V4_Analysis_Comparative.md` — ajouter V4.8

**Backend** (1) :
- `migrations/2026_06_13_fim_events_v48.sql` — CREATE TABLE ClickHouse

**Workboard** (cartes Deck) :
- T4.8.1 — BPF simplification (skel_soc.c)
- T4.8.2 — FdResolver
- T4.8.3 — MitreMapping
- T4.8.4 — CircuitBreaker
- T4.8.5 — FimCollector
- T4.8.6 — Metrics endpoint
- T4.8.7 — agent.cpp + tests E2E + chaos

---

## 7. Pièges anticipés (anticipés par l'investigation issue #6)

1. **kprobe `vfs_write` perd le basename sur certains fs** (ex: tmpfs, overlay). Solution : fallback `comm` seul.
2. **`/proc/<pid>/fd/<fd>` est un symlink qui change entre readlinkat et l'event**. Pas un problème (event déjà horodaté).
3. **Race kprobe/syscall** : on utilise 2 probes (vfs_write + __x64_sys_write) avec fusion par `(pid, ktime_ns)`. Tolérance 1ms.
4. **AppArmor ENFORCE** : le kprobe est kernel-side, AppArmor ne bloque pas. Validé par test #8.
5. **Memory leak du worker pool** : si un worker crash, son event est perdu. Solution : try/catch dans worker, `on_failure` du CB, drop counted.

---

## 8. Références

- Issue #6 : https://git.anytimeadmin.info/pixies/SOC-AGENT/issues/6
- BPF specs : `src/ebpf/skel_soc.c`, `docs/DevBrief_eBPF_v3.3.md`
- V4.7 pivot (option B) : CHANGELOG `[3.10.x]` (open_path_cache intro)
- T77_eicar pipeline : CHANGELOG `[3.23.1]`
- V4 analysis comparative : `docs/V4_Analysis_Comparative.md`
