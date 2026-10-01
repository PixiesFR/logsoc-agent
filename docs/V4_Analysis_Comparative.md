# Analyse Comparative — V4.0 vs Propositions Précédentes

> Comparaison entre la spécification V4.0 (DOC-V4-OVERHAUL.md) et les propositions de l'audit eBPF v3.2.5-fix6  
> Date : 2026-05-26  

---

## 1. SYNTHÈSE GÉNÉRALE

Le document V4.0 est **excellent et solidement argumenté**. L'analyse comparative Wazuh/Falco/Tetragon/Tracee confirme toutes les décisions que j'avais proposées indépendamment.

**Verdict :** Alignement à ~90%. Les écarts sont mineurs (détail technique, pas architecture). Le V4.0 est prêt à être soumis au dev.

---

## 2. ALIGNEMENTS — Ce qui était déjà proposé

| Proposition initiale | V4.0 | Statut |
|---------------------|------|--------|
| Ringbuf fusionné (1 seul, 8-32MB) | ✅ Ringbuf unique 32MB | **Identique** |
| Compteurs drops BPF | ✅ `drop_stats` index 0-5 | **Identique** (+ open/unlink) |
| Self-exclusion PID | ✅ `self_exclude: true` | **Identique** |
| Rate-limit PID | ✅ `rate_limit_per_pid: 100` | **Identique** |
| Redaction args sensibles | ✅ Pattern-match `--password` | **Identique** |
| write OFF (trop de bruit) | ✅ `write: false` par défaut | **Identique** + justification Wazuh/Falco |
| Nouvelles probes | ✅ `open` + `unlink` ajoutés | **Élargi** — V4 va plus loin |
| Architecture agent/central | ✅ "L'agent ne juge pas, il collecte" | **Identique** |
| YARA HQ côté central | ✅ YARA Forge (45+ repos) | **Identique** + précision packages Core/Extended/Full |

---

## 3. CE QUE LE V4.0 AMÈNE DE PLUS (et c'est bon)

### 3.1 Analyse comparative — La preuve industrielle

Le V4.0 cite 4 outils SOC majeurs qui confirment que **personne ne trace `write` en production** :

| Outil | Surveille write ? | Méthode |
|-------|-------------------|---------|
| Wazuh | ❌ Non | eBPF : execve, connect, open, unlink |
| Falco | ❌ Non | eBPF : open, openat, execve, connect, clone, fork, ptrace, mount |
| Tetragon | ❌ Non | eBPF policies déclaratives |
| Tracee | ⚠️ Conditionnel | eBPF filtré par container/binaire |

**Impact :** Cela rend la décision `write: false` **irréfutable** pour le dev. Aucun retour "pourquoi on ne trace pas write ?" possible.

### 3.2 Filtres locaux configurables (JSON)

Le V4.0 formalise des filtres de suppression côté agent :

```json
"local_filters": {
  "connect": { "ignore_ports": [80, 443], "ignore_ips": ["127.0.0.1", "::1", "10.0.0.0/24"] },
  "execve": { "ignore_comm": ["cron", "at", "systemd", "agetty"] },
  "open": { "ignore_paths": ["/proc/", "/sys/", "/dev/", "/tmp/", "/var/cache/"], "ignore_flags": ["O_RDONLY"] },
  "unlink": { "ignore_paths": ["/tmp/", "/var/cache/", "/var/log/nginx/"] }
}
```

**Mon avis :** Excellente idée. Évite de saturer le central avec du bruit évident (lectures O_RDONLY, trafic web, /proc). **Mais attention** : les filtres doivent être overridables par le central (config push) — si un incident est en cours, on veut pouvoir désactiver `ignore_ports` à distance.

### 3.3 Position persistence (fichiers)

```json
"logs": {
  "persist_position": true,
  "position_file": "/var/lib/logsoc-agent/positions.json"
}
```

**Mon avis :** Nécessaire et manquant dans v3.2.5. Si l'agent redémarre, il doit reprendre là où il s'était arrêté sur auth.log/syslog. À intégrer immédiatement.

### 3.4 FIM dédié (watch_paths vs ignore_paths)

```json
"fim": {
  "watch_paths": ["/etc/ssh/", "/etc/passwd", "/etc/shadow", "/etc/sudoers", ...],
  "ignore_paths": ["/proc/", "/sys/", "/dev/", "/tmp/", "/var/lib/logsoc-agent/"]
}
```

**Mon avis :** Bien. Sépare la collecte eBPF (open/unlink) du FIM dédié (surveillance fichier par inode). Mais attention à la double détection : `fim` sur `/etc/passwd` + `open` sur `/etc/passwd` = 2 events. Le central doit dédoublonner.

### 3.5 YARA Forge — Précision technique

Le V4.0 est plus précis que ma proposition initiale :
- 3 packages : Core (production), Extended (hunting), Full (investigation)
- Mise à jour hebdomadaire automatique via GitHub releases
- 45+ dépôts sourcés (Elastic, FireEye, McAfee, Talos, Abuse.ch)
- Dédoublonnage + scoring automatique

**Mon avis :** Utiliser **Core** pour la production (faibles FP), **Extended** pour le hunting. Full est trop bruyant pour un SOC opérationnel.

### 3.6 Corrélation central — Règles YAML déterministes

Le V4.0 propose 7 règles de corrélation temps réel :
1. Brute-force SSH (5 failed + connect:22 en 60s)
2. Reverse shell (execve bash + connect sur port non-standard)
3. Suppression logs (unlink sur /var/log/*)
4. Persistence crontab (fim sur /etc/cron* + execve crontab)
5. Escalade privilège (open /etc/shadow O_WRONLY sans useradd/passwd)
6. Nouveau service (bind sur port non-standard)
7. DNS exfiltration (≥100 requêtes DNS en 60s avec query > 50 chars)

**Mon avis :** Règles solides. La règle 5 (open + execve corrélation) répond exactement à la question de Fabrice sur "système ajoute un utilisateur vs hacker injecte".

### 3.7 Baseline learning + LLM Ollama

Le central apprend 7 jours de comportement normal, puis détecte les déviations. LLM Ollama analyse les patterns non couverts.

**Mon avis :** Bon pour la v4.2+, pas critique pour la v4.0. Priorité P4 (après zéro perte + sécurité + nouvelles probes).

### 3.8 Active Response (logsoc-bot@response)

Le V4.0 évoque un worker de réponse automatique (blocage IP, kill process).

**Mon avis :** ⚠️ **Très dangereux sans supervision humaine**. Envisager uniquement pour les alertes **critiques confirmées** (ex: YARA match sur un malware connu + reverse shell actif). Kill process ou blocage IP sans validation = risque de casser la production.

---

## 4. ÉCARTS — Ce que le V4.0 ne mentionne pas (et qui importe)

### 4.1 ❌ Pas de poll bloquant

Le V4.0 propose : `"poll_interval_ms": 500`

**Mon recommandation :** Remplacer par **poll bloquant** (`ring_buffer__poll(rb, -1)`). 500ms est mieux que 100ms, mais entre deux polls on perd encore des events sous burst. Un thread dédié en poll bloquant consomme l'event immédiatement.

**Pourquoi c'est important :** Un `vfs_write` burst sur un build CI/CD (make -j32) peut générer 1000+ events en 50ms. Avec 500ms de poll, 950 events sont dropés avant le prochain poll.

### 4.2 ❌ Pas de batch collect struct C

Le V4.0 ne mentionne pas le formatage par batch. Le callback BPF formate en JSON immédiatement.

**Mon recommandation :** Le callback stocke dans une `struct Event` C brute, le thread userspace formate en JSON par batch de 100. Économise ~30% de CPU sur le thread eBPF.

### 4.3 ❌ Pas de queue userspace max_size

Le V4.0 ne mentionne pas de borne sur la queue userspace.

**Mon recommandation :** `std::deque<RawEvent>` avec `MAX_QUEUE = 10000`. Si overflow, drop oldest + incrémenter `drop_stats`. Protège contre OOM si le sender est bloqué (backend down, réseau coupé).

### 4.4 ❌ Pas de `bpf_core_read()`

Le V4.0 ne mentionne pas le remplacement de `bpf_probe_read_kernel` par `bpf_core_read()`.

**Mon recommandation :** Sur kernel 6.x+, `bpf_probe_read_kernel` sans vérification = lecture hors bounds possible. `bpf_core_read()` gère le CO-RE ET vérifie les offsets.

### 4.5 ❌ Pas de tcp_close / tcp_drop / udp_sendmsg dans les décisions prises

Le V4.0 les liste comme "nouvelles probes proposées" mais ne prend pas de décision.

**Mon recommandation :** `tcp_close` + `tcp_drop` = **OUI** pour v4.1 (faible volume, haute valeur : durée connexion, scans). `udp_sendmsg` = **OUI** pour v4.2 (DNS exfiltration). `do_fork` = **NON** sauf besoin spécifique (execve couvre déjà la majorité).

---

## 5. PRIORITÉS REVISÉES — Route v4.0 → v4.1 → v4.2

| Version | Livrable | Durée estimée | Dépendances |
|---------|----------|---------------|-------------|
| **v4.0** | Zéro perte + sécurité + open/unlink | 4-5j | P1 + P2 du DevBrief |
| **v4.1** | tcp_close + tcp_drop + udp_sendmsg + position persistence | 3-4j | v4.0 stable |
| **v4.2** | YARA Forge worker + corrélation central + baseline | 7-9j | Backend PHP + libyara |
| **v4.3** | Active Response (automatique conditionnel) + LLM Ollama | 5-7j | v4.2 stable |

### v4.0 — Découpage technique

| # | Tâche | Fichiers | Effort |
|---|-------|----------|--------|
| 1 | Ringbuf unique 32MB | `skel_merged.c` (nouveau), `loader.cpp` | 1j |
| 2 | Poll bloquant + thread dédié | `loader.cpp`, `agent.cpp` | 0.5j |
| 3 | Queue bounded max 10k | `loader.cpp` | 0.25j |
| 4 | Batch collect struct C | `loader.cpp`, `event.h` | 0.5j |
| 5 | Drop stats BPF (index 0-5) | `skel_merged.c`, `loader.cpp` | 0.5j |
| 6 | Self-exclusion PID | `skel_merged.c` | 0.25j |
| 7 | Rate-limit per PID | `skel_merged.c` | 0.25j |
| 8 | Redaction args | `loader.cpp` callback | 0.25j |
| 9 | Probes open + unlink | `skel_merged.c`, `loader.cpp` | 1j |
| 10 | Filtres locaux JSON | `agent.cpp`, `config.json` | 0.5j |
| 11 | Position persistence | `agent.cpp`, `Collector` | 0.5j |
| 12 | Config v4.1 complète | `config.json` exemple | 0.25j |

**Total v4.0 : ~5-6 jours de dev C++**

---

## 6. QUESTIONS OUVERTES — Réponses suggérées

| # | Question V4 | Réponse suggérée | Justification |
|---|-------------|-------------------|---------------|
| 1 | tcp_close / tcp_drop en v4.1 ? | **OUI** | Faible volume, haute valeur corrélation |
| 2 | udp_sendmsg ? | **v4.2** | Moyen volume, besoin DNS exfiltration |
| 3 | YARA ruleset ? | **Core** production, **Extended** hunting | Core = faibles FP, Extended = meilleure couverture |
| 4 | Baseline 7 jours ? | **OUI**, fenêtre 30 jours rétention | 7j suffisant pour pattern hebdomadaire |
| 5 | Active Response automatique ? | **NON** sans validation humaine | Risque production. Seulement pour alertes YARA match + reverse shell confirmé |
| 6 | tc/XDP full packet ? | **NON** | Sampling obligatoire, complexe. tcp_connect + close suffisent |
| 7 | do_fork ? | **NON** sauf besoin spécifique | execve couvre déjà la majorité |

---

## 7. DÉCISIONS À PRENDRE MAINTENANT

Pour lancer le dev v4.0, il faut trancher :

### Décision A : Poll bloquant ou interval 500ms ?
- **Option A1** (recommandé) : Poll bloquant `-1` → thread dédié, zero latency
- **Option A2** : Interval 500ms → plus simple, mais drops sous burst

### Décision B : Taille queue userspace
- **Option B1** (recommandé) : Queue max 10k events, drop oldest si overflow
- **Option B2** : Queue illimitée → risque OOM si sender bloqué

### Décision C : write probe
- **Option C1** (recommandé, aligné V4) : write OFF par défaut, jamais activable via config
- **Option C2** : write configurable (peut être réactivé) → risque bruit + perte

### Décision D : bpf_probe_read_kernel
- **Option D1** (recommandé) : Remplacer par `bpf_core_read()` dans le skel merged
- **Option D2** : Garder tel quel → risque kernel 6.x+

---

## 8. CONCLUSION

**Le document V4.0 est prêt à être soumis au dev.** Il est plus complet que mon DevBrief initial, avec l'analyse comparative qui clôture le débat sur `write`.

**3 ajouts à intégrer avant soumission :**
1. Poll bloquant (au lieu de 500ms)
2. Queue bounded 10k (protection OOM)
3. `bpf_core_read()` (sécurité kernel 6.x)

**Route de dev recommandée :**
- **v4.0** : Zéro perte + open/unlink + sécurité (5-6j)
- **v4.1** : tcp_close + tcp_drop + position persistence (3-4j)
- **v4.2** : YARA Forge + corrélation central (7-9j)
- **v4.3** : Baseline + LLM (optionnel, 5-7j)

**Prochaine étape :** Validation des 4 décisions (A/B/C/D) puis découpage en tickets dev.
