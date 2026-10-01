# Configuration de l'agent — Référence exhaustive

> **Fichier** : `/etc/logsoc-agent/config.json`
> **Format** : JSON (UTF-8, sans BOM)
> **Rechargement** : SIGHUP pour `log_level`, `heartbeat_interval_sec`,
> `scan_paths`, `watch_paths`, `journald_exclude_ids`. Les autres
> options nécessitent un restart (`systemctl restart logsoc-agent`).
> **Validation** : la config est parsée au démarrage, les valeurs
> invalides font échouer l'agent (exit code 78 — `EX_CONFIG`).

Ce document décrit **toutes** les options supportées par l'agent
v4.8.x. Chaque option indique son type, sa valeur par défaut, son
comportement, et (le cas échéant) les pièges connus.

---

## Table des matières

1. [Sections principales](#sections-principales)
   - [`central_url`](#central_url)
   - [`hostname`](#hostname)
   - [`module_network` / `module_ebpf` / `module_journald`](#module_flags)
   - [`enabled_probes`](#enabled_probes)
   - [`network`](#network)
   - [`ebpf`](#ebpf)
   - [`local_filters`](#local_filters)
   - [`fim`](#fim)
   - [`fanotify_enabled` / `fanotify_file_mask` / `fanotify_dir_mask`](#fanotify)
   - [`heartbeat`](#heartbeat)
   - [`severity_map`](#severity_map)
   - [`journald_exclude_ids`](#journald_exclude_ids)
   - [`scan_paths` / `app_collector_enabled`](#scan_paths)
   - [`batch_interval_sec` / `batch_max_lines`](#batch)
   - [`hmac_window_sec` / `hmac_nonce_enabled`](#hmac)
   - [`storage`](#storage)
   - [`data_dir`](#data_dir)
2. [Opt-ins T13/T14](#opt-ins)
   - [`enable_xdp_scan` / `xdp_interface`](#xdp)
   - [`yara_enabled` + groupe YARA](#yara)
   - [`coalesce_enabled` / `coalesce_max_pids` (T14.0b)](#coalesce)
   - [`priority_enabled` (T14.0f)](#priority)
   - [`partial_success_enabled` (T14.0d)](#partial)
3. [Exemples de configurations](#exemples)

---

## Sections principales

### `central_url`

| Type   | Défaut                       | Hot-reload |
|--------|------------------------------|------------|
| string | (none — REQUIRED)            | non        |

URL HTTPS du central LogSOC-AI. **Obligatoire**. L'agent POST tous les
events à `<central_url>/api/v1/events/` et les heartbeats à
`<central_url>/api/v1/agents/heartbeat`.

**Format** : `https://host[:port]` (pas de trailing slash, pas de path).
Le TLS est obligatoire (HTTP plain refusé à l'init).

**Exemples valides** :
- `https://logsoc.example.com`
- `https://siem.internal:8443`
- `https://10.0.0.42`

**Pièges** :
- Auto-signed cert : nécessite `central.insecure_tls=true` (NON
  recommandé en prod) ou un CA custom installé dans le trust store.
- DNS qui ne résout pas : l'agent retry indéfiniment, les events
  s'accumulent dans le WAL. Vérifier avec `dig central_url`.

### `hostname`

| Type   | Défaut                  | Hot-reload |
|--------|-------------------------|------------|
| string | (auto-détect: `gethostname()`) | non |

Nom d'hôte utilisé dans tous les events shipés (`item["source_host"]`).
Si vide, l'agent appelle `gethostname()` au démarrage.

**Recommandation** : laisser vide (auto) en prod. Forcer une valeur
uniquement dans les conteneurs où `gethostname()` retourne un ID
éphémère.

### <a name="module_flags"></a>`module_network` / `module_ebpf` / `module_journald`

| Type | Défaut | Effet |
|------|--------|-------|
| bool | `network=false`, `ebpf=true`, `journald=true` | Active/désactive un module de collecte entier |

- `module_ebpf=false` : aucun eBPF program n'est attaché, le FIM eBPF
  est désactivé. Les events FIM viennent alors uniquement de
  fanotify (si activé).
- `module_network=false` : pcap_collector ne tourne pas, XDP non
  attaché (même si `enable_xdp_scan=true`).
- `module_journald=false` : AppCollector (lecture fichiers log) peut
  toujours tourner si `app_collector_enabled=true`.

### `enabled_probes`

| Type   | Défaut                                                                | Hot-reload |
|--------|-----------------------------------------------------------------------|------------|
| object | `{write:false, execve:true, tcp_connect:true, fim:true, open:true, unlink:true}` | non |

Active individuellement chaque sonde eBPF. **Ne fait rien si
`module_ebpf=false`.**

| Probe          | Syscall             | Surcharge CPU      | Volume events |
|----------------|---------------------|--------------------|---------------|
| `execve`       | `sys_execve`        | 1-3% (charge moyenne) | Élevé (chaque exec) |
| `open`         | `sys_enter_openat`  | 0.5-1%             | Très élevé (chaque open) |
| `unlink`       | `sys_unlink`        | < 0.5%             | Moyen |
| `tcp_connect`  | `tcp_connect`       | < 0.5%             | Élevé (chaque connexion) |
| `write`        | `vfs_write`         | 2-5% (charge élevée) | Très élevé (chaque write) |
| `fim`          | `vfs_write` + `openat` + `open_path_cache` | 1-2% | Moyen (filtré par `fim.watch_paths`) |

**Recommandation** :
- `execve`, `open`, `unlink`, `tcp_connect` : ON par défaut, faible coût
- `write` : OFF par défaut (très bruyant, à activer avec filtre
  `local_filters.open.ignore_paths` agressif)
- `fim` : ON si `module_ebpf=true` (chemin FIM kernel recommandé)

### `network`

```json
"network": {
  "interfaces": ["eth0"],
  "bpf_filter": "",
  "snaplen": 65535,
  "batch_interval_ms": 5000,
  "payload_preview_bytes": 256
}
```

| Champ                    | Type           | Défaut       | Effet                                                            |
|--------------------------|----------------|--------------|------------------------------------------------------------------|
| `interfaces`             | array<string>  | `["eth0"]`   | Interfaces à capturer (libpcap `pcap_open_live`)                  |
| `bpf_filter`             | string         | `""`         | Filtre BPF (syntaxe tcpdump). `""` = tout capturer              |
| `snaplen`                | int            | `65535`      | Taille max d'un paquet capturé (octets)                          |
| `batch_interval_ms`      | int            | `5000`       | Intervalle de batch des events réseau (ms)                       |
| `payload_preview_bytes`  | int            | `256`        | Octets de payload inclus dans l'event shipé (1-65535)            |

**Pièges** :
- `interfaces` vide → erreur fatale au démarrage
- `bpf_filter` malformé (syntaxe tcpdump) → erreur fatale au démarrage
- `snaplen < 64` → troncature des headers Ethernet/IP/TCP

### `ebpf`

```json
"ebpf": {
  "poll_interval_ms": 100,
  "rate_limit_per_pid": 100,
  "redact_patterns": ["password=", "passwd=", "secret=", "token=", "api_key=", "Authorization:"]
}
```

| Champ                | Type          | Défaut                                    | Effet                                            |
|----------------------|---------------|-------------------------------------------|--------------------------------------------------|
| `poll_interval_ms`   | int           | `100`                                     | Intervalle de poll du ring buffer BPF (ms)        |
| `rate_limit_per_pid` | int           | `100`                                     | Events/sec/PID max (backpressure, drop le reste)  |
| `redact_patterns`    | array<string> | (voir défaut)                             | Patterns à redact dans argv (execve)             |

**Pièges** :
- `rate_limit_per_pid=0` → pas de limite (dangereux, peut OOM le buffer)
- `redact_patterns` vide → argv complet shipé (fuite de secrets possible)
- `poll_interval_ms < 10` → haute charge CPU sans bénéfice

### `local_filters`

Filtres locaux par type d'event, appliqués **avant** la sérialisation.
Réduisent drastiquement le volume.

```json
"local_filters": {
  "connect": {
    "ignore_ports": ["80", "443"],
    "ignore_ips": ["127.0.0.1", "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"]
  },
  "execve": {
    "ignore_comm": ["systemd", "cron", "bash", "sh", "sshd"]
  },
  "open": {
    "ignore_paths": ["/proc/", "/sys/", "/dev/", "/tmp/"],
    "ignore_flags": ["O_RDONLY"]
  },
  "unlink": {
    "ignore_paths": ["/tmp/", "/var/tmp/"]
  }
}
```

| Section                | Champ          | Type           | Effet                                                       |
|------------------------|----------------|----------------|-------------------------------------------------------------|
| `connect.ignore_ports` | array<string>  | Ports TCP à ignorer (string pour supporter "80", "443", "8000-8100") |
| `connect.ignore_ips`   | array<string>  | IPs/CIDR à ignorer (loopback + RFC1918 par défaut)          |
| `execve.ignore_comm`   | array<string>  | Commandes (basename) à ignorer (process de bruit)            |
| `open.ignore_paths`    | array<string>  | Prefixes de chemin à ignorer (procfs, sysfs, tmp)            |
| `open.ignore_flags`    | array<string>  | Flags d'open à ignorer (ex: `O_RDONLY` pour éviter le bruit)|
| `unlink.ignore_paths`  | array<string>  | Prefixes de chemin à ignorer (tmp)                           |

**Recommandation** : la config par défaut est **raisonnable** pour un
serveur de production. Ajuster `ignore_comm` selon les processus
légitimes bruyants de votre fleet (ex: `["postgres", "redis-server"]`).

**Pièges** :
- `ignore_paths` est un **prefix match** (commence par). `/etc` ignore
  `/etc/*` mais PAS `/etc_backup/`. Mettre `/etc/` pour matcher le
  répertoire.
- `ignore_ips` supporte CIDR (`192.168.0.0/16`). **Pas** de ranges
  `1.2.3.0-1.2.3.255`.
- `ignore_comm` matche sur le **basename** du binaire (pas le chemin
  complet). `bash` matche `/bin/bash` ET `/usr/local/bin/bash`.

### `fim`

```json
"fim": {
  "watch_paths": [
    "/etc/passwd", "/etc/shadow", "/etc/sudoers",
    "/etc/ssh/", "/etc/cron*", "/root/.ssh/"
  ],
  "ignore_paths": ["/proc/", "/sys/", "/dev/"]
}
```

| Champ          | Type          | Effet                                                       |
|----------------|---------------|-------------------------------------------------------------|
| `watch_paths`  | array<string> | Chemins/fichiers/répertoires à monitorer (path absolu, **pas** de glob complexe) |
| `ignore_paths` | array<string> | Prefixes à exclure du monitoring (même syntaxe que `local_filters`) |

**Comportement** :
- Pour un **fichier** : tout write/open/unlink sur ce fichier → event FIM
- Pour un **répertoire** (suffixe `/`) : récursif sur tous les sous-fichiers
- Pour un **glob simple** (suffixe `*`) : expansion au démarrage, chaque
  match devient un watch path individuel

**Pièges** :
- Trop de `watch_paths` (> 10000 fichiers) → haute charge CPU
- `watch_paths` = `[]` → FIM désactivé (mais les events `fim` continuent
  d'arriver pour TOUS les fichiers, juste sans filtrage). Pour
  désactiver, mettre `enabled_probes.fim=false`.
- `/etc/` (sans `/` final) = matche le fichier exact `/etc/`, PAS le
  répertoire. Mettre `/etc/` pour récursif.

### <a name="fanotify"></a>`fanotify_enabled` / `fanotify_file_mask` / `fanotify_dir_mask`

| Champ                | Type   | Défaut          | Effet                                                  |
|----------------------|--------|-----------------|---------------------------------------------------------|
| `fanotify_enabled`   | bool   | `false`         | Active le FIM userspace via `fanotify(7)` API          |
| `fanotify_file_mask` | int    | `0x00000002`    | Fanotify mask pour les fichiers (`FAN_MODIFY`)         |
| `fanotify_dir_mask`  | int    | `0x00000002`    | Fanotify mask pour les répertoires (`FAN_MODIFY`)      |

**Important** : `fanotify_enabled=true` est **incompatible avec AppArmor
enforce mode** (les chemins absolus livrés par le noyau violent le
profil). Pour FIM en AppArmor enforce, utiliser `enabled_probes.fim=true`
(eBPF) à la place.

**Quand utiliser fanotify** :
- Vous avez besoin des **chemins absolus** dans les events (eBPF ne
  shippe que le basename par défaut, résolu via `open_path_cache`).
- Vous n'utilisez pas AppArmor enforce, OU vous avez un profil
  `unconfined` pour l'agent.
- Vous voulez la notification immédiate des `FAN_CREATE` /
  `FAN_DELETE` sur les répertoires (eBPF ne capte que les writes).

**Valeurs du mask** (combinaison bit-à-bit) :
- `0x00000001` = `FAN_ACCESS`
- `0x00000002` = `FAN_MODIFY` (défaut)
- `0x00000004` = `FAN_CLOSE_WRITE`
- `0x00000010` = `FAN_CREATE`
- `0x00000020` = `FAN_DELETE`
- `0x00000100` = `FAN_OPEN`
- `0x00000200` = `FAN_MOVED_FROM` / `FAN_MOVED_TO` (kernel 5.1+)

### `heartbeat`

```json
"heartbeat": {
  "interval_sec": 60
}
```

| Champ          | Type | Défaut | Effet                                            |
|----------------|------|--------|--------------------------------------------------|
| `interval_sec` | int  | `60`   | Intervalle entre heartbeats (secondes, min 10)   |

Le heartbeat POST un résumé (count events, top PIDs, FIM stats) au
central. Le central l'utilise pour détecter un agent down.

**Pièges** :
- `interval_sec < 10` → trop de bruit, préférer augmenter
- `interval_sec > 300` → détection de panne trop tardive

### `severity_map`

```json
"severity_map": {
  "write": "info",
  "execve": "notice",
  "tcp_connect": "notice",
  "fim": "info",
  "open": "info",
  "unlink": "warning",
  "journald": "info"
}
```

| Type   | Défaut                                                       | Effet                                       |
|--------|--------------------------------------------------------------|---------------------------------------------|
| object | (voir ci-dessus)                                             | Mapping event_type → severity (string syslog) |

**Valeurs autorisées** : `debug`, `info`, `notice`, `warning`, `error`,
`critical`, `alert`, `emergency` (convention syslog).

**Pièges** : toute valeur hors cette liste fait échouer la config au
démarrage (exit code 78).

### `journald_exclude_ids`

| Type   | Défaut       | Hot-reload    | Effet                                           |
|--------|--------------|---------------|-------------------------------------------------|
| array  | `["logsoc-agent"]` | OUI    | `SYSLOG_IDENTIFIER` à exclure du collecteur journald |

Empêche l'agent de capturer ses propres logs. La valeur par défaut
exclut `logsoc-agent` (l'agent lui-même). Ajouter d'autres identifiants
selon votre stack (ex: `["rsyslogd", "systemd"]` pour réduire le bruit).

**Hot-reload** : oui (envoyer SIGHUP à l'agent).

### <a name="scan_paths"></a>`scan_paths` / `app_collector_enabled`

| Champ                   | Type          | Défaut                       | Effet                                            |
|-------------------------|---------------|------------------------------|--------------------------------------------------|
| `scan_paths`            | array<string> | `[]`                         | Fichiers de log à lire (ex: `/var/log/auth.log`) |
| `app_collector_enabled` | bool          | `false`                      | Active l'AppCollector (v3.7+, lecture fichiers)  |

**Comportement** :
- `app_collector_enabled=false` : `scan_paths` ignoré
- `app_collector_enabled=true` + `scan_paths` non-vide : l'agent lit
  chaque fichier en mode tail, parse les nouvelles lignes, et ship
  en events `journald`-typed
- Rotation de fichier détectée automatiquement (inode change)

**Hot-reload** : oui pour `scan_paths` (SIGHUP). Non pour
`app_collector_enabled` (restart requis).

### <a name="batch"></a>`batch_interval_sec` / `batch_max_lines`

| Champ                | Type | Défaut | Effet                                                       |
|----------------------|------|--------|-------------------------------------------------------------|
| `batch_interval_sec` | int  | `30`   | Intervalle minimum entre 2 envois (secondes)                |
| `batch_max_lines`    | int  | `500`  | Taille max d'un batch (events). Adapté dynamiquement par T14.0e |

**T14.0e (adaptive batch size)** : le Sender mesure la latence HTTP EMA
et adapte `batch_max_lines` effectif :
- latence < 100ms → 1000
- 100ms-500ms → 500
- 500ms-2s → 200
- > 2s → 100

Le `batch_max_lines` configuré est la **limite haute**. L'effectif est
toujours ≤ cette valeur.

**Pièges** :
- `batch_max_lines > 10000` → timeout HTTP probable
- `batch_max_lines < 10` → overhead HTTP trop élevé par event
- `batch_interval_sec < 5` → pression inutile sur le central

### <a name="hmac"></a>`hmac_window_sec` / `hmac_nonce_enabled`

| Champ                 | Type | Défaut | Effet                                                       |
|-----------------------|------|--------|-------------------------------------------------------------|
| `hmac_window_sec`     | int  | `60`   | Fenêtre anti-replay (secondes). Reject si timestamp trop loin |
| `hmac_nonce_enabled`  | bool | `false` | Active le header `X-Nonce` (T14.1, opt-in)                 |

**`hmac_nonce_enabled`** : quand activé, l'agent ajoute un header
`X-Nonce: <counter>` à chaque requête, et le HMAC payload devient
`<ts>.<nonce>.<body_hash>` au lieu de `<ts>.<body_hash>`. Le central
doit implémenter un Redis SET pour rejeter les doublons. **Opt-in**
parce que le central ne supporte pas encore le nonce — activer
uniquement quand le central est patché.

### `storage`

```json
"storage": {
  "directory": "/var/lib/logsoc-agent/wal",
  "segment_max_size_mb": 10,
  "segment_max_age_sec": 300,
  "max_total_size_mb": 100,
  "wal_user": "logsoc",
  "wal_group": "logsoc",
  "rotation_max_files": 5
}
```

| Champ                  | Type   | Défaut                              | Effet                                          |
|------------------------|--------|-------------------------------------|------------------------------------------------|
| `directory`            | string | `/var/lib/logsoc-agent/wal`         | Répertoire des segments WAL chiffrés            |
| `segment_max_size_mb`  | int    | `10`                                | Taille max d'un segment avant rotation (MB)     |
| `segment_max_age_sec`  | int    | `300`                               | Âge max d'un segment avant rotation (secondes)  |
| `max_total_size_mb`    | int    | `100`                               | Quota total WAL (MB), drop oldest au-delà      |
| `wal_user`             | string | `logsoc`                            | User propriétaire des fichiers WAL              |
| `wal_group`            | string | `logsoc`                            | Groupe propriétaire                              |
| `rotation_max_files`   | int    | `5`                                 | Nombre max de segments gardés en backup         |

**Comportement** : le WAL est chiffré AES-256-GCM segment par segment.
À la rotation, le segment le plus ancien est supprimé. Si
`max_total_size_mb` est dépassé, les segments les plus vieux sont
droppés (warning loggé).

**Pièges** :
- `directory` non-writable → erreur fatale au démarrage
- `segment_max_size_mb=0` → rotation uniquement par âge
- `max_total_size_mb=0` → pas de quota (dangereux, peut remplir le disk)

### `data_dir`

| Type   | Défaut                       | Hot-reload | Effet                                  |
|--------|------------------------------|------------|----------------------------------------|
| string | `/var/lib/logsoc-agent`      | non        | Répertoire de données (WAL, FIM state, etc.) |

Contient :
- `wal/` : segments WAL chiffrés
- `agent.identity` : clé HMAC long-terme + agent_id (chmod 0600 root:root)
- `fim_cb_state.json` : circuit breaker FIM (auto-recovery après saturation)
- `install.sha256` : empreinte d'install (intégrité)

## <a name="opt-ins"></a>Opt-ins T13 / T14

### <a name="xdp"></a>`enable_xdp_scan` / `xdp_interface`

| Champ              | Type   | Défaut      | Effet                                              |
|--------------------|--------|-------------|----------------------------------------------------|
| `enable_xdp_scan`  | bool   | `false`     | Active XDP SYN scan detection (T13.4)              |
| `xdp_interface`    | string | `""` (auto) | Interface réseau où attacher le programme XDP     |

**Comportement** : quand activé, l'agent attache un programme XDP à
l'interface spécifiée (ou auto-détect : `eth0` par défaut). Le
programme détecte les SYN scans in-kernel et les remonte comme
events `network` (synthetic).

**Pièges** :
- Nécessite `module_ebpf=true` ET `module_network=true`
- Le programme XDP est **DR mode** (skb), compatible tous drivers.
  Pour `native` XDP, le driver doit supporter — voir
  [docs/decisions/ADR-003-xdp-mode.md](docs/decisions/ADR-003-xdp-mode.md).
- `xdp_interface` invalide (n'existe pas) → erreur fatale au démarrage
- Le programme XDP ne capture PAS le payload (juste les métadonnées)

### <a name="yara"></a>`yara_enabled` + groupe YARA

```json
"yara": {
  "enabled": false,
  "scan_flags": 1,
  "max_scan_file_mb": 10,
  "max_rule_size_kb": 64,
  "match_post_interval_sec": 30,
  "scan_timeout_ms": 5000,
  "rule_pull_interval_sec": 300,
  "compile_timeout_sec": 30,
  "ship_content": false,
  "ship_max_file_size": 4194304,
  "ship_heuristic_threshold": 3,
  "ship_queue_capacity": 1000
}
```

| Champ                          | Type | Défaut     | Effet                                                        |
|--------------------------------|------|------------|--------------------------------------------------------------|
| `yara.enabled`                 | bool | `false`    | Active le moteur YARA HQ                                     |
| `yara.scan_flags`              | int  | `1`        | Bitmask : 1=file, 2=memory, 4=network, 8=log                |
| `yara.max_scan_file_mb`        | int  | `10`       | Skip fichiers > N MB                                         |
| `yara.max_rule_size_kb`        | int  | `64`       | Skip règles > N KB (anti-bombes)                             |
| `yara.match_post_interval_sec` | int  | `30`       | Rate-limit envois de matches au central (sec)                |
| `yara.scan_timeout_ms`         | int  | `5000`     | Timeout d'un scan (ms)                                       |
| `yara.rule_pull_interval_sec`  | int  | `300`      | Pull ruleset depuis central (sec)                            |
| `yara.compile_timeout_sec`     | int  | `30`       | Timeout de compilation d'un ruleset (sec, 0=unbounded)       |
| `yara.ship_content`            | bool | `false`    | Ship le contenu du fichier au central (via POST /yara/scan)  |
| `yara.ship_max_file_size`      | int  | `4194304`  | Taille max fichier shipé (octets, défaut 4MB)                |
| `yara.ship_heuristic_threshold`| int  | `3`        | Seuil heuristique (0-10, 3=light filter)                    |
| `yara.ship_queue_capacity`     | int  | `1000`     | Taille de la queue d'upload (drop oldest au-delà)           |

**Modes YARA** (`scan_flags`) :
- `1` (bit 0) : scan fichiers au repos (FIM-integrated)
- `2` (bit 1) : scan mémoire des process (execve-target)
- `4` (bit 2) : scan payloads réseau (pcap-integrated)
- `8` (bit 3) : scan logs (journald-integrated)
- `15` = tous les modes

**Pièges** :
- `yara.enabled=true` sans `libyara >= 4.5` → erreur fatale au démarrage
- `scan_flags` invalide (hors bitmask 0-15) → erreur fatale
- `ship_content=true` avec `central` non accessible → drop de fichiers
  suspects (avec warning). Désactiver `ship_content` ou fixer le central.

### <a name="coalesce"></a>`coalesce_enabled` / `coalesce_max_pids` (T14.0b, opt-in)

| Champ                  | Type   | Défaut | Effet                                                       |
|------------------------|--------|--------|-------------------------------------------------------------|
| `coalesce_enabled`     | bool   | `false` | Active le coalescing d'events                               |
| `coalesce_max_pids`    | int    | `20`    | Cap du tableau `pids` dans un event mergé                    |

**Comportement** : le Sender groupe N events avec le même
`(event_type, path)` dans un batch en un seul event mergé :
```json
{
  "event_type": "open",
  "path": "/etc/passwd",
  "count": 5,
  "pids": [1234, 5678, 9012]
}
```

**Pièges** :
- Le central **doit** supporter le format mergé (présence de `count`
  et `pids`). Vérifier avant d'activer.
- Opt-in (défaut off) parce que le wire-protocol change.

### <a name="priority"></a>`priority_enabled` (T14.0f, opt-in)

| Champ               | Type | Défaut | Effet                                                       |
|---------------------|------|--------|-------------------------------------------------------------|
| `priority_enabled`  | bool | `false` | Active le reorder par tier (HIGH > MED > LOW) dans le batch |

**Tiers** :
- HIGH (0) : `fim`, `execve`, `unlink`, `write`
- MED (1) : `open`, `tcp_connect`, `connect`
- LOW (2) : tout le reste (journald, scan, etc.)

**Comportement** : le Sender over-draine 3× le batch, stable_sort par
tier, trim à la taille effective, push l'excès back. Garantit que les
events security-critical shipent en premier même sous charge.

**Pièges** :
- Over-drain 3× = 2 courtes écritures WAL temporaires (négligeable)
- Le central reçoit les events dans l'ordre tier, pas l'ordre
  chronologique strict

### <a name="partial"></a>`partial_success_enabled` (T14.0d, opt-in dormant)

| Champ                        | Type | Défaut | Effet                                                       |
|------------------------------|------|--------|-------------------------------------------------------------|
| `partial_success_enabled`    | bool | `false` | Active le handling du HTTP 207 Multi-Status du central     |

**Comportement** : quand activé ET que le central répond 207, l'agent
re-push le batch entier via le FallbackWAL (over-approximation
conservatrice — la déduplication par `event_id` côté central évite
les doublons). Sans body parsing (T14.0d-bis, future).

**Pièges** :
- Le central ne supporte pas 207 actuellement. Le code path est
  dormant — activer uniquement quand le central est patché.
- En activant sans support central, vous ne verrez **aucun** effet
  (le central retourne 201, pas 207).

## Exemples de configurations

### Serveur de production typique

```json
{
  "central_url": "https://siem.prod.example.com",
  "module_ebpf": true,
  "module_journald": true,
  "module_network": false,
  "enabled_probes": {
    "execve": true, "open": true, "unlink": true,
    "tcp_connect": true, "fim": true, "write": false
  },
  "local_filters": {
    "execve": { "ignore_comm": ["systemd", "cron", "bash", "sh", "sshd", "postgres", "redis-server"] },
    "open": { "ignore_paths": ["/proc/", "/sys/", "/dev/", "/tmp/"], "ignore_flags": ["O_RDONLY"] },
    "connect": { "ignore_ports": ["80", "443"], "ignore_ips": ["127.0.0.1", "10.0.0.0/8", "192.168.0.0/16"] }
  },
  "fim": {
    "watch_paths": ["/etc/passwd", "/etc/shadow", "/etc/sudoers", "/etc/ssh/", "/etc/cron*", "/root/.ssh/"]
  },
  "heartbeat": { "interval_sec": 60 },
  "severity_map": {
    "execve": "notice", "unlink": "warning", "fim": "info",
    "open": "info", "tcp_connect": "notice", "write": "info", "journald": "info"
  }
}
```

### Serveur de logs (high-volume, beaucoup de journaux)

```json
{
  "central_url": "https://siem.example.com",
  "module_ebpf": true,
  "module_journald": true,
  "app_collector_enabled": true,
  "scan_paths": ["/var/log/auth.log", "/var/log/syslog", "/var/log/kern.log"],
  "journald_exclude_ids": ["logsoc-agent", "rsyslogd", "systemd"],
  "batch_max_lines": 1000,
  "local_filters": {
    "open": { "ignore_paths": ["/var/log/"], "ignore_flags": ["O_RDONLY"] }
  }
}
```

### Endpoint exposé (DMZ, public-facing)

```json
{
  "central_url": "https://siem.example.com",
  "module_ebpf": true,
  "module_network": true,
  "enabled_probes": {
    "execve": true, "open": true, "unlink": true,
    "tcp_connect": true, "fim": true, "write": true
  },
  "network": {
    "interfaces": ["eth0"],
    "bpf_filter": "not port 80 and not port 443",
    "snaplen": 65535
  },
  "xdp": {},
  "enable_xdp_scan": true,
  "xdp_interface": "eth0",
  "fim": {
    "watch_paths": ["/etc/", "/usr/bin/", "/usr/sbin/", "/var/www/"]
  }
}
```

### Mode audit (YARA HQ activé)

```json
{
  "central_url": "https://siem.example.com",
  "module_ebpf": true,
  "yara_enabled": true,
  "yara": {
    "scan_flags": 15,
    "max_scan_file_mb": 50,
    "match_post_interval_sec": 60,
    "ship_content": true,
    "ship_heuristic_threshold": 5
  }
}
```

### Mode dry-run (agent démarre, shippe rien)

Utile pour tester qu'un agent peut démarrer sans toucher au central :
- commenter la ligne `central_url` ou la mettre à `""` → l'agent
  fail-fast au démarrage (volontaire : pas de fallback central par
  défaut, l'agent accumule dans le WAL).
- Pour un vrai dry-run, utiliser `coalesce_enabled=false` + un
  `central_url` valide, puis flagger les events avec un préfixe
  custom via `severity_map` (`"execve": "debug"`).

---

**Voir aussi** :
- [README.md](../README.md) — vue d'ensemble + install
- [CHANGELOG.md](../CHANGELOG.md) — historique
- [doc/developer-backend.md](developer-backend.md) — contrat wire-protocol (dev central)
- [docs/adr/](docs/adr/) — Architecture Decision Records
