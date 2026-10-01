# Configuration de l'agent LogSOC

Le fichier de configuration se trouve à `/etc/logsoc-agent/config.json`. Il est au format JSON et contient toutes les options de l'agent. Certaines options peuvent être modifiées à chaud (hot-reload) sans redémarrer l'agent via le champ `log_level`.

---

## Options générales

| Option | Type | Défaut | Description |
|--------|------|--------|-------------|
| `version` | string | `"3.5.0"` | Version du schéma de config (informationnelle, non utilisée par l'agent). La version réelle de l'agent est compilée dans le binaire. |
| `hostname` | string | `""` | Nom d'hôte de la machine. Vide = détection automatique via `gethostname()`. Peut être forcé manuellement. |
| `central_url` | string | `"https://logsoc.anytimeadmin.info"` | URL du backend LogSOC. C'est l'adresse où l'agent envoie ses events, heartbeats et récupère ses règles. |
| `log_level` | int | `2` | Niveau de verbosité des logs. `0`=ERROR, `1`=WARN, `2`=INFO, `3`=NOTICE, `4`=DEBUG, `5`=TRACE. Modifiable à chaud. |
| `data_dir` | string | `"/var/lib/logsoc-agent"` | Répertoire de données de l'agent (identité, hash d'intégrité). |

**Exemple :**
```json
{
  "hostname": "mon-serveur",
  "central_url": "https://logsoc.anytimeadmin.info",
  "log_level": 2
}
```

---

## Modules

| Option | Type | Défaut | Description |
|--------|------|--------|-------------|
| `module_network` | bool | `true` | Active la capture du trafic réseau via eBPF. |
| `module_ebpf` | bool | `true` | Active les sondes eBPF (processus, fichiers, réseau). |
| `module_journald` | bool | `true` | Active la collecte des logs systemd journald. |

**Exemple :**
```json
{
  "module_network": true,
  "module_ebpf": true,
  "module_journald": true
}
```

---

## YARA

Configuration du scanner de fichiers YARA.

| Option | Type | Défaut | Description |
|--------|------|--------|-------------|
| `enabled` | bool | `true` | Active le scanner YARA. |
| `scan_flags` | int | `1` | Drapeaux de scan YARA. `1` = SCAN_FLAGS_FAST_MODE. |
| `max_scan_file_mb` | int | `10` | Taille maximale des fichiers à scanner (en MB). Les fichiers plus grands sont ignorés. |
| `max_rule_size_kb` | int | `64` | Taille maximale d'une règle YARA (en KB). |
| `match_post_interval_sec` | int | `30` | Intervalle entre l'envoi des matchs YARA au backend (en secondes). |
| `scan_timeout_ms` | int | `5000` | Timeout pour le scan d'un fichier (en millisecondes). |
| `rule_pull_interval_sec` | int | `300` | Intervalle de récupération des règles YARA depuis le backend (en secondes). |

**Exemple :**
```json
{
  "yara": {
    "enabled": true,
    "max_scan_file_mb": 50,
    "scan_timeout_ms": 10000,
    "rule_pull_interval_sec": 600
  }
}
```

---

## Réseau (capture eBPF)

| Option | Type | Défaut | Description |
|--------|------|--------|-------------|
| `interfaces` | array | `["eth0"]` | Liste des interfaces réseau à surveiller. Mettre `["enp1s0"]` ou `["ens33"]` selon la machine. |
| `bpf_filter` | string | `""` | Filtre BPF optionnel (syntaxe tcpdump). Ex: `"port 22 or port 443"`. |
| `snaplen` | int | `65535` | Taille maximale de capture par paquet (en bytes). |
| `batch_interval_ms` | int | `5000` | Intervalle de regroupement des paquets avant envoi (en millisecondes). |
| `payload_preview_bytes` | int | `256` | Nombre de bytes de payload capturés par paquet pour l'aperçu. |

**Exemple :**
```json
{
  "network": {
    "interfaces": ["enp1s0"],
    "bpf_filter": "",
    "snaplen": 65535,
    "batch_interval_ms": 5000
  }
}
```

---

## eBPF

| Option | Type | Défaut | Description |
|--------|------|--------|-------------|
| `poll_interval_ms` | int | `100` | Intervalle de polling des sondes eBPF (en millisecondes). Plus bas = plus de précision, plus de CPU. |
| `rate_limit_per_pid` | int | `100` | Limite d'événements par PID par intervalle (anti-bruit). |
| `redact_patterns` | array | (voir config) | Patterns à masquer dans les événements (secrets, mots de passe). Les valeurs correspondantes sont remplacées par `***REDACTED***`. |

**Patterns de masquage par défaut :**
- `"password="`, `"passwd="`, `"secret="`, `"token="`, `"api_key="`, `"Authorization:"`

**Exemple :**
```json
{
  "ebpf": {
    "poll_interval_ms": 200,
    "rate_limit_per_pid": 200,
    "redact_patterns": ["password=", "token=", "Authorization:"]
  }
}
```

---

## Sondes eBPF activées

| Option | Type | Défaut | Description |
|--------|------|--------|-------------|
| `write` | bool | `false` | Capture les appels `write()`. Très verbeux, désactivé par défaut. |
| `execve` | bool | `true` | Capture l'exécution de processus. |
| `tcp_connect` | bool | `true` | Capture les connexions TCP. |
| `fim` | bool | `true` | Active le File Integrity Monitoring (FIM). |
| `open` | bool | `true` | Capture les ouvertures de fichiers. |
| `unlink` | bool | `true` | Capture les suppressions de fichiers. |

**Exemple :**
```json
{
  "enabled_probes": {
    "write": false,
    "execve": true,
    "tcp_connect": true,
    "fim": true,
    "open": true,
    "unlink": true
  }
}
```

---

## Filtres locaux

Les filtres réduisent le bruit en ignorant certains événements courants.

### Connexions réseau (`connect`)

| Option | Type | Description |
|--------|------|-------------|
| `ignore_ports` | array | Ports à ignorer (ex: `["80", "443"]` pour le trafic web). |
| `ignore_ips` | array | IPs ou plages à ignorer (ex: `["127.0.0.1", "192.168.0.0/16"]`). |

### Exécution (`execve`)

| Option | Type | Description |
|--------|------|-------------|
| `ignore_comm` | array | Noms de processus à ignorer (ex: `["systemd", "cron"]`). |

### Ouverture de fichiers (`open`)

| Option | Type | Description |
|--------|------|-------------|
| `ignore_paths` | array | Chemins à ignorer (ex: `["/proc/", "/sys/"]`). |
| `ignore_flags` | array | Drapeaux à ignorer (ex: `["O_RDONLY"]` ignore les lectures seules). |

### Suppression (`unlink`)

| Option | Type | Description |
|--------|------|-------------|
| `ignore_paths` | array | Chemins à ignorer pour les suppressions. |

**Exemple :**
```json
{
  "local_filters": {
    "connect": {
      "ignore_ports": ["80", "443", "53"],
      "ignore_ips": ["127.0.0.1", "10.0.0.0/8"]
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
}
```

---

## File Integrity Monitoring (FIM)

Surveille les modifications de fichiers critiques.

| Option | Type | Défaut | Description |
|--------|------|--------|-------------|
| `watch_paths` | array | (voir config) | Liste des fichiers et répertoires à surveiller. Supporte les répertoires récursifs. |
| `ignore_paths` | array | `["/proc/", "/sys/", "/dev/"]` | Chemins à ignorer dans le FIM. |

**Chemins surveillés par défaut :**
- `/etc/ssh/sshd_config`, `/etc/passwd`, `/etc/shadow`, `/etc/sudoers`
- `/etc/crontab`, `/etc/hosts`, `/etc/resolv.conf`, `/etc/hostname`
- `/etc/pam.d/`, `/etc/security/`, `/etc/sudoers.d/`
- `/etc/cron.d/`, `/etc/cron.daily/`, `/etc/cron.hourly/`
- `/var/spool/cron/`
- `/root/.bashrc`, `/root/.ssh/authorized_keys`, `/root/.ssh/known_hosts`
- `/home/` (récursif)

**Exemple :**
```json
{
  "fim": {
    "watch_paths": [
      "/etc/ssh/sshd_config",
      "/etc/passwd",
      "/etc/shadow",
      "/etc/nginx/nginx.conf",
      "/home/"
    ],
    "ignore_paths": ["/proc/", "/sys/", "/dev/"]
  }
}
```

---

## Heartbeat

| Option | Type | Défaut | Description |
|--------|------|--------|-------------|
| `interval_sec` | int | `60` | Intervalle entre les heartbeats envoyés au backend (en secondes). Le backend marque l'agent comme inactif après 5 minutes sans heartbeat. |

**Exemple :**
```json
{
  "heartbeat": {
    "interval_sec": 30
  }
}
```

---

## Sévérité des événements

Associe chaque type d'événement à un niveau de sévérité.

| Valeur | Description |
|--------|-------------|
| `info` | Information (faible priorité) |
| `notice` | Remarque (comportement inhabituel) |
| `warning` | Avertissement (action suspecte) |
| `error` | Erreur (problème critique) |

**Exemple :**
```json
{
  "severity_map": {
    "write": "info",
    "execve": "notice",
    "tcp_connect": "notice",
    "fim": "info",
    "open": "info",
    "unlink": "warning",
    "journald": "info"
  }
}
```

---

## Collecte journald

| Option | Type | Défaut | Description |
|--------|------|--------|-------------|
| `journald_exclude_ids` | array | `["logsoc-agent"]` | Identifiants systemd à exclure de la collecte (pour éviter les boucles de log). |

---

## Storage (WAL)

Le Write-Ahead Log stocke les événements localement avant de les envoyer au backend.

| Option | Type | Défaut | Description |
|--------|------|--------|-------------|
| `directory` | string | `"/var/lib/logsoc-agent/wal"` | Répertoire de stockage des segments WAL. |
| `segment_max_size_mb` | int | `10` | Taille maximale d'un segment WAL (en MB). |
| `segment_max_age_sec` | int | `300` | Âge maximal d'un segment avant rotation (en secondes). |
| `max_total_size_mb` | int | `100` | Taille totale maximale du WAL (en MB). Au-delà, les plus anciens segments sont supprimés. |
| `wal_user` | string | `"logsoc"` | Utilisateur système pour le processus de writing (séparation de privilèges). |
| `wal_group` | string | `"logsoc"` | Groupe système pour le processus de writing. |
| `rotation_max_files` | int | `5` | Nombre maximum de fichiers WAL conservés. |

**Exemple :**
```json
{
  "storage": {
    "directory": "/var/lib/logsoc-agent/wal",
    "segment_max_size_mb": 20,
    "max_total_size_mb": 200,
    "rotation_max_files": 10
  }
}
```

---

## Batch (envoi des événements)

| Option | Type | Défaut | Description |
|--------|------|--------|-------------|
| `batch_interval_sec` | int | `30` | Intervalle d'envoi des batches d'événements au backend (en secondes). |
| `batch_max_lines` | int | `500` | Nombre maximum d'événements par batch. |
| `hmac_window_sec` | int | `60` | Fenêtre de validité du HMAC pour l'authentification (en secondes). |

---

## Autres options

| Option | Type | Défaut | Description |
|--------|------|--------|-------------|
| `fanotify_enabled` | bool | `false` | Active le collecteur Fanotify (alternative à eBPF pour la surveillance de fichiers). Nécessite des privilèges root. |
| `scan_paths` | array | `[]` | Chemins supplémentaires à scanner avec YARA en plus du FIM. |
| `app_collector_enabled` | bool | `false` | Active le collecteur d'applications (logs applicatifs). |

---

## Configuration complète par défaut

```json
{
  "version": "3.5.0",
  "hostname": "",
  "central_url": "https://logsoc.anytimeadmin.info",
  "log_level": 2,
  "data_dir": "/var/lib/logsoc-agent",
  "module_network": true,
  "module_ebpf": true,
  "module_journald": true,
  "yara": {
    "enabled": true,
    "scan_flags": 1,
    "max_scan_file_mb": 10,
    "max_rule_size_kb": 64,
    "match_post_interval_sec": 30,
    "scan_timeout_ms": 5000,
    "rule_pull_interval_sec": 300
  },
  "network": {
    "interfaces": ["eth0"],
    "bpf_filter": "",
    "snaplen": 65535,
    "batch_interval_ms": 5000,
    "payload_preview_bytes": 256
  },
  "ebpf": {
    "poll_interval_ms": 100,
    "rate_limit_per_pid": 100,
    "redact_patterns": ["password=", "passwd=", "secret=", "token=", "api_key=", "Authorization:"]
  },
  "enabled_probes": {
    "write": false,
    "execve": true,
    "tcp_connect": true,
    "fim": true,
    "open": true,
    "unlink": true
  },
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
  },
  "fim": {
    "watch_paths": [
      "/etc/ssh/sshd_config", "/etc/passwd", "/etc/shadow", "/etc/sudoers",
      "/etc/crontab", "/etc/ssh/ssh_config", "/etc/hosts", "/etc/resolv.conf",
      "/etc/hostname", "/etc/pam.d/", "/etc/security/", "/etc/sudoers.d/",
      "/etc/cron.d/", "/etc/cron.daily/", "/etc/cron.hourly/",
      "/var/spool/cron/", "/root/.bashrc",
      "/root/.ssh/authorized_keys", "/root/.ssh/known_hosts", "/home/"
    ],
    "ignore_paths": ["/proc/", "/sys/", "/dev/"]
  },
  "fanotify_enabled": false,
  "heartbeat": {
    "interval_sec": 60
  },
  "severity_map": {
    "write": "info",
    "execve": "notice",
    "tcp_connect": "notice",
    "fim": "info",
    "open": "info",
    "unlink": "warning",
    "journald": "info"
  },
  "journald_exclude_ids": ["logsoc-agent"],
  "scan_paths": [],
  "app_collector_enabled": false,
  "batch_interval_sec": 30,
  "batch_max_lines": 500,
  "hmac_window_sec": 60,
  "storage": {
    "directory": "/var/lib/logsoc-agent/wal",
    "segment_max_size_mb": 10,
    "segment_max_age_sec": 300,
    "max_total_size_mb": 100,
    "wal_user": "logsoc",
    "wal_group": "logsoc",
    "rotation_max_files": 5
  }
}
```

---

## Hot-reload

Certaines options peuvent être modifiées à chaud via le backend (envoi d'un message de hot-reload à l'agent) :

- `log_level` : change le niveau de verbosité sans redémarrer
- `yara.rule_pull_interval_sec` : change l'intervalle de récupération des règles
- `heartbeat.interval_sec` : change l'intervalle du heartbeat

Pour les autres options, il faut redémarrer l'agent :
```bash
systemctl restart logsoc-agent
```

---

## Vérification de la configuration

Après avoir modifié la configuration, vérifiez qu'elle est valide :
```bash
python3 -c "import json; json.load(open('/etc/logsoc-agent/config.json')); print('OK')"
```

Puis redémarrez l'agent :
```bash
systemctl restart logsoc-agent
```

Vérifiez les logs :
```bash
journalctl -u logsoc-agent -f
```