# Wire-Protocol Agent ↔ Central — Guide du dev backend

> **Audience** : développeurs qui maintiennent le central LogSOC-AI
> (LogSOC-Web, FastAPI/Python, ingestion endpoint).
> **Agent version couverte** : v4.8.x (les breaking changes sont
> signalés et la compatibilité descendante est garantie entre
> versions mineures).
> **Objectif** : expliquer en détail **tous** les endpoints appelés
> par l'agent, le format exact des payloads, les headers, la
> sémantique des codes HTTP, et les **contrats implicites** que le
> central doit respecter (dedup par event_id, fenêtre HMAC, etc.)

---

## Table des matières

1. [Vue d'ensemble](#vue-densemble)
2. [Authentification HMAC](#authentification-hmac)
3. [Endpoints](#endpoints)
   - [`POST /api/v1/events/`](#post-apiv1events)
   - [`POST /api/v1/agents/{id}/heartbeat`](#post-apiv1agentsidheartbeat)
   - [`POST /api/v1/agents/{id}/action-report`](#post-apiv1agentsidaction-report)
   - [`POST /api/v1/yara/scan`](#post-apiv1yarascan)
   - [`GET /api/v1/yara/ruleset`](#get-apiv1yararuleset)
4. [Format des events](#format-des-events)
5. [Sémantique des codes HTTP](#sémantique-des-codes-http)
6. [Contrats implicites](#contrats-implicites)
7. [Identité d'agent et renames d'hôte](#identité-dagent-et-renames-dhôte) **NOUVEAU**
8. [Compatibilité & opt-ins](#compatibilité--opt-ins)
9. [Dépannage côté central](#dépannage-côté-central)
10. [Référence rapide](#référence-rapide)

---

## Vue d'ensemble

L'agent est un **client HTTP strict** qui appelle 5 endpoints sur le
central. Tous les appels sont en HTTPS (HTTP plain refusé à l'init).
Chaque appel est signé HMAC-SHA256 (header `X-Signature`).

```
┌─────────────────┐                       ┌─────────────────┐
│  Agent          │                       │  Central        │
│  (C++17)        │  POST /events         │  (FastAPI)      │
│                 │ ────────────────────> │                 │
│  4 collectors   │  POST /heartbeat      │  Pydantic v2    │
│  + FIM poller   │ ────────────────────> │  SQLAlchemy     │
│  + YARA HQ      │  POST /action-report  │  MariaDB        │
│  + Sender       │ ────────────────────> │                 │
└─────────────────┘  POST /yara/scan      └─────────────────┘
                     ────────────────────>
                     GET  /yara/ruleset
                     <────────────────────
```

L'agent **ne maintient pas de connexion persistante** (chaque batch
est une nouvelle connexion TCP). Le central doit supporter le
reconnect agressif (le Sender peut ouvrir 1 connexion / 5 secondes en
cas de WAL saturation).

## Authentification HMAC

Chaque requête POST/PUT porte :

| Header        | Format                              | Exemple                                        |
|---------------|-------------------------------------|------------------------------------------------|
| `X-Agent-Id`  | UUID v4 (lowercase, hyphenated)     | `550e8400-e29b-41d4-a716-446655440000`         |
| `X-Timestamp` | Unix epoch (decimal seconds)        | `1750205047`                                   |
| `X-Signature` | hex-encoded HMAC-SHA256 (64 chars)  | `a3f5...` (64 hex chars)                       |
| `X-Nonce`     | uint64 counter (opt-in, T14.1)      | `42` (présent seulement si opt-in activé)      |

### Calcul de la signature

```
canonical_payload = <X-Timestamp> + "." + <X-Nonce-or-empty> + "." + <body_sha256_hex>

hmac_key = PBKDF2_HMAC_SHA256(secret=agent.hmac_secret,
                              salt=agent_id_bytes,
                              iterations=600_000,
                              dklen=32)  // 32 bytes

X-Signature = HMAC_SHA256(key=hmac_key, message=canonical_payload).hex()
```

Le central doit :
1. **Refuser** les requêtes dont `|now - X-Timestamp| > hmac_window_sec`
   (60s par défaut, configurable par agent via `config.json`).
2. **Recalculer** la signature avec le même algorithme et la même clé
   partagée. **Comparer en temps constant** (`hmac.compare_digest` en
   Python).
3. **(Opt-in T14.1)** Si `X-Nonce` est présent, le central doit
   maintenir un Redis SET des nonces vus dans la fenêtre
   `hmac_window_sec` et rejeter les doublons (réponse 401).
4. **Si `hmac_nonce_enabled=false` côté agent** (défaut), le header
   `X-Nonce` est **absent** et le payload est
   `<ts>.<body_sha256_hex>` (compatibilité ascendante).

### Pièges courants

- **Format de la clé** : la clé partagée est en **binaire** (32 bytes
  dérivés via PBKDF2) ou en **hex** (64 chars). Le central doit
  supporter les deux. Demander à l'admin de copier la clé **telle
  quelle** depuis le dashboard agent.
- **Endianness / encodage** : tous les bytes sont en **little-endian**
  pour les timestamps (epoch seconds), **UTF-8** pour les strings.
- **Body SHA-256** : calculer sur le **body brut** (bytes exacts
  envoyés par l'agent, pas un re-parse JSON).

## Endpoints

### `POST /api/v1/events/`

**Usage** : ingestion d'un batch d'events collectés. C'est l'endpoint
le plus chaud (plusieurs requêtes/sec en régime normal).

**Headers** :
- `Content-Type: application/json`
- `X-Agent-Id`, `X-Timestamp`, `X-Signature` (+ `X-Nonce` opt-in)
- `User-Agent: logsoc-agent/4.8.x` (informational, non signé)

**Body** :
```json
{
  "agent_id": "550e8400-e29b-41d4-a716-446655440000",
  "agent_version": "4.8.17",
  "host_ips": "10.0.0.42,fe80::1",
  "lines": [
    {
      "event_id": "uuid-v4",
      "source_host": "hestia",
      "severity": "notice",
      "service": "ebpf",
      "ts": 1750205047.123,
      "event": "execve",
      "comm": "bash",
      "pid": 12345,
      "uid": 0,
      "username": "root",
      "filename": "/usr/bin/apt",
      "argv": ["apt", "install", "vim"],
      "tags": ["package-management"]
    },
    {
      "event_id": "uuid-v4",
      "source_host": "hestia",
      "severity": "warning",
      "event": "fim",
      "ts": 1750205047.456,
      "filename": "/etc/passwd",
      "action": "modify",
      "sha256": "abc123..."
    }
  ]
}
```

**Codes de réponse attendus** :

| Code | Signification          | Action agent                                  |
|------|------------------------|------------------------------------------------|
| 201  | Tous les events acceptés | continue, next batch                         |
| 200  | Idem (alias historique) | idem                                          |
| 207  | Multi-Status (T14.0d, opt-in) | re-push les failed event_ids (T14.0d-bis) |
| 400  | Payload malformé        | log + drop batch (no retry)                  |
| 401  | Signature invalide / nonce replay | log + rotate HMAC key (v2)            |
| 403  | Agent révoqué par admin | strike counter +3, stop après 3 strikes     |
| 404  | Agent ID inconnu        | idem 403                                      |
| 413  | Payload > max body size | reduce batch_max_lines + retry                |
| 429  | Rate-limit dépassé      | exponential backoff (5s → 10s → 20s → 40s)  |
| 5xx  | Erreur serveur          | exponential backoff + WAL fallback           |

**Pièges** :
- **201 vs 200** : l'agent accepte les deux. Le central peut renvoyer
  l'un ou l'autre, mais **201 Created** est sémantiquement plus
  correct (on a créé des events).
- **207 Multi-Status** : ne pas l'émettre tant que T14.0d-bis n'est
  pas shippé côté agent (l'agent over-approxime actuellement, ce qui
  peut créer des doublons que le central dedup par event_id).
- **Content-Length** : le central doit accepter des bodies jusqu'à
  ~10MB (1000 events × ~10KB max). Au-delà → 413.

### `POST /api/v1/agents/{id}/heartbeat`

**Usage** : signal de vie périodique + métriques agrégées. Le central
doit mettre à jour `agents.last_seen` et idéalement alerter si
`last_seen > 3 × heartbeat_interval_sec`.

**Headers** : idem `/events/`.

**Body** :
```json
{
  "agent_id": "550e8400-...",
  "agent_version": "4.8.17",
  "hostname": "hestia",
  "ip_addresses": ["10.0.0.42"],
  "os_name": "Ubuntu",
  "os_version": "22.04",
  "kernel_version": "5.15.0-105-generic",
  "uptime_sec": 12345,
  "agent_start_ts": 1750123456,
  "events_collected_total": 1234567,
  "events_shipped_total": 1234500,
  "events_dropped_total": 67,
  "fim": {
    "watch_paths_count": 142,
    "events_shipped": 8500,
    "events_dropped": 0,
    "circuit_breaker_state": "closed"
  },
  "ebpf": {
    "bpf_programs_attached": 6,
    "bpf_links_active": 6,
    "ring_buffer_cur": 518,
    "ring_buffer_max": 500000
  },
  "yara": {
    "enabled": true,
    "rules_loaded": 7728,
    "matches_total": 42
  },
  "wal": {
    "directory": "/var/lib/logsoc-agent/wal",
    "segments_count": 3,
    "total_size_mb": 28
  }
}
```

**Codes attendus** : 200, 401, 403, 404 (idem `/events/`).

**Fréquence** : `heartbeat.interval_sec` côté agent (60s par défaut).

### `POST /api/v1/agents/{id}/action-report`

**Usage** : rapport d'exécution d'une action commandée par le central
(isolate, kill, quarantine, etc.). C'est une **réponse** à un
`POST /api/v1/agents/{id}/command` que le central a envoyé
précédemment (système d'actions T12.10c).

**Body** :
```json
{
  "action_id": "uuid-v4",
  "command_id": "uuid-v4",
  "agent_id": "uuid-v4",
  "status": "success",      // ou "error", "partial", "permission_denied"
  "duration_ms": 1234,
  "result_message": "process 12345 killed",
  "stdout": "...",
  "stdout_truncated": false,
  "stdout_orig_len": 1234
}
```

**Codes attendus** : 200, 401, 403, 404.

**Pièges** : `action_id` est **distinct** de `command_id`. L'agent
génère un `action_id` localement, le central stocke le `command_id`
qu'il a envoyé.

### `POST /api/v1/yara/scan`

**Usage** : upload d'un fichier suspect pour scan YARA profond côté
central. Activé par `yara.ship_content=true` côté agent (opt-in).

**Body** : `multipart/form-data` avec :
- `agent_id` (text)
- `file` (binary, max `yara.ship_max_file_size` = 4MB par défaut)
- `path` (text, chemin original du fichier)
- `sha256` (text, hash du fichier)
- `reason` (text, règle YARA qui a déclenché)

**Codes attendus** : 200 (scan result), 413 (file too big), 401, 403, 404.

**Réponse type** :
```json
{
  "scan_id": "uuid-v4",
  "matches": [
    { "rule": "MALWARE_Backdoor_X", "tags": ["trojan", "c2"], "meta": {...} }
  ],
  "scanned_at": 1750205047
}
```

### `GET /api/v1/yara/ruleset`

**Usage** : pull du ruleset YARA HQ à jour depuis le central. Activé
par `yara_enabled=true` côté agent.

**Headers** : idem (HMAC).

**Query params** : `?since=<unix_ts>` (optionnel, pour diff sync).

**Codes attendus** : 200, 304 (not modified), 401, 403, 404.

**Réponse type (200)** :
```json
{
  "version": "2026-06-18-r7728",
  "compiled_at": 1750205047,
  "ruleset_blob_b64": "base64-encoded-YARA-compiled-ruleset",
  "rule_count": 7728
}
```

**Pièges** : `ruleset_blob_b64` est un **ruleset YARA compilé** (pas
du source). Le central doit le compiler avec `libyara 4.5+` côté
backend. Format binaire opaque (`.yarc`).

**Fréquence** : `yara.rule_pull_interval_sec` côté agent (300s par
défaut).

## Format des events

### Champs communs (tous types)

| Champ         | Type     | Obligatoire | Description                                              |
|---------------|----------|-------------|----------------------------------------------------------|
| `event_id`    | string   | OUI         | UUID v4, généré côté agent, **unique globalement**       |
| `source_host` | string   | OUI         | Hostname de l'agent (peut être surchargé par le central) |
| `severity`    | string   | OUI         | `info`, `low`, `medium`, `high`, `critical` (lowercase) |
| `ts`          | float    | OUI         | Unix epoch en secondes (avec décimales, précision ms)    |
| `event`       | string   | OUI         | Type d'event (cf. table ci-dessous)                      |
| `service`     | string   | NON         | Sous-système émetteur (`ebpf`, `fim`, `journald`, etc.)  |
| `tags`        | array    | NON         | Tags libres pour filtrage/corrélation                    |
| `message`     | string   | OUI         | Représentation textuelle de l'event (max 4096 chars)    |
| `truncated`   | bool     | NON         | `true` si `message` a été tronqué                        |
| `orig_len`    | int      | NON         | Taille originale si troncation                           |

### Types d'events (`event` field)

| Event          | Source     | Champs spécifiques                                                |
|----------------|------------|--------------------------------------------------------------------|
| `execve`       | eBPF       | `comm`, `pid`, `uid`, `username`, `filename`, `argv[]`            |
| `open`         | eBPF       | `comm`, `pid`, `uid`, `username`, `filename`, `flags`             |
| `write`        | eBPF       | `comm`, `pid`, `uid`, `filename`, `bytes_size`                    |
| `unlink`       | eBPF       | `comm`, `pid`, `uid`, `username`, `filename`                      |
| `tcp_connect`  | eBPF       | `comm`, `pid`, `uid`, `dst_ip`, `dst_port`, `family`              |
| `connect`      | libpcap    | `comm`, `pid`, `uid`, `dst_ip`, `dst_port`, `family`              |
| `fim` / `fim_v4_8` | eBPF   | `comm`, `pid`, `uid`, `filename`, `action`, `sha256`              |
| `xdp_syn_scan` | XDP (T13.4)| `src_ip`, `dst_ip`, `dst_port`, `packet_count`                    |
| `journald`     | journald   | `journald_unit`, `journald_match`, `journald_message`             |
| `yara_match`   | YARA HQ    | `filename`, `rule`, `tags[]`, `meta{}`                            |
| `policy_violation` | action_validator | `rule`, `expected`, `actual`                              |

### Champs spécifiques par type

#### `execve`
```json
{
  "event": "execve",
  "comm": "bash",
  "pid": 12345,
  "uid": 0,
  "username": "root",
  "filename": "/usr/bin/apt",
  "argv": ["apt", "install", "vim"],
  "redacted": false
}
```

**Pièges** :
- `argv` peut contenir des secrets (`password=...`, `api_key=...`).
  L'agent redact via `ebpf.redact_patterns` (défaut:
  `password=`, `passwd=`, `secret=`, `token=`, `api_key=`,
  `Authorization:`). Le central peut compléter avec ses propres
  règles.
- Si troncation d'argv, `redacted=true` est ajouté.

#### `fim` / `fim_v4_8`
```json
{
  "event": "fim",
  "filename": "/etc/passwd",
  "action": "modify",
  "sha256": "abc123...",
  "old_sha256": "def456...",
  "size": 1234,
  "pid": 12345,
  "comm": "vim",
  "uid": 0
}
```

**Pièges** :
- `fim_v4_8` est la nouvelle forme (chemins absolus résolus via
  `open_path_cache`). `fim` (sans suffixe) est la forme legacy
  (basename only). Le central devrait accepter les deux.
- `action` ∈ {`create`, `modify`, `delete`, `rename`, `attribute`}.

#### `tcp_connect` / `connect`
```json
{
  "event": "tcp_connect",
  "comm": "curl",
  "pid": 12345,
  "uid": 0,
  "dst_ip": "1.2.3.4",
  "dst_port": 443,
  "family": "ipv4"   // ou "ipv6"
}
```

**Pièges** :
- `dst_ip` peut être IPv6 (format `2001:db8::1`).
- `family` peut être `unix` pour les sockets AF_UNIX (rare).

#### `journald`
```json
{
  "event": "journald",
  "journald_unit": "ssh.service",
  "journald_identifier": "sshd",
  "journald_message": "Accepted publickey for root from 1.2.3.4 port 54321 ssh2",
  "priority": "info"
}
```

#### `yara_match`
```json
{
  "event": "yara_match",
  "filename": "/tmp/suspect.bin",
  "rule": "MALWARE_Backdoor_X",
  "tags": ["trojan", "c2"],
  "meta": {
    "author": "analyst@example.com",
    "description": "Detects X backdoor variant",
    "severity": "high"
  },
  "sha256": "abc123..."
}
```

## Sémantique des codes HTTP

| Code | Sémantique attendue | Action côté central                            |
|------|---------------------|-------------------------------------------------|
| 200  | OK (tous acceptés)  | Persister, ack                                  |
| 201  | Created (préféré)   | Persister, ack                                  |
| 207  | Multi-Status (T14.0d opt-in) | Body: `{"failed_event_ids":[...], "errors":{...}}` |
| 400  | Bad request (payload cassé) | Logger, pas de retry agent               |
| 401  | Signature invalide / replay | Logger, incrémenter counter auth failures |
| 403  | Agent révoqué        | Marquer `agents.revoked=true`, **ne pas** delete |
| 404  | Agent ID inconnu     | Logger, créer agent en pending                  |
| 413  | Payload trop gros    | Logger, suggérer reduce `batch_max_lines`       |
| 429  | Rate-limit           | Logger, header `Retry-After: <sec>`             |
| 5xx  | Erreur serveur       | Logger, agent retry avec backoff                |

## Contrats implicites

Le central **doit** garantir :

### 1. Idempotence par `event_id`

Chaque event a un `event_id` UUID v4. Le central **doit** dedup
(contrainte `UNIQUE` SQL ou Redis SET). Sans dedup, l'agent peut
ré-envoyer le même event (WAL recovery après crash, 207 re-push,
etc.) et créer des doublons.

**Recommandation** :
```sql
CREATE TABLE events (
  id BIGINT AUTO_INCREMENT PRIMARY KEY,
  event_id CHAR(36) NOT NULL UNIQUE,  -- dedup key
  ...
);
```

### 2. Fenêtre HMAC (replay defense)

Le timestamp `X-Timestamp` doit être dans `±hmac_window_sec` de
`now()` (60s par défaut, configurable par agent). Au-delà, rejeter en
401.

**Pièges** : NTP skew ! Synchroniser les agents et le central via
NTP. Tolérance recommandée : 30s de skew max.

### 3. Préservation de l'ordre (best effort)

L'agent ne garantit pas un ordre strict (T14.0f priority reorder,
T14.0b coalescing). Le central doit `ORDER BY ts` côté SQL, pas
assumer l'ordre d'arrivée.

### 4. Schéma évolutif

Le central doit **ignorer** les champs inconnus (forward compat) et
**tolérer** les champs manquants (backward compat). Utiliser Pydantic
`model_config = ConfigDict(extra='ignore')`.

### 5. Response rapide

Le Sender attend la réponse avant d'envoyer le batch suivant. Le
central doit répondre en < 5s idéalement (15s timeout agent). Si le
central est lent, l'agent réduit la taille de batch
(T14.0e adaptive).

### 6. Pas de connexion keep-alive requise

L'agent ouvre une nouvelle connexion TCP par batch (HTTPS simple).
Le central doit supporter le rate de reconnexion (peut être 1
connexion / 5s en régime normal, plus en WAL flush).

## 7. Identité d'agent et renames d'hôte

> **NOUVEAU** (2026-06-19) — clarification suite à un cas opérationnel :
> "que se passe-t-il si un serveur change de nom ?" Réponse courte :
> le central **doit** suivre `agent_id`, pas `source_host`.

### Le modèle d'identité

L'agent possède **deux identifiants distincts** :

| Identifiant | Origine | Stabilité | Usage |
|-------------|---------|-----------|-------|
| `agent_id` (UUID v4) | Généré au **premier démarrage** de l'agent, stocké dans `/var/lib/logsoc-agent/agent.identity` | **Stable** (survit aux redémarrages, aux renames OS, aux redéploiements) | Clé primaire d'identification côté central |
| `source_host` (hostname) | Lu via `gethostname()` (ou `config.json` `hostname` si forcé) au **démarrage** de l'agent | **Volatile** (change si l'OS est renommé, le conteneur recréé, la VM migrée) | Information descriptive uniquement |

**Au démarrage de l'agent** (que ce soit un restart, un crash recovery, ou
un premier démarrage) :

1. Lecture de `gethostname()` → mis en mémoire (`cfg_.hostname`)
2. Lecture de `/var/lib/logsoc-agent/agent.identity` → `agent_id` stable
3. Envoi d'un heartbeat `POST /api/v1/agents/{agent_id}/heartbeat` avec
   `body.hostname = cfg_.hostname`

**Si le hostname a changé entre deux démarrages** (rename OS, conteneur
recréé, VM migrée) :
- L'agent **garde le même `agent_id`** (le fichier `agent.identity` est intact)
- L'agent **envoie un nouveau `source_host`** dans le heartbeat
- Le central doit reconnaître que c'est le **même agent** sur un **nouveau host**

### Comportement attendu du central

**Règle d'or** : **`agent_id` est la primary key, `source_host` est un attribut**.

#### Schéma recommandé pour la table `agents`

```sql
CREATE TABLE agents (
  agent_id              CHAR(36)    PRIMARY KEY,   -- UUID stable, identité unique
  source_host           VARCHAR(255) NOT NULL,     -- hostname du DERNIER contact
  source_host_history   Array(String),             -- historique des hostnames vus
  first_seen            DateTime,
  last_seen             DateTime,
  -- ... autres colonnes existantes ...
);

-- Index pour recherche par hostname (utile pour les requêtes "qui est sur srv-02 ?")
ALTER TABLE agents ADD INDEX idx_source_host (source_host) TYPE bloom_filter() GRANULARITY 4;
```

**Ne PAS** :
- ❌ Utiliser `source_host` comme primary key (un rename = nouvel "agent" fantôme)
- ❌ Utiliser `(source_host, agent_id)` comme clé composite (même problème)
- ❌ Créer un nouvel "agent" quand `source_host` change

#### Logique d'ingestion du heartbeat

```python
@router.post("/api/v1/agents/{agent_id}/heartbeat")
async def heartbeat(agent_id: str, body: AgentHeartbeatRequest):
    agent = get_agent(agent_id)  # SELECT WHERE agent_id = ?

    if agent is None:
        # Premier contact de cet agent_id → créer
        insert_agent(agent_id, body.hostname, now(), source_host_history=[body.hostname])
        return {"status": "registered", "first_seen": now()}

    # Agent connu → update
    if agent.source_host != body.hostname:
        # Le hostname a changé depuis le dernier contact
        audit_log.warning(
            "agent_rename",
            agent_id=agent_id,
            old_host=agent.source_host,
            new_host=body.hostname,
            last_seen=agent.last_seen,
        )
        # Optionnel : alerte sécurité "agent X seen on new host"
        # (peut indiquer un mouvement d'agent suspect, vol d'identité, etc.)
        new_history = (agent.source_host_history or []) + [body.hostname]
        # Dédupe l'history (garder les N derniers, pas d'unbounded growth)
        if len(new_history) > 20:
            new_history = new_history[-20:]
        update_agent(agent_id,
                     source_host=body.hostname,
                     source_host_history=new_history,
                     last_seen=now())
    else:
        # Heartbeat normal, juste update last_seen
        update_agent(agent_id, last_seen=now())
    return {"status": "ok"}
```

#### Logique d'ingestion des events

`POST /api/v1/events/` reçoit un batch avec :
- `agent_id` dans le **body** (`payload["agent_id"]`)
- `X-Agent-Id` dans le **header** (redondant, pour vérification HMAC)

**Le central DOIT** :
1. Identifier l'agent par `agent_id` (header ou body)
2. Vérifier que l'agent existe (sinon le créer / marquer "pending")
3. Associer chaque event à cet `agent_id`
4. Stocker `source_host` de l'event comme **attribut de l'event**, pas comme
   identifiant de l'agent

**Le central NE DOIT PAS** :
1. ❌ Créer un nouvel "agent" quand un `source_host` inconnu apparaît
2. ❌ Référencer l'event par `(source_host, timestamp)` au lieu de `(agent_id, event_id)`
3. ❌ Rejeter un event parce que `source_host` n'existe pas dans la table `agents`

### Scénarios concrets

#### Scénario 1 : rename OS simple

```bash
# Sur srv-01
sudo hostname srv-02
sudo systemctl restart logsoc-agent
# L'agent lit "srv-02" et envoie heartbeat avec source_host="srv-02"
```

**Comportement attendu** :
- ✅ Le central reconnaît le même `agent_id`, met à jour `source_host = "srv-02"`
- ✅ Le dashboard affiche "agent X seen on new host srv-02"
- ✅ Les events d'avant (source_host="srv-01") et d'après (source_host="srv-02")
   sont **groupés par agent_id**, pas par source_host
- ✅ `source_host_history` contient `["srv-01", "srv-02"]`

**Comportement à éviter** :
- ❌ Création d'un "nouvel agent" avec agent_id différent
- ❌ Perte de la traçabilité (events orphelins sous "srv-01" sans agent)

#### Scénario 2 : conteneur Docker qui restart

```yaml
# docker-compose.yml
services:
  logsoc-agent:
    image: logsoc-agent:4.8.x
    # hostname est forcé pour stabilité
    hostname: prod-app-01
    volumes:
      - /var/lib/logsoc-agent:/var/lib/logsoc-agent  # persistance agent.identity
```

**Sans `hostname: prod-app-01`** : `gethostname()` retourne le container ID
(éphémère, change à chaque restart). Le central voit des hostnames aléatoires
à chaque restart du conteneur. C'est **un anti-pattern**. Forcer le hostname.

**Avec `hostname: prod-app-01`** : stable, le central voit un seul host.

**Comportement attendu** : comme le scénario 1.

#### Scénario 3 : VM cloud recréée (resize, migration)

Le `agent.identity` est sur un volume persistant (sinon c'est un autre problème).
L'agent redémarre sur la nouvelle VM avec le **même `agent_id`**, mais un
nouveau hostname (par exemple `i-0abc123` → `i-0def456` chez AWS).

**Comportement attendu** : comme le scénario 1, le central trace le changement
de host.

**Alerte de sécurité recommandée** : "agent X seen on new host i-0def456
(was i-0abc123, 2 hours ago)". Utile pour détecter un vol d'agent.identity
entre deux VMs.

#### Scénario 4 : migration manuelle d'agent (volontaire)

Un admin copie `/var/lib/logsoc-agent/agent.identity` d'un serveur vers un
autre (par exemple pour réutiliser l'enregistrement au central).

**Comportement** : le central voit l'agent_id sur un nouveau host. Sans
mécanisme d'alerte, c'est **silencieux**. **Recommandation** : ajouter une
alerte `agent_rename` quand `source_host_history` s'agrandit (cf. section
"Logique d'ingestion du heartbeat" ci-dessus).

### Cas particulier : `hostname` forcé dans `config.json`

Si l'agent a `hostname: "forced-name"` dans `config.json`, il utilise cette
valeur au lieu de `gethostname()`. L'OS peut être renommé sans impact sur
l'agent. Le central voit toujours `source_host = "forced-name"`.

**Usage légitime** : environnements où le hostname OS est instable (cloud,
conteneurs sans `hostname:` Docker) ou pour forcer une convention de nommage
(même nom pour tous les agents d'un cluster).

**Piège** : si on copie `config.json` entre deux machines différentes avec
le même `hostname` forcé, **et** le même `agent.identity`, le central voit
deux agents avec le même `agent_id` ET le même `source_host`. C'est
indistinguable d'un bug. **Recommandation** : ne pas copier `agent.identity`
manuellement. Utiliser le mécanisme d'enrollment du central.

### Pièges connus côté agent

| Piège | Comportement | Mitigation |
|-------|--------------|------------|
| `gethostname()` dans un conteneur sans `hostname:` Docker | hostname change à chaque restart | Forcer `hostname` dans `config.json` |
| `agent.identity` ownership reset après `dpkg -i` | Agent ne peut plus lire sa clé HMAC | `chown root:root /var/lib/logsoc-agent/agent.identity` après install |
| `agent.identity` copié entre 2 machines | Le central voit le même `agent_id` sur 2 hosts | Ne pas copier manuellement, utiliser l'enrollment |
| Pas de hot-reload sur `hostname` | Un rename OS ne prend effet qu'au restart | Acceptable, documenter dans le runbook |

### À ajouter côté agent (T14.6-bis, futur)

- **Détection proactive** : logger un warning si `gethostname()` au boot
  diffère de la dernière valeur connue (via un fichier d'état
  `/var/lib/logsoc-agent/last_hostname`). Permet de détecter un rename OS
  même sans restart.
- **Hot-reload** : ajouter `hostname` à la whitelist des champs
  hot-reloadable (actuellement : `log_level, heartbeat_interval_sec,
  scan_paths, watch_paths, journald_exclude_ids`).

### Résumé pour le dev backend

| Règle | Pourquoi |
|-------|----------|
| Primary key de `agents` = `agent_id` (UUID) | Stable à travers tous les renames/redémarrages |
| `source_host` = attribut mis à jour | Change possible à chaque restart, pas une identité |
| Stocker `source_host_history` | Permet de tracer les mouvements d'agent dans le temps |
| Logger/auditer les changements de `source_host` | Détecte les mouvements suspects (vol d'identité) |
| Ne PAS créer de nouvel "agent" sur changement de hostname | C'est le même agent, juste sur un autre host |
| Filtrage possible par `source_host` dans le dashboard | Utile pour "qui est sur srv-02 actuellement" mais ne doit pas être la PK |

## 8. Compatibilité & opt-ins

L'agent applique la philosophie **"agent first, central s'adaptera"**
(T14.1) : les features touchant le wire-protocol sont **opt-in
dormantes** tant que le central n'est pas patché.

| Feature                       | Agent flag                       | Status central     | Active ? |
|-------------------------------|----------------------------------|--------------------|----------|
| HMAC legacy (ts.body_hash)    | (always)                         | supported v1+      | OUI      |
| HMAC nonce (ts.nonce.body_hash) | `hmac_nonce_enabled` (T14.1)   | not yet            | NON      |
| Adaptive batch size           | (always, T14.0e)                 | transparent        | OUI      |
| Dedup filter                  | (always, T14.0c)                 | transparent        | OUI      |
| Coalesced events (count/pids) | `coalesce_enabled` (T14.0b)     | not yet            | NON      |
| Priority reorder              | `priority_enabled` (T14.0f)     | transparent        | NON      |
| 207 partial-success           | `partial_success_enabled` (T14.0d) | not yet         | NON      |

**Activer une opt-in** : quand le central supporte la feature, l'admin
flippe le flag dans `config.json` de l'agent et restart.

## Dépannage côté central

### "L'agent spam des 403"

Le central renvoie 403, l'agent incrémente `consecutive_403_404_`. À 3
strikes, l'agent s'arrête. Causes possibles :
- Clé HMAC changée côté dashboard sans rotation agent
- Agent `revoked` par erreur (vérifier `agents.revoked`)
- TLS cert expiré (vérifier `central_url` accessible en `curl -v`)

### "L'agent accumule dans le WAL, n'envoie plus"

Vérifier :
- `journalctl -u logsoc-agent | grep SENDER` → voir les codes HTTP
- `tail -f /var/lib/logsoc-agent/wal/*.log` → taille qui croît
- Si tous les codes sont 5xx → central down, backoff
- Si tous les codes sont 429 → rate-limit, ajuster

### "L'agent envoie mais le central voit des doublons"

- Vérifier la contrainte `UNIQUE` sur `event_id` côté central
- Vérifier que le WAL recovery n'envoie pas 2x au boot (devrait être
  atomique, mais peut arriver en cas de crash mid-flush)
- Augmenter `wal.segment_max_age_sec` pour réduire la fréquence de
  rotation

### "HMAC signature failed"

- Vérifier que la clé partagée côté central = clé côté agent
  (l'admin doit copier la clé **binaire**, pas la version affichée
  hex)
- Vérifier le calcul PBKDF2 : salt = `agent_id_bytes`, iterations =
  600000, dklen = 32
- Vérifier le body SHA-256 : doit être sur le body **brut** (pas
  un re-parse)

## Référence rapide

### Curl example (test d'ingestion)

```bash
# Variables
AGENT_ID="550e8400-e29b-41d4-a716-446655440000"
HMAC_SECRET="<hex 64 chars from dashboard>"
CENTRAL_URL="https://siem.example.com"
TS=$(date +%s)
BODY='{"agent_id":"'$AGENT_ID'","lines":[{"event_id":"a1b2c3d4-","severity":"info","ts":'$TS',"event":"execve","comm":"bash","pid":12345,"filename":"/bin/ls","argv":["ls"]}]}'

# Compute signature
BODY_SHA=$(echo -n "$BODY" | sha256sum | awk '{print $1}')
PAYLOAD="${TS}.${BODY_SHA}"
SIG=$(echo -n "$PAYLOAD" | openssl dgst -sha256 -mac HMAC -macopt key:$HMAC_SECRET | awk '{print $2}')

# POST
curl -v -X POST "$CENTRAL_URL/api/v1/events/" \
  -H "Content-Type: application/json" \
  -H "X-Agent-Id: $AGENT_ID" \
  -H "X-Timestamp: $TS" \
  -H "X-Signature: $SIG" \
  -d "$BODY"
```

### Curl example (heartbeat)

```bash
TS=$(date +%s)
BODY='{"agent_id":"'$AGENT_ID'","hostname":"test","agent_version":"4.8.17"}'
BODY_SHA=$(echo -n "$BODY" | sha256sum | awk '{print $1}')
SIG=$(echo -n "${TS}.${BODY_SHA}" | openssl dgst -sha256 -mac HMAC -macopt key:$HMAC_SECRET | awk '{print $2}')

curl -X POST "$CENTRAL_URL/api/v1/agents/$AGENT_ID/heartbeat" \
  -H "Content-Type: application/json" \
  -H "X-Agent-Id: $AGENT_ID" \
  -H "X-Timestamp: $TS" \
  -H "X-Signature: $SIG" \
  -d "$BODY"
```

### Endpoints summary

| Endpoint                                  | Méthode | Fréquence          | Body size max |
|-------------------------------------------|---------|--------------------|---------------|
| `/api/v1/events/`                         | POST    | 1 / 30s (config)   | ~10MB         |
| `/api/v1/agents/{id}/heartbeat`           | POST    | 1 / 60s (config)   | ~10KB         |
| `/api/v1/agents/{id}/action-report`       | POST    | sur action         | ~1MB          |
| `/api/v1/yara/scan`                       | POST    | sur match          | ~4MB          |
| `/api/v1/yara/ruleset`                    | GET     | 1 / 5min (config)  | -             |

---

**Voir aussi** :
- [README.md](../README.md) — vue d'ensemble + install
- [doc/configuration.md](configuration.md) — toutes les options `config.json`
- [CHANGELOG.md](../CHANGELOG.md) — breaking changes par version
- [docs/COMMUNICATION_PROTOCOL.md](../docs/COMMUNICATION_PROTOCOL.md) — protocole bas-niveau (legacy)
