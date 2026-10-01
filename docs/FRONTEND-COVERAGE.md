# FRONTEND-COVERAGE — Inventaire des options gérées par le backend à exposer

**Repo** : `logsoc-web` (`git.anytimeadmin.info/pixies/logsoc-web`)
**Date** : 6 juin 2026
**Objectif** : lister exhaustivement **tous** les champs, options, filtres, switches et boutons gérés par le backend FastAPI qui devraient apparaître dans l'UI React, et signaler ceux déjà présents vs manquants.

**Sources analysées** :
- `app/models.py` (schémas MariaDB)
- `app/schemas.py` (Pydantic)
- `app/routers/*.py` (endpoints)
- `web/src/pages/*.tsx` (UI existante)

**Légende statut** :
- ✅ **présent** = visible sur la page frontend actuelle
- ❌ **manquant** = géré par le backend mais aucune UI ne l'expose
- ⚠️ **partiel** = exposé partiellement ou dans une autre page

---

## 1. Agents (`/api/v1/agents/*`)

### Modèle `Agent` (table `agents`)

| Champ backend | Type | Où géré | Statut frontend | À ajouter |
|---|---|---|---|---|
| `agent_id` | str(36) | register | ✅ Agents.tsx | — |
| `hostname` | str(255) | register | ✅ Agents.tsx | — |
| `version` | str(32) | register + heartbeat v0.7.1 | ✅ Agents.tsx (v{version}) | — |
| `platform` | str(64) | register | ⚠️ part. (peut-être dans détail) | chip dans la liste |
| `status` | enum pending/active/revoked/deleted | register + admin | ✅ Agents.tsx | — |
| `group_id` | int | admin | ❌ manquant | dropdown pour réassigner |
| `created_at` | datetime | register | ❌ manquant | colonne "Registered" |
| `approved_by` | int | admin | ❌ manquant | tooltip |
| `approved_at` | datetime | admin | ❌ manquant | tooltip |
| `revoked_by` | int | admin | ❌ manquant | historique |
| `revoked_at` | datetime | admin | ❌ manquant | historique |
| `last_seen` | datetime | heartbeat | ✅ Agents.tsx | "X minutes ago" (live) |
| `ebpf_status` | enum pending/enabled/disabled/unsupported | heartbeat | ❌ manquant | badge + filtre |
| `ebpf_reason` | str(255) | heartbeat | ❌ manquant | tooltip sur le badge |
| `ebpf_alert_ack` | bool | admin | ❌ manquant | bouton "Ack" |
| `ebpf_updated_at` | datetime | heartbeat | ❌ manquant | timestamp |
| `mac` | str(12) | register | ❌ manquant | colonne détail |
| `os_name` | str(64) | heartbeat v0.7.1 | ❌ manquant | colonne détail |
| `os_version` | str(32) | heartbeat v0.7.1 | ❌ manquant | colonne détail |
| `arch` | str(16) | register | ❌ manquant | colonne détail |
| `cpu_model` | str(128) | register | ❌ manquant | colonne détail |
| `memory_mb` | int | register | ❌ manquant | colonne détail |
| `disk_gb` | int | register | ❌ manquant | colonne détail |
| `wal_fallback_key_created_at` | datetime | admin | ❌ manquant | — (sécurité) |
| `wal_fallback_key_rotated_at` | datetime | admin | ❌ manquant | bouton "Rotate key" |
| `device_fingerprint` | str(64) | register v0.5 | ❌ manquant | — (sécurité) |
| `device_fingerprint_first_seen` | datetime | register v0.5 | ❌ manquant | — (sécurité) |

### Endpoints à exposer sur UI
| Endpoint | Action frontend |
|---|---|
| `POST /agents/register` | (agent-only, pas d'UI) |
| `POST /agents/heartbeat` | (agent-only) |
| `GET /agents/heartbeat` response contient `config` | agent-only |
| `GET /assets/{id}/heartbeats` | série temporelle dans détail agent |
| `POST /agents/{id}/approve` | bouton "Approve" sur pending |
| `POST /agents/{id}/revoke` | bouton "Revoke" (admin+) |
| `POST /agents/{id}/wal/rotate` | bouton "Rotate WAL key" (admin+) |
| `POST /agents/{id}/ebpf-ack` | bouton "Ack eBPF alert" |

---

## 2. YARA Rules (`/api/v1/yara/*`)

### Modèle `YaraRule` (table `yara_rules`)

| Champ backend | Type | Statut frontend | À ajouter |
|---|---|---|---|
| `rule_id` | str(8) | ✅ YaraRules.tsx | — |
| `name` | str(255) | ✅ YaraRules.tsx | — |
| `description` | text | ✅ YaraRules.tsx | — |
| `rule_text` | text (YARA source) | ✅ YaraRules.tsx (textarea) | — |
| `severity` | enum low/medium/high/critical | ✅ YaraRules.tsx | — |
| `is_active` | bool | ✅ YaraRules.tsx (toggle) | — |
| `match_count` | int | ✅ YaraRules.tsx ("Matches: N") | — |
| `last_match_at` | datetime | ❌ manquant | "Last match: X min ago" |
| `tags` | str(255) csv | ✅ YaraRules.tsx | — |
| `framework` | str(64) CIS/NIST/PCI-DSS | ✅ YaraRules.tsx | — |
| `control_id` | str(64) CIS 4.1 | ✅ YaraRules.tsx | — |
| `scan_flags` | smallint bitmask 0..15 | ❌ manquant | **CRITIQUE** — checkboxes 4 modes (file/memory/network/logs) |
| `rule_hash` | str(64) SHA256 | ❌ manquant | tooltip "sha256:..." pour debug |
| `created_by` | int | ❌ manquant | tooltip "Created by user X" |
| `created_at` | datetime | ❌ manquant | colonne "Created" |
| `updated_at` | datetime | ❌ manquant | tooltip |

### Modèle `YaraScanResult` (table `yara_scan_results`)

| Champ backend | Type | Statut frontend | À ajouter |
|---|---|---|---|
| `rule_id` | str | ❌ manquant | colonne ou lien |
| `rule_name` | str | ❌ manquant | colonne |
| `agent_id` | str | ❌ manquant | colonne (UUID) |
| `source_type` | enum file/memory/network/log | ❌ manquant | **CRITIQUE** — badge par type |
| `target_path` | str(512) | ❌ manquant | colonne (file path, /proc/<pid>/exe, tcp:ip:port) |
| `payload_sha256` | str(64) | ❌ manquant | tooltip "sha256:..." |
| `severity` | enum | ❌ manquant | badge couleur |
| `raw_match` | text (YARA strings output) | ❌ manquant | expandable detail |
| `action_taken` | enum log/alert | ❌ manquant | icône log/alert |
| `matched_at` | datetime | ❌ manquant | colonne "When" |

### Endpoints à exposer
| Endpoint | Action frontend |
|---|---|
| `GET /yara/rules` (filtres: is_active, framework, severity) | ✅ YaraRules.tsx (filtres partiels) — ajouter is_active=active/inactive toggle |
| `POST /yara/rules` (admin+) | ✅ YaraRules.tsx (form create) — ajouter scan_flags picker |
| `GET /yara/active?scan_flag=N` | (agent-only) |
| `POST /yara/results` | (agent-only) |
| `GET /yara/results` (filtres: severity, source_type, agent_id, since) | ❌ manquant — page Results à créer |
| `GET /yara/stats` | ❌ manquant — page Stats à créer (4 tiles: total_rules, active_rules, total_results, last_match) |
| `GET /yara/rules/{rule_id}` | ❌ manquant — page détail (rule_text, match history) |
| `PUT /yara/rules/{rule_id}` | ❌ manquant — bouton "Edit" |
| `DELETE /yara/rules/{rule_id}` | ❌ manquant — bouton "Delete" (admin+) |
| `POST /yara/rules/{rule_id}/toggle` | ✅ YaraRules.tsx (toggle ON/OFF) — améliorer feedback |

### Stats à exposer (4 tiles)
- **total_rules** + **active_rules** (ratio)
- **rules_by_scan_flag** : histogramme {0: N disabled, 1: file only, 2: mem only, 3: file+mem, ..., 15: all}
- **total_results** + delta 24h
- **results_by_severity** : pie chart {low, medium, high, critical}
- **results_by_source_type** : bar chart {file, memory, network, log}
- **last_match_at** : "Last match: 5 min ago"

---

## 3. Sigma Rules (`/api/v1/sigma/*`)

### Modèle `SigmaRule` (existant)

| Champ backend | Statut frontend |
|---|---|
| `rule_uuid`, `title`, `description`, `severity`, `is_active`, `level` | ✅ Sigma.tsx |
| `query_compiled`, `query_supported` | ✅ Sigma.tsx (color-coded) |
| `logsource_product/category/service` | ✅ Sigma.tsx |
| `mitre_technique` (97 uniques) | ✅ Sigma.tsx (pills) |
| `match_count_24h` | ✅ Sigma.tsx |
| `last_evaluated` | ❌ manquant ("Last evaluated: ...") |
| `falsepositives`, `references` | ❌ manquant (expandable detail) |
| `tags` | ❌ manquant (chips) |

### Endpoints
| Endpoint | Statut |
|---|---|
| `GET /sigma/stats` | ✅ Sigma.tsx (4 tiles) |
| `GET /sigma/` filtres | ✅ Sigma.tsx (severity, supported, mitre) |
| `GET /sigma/{uuid}` | ✅ Sigma.tsx (expandable) |
| `PATCH /sigma/{uuid}` (toggle) | ✅ Sigma.tsx (ON/OFF) |
| `POST /sigma/import` (admin+) | ✅ Sigma.tsx (bouton) |
| `POST /sigma/evaluate` (admin+) | ✅ Sigma.tsx (bouton) |

### Améliorations à apporter
- Filtre **logsource_product** (process_creation, file_event, network_connection, auditd)
- Toggle **is_active** visible dans la liste (pas seulement dans le détail)
- Bouton **"Test evaluate"** avec preview du SQL avant commit

---

## 4. Events (`/api/v1/events/*`)

### Modèle `Event` (ClickHouse `siem_logs`)

| Champ | Statut frontend | À ajouter |
|---|---|---|
| `received_at` | ✅ Events.tsx | — |
| `event_id` | ❌ manquant | tooltip "Copy UUID" |
| `source_host` | ✅ Events.tsx | — |
| `severity` | ✅ Events.tsx (badge) | — |
| `message` | ✅ Events.tsx (texte) | — |
| `event` (type) | ✅ Events.tsx (filtre) | — |
| `comm` (process name) | ✅ Events.tsx | — |
| `pid`, `uid`, `username` | ✅ Events.tsx | — |
| `filename`, `flags` | ✅ Events.tsx | — |
| `os_name`, `os_version`, `kernel_version`, `agent_version` | ❌ manquant | colonne host context (info-bulle sur source_host) |
| `host_ips` | ❌ manquant | sous le hostname |
| `tags` | ❌ manquant | chips |
| `journald_match`, `journald_message`, `journald_unit`, `journald_identifier`, `correlation_window_ms` | ❌ manquant | section "Correlation" expandable |
| `raw` (raw line) | ❌ manquant | expandable "Show raw" |

### Filtres à exposer
- ✅ `event` (write/execve/connect/fim/open/unlink)
- ✅ `severity`
- ✅ `source_host`
- ❌ `time_range` (preset: 5min/1h/24h/7d/30d) + custom
- ❌ `comm` (process name)
- ❌ `pid`
- ❌ `agent_id`
- ❌ `os_name` / `os_version`
- ❌ `correlation_match=true` (events avec match journald)

---

## 5. Assets (`/api/v1/assets/*`)

### Modèle `Asset` (alias Agent enrichi)

Voir section 1 (mêmes champs, présentation différente).

### AssetGroup (table `asset_groups`)

| Champ | Statut frontend |
|---|---|
| `id`, `name` | ❌ manquant — page Groupes à créer |
| `description` | ❌ manquant |
| `agent_ids` (membres) | ❌ manquant |
| `created_at` | ❌ manquant |

### Endpoints
| Endpoint | Statut |
|---|---|
| `GET /assets/groups` | ❌ manquant |
| `POST /assets/groups` (admin+) | ❌ manquant |
| `DELETE /assets/groups/{id}` (admin+) | ❌ manquant |
| `GET /assets/` (liste) | ✅ Assets.tsx (probablement) |
| `GET /assets/{id}` | ✅ Assets.tsx |
| `PUT /assets/{id}` (admin+) | ❌ manquant — bouton "Edit" |
| `GET /assets/{id}/heartbeats` | ❌ manquant — graphique live |
| `GET /assets/stats/summary` | ❌ manquant — page summary |

---

## 6. Alerts (`/api/v1/alerts/*`)

### Modèle `Alert` (table `alerts`)

| Champ | Statut frontend | À ajouter |
|---|---|---|
| `alert_id` | ✅ Alerts.tsx | — |
| `severity` | ✅ Alerts.tsx | — |
| `status` (new/ack/resolved/fp) | ✅ Alerts.tsx (filtre) | — |
| `title`, `description` | ✅ Alerts.tsx | — |
| `source_host` | ✅ Alerts.tsx | — |
| `rule_id` | ❌ manquant | lien vers la rule Sigma/YARA qui l'a générée |
| `related_log_ids` | ❌ manquant | expandable "Show related events" |
| `llm_analysis` | ❌ manquant | expandable "AI analysis" (si présent) |
| `assigned_to` | int | ❌ manquant — dropdown "Assign to user" |
| `acknowledged_at`, `resolved_at` | ❌ manquant | timestamps |

### Endpoints
- `GET /alerts/` filtres : severity, status, source_host, time_range — ✅ Alerts.tsx (partiel)
- `GET /alerts/summary` — ✅ Alerts.tsx (probable tile)
- `GET /alerts/{id}` — ✅ Alerts.tsx (expandable)
- ❌ `POST /alerts/{id}/ack` — bouton "Acknowledge" (analyst+)
- ❌ `POST /alerts/{id}/resolve` — bouton "Resolve" (analyst+)
- ❌ `POST /alerts/{id}/assign` — bouton "Assign to..."

---

## 7. Compliance (`/api/v1/compliance/*`)

| Champ | Statut |
|---|---|
| `framework` (CIS/NIST/PCI-DSS) | ❌ manquant — page Compliance existe mais... |
| `control_id`, `title`, `description`, `category` | ✅ Compliance.tsx (part.) |
| `status` (pass/fail/na/unknown) | ✅ Compliance.tsx |
| `score` 0-100 | ✅ Compliance.tsx |
| `evidence`, `last_checked` | ❌ manquant |

À ajouter :
- Sélecteur de framework (toggle CIS / NIST / PCI-DSS)
- Bouton "Re-scan compliance"
- Vue par catégorie (catégories CIS, NIST families)

---

## 8. MITRE ATT&CK (`/api/v1/mitre/*`)

| Champ | Statut |
|---|---|
| `technique_id` (T1003, T1059) | ❌ manquant — page Mitre.tsx existe mais... |
| `technique_name` | ✅ Mitre.tsx (probable) |
| `tactic` (TA0001 Initial Access) | ✅ Mitre.tsx |
| `detection_source` (ebpf/journald/syslog/fim/correlation/network) | ❌ manquant — filtre |
| `query_template` | ❌ manquant — expandable |
| `correlation_window` | ❌ manquant |
| `correlation_after` (parent_rule_id) | ❌ manquant |
| `is_sub_rule`, `parent_rule_id` | ❌ manquant |
| `notes` | ❌ manquant |

À ajouter :
- Filtre par tactic (12 tactics ATT&CK)
- Filtre par detection_source
- Vue graphe des sub-rules
- Compteur de techniques couvertes / non couvertes

---

## 9. AI Insights (`/api/v1/ai/*`)

| Champ | Statut |
|---|---|
| `insight_text` | ✅ AIInsights.tsx |
| `severity`, `category` | ✅ AIInsights.tsx (probable) |
| `related_alert_id` | ❌ manquant — lien vers alert source |
| `created_at` | ✅ AIInsights.tsx |

À ajouter :
- Bouton "Regenerate insight" (force LLM re-analyze)
- Bouton "Mark as resolved"

---

## 10. Auth & Users (`/api/v1/auth/*`, `/api/v1/users/*`)

| Champ | Statut |
|---|---|
| `username`, `email`, `role` | ✅ Users.tsx |
| `display_name`, `is_active` | ✅ Users.tsx |
| `last_login_at` | ❌ manquant — colonne détail |
| `created_at` | ❌ manquant |

À ajouter (admin+) :
- Page "Create user" form
- Bouton "Reset password"
- Bouton "Deactivate user"
- Dropdown role (superadmin/admin/analyst/viewer)
- 2FA setup (si implémenté)

---

## 11. System / Settings (`/api/v1/system/*`)

Pas d'endpoint system exposé actuellement. Mais à créer pour les settings globaux :
- `GET/PUT /system/settings` (clé-valeur) : perf_event_paranoid, sysctl, retention
- `GET /system/health` : status services (FastAPI, MariaDB, ClickHouse, agents count)
- `GET /system/audit-log` : actions admin (qui a fait quoi quand)
- `GET /system/version` : version backend + frontend build hash

---

## 12. WebSocket (`/api/v1/ws/*`)

- ❌ manquant — page Live Events (stream temps réel)
- ❌ manquant — page Live Alerts (push notifications)

---

## Récapitulatif priorités

### P0 — bloquant (sans ça l'UI est inutilisable)
- YARA : ajouter **`scan_flags`** bitmask picker (4 checkboxes) dans YaraRules form
- YARA : créer page **Results** + page **Stats** (4 tiles)
- Agents : afficher **ebpf_status** badge

### P1 — utile
- Agents : colonnes **os_name/os_version/arch/cpu/mem/disk** dans le détail
- Events : filtres **time_range** presets + **correlation_match**
- Alerts : boutons **Acknowledge/Resolve/Assign**
- Compliance : sélecteur de framework

### P2 — nice to have
- Sigma : filtres **logsource_product** + tags
- MITRE : filtres par tactic + detection_source
- Asset groups : CRUD complet
- WAL rotate, device fingerprint display

### P3 — futur
- WebSocket live stream
- System settings page
- Audit log admin

---

## Inventaire fichiers à modifier (frontend)

- `web/src/pages/Agents.tsx` : colonnes host context, ebpf_status, approve/revoke buttons
- `web/src/pages/YaraRules.tsx` : scan_flags picker, last_match_at, rule_hash tooltip, edit/delete buttons
- `web/src/pages/YaraResults.tsx` : **NOUVEAU** — liste des matches avec filtres
- `web/src/pages/YaraStats.tsx` : **NOUVEAU** — 4 tiles + 2 charts
- `web/src/pages/Events.tsx` : filtres time_range, correlation_match, host context tooltip
- `web/src/pages/Alerts.tsx` : ack/resolve/assign buttons, related_log_ids expandable
- `web/src/pages/Compliance.tsx` : framework selector
- `web/src/pages/Mitre.tsx` : filters tactic + detection_source
- `web/src/pages/AssetGroups.tsx` : **NOUVEAU** — CRUD groupes
- `web/src/pages/Users.tsx` : reset pwd, deactivate, role dropdown
- `web/src/pages/SystemSettings.tsx` : **NOUVEAU** — settings + health + audit log
- `web/src/pages/LiveEvents.tsx` : **NOUVEAU** — WebSocket stream
- `web/src/api/index.ts` : ajouter les types pour les nouveaux endpoints
- `web/src/App.tsx` : lazy routes pour les nouvelles pages
- `web/src/components/layout/Sidebar.tsx` : entrées YARA Results, YARA Stats, Asset Groups, etc.
- `web/src/pages/index.ts` : exports des nouvelles pages
