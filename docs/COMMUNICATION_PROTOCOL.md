# LogSOC-AI — Protocole de communication Agent V3 ↔ Backend PHP

**Version:** 3.1.1 (baseline) / 3.2 (avec eBPF)  
**Format:** JSON sur HTTPS  
**Auth:** HMAC SHA256 avec `secret_key` partagé (échangé au register)  
**Content-Type:** `application/json`

---

## 1. REGISTER — Enregistrement initial

### Agent → Backend
```bash
POST /api/v1/register.php
```

```json
{
    "agent_id":    "uuid-v4",
    "hostname":    "monhost",
    "os":          "Linux 6.17 ibm-lx86xxx",
    "version":     "3.1.1",
    "ip":          "192.168.1.X"
}
```

### Backend → Agent
```json
// HTTP 201 = nouveau registre
{
    "success": true,
    "status": "registered",
    "request_id": "uuid-v4"
}
```

```json
// HTTP 200 = deja connu
{
    "success": true,
    "status": "already_registered",
    "request_id": "agent_id"
}
```

**Stockage:** `INSERT INTO agents_v3 (...)`  
**Clé:** `request_id → secret_key` stocké dans `/etc/logsoc/key.json`

---

## 2. HEARTBEAT — Survie périodique

### Agent → Backend
```bash
POST /api/v1/agent/heartbeat.php
Headers: X-LogSoc-Agent: <agent_id>, X-LogSoc-Sig: <HMAC>
```

```json
{
    "agent_id":           "uuid-v4",
    "hostname":           "monhost",
    "ip":                 "192.168.1.X",
    "timestamp":          1716580000,
    "metrics":            null,
    "secret_key_hash":    "sha256-de-la-cle"
}
```

### Backend → Agent
```json
{
    "success": true,
    "status": "active"
}
```

**Stockage:** `UPDATE agents_v3 SET last_seen = NOW(), status = 'active'`

---

## 3. HEARTBEAT eBPF (V3.2+) — Etat sonde noyau

### Agent → Backend
```bash
POST /api/v1/agent/heartbeat-ebpf.php
Headers: X-LogSoc-Agent: <agent_id>, X-LogSoc-Sig: <HMAC>
```

```json
{
    "agent_id":        "uuid-v4",
    "ebpf_status":     "loaded",
    "ebpf_reason":     "kernel 6.17 with bpf syscall and ringbuf",
    "ebpf_updated_at": "2026-05-24T20:00:00Z"
}
```

`ebpf_status` peut être : `loaded` | `unsupported` | `failed`  
Si `unsupporte`: `ebpf_reason` dit pourquoi (kernel trop vieux, pas de BTF, etc.)

### Backend → Agent
```json
{
    "success": true,
    "status": "active",
    "ebpf_acknowledged": false
}
```

**Stockage:** `UPDATE agents_v3 SET ebpf_status=..., ebpf_reason=..., ebpf_alert_ack=0`

---

## 4. PUSH — Envoi d'événements collectés

### Agent → Backend
```bash
POST /api/v1/push.php
Headers: X-LogSoc-Agent: <agent_id>, X-LogSoc-Sig: <HMAC>
```

```json
{
    "agent_id": "uuid-v4",
    "events": [
        {"timestamp": 1716580001, "type": "write",   "severity": "info",  "data": "{"path":"/etc/passwd","size":123}"},
        {"timestamp": 1716580002, "type": "execve",  "severity": "warn",  "data": "{"args":"/bin/bash -c rm -rf /"}"},
        {"timestamp": 1716580003, "type": "connect", "severity": "info",  "data": "{"daddr":"1.2.3.4","dport":4444}"},
        {"timestamp": 1716580004, "type": "fim",     "severity": "alert", "data": "{"path":"/etc/shadow","action":"modified"}"}
    ]
}
```

### Backend → Agent
```json
{
    "success": true,
    "status": "ingested",
    "count": 4
}
```

---

## 5. STATUS PING — Diagnostic backend (pas d'auth)

### Agent → Backend
```bash
GET /api/v1/status.php
```

### Backend → Agent (toute source)
```json
{
    "status": "ok",
    "version": "3.1.4",
    "time": "2026-05-24T20:00:00Z"
}
```

HTTP 200 = backend vivant.

---

## Séquence normale d'opération

```
  ┌─────────────┐     register (HTTP 201/200)     ┌─────────────┐
  │   Agent     │ ───────────────────────────────▶ │   Backend   │
  │   (v3.1+)   │     ← secret_key                 │    PHP      │
  └──────┬──────┘                                   └─────────────┘
         │
         │     heartbeat (toutes les 30s)
         │ ──────────────────────────────────▶ UPDATE agents_v3
         │     ← {success:true, status:active}
         │
         │     push (quand WAL atteint seuil ou timer 5s)
         │ ──────────────────────────────────▶  INSERT clickhouse
         │     ← {success:true, status:ingested}
         │
         │     heartbeat-ebpf (V3.2+, toutes les 60s)
         │ ──────────────────────────────────▶  UPDATE ebpf_status
         │     ← {success:true, ebpf_acknowledged:false|true}
```

---

## Codes HTTP utilisés

| Code | Signification |
|------|---------------|
| 200  | OK (register existant, heartbeat, push, status) |
| 201  | Created (nouvel agent registre) |
| 401  | HMAC invalide ou agent inconnu |
| 403  | Agent rejeté ou révoqué |
| 404  | Endpoint inexistant |
| 422  | JSON malformé |
| 500  | Erreur serveur interne |

---

## Headers standardisés

| Header | Présent dans | Valeur |
|--------|------------|--------|
| `Content-Type` | Tout | `application/json` |
| `X-LogSoc-Agent` | heartbeat, push, ebpf | `agent_id` |
| `X-LogSoc-Sig` | heartbeat, push, ebpf | `HMAC-SHA256(body, secret_key)` |
| `X-LogSoc-Version` | heartbeat, push | Version agent (ex: `3.1.1`) |
