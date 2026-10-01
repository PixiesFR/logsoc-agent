# ROADMAP — Auth Persistence & Identity v4.0

## Contexte

Problème actuel : l'agent C++ se reregister a chaque redemarrage, creant
un nouvel agent_id et request_id. Le dashboard accumule les doublons.
L'admin doit re-approuver a chaque fois. L'IP affichee est celle du proxy
(NAT), pas celle reelle de l'agent.

## Objectif

Un agent = un identity stable, auto-reconnexion sans approbation admin,
etendue des metadonnees envoyees au backend.

---

## TACHE A : Agent Identity Persistente (P1 — CRITIQUE)

### A.1 — Fichier `agent_id.txt` immuable
- Cree au premier register, jamais supprime meme par `clear_auth()`
- Content : UUID v4 sur une seule ligne
- Perms : 0600, `logsoc:logsoc`
- Path : `data_dir` (`/var/lib/logsoc-agent/`)

### A.2 — `perform_registration()` — reutilise agent_id connu
- Si `agent_id.txt` existe, lire et envoyer dans le payload :
  ```cpp
  req["agent_id"] = known_agent_id;
  ```
- Backend DOIT reconnaitre un agent_id deja connu et retourner :
  - Si `active` : `200` + secrets (fast-path sans approbation)
  - Si `pending` (jamais approuve) : `202` + request_id existant
  - Si `revoked` : `403`

### A.3 — `load_agent_id()` / `save_agent_id()` helpers
  ```cpp
  bool load_persistent_agent_id(const std::string& dir, std::string& out);
  bool save_persistent_agent_id(const std::string& dir, const std::string& id);
  ```

### A.4 — `main()` — flow corrigee
  ```
  if (load_credentials(auth.json)) {
      goto ACTIVATED;
  }
  if (load_persistent_agent_id(agent_id.txt)) {
      // Heartbeat-like query : est-ce que je suis deja active ?
      if (query_active_status(known_agent_id, cred)) {
          save_credentials(auth.json);
          goto ACTIVATED;
      }
  }
  if (load_pending_state(pending.json)) {
      poll_activation_status(request_id);
      goto ACTIVATED;
  }
  // Dernier recours :
  register_new_agent();
  save_agent_id(agent_id.txt);
  save_pending_state(pending.json);
  poll_activation_status(request_id);
  ```

---

## TACHE B : Hostname + IP Reelle + Metadata (P2)

### B.1 — `perform_registration()` payload enrichi
  ```cpp
  req["hostname"]    = get_hostname();      // gethostname() + uname.nodename
  req["local_ip"]    = get_primary_ip();    // premier non-loopback, AF_INET
  req["mac_address"] = get_primary_mac();   // ou hash si privacy
  req["version"]     = AGENT_VERSION;
  req["platform"]    = "linux-x86_64";
  req["kernel"]      = uname.release;
  req["agent_id"]    = known_agent_id;       // si existant (A.2)
  ```

### B.2 — `get_primary_ip()` helper
  ```cpp
  int get_primary_ip(std::string& out) {
      // ifaddrs AF_INET, skip 127.0.0.1
  }
  ```

### B.3 — Backend PHP : reception
- `register.php` accepte le champ `agent_id` (opt-in)
- Si `agent_id` fourni + present en DB + status `active` → retourne `200` + secrets
- Si `agent_id` fourni + status `pending` → retourne le request_id existant (`202`)
- Table `agents` : colonnes `local_ip`, `mac_address`, `kernel`, `first_seen`, `last_seen`

---

## TACHE C : Backend PHP — X-Forwarded-For (P2)

### C.1 — Detection IP reelle client
  ```php
  $client_ip = $_SERVER['HTTP_X_FORWARDED_FOR'] ??
               $_SERVER['HTTP_X_REAL_IP'] ??
               $_SERVER['REMOTE_ADDR'];
  ```
- Si proxy local (192.168.*), fallback sur `local_ip` du payload (Task B.1)
- Priorite : payload `local_ip` > X-Forwarded-For > REMOTE_ADDR

### C.2 — Table `agents` update
- Nouvelles colonnes : `local_ip`, `mac_address`, `kernel`, `first_seen`, `last_seen`

---

## TACHE D : Service systemd — Robustesse (P2)

### D.1 — `TimeoutStartSec=0` (deja fait)
- Le polling pending dure potentiellement des heures

### D.2 — `Type=notify` + sd_notify (optionnel)
- Envoye `READY=1` apres activation
- systemd comprend que le service est "demarre" meme sans accept()

---

## TACHE E : sender.cpp / curl_global_init (P1)

### E.1 — Deplacer `curl_global_init/cleanup` dans `main()`
- Avant tout thread, apres `main()` init
- Sender thread et heartbeat thread NE DOIVENT PAS appeler `curl_global_init`

---

## FICHIERS A MODIFIER

| Fichier | Changements |
|---------|-------------|
| `src/agent_auth.cpp` | A.2, A.3, B.1, B.2 |
| `src/agent_auth.hpp` | A.3 (declarations) |
| `src/agent.cpp` | A.4 (flow main), E.1 |
| `packaging/debian/DEBIAN/postinst` | Creer `agent_id.txt` vide (pre-pop) |
| `src/ebpf/loader.cpp` | N/A — auth pas dans ebpf |

---

## CLE DE DECISION

- **Backend PHP :** Non touche dans cette session (user a dit "hors backend PHP")
- **C++ Agent :** A implementer pour v3.3.1 ou v3.4.0
- **Priorite :** A.1 + A.2 + E.1 (bloquant pour production)

---

## REFERENCES

- Bug tracker : skill `logsoc-agent`, bug #1 (agent_id persistant)
- Session gap analysis : 20260525_004540_8b4c38
