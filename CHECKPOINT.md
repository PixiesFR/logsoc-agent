# LogSOC-AI Agent V3 — Checkpoint Pause

**Date:** 2026-05-24
**Contexte:** Pause entre A3 et A4/A5. Tous les commits sont poussés.

## ✅ Phases accomplies

| Phase | Commit | État |
|---|---|---|
| A1+A2 | `1b61127` | 4 programmes BPF C + `ebpf_payload.h` (442 Ko) + script build |
| A3 | `a428f50` | Loader statique maison (`loader.hpp` + `loader.cpp`, 4.3 Ko), compilé objet OK |
| B1+B2 | `8ff396a` | Heartbeat eBPF PHP + migration `agents_v3` |
| A4 | `ec7f4a3` | Thread `EbpfCollector` intégré dans `agent_v3.cpp`, compile OK |
| A5 | `833929b` | Loader BPF réel `libbpf`, 4 kprobes, ringbuf poll intégré |
| E1/E2 | `5f50863` | Packaging v3.2 `.deb` + `.rpm` avec capabilities BPF/PERFMON/NET_RAW |

---

## ⏳ Prochaines étapes (F2 — Test E2E)

- [ ] Déploiement `.deb` sur Hestia 10.0.0.10
- [ ] Lancer agent → register → heartbeat eBPF → dashboard
- [ ] Générer trafic test → vérifier ingestion

---

## Workflow "Base Correcte" — Verification avant A4/A5

### 1. Pull & etat
```bash
cd ~/log-soc-ai/repo-agent/
git pull
git log --oneline -5
```

### 2. Compilation statique v3.1.1 (baseline qui marche)
```bash
make clean
make agent_v3.1   # ou make agent_v3 selon ton Makefile
file build/agent_v3.1
ldd build/agent_v3.1  # doit dire "not a dynamic executable"
```

### 3. Lancer l'agent en mode verbeux
```bash
sudo ./build/agent_v3.1 \
  --server https://logsoc.anytimeadmin.info \
  --keyfile /etc/logsoc/key.json \
  --agent-id $(cat /etc/logsoc/uuid.txt 2>/dev/null || uuidgen) \
  --verbose 2>&1 | tee /tmp/agent_test.log
```

### 4. Verifier les 4 etapes de connexion dans les logs
```bash
# Dans un autre terminal pendant que l'agent tourne:
grep -E "register|heartbeat|200 OK|push" /tmp/agent_test.log
```

Attendu dans les logs :
1. `register: success / registered` ou `already registered`
2. `heartbeat: success / 200 OK`
3. `push: success / 200 OK`

### 5. Ping backend PHP (independant de l'agent)
```bash
curl -s -o /dev/null -w "%{http_code}" \
  https://logsoc.anytimeadmin.info/api/v1/status.php
# Doit retourner 200
```

### 6. Verifier en base que l'agent apparait
```bash
# SSH sur Hestia
ssh root@10.0.0.10 "mysql -u logsoc logsoc -e 'SELECT agent_id, status, last_seen FROM agents_v3 ORDER BY last_seen DESC LIMIT 3;'"
```

### 7. Si tout est OK → passer a A4. Si KO → debug baseline avant touche au code eBPF.

---

## Commandes de reprise rapide (minimal)

```bash
# Agent local
cd ~/log-soc-ai/repo-agent/
git pull

# Compiler l'objet loader (verification)
g++ -std=c++17 -c src/ebpf/loader.cpp -o /tmp/loader.o

# Backend Hestia
ssh root@10.0.0.10
cd /home/anytimeadmin/web/logsoc.anytimeadmin.info/public_html/
git pull
```
