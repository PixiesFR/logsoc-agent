# BUG-FIM — kprobe `vfs_write` stocke le basename au lieu du path complet

**Repo** : `SOC-AGENT` (`git.anytimeadmin.info/pixies/SOC-AGENT`)
**Sévérité** : Moyenne (audit dégradé, YARA HQ non bloqué mais opportunités perdues)
**Découverte** : 5-6 juin 2026, lors du développement T5 YARA HQ
**Tentatives de fix locales** : 2, toutes deux rejetées par le BPF verifier kernel 6.8
**Statut** : À traiter en P8 (maintenance), hors scope YARA HQ

---

## Symptôme

Les events FIM (File Integrity Monitoring) émis par l'agent LogSOC ont un champ `filename` qui contient **uniquement le basename** du fichier (ex: `passwd` au lieu de `/etc/passwd`).

Preuve sur Hestia (prod, kernel 6.8.0-117) :
```bash
$ bpftool prog show | grep trace_fim
9152: kprobe  name trace_fim  ...  run_cnt 71189
# ↑ le kprobe fire bien 71k fois

# Mais les events FIM en DB ont des basenames :
$ curl -s 'https://logsoc.anytimeadmin.info/api/v1/events/?event=fim&limit=20' \
   | jq -r '.[].filename' | sort -u
clickhouse-server.log
primary.cidx
ib_logfile0
syslog
TCP
agent_debug.log
# ↑ AUCUN /etc/* ou /usr/* — que des basenames
```

À l'inverse, les events `open` (type 5, tracepoint `sys_enter_openat`) ont des paths **complets** :
```bash
$ curl -s '.../api/v1/events/?event=open&limit=500' | jq -r '.[].filename' \
   | grep -E '^/' | head -3
/var/lib/clickhouse/store/ca8/ca888648-.../...
/var/lib/clickhouse/store/870/87008708-.../...
```

La différence entre FIM (basename) et open (full path) confirme que le bug est dans le kprobe FIM uniquement.

---

## Cause racine

**Fichier** : `src/ebpf/skel_soc.c` lignes 247-253

```c
SEC("kprobe/vfs_write")
int trace_fim(struct pt_regs *ctx)
{
    ...
    struct file *file = (struct file *)PT_REGS_PARM1(ctx);
    ...
    bpf_probe_read_kernel(&f_path, sizeof(f_path), &file->f_path);
    dentry = f_path.dentry;

    if (dentry) {
        struct qstr d_name = {};
        bpf_probe_read_kernel(&d_name, sizeof(d_name), &dentry->d_name);
        if (d_name.name)
            bpf_probe_read_kernel_str(e->u.f.filename, sizeof(e->u.f.filename), d_name.name);
        //                                                ^^^^^^^^^^^^
        //              BUG: d_name.name est le BASENAME, pas le path complet
    }
    ...
}
```

**Explication** : `struct dentry->d_name` ne contient que **le dernier composant** du chemin (le basename). Pour `/etc/passwd` :
- `dentry->d_name.name` → pointeur vers `"passwd"` (6 bytes)
- `dentry->d_name.len` → 6
- `dentry->d_parent` → pointeur vers le dentry de `/etc`
- qui a son propre `d_parent` → `/` (root)

Pour reconstruire le path complet, il faut **remonter la chaîne `d_parent`** dans le programme BPF.

---

## Impact

### 1. Dashboard FIM dégradé
La page Events filtrée sur `event=fim` affiche des basenames sans contexte. L'analyste voit `passwd` sans savoir si c'est `/etc/passwd`, `/var/tmp/passwd` ou autre. Audit FIM peu exploitable.

### 2. `fim.watch_paths` jamais matché
La config agent (`/etc/logsoc-agent/config.json` section `ebpf.local_filters`) prévoit une whitelist/blacklist de paths à surveiller. **Aucun match possible** : `fim.watch_paths: ["/etc/passwd"]` ne matche jamais l'event dont le filename est `passwd`.

### 3. Hook YARA ne scanne JAMAIS via FIM
`src/agent.cpp` ligne 1380-1386 :
```cpp
if (cfg_.yara_enabled && yara_engine_ &&
    (ev_type == "fim" || ev_type == "open")) {
    std::string yfname = ev.value("filename", "");
    if (!yfname.empty() && yfname[0] == '/') {  // ← filtre basename-only
        yara_engine_->scan_file(yfname, "file");
    }
}
```

Le filtre `yfname[0] == '/'` exclut les basenames. **Seuls les events `open` déclenchent un scan YARA**. YARA HQ fonctionne donc en pratique (open events ont le path complet via tracepoint), mais l'opportunité de scan sur **write** est perdue.

### 4. BPF verifier -13 / -22 sur restart
Quand l'agent crash (pkill -9) sans cleanup, le `bpf_link` du programme FIM leak dans le kernel. Au prochain démarrage, libbpf tente de recharger `trace_fim` avec le même nom → conflit avec le programme leaked → erreur **-22 EINVAL** :
```
libbpf: prog 'trace_fim': failed to load: -22
libbpf: failed to load object 'xxx-eb48'
ebpf init: bpf_object__load failed for skel_soc
2026-06-06 13:40:44 [WARN] [eBPF] init() failed, reason: init_failed:ok
```
→ Tous les autres probes (open, execve, connect) sont aussi désactivés en cascade (le `bpf_object__load` est global).

Workaround temporaire : `pkill -9 -f logsoc-agent; sleep 2` pour que systemd redémarre (mais systemd relance avant le cleanup complet, donc le prog leak reste). Solution durable : implémenter un signal handler qui appelle `ebpf::cleanup()` proprement (loader.cpp ligne 661+).

---

## Tentatives de fix rejetées (locales)

### Tentative #1 : algo walk d_parent avec `break` dans boucle

Code (extrait) :
```c
struct dentry *cur = dentry;
#pragma unroll
for (int i = 0; i < 8; i++) {
    if (!cur) break;
    struct qstr d_name = {};
    bpf_probe_read_kernel(&d_name, sizeof(d_name), &cur->d_name);
    /* Stop at root BEFORE writing */
    if (d_name.len == 1 && d_name.name) {
        char first = 0;
        bpf_probe_read_kernel(&first, sizeof(first), d_name.name);
        if (first == '/') break;
    }
    /* prepend "/" + name */
    int need = d_name.len + 1;
    if (pos - need < 0) break;
    pos -= need;
    tmp[pos] = '/';
    bpf_probe_read_kernel(&tmp[pos + 1], d_name.len, d_name.name);
    /* next parent */
    struct dentry *parent = NULL;
    bpf_probe_read_kernel(&parent, sizeof(parent), &cur->d_parent);
    cur = parent;
}
```

**Erreur** : `libbpf: prog 'trace_fim': failed to load: -13` (EACCES).

**Cause** : le BPF verifier exige des boucles **bornées statiquement et sans `break` dynamique**. Le `break` (early-exit) empêche le verifier de prouver la terminaison en un nombre d'itérations connu. `#pragma unroll` n'aide pas car la condition de break dépend de l'état runtime (`!cur`).

### Tentative #2 : boucle sans break, copie via `bpf_probe_read_kernel`

Code (extrait) :
```c
struct dentry *cur = dentry;
#pragma unroll
for (int i = 0; i < 8; i++) {
    if (cur) {  // garde NULL-check
        struct qstr d_name = {};
        bpf_probe_read_kernel(&d_name, sizeof(d_name), &cur->d_name);
        int is_root = 0;
        if (d_name.len == 1 && d_name.name) {
            char first = 0;
            bpf_probe_read_kernel(&first, sizeof(first), d_name.name);
            if (first == '/') is_root = 1;
        }
        if (!is_root && d_name.name && d_name.len > 0
            && pos - (int)d_name.len - 1 >= 0) {
            pos -= d_name.len + 1;
            tmp[pos] = '/';
            bpf_probe_read_kernel(&tmp[pos + 1], d_name.len, d_name.name);
        }
        struct dentry *parent = NULL;
        bpf_probe_read_kernel(&parent, sizeof(parent), &cur->d_parent);
        if (is_root) cur = NULL; else cur = parent;
    }
}
/* Copy tmp[pos..] into ringbuf event */
if (pos < (int)sizeof(tmp)) {
    int src_off = pos;
    int remaining = (int)sizeof(tmp) - src_off;
    int copy_n = remaining < (int)sizeof(e->u.f.filename) - 1
                  ? remaining
                  : (int)sizeof(e->u.f.filename) - 1;
    bpf_probe_read_kernel(e->u.f.filename, copy_n, &tmp[src_off]);
    e->u.f.filename[copy_n] = '\0';
}
```

**Erreur** : `libbpf: prog 'trace_fim': failed to load: -22` (EINVAL).

**Causes identifiées** :
1. `bpf_probe_read_kernel(dst, copy_n, src)` avec `copy_n` calculé dynamiquement → verifier BPF rejette (taille non constante)
2. `__builtin_memcpy(dst, src, dyn_size)` → `error: A call to built-in function 'memcpy' is not supported`
3. Stack BPF saturée : `char tmp[192]` + 8 itérations × ~32 bytes de `struct qstr` + variables locales ≈ 400 bytes, proche de la limite 512 bytes

---

## Pistes recommandées pour le dev repreneur

### Piste 1 — `bpf_d_path()` kfunc (RECOMMANDÉE)

Le kernel expose depuis 5.10 un kfunc `bpf_d_path()` qui prend un `struct path *` et écrit le path formaté kernel-style dans un buffer.

Pré-requis (déjà remplis sur Hestia) :
- Kernel ≥ 5.10 ✅ (Hestia = 6.8.0-117)
- BTF activé ✅ (`/sys/kernel/btf/vmlinux` 6.9 MB)
- Programme CO-RE ✅ (le code inclut `bpf/bpf_core_read.h`)

**Code attendu** :
```c
/* Dans skel_soc.c, en haut avec les autres extern */
extern int bpf_d_path(struct path *path, char *buf, u32 buf_sz) __ksym;

/* Dans trace_fim(), remplacer le bloc "if (dentry) { ... }" par : */
if (dentry) {
    struct path f_path = {};
    bpf_probe_read_kernel(&f_path, sizeof(f_path), &file->f_path);
    int ret = bpf_d_path(&f_path, e->u.f.filename, sizeof(e->u.f.filename));
    if (ret < 0) {
        /* fallback: store basename + log via ringbuf event flag */
        struct qstr d_name = {};
        bpf_probe_read_kernel(&d_name, sizeof(d_name), &dentry->d_name);
        if (d_name.name)
            bpf_probe_read_kernel_str(e->u.f.filename, sizeof(e->u.f.filename), d_name.name);
    }
}
```

**Risques** :
- kfunc BPF ≠ helper BPF : nécessite `extern ... __ksym` et BTF resolution
- Sur kernel 6.8, `bpf_d_path` est listé dans `/sys/kernel/btf/vmlinux` (vérifié, ligne 159256 de `vmlinux.h`)
- Si BTF resolution échoue au load, le programme entier est refusé
- Validation : rebuild + déploiement sur Hestia, vérifier `bpftool prog show | grep trace_fim` retourne un prog avec `run_cnt > 0` et query API events fim → doit montrer `/etc/passwd`, `/usr/bin/...`, etc.

**Avantages** : pas de boucle, pas de stack limit, robuste (gère les `..`, les symlinks, les mounts).

### Piste 2 — Walk d_parent avec taille copie CONSTANTE

Le problème de la tentative #2 est la **taille de copie dynamique**. Si on contraint `copy_n` à une constante compile-time (toujours copier 63 bytes), `bpf_probe_read_kernel` devient acceptée par le verifier.

**Code attendu** :
```c
char tmp[192] = {};
int pos = sizeof(tmp) - 1;
struct dentry *cur = dentry;
#pragma unroll
for (int i = 0; i < 8; i++) {
    if (cur) {
        struct qstr d_name = {};
        bpf_probe_read_kernel(&d_name, sizeof(d_name), &cur->d_name);
        int is_root = (d_name.len == 1 && d_name.name);  // will read first byte below
        char first = 0;
        if (d_name.name)
            bpf_probe_read_kernel(&first, 1, d_name.name);
        is_root = (d_name.len == 1 && first == '/');
        if (!is_root && d_name.name && d_name.len > 0
            && pos - (int)d_name.len - 1 >= 0) {
            pos -= d_name.len + 1;
            tmp[pos] = '/';
            bpf_probe_read_kernel(&tmp[pos + 1], d_name.len, d_name.name);
        }
        struct dentry *parent = NULL;
        bpf_probe_read_kernel(&parent, sizeof(parent), &cur->d_parent);
        if (is_root) cur = NULL; else cur = parent;
    }
}
/* COPY: taille fixe 63 bytes, acceptée par verifier */
if (pos < (int)sizeof(tmp) - 63) {  // garde optionnelle, refuse de copier si path trop long
    /* VERIFIER n'aime pas bpf_probe_read_kernel non plus si src est sur la stack */
    /* Faut utiliser bpf_probe_read_kernel_str si le verifier accepte,
       sinon utiliser une approche userspace : stocker seulement les
       63 derniers bytes après préfixe calculé. */
}
```

**Risque majeur** : `bpf_probe_read_kernel` (helper) avec src sur la stack BPF peut aussi être rejeté. Dans ce cas, **utiliser un ringbuf event field direct** : faire la copie inline, byte par byte, dans la branche de la boucle, au lieu d'accumuler dans `tmp` puis copier à la fin.

**Alternative** : structure de données différente — émettre **chaque segment** comme un event séparé (ringbuf multi-event), puis reconstituer le path en userspace.

### Piste 3 — Lookup userspace via `/proc/<pid>/fd/`

Émettre un event FIM enrichi avec **inode + dev** (déjà fait dans `e->u.f.inode`). Au moment où l'event est reçu dans `loader.cpp::ringbuf_callback`, faire un lookup dans `/proc/<pid>/fd/<fd>` pour récupérer le path complet. Inconvénient : coût userspace (~5-10ms par event) et instable (le fd peut être fermé au moment du lookup).

**Non recommandée** pour FIM (déjà trop bruité), mais acceptable pour un sous-ensemble (ex: fichiers dans `/etc`, `/usr/bin`).

### Piste 4 — Abandonner FIM, doubler open

Le tracepoint `sys_enter_openat` capture déjà tous les opens avec le path complet. On pourrait :
1. Garder FIM uniquement pour la **détection** (sample 1/8, sans path)
2. Compter sur `open` (pas de sampling) pour le path complet → hook YARA fonctionne déjà comme ça
3. Renommer FIM en `fim_audit` et clarifier dans la doc qu'il n'a pas le path

**Acceptable** mais perd la valeur de FIM en tant que signal d'intégrité fichier.

---

## Tests à faire après fix

1. **Compil BPF** : `cd src && make static_soc_agent` doit compiler sans warning `loop not unrolled`
2. **Build .deb** : `bash packaging/scripts/build-deb.sh` doit produire un .deb avec le nouveau binaire
3. **Deploy Hestia** : push base64 chunked, `dpkg --unpack` + `dpkg --configure`, start
4. **Vérif BPF chargé** : `bpftool prog show | grep trace_fim` → prog avec `run_cnt > 0` et **pas** d'erreur libbpf
5. **Vérif path complet** :
   ```bash
   touch /tmp/fim_test_$(date +%s)
   echo x >> /etc/hostname
   sleep 65  # YARA rate limit 30s + 30s + buffer
   curl -s 'https://logsoc.anytimeadmin.info/api/v1/events/?event=fim&limit=200' \
     | jq -r '.[] | select(.filename | test("^/")) | .filename' | head -3
   # doit retourner au moins un /etc/* ou /usr/*
   ```
6. **Test YARA via FIM** : créer `/etc/yara_eicar_via_fim.txt` avec contenu EICAR, faire `echo x >> fichier`, attendre 60s, query `yara_scan_results` → doit contenir une ligne avec `file_path=/etc/yara_eicar_via_fim.txt`
7. **Test match `fim.watch_paths`** : si la config contient `fim.watch_paths: ["/etc/passwd"]`, faire `echo x >> /etc/passwd` et vérifier qu'un event FIM est présent en DB avec filename=`/etc/passwd`

---

## Fichiers à fournir au dev

- `src/ebpf/skel_soc.c` lignes 195-292 (handler `trace_fim` complet)
- `src/ebpf/event.h` (struct event, type 4 = fim, taille `filename[64]`)
- `src/ebpf/vmlinux.h` ligne 159256 (typedef bpf_d_path)
- `src/ebpf/loader.cpp` case 4 dans `ringbuf_callback` (handler userspace FIM)
- `src/agent.cpp` ligne 1380-1386 (hook YARA)
- `~/.hermes/skills/devops/logsoc-yara-hq/references/libyara-cpp-pitfalls.md` §14 (discussion complète + 2 tentatives de code rejetées + 4 alternatives)

---

## Contexte environnement

- **Kernel cible** : 6.8.0-117-generic (Ubuntu 24.04 Noble)
- **BTF** : `/sys/kernel/btf/vmlinux` = 6.9 MB
- **Outils** : clang 17, llvm-objdump-17, libbpf 1.5
- **Build script** : `scripts/build_ebpf.sh` (compile BPF + génère `src/ebpf_payload.h`)
- **Target C++** : `make static_soc_agent` → `src/static_soc_agent` → `.deb` via `packaging/scripts/build-deb.sh`
- **Validation E2E** : impossible de compiler sur Hestia (règle absolue, INTERDICTION de compiler C++ sur Hestia), tout doit être compilé localement et déployé en binaire

## Contact / hand-off

Pour toute question, le bug est référencé dans :
- Skill `logsoc-yara-hq/references/libyara-cpp-pitfalls.md` §14
- CHANGELOG.md de l'agent entrée `[3.10.0] — 2026-06-06` (section "Bug BPNF : FIM kprobe émet basename uniquement")
