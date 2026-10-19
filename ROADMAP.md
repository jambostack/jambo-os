# ROADMAP DU DÉVELOPPEMENT AUTONOME — JamboOS

> **Dernière mise à jour** : 2026-10-19 13:03 UTC  
> **Version actuelle** : `v0.2.69`  
> **Statut global** : Pré-Alpha active — Micro-noyau de 3e génération orienté capacités (`#![no_std]`)  
> **Cycle de développement autonome** : 10 minutes via le Planificateur de Tâches & Crons d'Antigravity WebUI  

---

## 1. Principes et Règles du Cycle Autonome

À chaque itération du cron (toutes les 10 minutes) :
1. **Inspection** : `git status`, `git log -n 5`, tests unitaires et d'intégration `cargo xtask test`.
2. **Priorisation** : Sélection de la prochaine phase selon ce roadmap.
3. **Implémentation réelle** : Aucune simulation, aucun mock factice, code Rust strict `#![no_std]`.
4. **Validation prouvée** : Exécution de `cargo xtask test` sous QEMU avant tout commit.
5. **Traçabilité & Documentation** : Mise à jour de ce fichier `ROADMAP.md`, du `README.md`, et commit Git versionné (`v0.*.*`).

---

## 2. État d'Avancement des Phases d'Ingénierie

### Phases Validées (v0.1.0 à v0.2.67)

| Jalon / Version | Phase | Composant | Description Technique | Statut |
| :--- | :---: | :--- | :--- | :---: |
| **v0.1.0 - v0.2.38** | 1 - 38 | Kernel & Drivers | Micro-noyau, CSpace, MMU Buddy/SLUB, IPC zéro-copie, VFS CoW, VirtIO Ring 3, APIC SMP | ✅ Validé |
| **v0.2.39** | 39 | Exécution Ring 3 | Commutation CPL 3, syscall roundtrip, `sysretq` | ✅ Validé |
| **v0.2.40** | 40 | APIC & EEVDF | Ordonnancement préemptif EEVDF monotone | ✅ Validé |
| **v0.2.41** | 41 | UART RX Interrupt | Tampon annulaire interactif, interruptions série | ✅ Validé |
| **v0.2.42** | 42 | Shell `jsh` | Shell Ring 3 orienté capacités, commandes natives | ✅ Validé |
| **v0.2.43** | 43 | VFS & JamboFS | Fichiers CoW transactionnels, intégrité Merkle | ✅ Validé |
| **v0.2.44** | 44 | Réseau `jambo-netd` | Pile TCP/IP sans autorité ambiante, sockets Ring 3 | ✅ Validé |
| **v0.2.45** | 45 | Coreutils | Pipelines d'objets structurés, ps, top, capstat | ✅ Validé |
| **v0.2.46** | 46 | Graphisme `jambo-comp` | Compositeur VirtIO-GPU, framework `jambo-ui` | ✅ Validé |
| **v0.2.47** | 47 | Compatibilité POSIX/WASI | Couche POSIX Ring 3 `jambo-linux`, WASI Preview 1 | ✅ Validé |
| **v0.2.48** | 48 | Paquets `jambo-pkgd` | Paquets `.jpkg` immuables (Ed25519/BLAKE3), staging A/B | ✅ Validé |
| **v0.2.49** | 49 | IA Locale `jambo-aid` | Indexation vectorielle PPM, recherche sémantique Top-K | ✅ Validé |
| **v0.2.50** | 50 | Sécurité & Fuzzing | Fuzzing SMAP/SMEP, isolation IOMMU VT-d, chaos FLR | ✅ Validé |
| **v0.2.51** | 51 | Bus RPC `jambo-rpc` | Jetons `DistributedCapToken`, bascule O(1) grappe | ✅ Validé |
| **v0.2.52** | 52 | Audit `jambo-auditd` | Registre cryptographique inaltérable scellé | ✅ Validé |
| **v0.2.53** | 53 | Énergie `jambo-powerd` | ACPI Ring 3, régulation C-states SMP, S0/S3/S5 | ✅ Validé |
| **v0.2.54** | 54 | Chiffrement `jambo-cryptod` | ChaCha20/XTS, scellement TPM 2.0 démarrage mesuré | ✅ Validé |
| **v0.2.55** | 55 | Auth `jambo-authd` | Identités Ed25519, tokens de session, zero-knowledge | ✅ Validé |
| **v0.2.56** | 56 | Micro-VMM `jambo-vmm` | Hyperviseur Type-2 Ring 3, pagination EPT | ✅ Validé |
| **v0.2.57** | 57 | Vhost `jambo-vhostd` | Virtualisation découplée Virtqueues VirtIO-Net/Block | ✅ Validé |
| **v0.2.58** | 58 | Horloge `jambo-timed` | Asservissement PLL/FLL, PTP (IEEE 1588), NTP | ✅ Validé |
| **v0.2.59** | 59 | Consensus `jambo-raft` | Quorum strict, journal répliqué, élection leader | ✅ Validé |
| **v0.2.60** | 60 | Magasin `jambo-kvd` | KV store transactionnel MVCC, baux, CAS | ✅ Validé |
| **v0.2.61** | 61 | Ordonnanceur `jambo-schedd`| Placement multi-critère, conteneurs, migration à chaud | ✅ Validé |
| **v0.2.62** | 62 | Événements `jambo-eventd` | Bus Pub/Sub zéro-copie, filtrage hiérarchique | ✅ Validé |
| **v0.2.63** | 63 | Maillage `jambo-meshd` | Réseau maillé chiffré P2P, anti-rejeu | ✅ Validé |
| **v0.2.64** | 64 | Stockage `jambo-dfsd` | CAS distribué dédupliqué, réplication multi-nœuds | ✅ Validé |
| **v0.2.65** | 65 | Ingress `jambo-gwd` | Passerelle L4/L7, Round-Robin/LeastConns, coupe-circuit | ✅ Validé |
| **v0.2.66** | 66 | Coffre `jambo-vaultd` | Secrets distribués, partage Shamir à seuil K-sur-N | ✅ Validé |
| **v0.2.67** | 67 | Métriques `jambo-metricsd`| Séries temporelles, anneaux bornés, alertes | ✅ Validé |
| **v0.2.68** | 68 | Découverte `jambo-serviced`| Registre dynamique, TTL/heartbeat, résolution IP:port | ✅ Validé |
| **v0.2.69** | 69 | Politiques `jambo-policyd` | ABAC déclaratif, Deny-by-default, préséance refus | ✅ Validé |
| **v0.2.70** | 70 | Traçage `jambo-traced` | Spans bornés, propagation W3C TraceContext | ✅ Validé |
| **v0.2.71** | 71 | Certificats `jambo-certd`| PKI éphémère de grappe, mTLS, CertCap, CRL | ✅ Validé |

---

## 3. Prochaines Étapes Prioritaires

### 🎯 Prochaine Tâche Immédiate : Phase 72 — v0.2.70
* **Composant** : `services/jambo-init`
* **Objectif** : Superviseur Système PID 1 en Ring 3
* **Tâches précises** :
  1. Gestion des dépendances de démarrage entre démons (DAG).
  2. Redémarrage automatique en cas de crash (supervision et relance).
  3. Commandes d'administration système `init [status | restart <daemon> | shutdown]`.
  4. Validation `cargo xtask test` et commit `v0.2.70`.

### 🎯 Tâche Suivante : Phase 73 — v0.2.71
* **Composant** : `services/jambo-wasm`
* **Objectif** : Exécuteur Sandboxed WebAssembly `#![no_std]`
* **Tâches précises** :
  1. Interpréteur de bytecode WASM compact avec validation stricte de mémoire linéaire.
  2. Intégration aux capacités `WasmCap` et test d'exécution d'un module compilé.
  3. Validation `cargo xtask test` et commit `v0.2.71`.

### 🎯 Tâche Suivante : Phase 74 — v0.2.72
* **Composant** : `services/jambo-dnsd`
* **Objectif** : Résolveur et Serveur DNS d'Autorité de Grappe
* **Tâches précises** :
  1. Résolution de domaines locaux `.jambo` et enregistrements A/AAAA/SRV.
  2. Confinement capabilaire `DnsCap` et intégration avec `jambo-serviced`.
  3. Validation `cargo xtask test` et commit `v0.2.72`.

---

## 4. Journal d'Exécution des Cycles

* **2026-10-19 12:47 UTC** : Validation complète Phase 69 (`jambo-policyd`), passage avec succès de la suite de tests QEMU (`cargo xtask test`). Commit `6a5738d` étiqueté `v0.2.67`.
* **2026-10-19 12:51 UTC** : Enregistrement du cycle autonome de 10 minutes dans le Planificateur de Tâches & Crons d'Antigravity WebUI (`jambo-os-cycle`, `*/10 * * * *`, ticker actif).
* **2026-10-19 12:52 UTC** : Validation complète Phase 70 (`jambo-traced`), passage avec succès de la suite de tests QEMU (`cargo xtask test`). Commit `65903bd` étiqueté `v0.2.68`.
* **2026-10-19 13:02 UTC** : Validation complète Phase 71 (`jambo-certd`), passage avec succès de la suite de tests QEMU (`cargo xtask test`, code 0) et des tests unitaires (`cargo test --workspace --lib`). Prêt pour tag `v0.2.69`.

