# ROADMAP DU DÉVELOPPEMENT AUTONOME — JamboOS

> **Dernière mise à jour** : 2026-10-19 22:15 UTC  
> **Version actuelle** : `v0.2.93`  
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

### Phases Validées (v0.1.0 à v0.2.90)

| Jalon / Version | Phase | Composant | Description Technique | Statut |
| :--- | :---: | :--- | :--- | :--- |
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
| **v0.2.67** | 69 | Politiques `jambo-policyd` | ABAC déclaratif, Deny-by-default, préséance refus | ✅ Validé |
| **v0.2.68** | 70 | Traçage `jambo-traced` | Spans bornés, propagation W3C TraceContext | ✅ Validé |
| **v0.2.69** | 71 | Certificats `jambo-certd`| PKI éphémère de grappe, mTLS, CertCap, CRL | ✅ Validé |
| **v0.2.70** | 72 | Superviseur `jambo-init` | Superviseur PID 1, ordonnancement DAG, auto-guérison, shutdown | ✅ Validé |
| **v0.2.71** | 73 | Wasm Sandbox `jambo-wasm` | Exécuteur WebAssembly `#![no_std]`, stack machine, WasmCap, WASI | ✅ Validé |
| **v0.2.72** | 74 | DNS de Grappe `jambo-dnsd` | Résolveur d'autorité `.jambo`, A/AAAA/SRV/TXT/PTR, RFC 1035 wire-format, DnsCap, synchro `jambo-serviced` | ✅ Validé |
| **v0.2.73** | 75 | Journalisation `jambo-logd` | Journalisation structurée `#![no_std]`, anneau borné haute performance, scellement cryptographique inviolable, LogCap, archivage chiffré `jambo-dfsd` | ✅ Validé |
| **v0.2.74** | 76 | Filtrage eBPF `jambo-bpfd` | Interpréteur eBPF souverain, vérificateur formel DAG (0 boucle), maps partagées, crochets XDP, BpfCap | ✅ Validé |
| **v0.2.75** | 77 | Multiplexeur IPC `jambo-ipcd` | Multiplexage de canaux IPC inter-nœuds chiffrés, routage déterministe par priorité (Critical/High/Normal/Background), anti-rejeu, IpcCap | ✅ Validé |
| **v0.2.76** | 78 | Attestation TPM 2.0 `jambo-secpolicyd` | Attestation matérielle distante TPM 2.0, citations signées TpmQuote, défi-réponse anti-rejeu, confinement de grappe, SecPolicyCap | ✅ Validé |
| **v0.2.77** | 79 | Pare-feu `jambo-walld` | Pare-feu d'état distribué, machine FSM conntrack, synchronisation d'état scellée HMAC, Zero-Trust adaptatif, auto-blocage scans, WallCap | ✅ Validé |
| **v0.2.78** | 80 | Diagnostics `jambo-diagd` | Surveillance active PCIe/NVMe/VirtIO/ECC/MCA, auto-remédiation (Link Retraining, FLR, Hot-Failover), scellement SHA-256, DiagCap | ✅ Validé |
| **v0.2.79** | 81 | Confinement `jambo-sandd` | Confinement Seccomp/Landlock Zero-Ambient, resserrement monotone, SandCap, audit SHA-256 | ✅ Validé |
| **v0.2.80** | 82 | Watchdog `jambo-watchdogd` | Chien de garde matériel/logiciel, détection dérive event loop, isolation NMI, vivacité grappe, WatchdogCap | ✅ Validé |
| **v0.2.81** | 83 | Core Dumps `jambo-cored` | Capture d'état post-mortem, crash dumps ELF64 scellés SHA-256, isolation mémoire & quarantaine, télémétrie post-crash, CoreCap | ✅ Validé |
| **v0.2.82** | 84 | Livepatching `jambo-patchd` | Rechargement à chaud de binaires Ring 3, injection atomique de trampolines, quiescence de threads, conformité ABI, PatchCap | ✅ Validé |
| **v0.2.83** | 85 | Profilage `jambo-profilerd` | Échantillonnage de compteurs de performance matérielle (PMC/PEBS), profils de flammes (Flamegraphs) et analyse de latence Ring 3 | ✅ Validé |
| **v0.2.84** | 86 | Débogueur `jambo-dbg` | Débogage dynamique d'espace utilisateur, registres de points d'arrêt matériels DR0..DR7, pas à pas et introspection mémoire | ✅ Validé |
| **v0.2.85** | 87 | Éditeur de Liens `jambo-dynlinkd` | Édition de liens dynamiques Ring 3, bibliothèques partagées ELF64 `.jso`, tables GOT/PLT, résolution différée et durcissement RELRO | ✅ Validé |
| **v0.2.86** | 88 | Seccomp BPF `jambo-seccomp` | Filtres d'appels système granulaires BPF, validation DAG O(N), actions (Allow, Kill, Trap, Errno), TSYNC, no_new_privs & conformité POSIX | ✅ Validé |
| **v0.2.87** | 89 | Mandat d'Accès MAC `jambo-mac` | MLS Bell-LaPadula (confidentialité NRU/NWD), Biba (intégrité NRD/NWU), treillis de compartiments, déclassification contrôlée, MacCap & scellement SHA-256 | ✅ Validé |
| **v0.2.88** | 90 | Confinement VFS `jambo-landlock` | Sandboxing VFS sans autorité ambiante, règles d'arborescence path_beneath, empilement monotone irréversible, héritage fork, LandlockCap & audit SHA-256 | ✅ Validé |
| **v0.2.89** | 91 | Spécification CSpace `jambo-capspec` | Spécification formelle, vérification dynamique d'invariants CSpace, atténuation monotone, absence d'autorité ambiante, CapSpecCap & scellement SHA-256 | ✅ Validé |
| **v0.2.90** | 92 | Environnements TEE `jambo-tee` | Enclaves matérielles isolées (SGX/TDX & TrustZone/CCA), mémoire chiffrée, scellement SHA-256, TeeCap | ✅ Validé |
| **v0.2.91** | 93 | Attestation Grappe `jambo-attest` | Attestation cryptographique à distance, preuves Zero-Knowledge (ZKP) Schnorr/Fiat-Shamir, revendications d'intégrité, confinement de grappe & scellement SHA-256 | ✅ Validé |
| **v0.2.92** | 94 | Sécurité Matérielle `jambo-hsm` | Module de sécurité matériel HSM Ring 3, dérivation PKCS#11, scellement KEK, zéroïsation d'urgence & audit SHA-256 | ✅ Validé |
| **v0.2.93** | 95 | Calcul MPC `jambo-mpc` | Calcul Multipartite Sécurisé (MPC), corps GF(256), partage secret de seuil de Shamir (SSS/VSS), triplés de Beaver, détection byzantine & audit SHA-256 | ✅ Validé |
| **v0.2.94** | 96 | Cryptographie Post-Quantique `jambo-pqc` | Cryptographie Post-Quantique (ML-KEM / Kyber-768 & ML-DSA / Dilithium-65), arithmétique d'anneaux négacycliques, Dual-Defense HKDF, transition quantique & audit SHA-256 | ✅ Validé |

---

## 3. Prochaines Étapes Prioritaires

### 🎯 Prochaine Tâche Immédiate : Phase 97 — v0.2.95
* **Composant** : `services/jambo-zksnark`
* **Objectif** : Preuves à Divulgation Nulle de Connaissance (zk-SNARKs), circuits arithmétiques R1CS et vérification succincte Ring 3
* **Tâches précises** :
  1. Moteur de vérification de contraintes R1CS `#![no_std]`.
  2. Preuves succinctes non-interactives et validation `cargo xtask test`.

### 🎯 Tâche Suivante : Phase 98 — v0.2.96
* **Composant** : `services/jambo-fhe`
* **Objectif** : Chiffrement Complètement Homomorphe (FHE), schémas BFV/CKKS sur anneaux et calculs aveugles en Ring 3
* **Tâches précises** :
  1. Arithmétique d'anneaux homomorphes et bootstrapp `#![no_std]`.
  2. Opérations arithmétiques chiffrées et validation `cargo xtask test`.

---

## 4. Journal d'Exécution des Cycles

* **2026-10-19 12:47 UTC** : Validation complète Phase 69 (`jambo-policyd`), passage avec succès de la suite de tests QEMU (`cargo xtask test`). Commit `6a5738d` étiqueté `v0.2.67`.
* **2026-10-19 12:51 UTC** : Enregistrement du cycle autonome de 10 minutes dans le Planificateur de Tâches & Crons d'Antigravity WebUI (`jambo-os-cycle`, `*/10 * * * *`, ticker actif).
* **2026-10-19 12:52 UTC** : Validation complète Phase 70 (`jambo-traced`), passage avec succès de la suite de tests QEMU (`cargo xtask test`). Commit `65903bd` étiqueté `v0.2.68`.
* **2026-10-19 13:02 UTC** : Validation complète Phase 71 (`jambo-certd`), passage avec succès de la suite de tests QEMU (`cargo xtask test`, code 0) et des tests unitaires (`cargo test --workspace --lib`). Tag `v0.2.69`.
* **2026-10-19 13:22 UTC** : Validation complète Phase 72 (`jambo-init`), passage avec succès de la suite de tests QEMU (`cargo xtask test`, code 0) et des tests unitaires (`cargo test --workspace --lib`). Tag `v0.2.70`.
* **2026-10-19 13:42 UTC** : Validation complète Phase 73 (`jambo-wasm`), passage avec succès de la suite de tests QEMU (`cargo xtask test`, code 0) et des tests unitaires (`cargo test --workspace --lib`). Tag `v0.2.71`.
* **2026-10-19 14:08 UTC** : Validation complète Phase 74 (`jambo-dnsd`), passage avec succès de la suite de tests QEMU (`cargo xtask test`, code 0) et des tests unitaires (`cargo test --workspace --lib`). Tag `v0.2.72`.
* **2026-10-19 14:22 UTC** : Validation complète Phase 75 (`jambo-logd`), passage avec succès de la suite de tests QEMU (`cargo xtask test`, code 0) et des tests unitaires (`cargo test --workspace --lib`). Tag `v0.2.73`.
* **2026-10-19 14:42 UTC** : Validation complète Phase 76 (`jambo-bpfd`), passage avec succès de la suite de tests QEMU (`cargo xtask test`, code 0) et des tests unitaires (`cargo test --workspace --lib`). Tag `v0.2.74`.
* **2026-10-19 15:05 UTC** : Validation complète Phase 77 (`jambo-ipcd`), passage avec succès de la suite de tests QEMU (`cargo xtask test`, code 0) et des tests unitaires (`cargo test --workspace --lib`). Tag `v0.2.75`.
* **2026-10-19 15:23 UTC** : Validation complète Phase 78 (`jambo-secpolicyd`), passage avec succès de la suite de tests QEMU (`cargo xtask test`, code 0) et des tests unitaires (`cargo test --workspace --lib`). Tag `v0.2.76`.
* **2026-10-19 15:45 UTC** : Validation complète Phase 79 (`jambo-walld`), passage avec succès de la suite de tests QEMU (`cargo xtask test`, code 0) et des tests unitaires (`cargo test --workspace --lib`). Tag `v0.2.77`.
* **2026-10-19 16:05 UTC** : Validation complète Phase 80 (`jambo-diagd`), passage avec succès de la suite de tests QEMU (`cargo xtask test`, code 0) et des tests unitaires (`cargo test --workspace --lib`). Tag `v0.2.78`.
* **2026-10-19 16:20 UTC** : Validation complète Phase 81 (`jambo-sandd`), passage avec succès de la suite de tests QEMU (`cargo xtask test`, code 0) et des tests unitaires (`cargo test --workspace --lib`). Tag `v0.2.79`.
* **2026-10-19 16:42 UTC** : Validation complète Phase 82 (`jambo-watchdogd`), passage avec succès de la suite de tests QEMU (`cargo xtask test`, code 0) et des tests unitaires (`cargo test --workspace --lib`). Tag `v0.2.80`.
* **2026-10-19 17:05 UTC** : Validation complète Phase 83 (`jambo-cored`), passage avec succès de la suite de tests QEMU (`cargo xtask test`, code 0) et des tests unitaires (`cargo test -p jambo-cored`). Tag `v0.2.81`.
* **2026-10-19 17:25 UTC** : Validation complète Phase 84 (`jambo-patchd`), passage avec succès de la suite de tests QEMU (`cargo xtask test`, code 0) et des tests unitaires (`cargo test -p jambo-patchd`). Tag `v0.2.82`.
* **2026-10-19 17:40 UTC** : Validation complète Phase 85 (`jambo-profilerd`), passage avec succès de la suite de tests QEMU (`cargo xtask test`, code 0) et des tests unitaires (`cargo test -p jambo-profilerd`). Tag `v0.2.83`.
* **2026-10-19 18:00 UTC** : Validation complète Phase 86 (`jambo-dbg`), passage avec succès de la suite de tests QEMU (`cargo xtask test`, code 0) et des tests unitaires (`cargo test -p jambo-dbg`). Tag `v0.2.84`.
* **2026-10-19 18:20 UTC** : Validation complète Phase 87 (`jambo-dynlinkd`), passage avec succès de la suite de tests QEMU (`cargo xtask test`, code 0) et des tests unitaires (`cargo test -p jambo-dynlinkd`). Tag `v0.2.85`.
* **2026-10-19 20:00 UTC** : Validation complète Phase 88 (`jambo-seccomp`), passage avec succès de la suite de tests QEMU (`cargo xtask test`, code 0) et des tests unitaires (`cargo test -p jambo-seccomp`). Tag `v0.2.86`.
* **2026-10-19 20:20 UTC** : Validation complète Phase 89 (`jambo-mac`), passage avec succès de la suite de tests QEMU (`cargo xtask test`, code 0) et des tests unitaires (`cargo test -p jambo-mac`). Tag `v0.2.87`.
* **2026-10-19 20:35 UTC** : Validation complète Phase 90 (`jambo-landlock`), passage avec succès de la suite de tests QEMU (`cargo xtask test`, code 0) et des tests unitaires (`cargo test -p jambo-landlock`). Tag `v0.2.88`.
* **2026-10-19 21:05 UTC** : Validation complète Phase 91 (`jambo-capspec`), passage avec succès de la suite de tests QEMU (`cargo xtask test`, code 0) et des tests unitaires (`cargo test -p jambo-capspec`). Tag `v0.2.89`.
* **2026-10-19 21:20 UTC** : Validation complète Phase 92 (`jambo-tee`), passage avec succès de la suite de tests QEMU (`cargo xtask test`, code 0) et des tests unitaires (`cargo test -p jambo-tee`). Tag `v0.2.90`.
* **2026-10-19 21:35 UTC** : Validation complète Phase 93 (`jambo-attest`), passage avec succès de la suite de tests QEMU (`cargo xtask test`, code 0) et des tests unitaires (`cargo test -p jambo-attest`). Tag `v0.2.91`.
* **2026-10-19 21:55 UTC** : Validation complète Phase 94 (`jambo-hsm`), passage avec succès de la suite de tests QEMU (`cargo xtask test`, code 0) et des tests unitaires (`cargo test -p jambo-hsm`). Tag `v0.2.92`.
* **2026-10-19 22:15 UTC** : Validation complète Phase 95 (`jambo-mpc`), passage avec succès de la suite de tests QEMU (`cargo xtask test`, code 0) et des tests unitaires (`cargo test -p jambo-mpc`). Tag `v0.2.93`.
* **2026-10-19 22:55 UTC** : Validation complète Phase 96 (`jambo-pqc`), passage avec succès de la suite de tests QEMU (`cargo xtask test`, code 0) et des tests unitaires (`cargo test -p jambo-pqc`). Tag `v0.2.94`.






