<p align="center">
  <img src="docs/assets/banner.png" alt="JamboOS Banner" width="800">
</p>

<p align="center">
  <img src="docs/assets/logo.svg" alt="JamboOS Logo" width="110" height="110">
  &nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;
  <img src="docs/assets/mascot.svg" alt="JamboOS Mascot" width="110" height="110">
</p>

<h1 align="center"><strong>JamboOS (jambostack/jambo-os)</strong></h1>
<p align="center"><strong>Système d'Exploitation Micro-noyau de 3e Génération Orienté Capacités en Rust <code>#![no_std]</code></strong></p>

<p align="center">
  <a href="https://github.com/jambostack/jambo-os/actions/workflows/ci.yml"><img src="https://github.com/jambostack/jambo-os/actions/workflows/ci.yml/badge.svg" alt="CI"></a>
  <a href="https://github.com/jambostack/jambo-os"><img src="https://img.shields.io/badge/version-v0.2.123-orange.svg" alt="Version"></a>
  <a href="LICENSE"><img src="https://img.shields.io/badge/license-MIT%20OR%20Apache--2.0-green.svg" alt="License"></a>
  <a href="https://www.rust-lang.org/"><img src="https://img.shields.io/badge/rust-nightly%20%23!%5Bno__std%5D-red.svg" alt="Rust"></a>
</p>

<p align="center">
  <em>Auteur & Architecte Principal</em> : <strong>ASSOGBA Prudence Dieudonné</strong> &bull;
  <em>Dépôt officiel</em> : <a href="https://github.com/jambostack/jambo-os">https://github.com/jambostack/jambo-os</a><br>
  <em>Architectures cibles</em> : x86-64 (Long Mode 64 bits) & AArch64 (ARM64) / Multicœur SMP / UEFI 2.11 (Limine v3 Protocol)
</p>

---

> [!IMPORTANT]
> **Statut du Projet : Version v0.2.123 (Gestion de la Posture de Sécurité Cloud/Grappe (CSPM), Détection de Dérive & Remédiation Autonome jambo-cspm)**  
> Le projet JamboOS progresse méthodiquement dans son cycle pré-alpha `v0.*.*`. La version `v0.2.123` introduit le système souverain de Gestion de Posture de Sécurité Cloud/Grappe (CSPM) en espace utilisateur (`services/jambo-cspm`) : moteur d'audit continu de conformité par rapport aux baselines durcies souveraines (CIS Microkernel, DISA STIG, ANSSI SecNumCloud, JamboOS Sovereign), détection de dérive de configuration (drift detection) en temps réel, calcul d'indice de risque de grappe (0-1000) et score de posture (0-100), remédiation autonome en temps réel réalignant les paramètres déviants, contrôle d'accès capabilaire strict `CspmCap` et scellement d'audit cryptographique inviolable par chaînage SHA-256 avec commandes interactives `cspm [status | baselines | items | scan | remediate | verify]` dans le shell `jsh`.

---


## **1. Vue d'ensemble architecturale**

**JamboOS** est un système d'exploitation conçu et développé à partir de zéro (*from scratch*) en Rust `#![no_std]` et Assembleur. Contrairement aux systèmes d'exploitation monolithiques traditionnels (Linux, Windows NT, BSD) dont les dizaines de millions de lignes de code s'exécutent en espace privilégié (Ring 0 / EL1), JamboOS repose sur une architecture de **micro-noyau pragmatique de 3e génération orienté capacités** (*Object-Capability Microkernel*).

### **Les 4 Piliers Fondamentaux**

1. **Base Informatique de Confiance (TCB) Minimale** : Le noyau superviseur (`JamboKernel`) est confiné à moins de 25 000 lignes de code strictement vérifiées. Il ne gère que les primitives irréductibles : ordonnancement EEVDF, pagination MMU/VMO, application des droits de capacités (`CSpace`), transport IPC et programmation IOMMU.
2. **Communication Inter-Processus (IPC) Hybride Zéro-Copie** :
   - *Fastpath synchrone* en registres CPU (temps de commutation < 120 cycles CPU).
   - *Anneaux circulaires partagés asynchrones* (*Shared Ring Buffers* de soumission et complétion) éliminant tout goulot d'étranglement historique des micro-noyaux.
3. **Isolation Matérielle Totale des Pilotes en Ring 3 (IOMMU)** :
   - Tous les pilotes (VirtIO, NVMe 1.4, USB xHCI, VirtIO-Net, VirtIO-GPU) s'exécutent en espace utilisateur sans privilèges.
   - Les accès DMA matériels sont confinés par domaines IOMMU Intel VT-d. En cas d'anomalie ou de crash, le gestionnaire de bus PCIe réinitialise le composant par *Function-Level Reset* (FLR) et le redémarre à chaud en moins de 15 millisecondes sans panique du noyau.
4. **Modèle de Sécurité par Capacités pures (Zéro Autorité Ambiante)** :
   - Aucune ressource système (fichier, mémoire, port réseau, interruption, fenêtre graphique) n'est accessible sans un `Handle` de capacité 64 bits valide (avec protection anti-ABA par compteur de génération).
   - Les droits sont explicitement délégués selon le principe du moindre privilège (*Least Privilege*).

---

## **2. Tableau synoptique d'avancement des phases d'ingénierie**

Toutes les **39 phases** du *Plan Directeur d'Ingénierie* sont intégralement développées, testées et validées sous environnement QEMU UEFI multicœur.

| Phase | Intitulé du Composant | Statut | Responsabilité Technique |
| :---: | :--- | :---: | :--- |
| **0** | **Architecture & ADRs** | ✅ **Terminé** | Spécifications formelles, 6 ADRs architecturales, charte de sécurité `unsafe`. |
| **1** | **Chaîne d'outillage & CI** | ✅ **Terminé** | CI GitHub Actions, `xtask` orchestrateur, `rustfmt`, `clippy -D warnings`. |
| **2** | **Bootstrap & Affichage** | ✅ **Terminé** | Protocole Limine v3 Higher-Half, console UART 16550 COM1, Framebuffer GOP. |
| **3** | **CPU, IDT & SMP** | ✅ **Terminé** | GDT/TSS 64-bit, IDT 256 vecteurs, LAPIC / IOAPIC, réveil SMP des cœurs AP. |
| **4** | **Gestion Mémoire (MMU)** | ✅ **Terminé** | PMM Buddy Allocator, allocateur de tas SLUB (`GlobalAlloc`), VMM 4 niveaux, objets VMO Copy-on-Write (CoW). |
| **5** | **Processus, Threads & Sched** | ✅ **Terminé** | Ordonnanceur EEVDF (Earliest Eligible Virtual Deadline First), commutation de contexte Ring 3. |
| **6** | **CSpace, Syscalls & IPC** | ✅ **Terminé** | Table de capacités CSpace anti-ABA 64 bits, table de 24 appels système, IPC Fastpath registres et Anneaux partagés. |
| **7** | **Système de Fichiers JamboFS** | ✅ **Terminé** | VFS asynchrone, CoW B+Tree, intégrité cryptographique par arbres de Merkle BLAKE3, instantanés atomiques O(1). |
| **8** | **IOMMU & Pilotes Isolés** | ✅ **Terminé** | Domaines IOMMU VT-d, gestionnaire PCIe ECAM/MSI-X, pilotes Ring 3 NVMe 1.4 et USB xHCI avec auto-guérison FLR. |
| **9** | **Pile Réseau `jambo-netd`** | ✅ **Terminé** | Pilote `virtio-net` zéro-copie, pile TCP/IP (RFC 9293), DNS-over-TLS (port 853), TLS 1.3, filtrage par `NetCap`. |
| **10** | **Shell `jsh` & Coreutils** | ✅ **Terminé** | Shell orienté objets `jsh` (délégation de capacités sans autorité ambiante), utilitaires `ps`, `capstat`, `top`, `jpkg`. |
| **11** | **Compositeur `JamboComp`** | ✅ **Terminé** | Pilote VirtIO-GPU, compositeur 60/120 Hz avec Damage Tracking & VSync, toolkit déclaratif `jambo-ui` & terminal `jambo-term`. |
| **12** | **Paquets `JamboPkg` & SDK** | ✅ **Terminé** | Magasin CAS `/pkg/store/<hash>`, paquets immuables `.jpkg` (Ed25519/BLAKE3), staging A/B et rollback O(1), `jambo-sdk`. |
| **13** | **Compatibilité & WASI** | ✅ **Terminé** | Traducteur POSIX Ring 3 `jambo-linux` (zéro dette Ring 0), moteur sandboxed WebAssembly / WASI Snapshot Preview 1. |
| **14** | **Vérification Formelle** | ✅ **Terminé** | 8 preuves formelles Kani/Verus validées au boot (CSpace anti-ABA, MMU W^X, Buddy disjoint, EEVDF monotone, CDT atténuation, IPC anti-deadlock, CoW isolation, transfert linéaire). |
| **15** | **Sous-système d'IA Locale** | ✅ **Terminé** | Démon Ring 3 `jambo-aid`, indexation vectorielle normalisée (PPM), recherche Top-K, tiny embedder n-grammes et intentions typées. |
| **16** | **Sécurité Offensive & Fuzzing** | ✅ **Terminé** | Fuzzing (10k mutations sans panique), débordements IPC, stress CoW, barrière SMAP/SMEP, confinement IOMMU 100%, chaos FLR 12 ms. |
| **17** | **Bus RPC Distribué & Écosystème Grappe** | ✅ **Terminé** | Démon `jambo-rpc`, jetons `DistributedCapToken`, dispatch typé, heartbeats et bascule transparente O(1). |
| **18** | **Audit Cryptographique & Observabilité** | ✅ **Terminé** | Démon `jambo-auditd`, registre inaltérable scellé, capacités `AuditCap`, détection d'anomalies en temps réel. |
| **19** | **Gestion d'Énergie & ACPI Ring 3** | ✅ **Terminé** | Démon `jambo-powerd`, capacités `PowerCap`, transitions S0/S3/S5, régulation C-states SMP et batterie d'urgence. |
| **20** | **Chiffrement de Bloc & TPM 2.0** | ✅ **Terminé** | Démon `jambo-cryptod`, capacités `CryptoVolumeCap`, ChaCha20/XTS, scellement PCR démarrage mesuré. |
| **21** | **Identité Cryptographique & Sessions** | ✅ **Terminé** | Démon `jambo-authd`, identité Ed25519, défi-réponse zéro-connaissance, jetons `SessionTokenCap`, isolation CSpace. |
| **22** | **Micro-VMM & Isolation Type-2** | ✅ **Terminé** | Démon `jambo-vmm`, capacités `VmCap`, pagination imbriquée EPT, piégeage VM-Exits I/O et vCPUs. |
| **23** | **Périphériques Virtuels vhost-user** | ✅ **Terminé** | Démon `jambo-vhostd`, capacités `VhostCap`, émulation VirtIO-Net/Block découplée, virtqueues zéro-copie. |
| **24** | **Synchronisation Horlogère PTP/NTP** | ✅ **Terminé** | Démon `jambo-timed`, capacités `TimeSyncCap`, asservissement PLL/FLL, monotonicité garantie, PTP (IEEE 1588). |
| **25** | **Consensus Distribué Raft** | ✅ **Terminé** | Démon `jambo-raft`, capacités `RaftCap`, quorum strict, journal répliqué, élection de leader et FSM linéaire. |
| **26** | **Magasin Clé-Valeur Transactionnel** | ✅ **Terminé** | Démon `jambo-kvd`, capacités `KvCap`, MVCC monotone, baux temporels (*leases*), Compare-And-Swap (CAS). |
| **27** | **Ordonnanceur de Tâches & Conteneurs** | ✅ **Terminé** | Démon `jambo-schedd`, capacités `SchedCap`, placement multi-critère, migration à chaud, éviction contrôlée (*drain*). |
| **28** | **Bus d'Événements Pub/Sub Asynchrone** | ✅ **Terminé** | Démon `jambo-eventd`, capacités `EventCap`, files annulaires bornées, filtrage hiérarchique par préfixe, drop-oldest. |
| **29** | **Maillage Réseau Chiffré & Zero-Trust** | ✅ **Terminé** | Démon `jambo-meshd`, capacités `MeshCap`, encapsulation chiffrée symétrique MAC 128 bits, table de routage virtuelle, anti-rejeu monotone. |
| **30** | **Stockage Distribué Adressable par Contenu** | ✅ **Terminé** | Démon `jambo-dfsd`, capacités `DfsCap`, adressage CAS 256 bits, déduplication globale, réplication multi-nœuds, anti-corruption. |
| **31** | **Passerelle Réseau L4/L7 & Équilibrage** | ✅ **Terminé** | Démon `jambo-gwd`, capacités `GatewayCap`, aiguillage RoundRobin/LeastConns/IpHash, coupe-circuit réactif, failover. |
| **32** | **Coffre-Fort de Secrets & Quorum à Seuil** | ✅ **Terminé** | Démon `jambo-vaultd`, capacités `VaultCap`, déverrouillage K-sur-N, chiffrement d'enveloppe, baux temporels, rotation. |
| **33** | **Métriques Distribuées & Séries Temporelles** | ✅ **Terminé** | Démon `jambo-metricsd`, capacités `MetricsCap`, anneaux bornés, agrégats O(1), règles d'alerte, détection de seuils. |
| **34** | **Découverte de Services & Résolution de Noms** | ✅ **Terminé** | Démon `jambo-serviced`, capacités `DiscoveryCap`, enregistrement d'instances, TTL/heartbeat, purge automatique. |
| **35** | **Politiques de Sécurité & Contrôle d'Admission** | ✅ **Terminé** | Démon `jambo-policyd`, capacités `PolicyCap`, filtrage ABAC déterministe, Deny-by-default, baux de règles. |
| **36** | **Traçage Distribué & Analyse de Latence** | ✅ **Terminé** | Démon `jambo-traced`, capacités `TraceCap`, arborescences de portées (spans), W3C TraceContext, ring buffers. |
| **37** | **PKI Éphémère & Gestion des Certificats** | ✅ **Terminé** | Démon `jambo-certd`, capacités `CertCap`, autorité CA de grappe, attestations courtes durées, révocation. |
| **38** | **Initrd & Packaging Userspace** | ✅ **Terminé** | Packaging `initrd.tar`, linker script `user-x86_64.ld`, décodeur UStar `#![no_std]` et extraction ELF Limine. |
| **39** | **Exécution Ring 3 & Syscall** | ✅ **Terminé** | Saut matériel `enter_user_mode` (CPL 3), piégeage `syscall`, commutation de contexte et retour `sysretq`. |

---

## **3. Arborescence du projet**

```
jambo-os/
├── abi/
│   └── jambo-abi/           # ABI binaire, constantes d'appels système et types de capacités
├── boot/
│   └── limine.cfg           # Configuration du chargeur d'amorçage Limine v3
├── docs/
│   ├── adr/                 # Architecture Decision Records (ADR-0001 à ADR-0026)
│   ├── assets/              # Identité visuelle, logos, bannières et mascottes officielles
│   └── specs/               # Spécifications de la carte mémoire, ABI et sécurité
├── drivers/
│   ├── nvme/                # Contrôleur de stockage NVMe 1.4 Ring 3
│   ├── virtio/              # Pilotes VirtIO 1.2 (Bloc, Réseau, GPU)
│   └── xhci/                # Contrôleur USB 3.0 xHCI et décodeur HID Ring 3
├── kernel/
│   └── src/
│       ├── arch/x86_64/     # GDT, IDT, APIC, SMP, IOMMU VT-d, ports série
│       ├── cap/             # Gestionnaire CSpace et tables de capacités
│       ├── formal.rs        # Vérifications formelles mathématiques
│       ├── ipc/             # Fastpath IPC et files circulaires partagées
│       ├── mm/              # PMM Buddy, tas SLUB, VMM 4 niveaux et objets VMO
│       ├── sched/           # Ordonnanceur EEVDF multicœur
│       └── syscall/         # Dispatcher des 24 appels système sécurisés
├── libs/
│   ├── jambo-sdk/           # SDK officiel pour le développement d'applications natives
│   ├── jambo-ui/            # Toolkit graphique déclaratif et terminal interactif
│   └── libjambo/            # Bibliothèque d'encapsulation des syscalls et primitives Ring 3
├── services/
│   ├── jambo-aid/           # Démon d'intelligence artificielle locale et recherche sémantique
│   ├── jambo-ai-sec/        # Garde-fous de sécurité IA, détection d'injections & empoisonnement de modèles
│   ├── jambo-attest/        # Attestation cryptographique distante, preuves Zero-Knowledge & confinement grappe
│   ├── jambo-auditd/        # Registre d'audit cryptographique et détection d'anomalies
│   ├── jambo-authd/         # Identité cryptographique Ed25519 et sessions isolées
│   ├── jambo-bpfd/          # Moteur eBPF souverain, vérificateur DAG & filtrage XDP
│   ├── jambo-capspec/       # Spécification formelle, invariants CSpace et atténuation monotone
│   ├── jambo-certd/         # Infrastructure de certificats éphémères & autorité CA
│   ├── jambo-comp/          # Compositeur d'affichage fenêtré zéro-copie
│   ├── jambo-coreutils/     # Utilitaires système (ps, capstat, top, jpkg)
│   ├── jambo-cored/         # Capture d'état post-mortem, crash dumps ELF scellés & télémétrie
│   ├── jambo-dbg/           # Débogage dynamique d'espace utilisateur, DR0..DR7 & introspection
│   ├── jambo-ddos/          # Mitigation Anti-DDoS L3/L4/L7, SYN Cookies & seaux à jetons
│   ├── jambo-dynlinkd/      # Édition de liens dynamiques Ring 3, ELF64 .jso, GOT/PLT & lazy binding
│   ├── jambo-edr/           # Détection & Réponse Terminaux (EDR), filiations, injections & EdrCap
│   ├── jambo-forensics/     # Forensique, capture mémoire volatile & scellement Ed25519/BLAKE3
│   ├── jambo-cryptod/       # Chiffrement de bloc transparent ChaCha20 et scellement TPM 2.0
│   ├── jambo-dfsd/          # Stockage distribué adressable par contenu (CAS) & réplication
│   ├── jambo-diagd/         # Diagnostic matériel autonome, auto-réparation & télémétrie
│   ├── jambo-dnsd/          # Serveur & résolveur DNS d'autorité de grappe (.jambo)
│   ├── jambo-eventd/        # Bus d'événements Pub/Sub asynchrone et découplage de grappe
│   ├── jambo-fhe/           # Chiffrement complètement homomorphe (FHE BFV/CKKS) & calcul aveugle
│   ├── jambo-fs/            # Système de fichiers transactionnel Merkle Copy-on-Write
│   ├── jambo-fuzz/          # Moteur de fuzzing offensif et tests de résilience
│   ├── jambo-gwd/           # Passerelle réseau L4/L7 & équilibrage de charge élastique
│   ├── jambo-hsm/           # Module de sécurité matériel HSM Ring 3, dérivation PKCS#11 & scellement KEK
│   ├── jambo-hsm2/          # HSM distribué, fédération de clés à seuil multi-puces & GKA
│   ├── jambo-idps/          # Détection et prévention d'intrusions Ring 3, heuristique IPC & quarantaine
│   ├── jambo-mpc/           # Calcul multipartite sécurisé (MPC), partage secret de Shamir & triplés de Beaver
│   ├── jambo-init/          # Superviseur système PID 1 en espace utilisateur
│   ├── jambo-ipcd/          # Multiplexeur et passerelle de messagerie IPC distribuée
│   ├── jambo-kms/           # Gestion et séquestre de clés de grappe distribuée & baux temporels
│   ├── jambo-kvd/           # Magasin clé-valeur transactionnel distribué (MVCC & baux)
│   ├── jambo-linux/         # Traducteur d'appels système Linux (compatibilité POSIX)
│   ├── jambo-logd/          # Démon de journalisation structurée et agrégation distribuée
│   ├── jambo-meshd/         # Maillage réseau chiffré P2P et routage zero-trust
│   ├── jambo-metricsd/      # Moteur de métriques distribuées & séries temporelles
│   ├── jambo-mixnet/        # Réseau de mixage anonyme Sphinx & dissimulation de métadonnées
│   ├── jambo-netd/          # Démon réseau TCP/IP, TLS 1.3 et DNS sécurisé
│   ├── jambo-pkgd/          # Gestionnaire de paquets immuables et mises à jour A/B
│   ├── jambo-patchd/        # Rechargement à chaud de binaires Ring 3 & conformité ABI
│   ├── jambo-pki2/          # PKI hybride post-quantique (ML-DSA + Ed25519) & fédération CA
│   ├── jambo-policyd/       # Moteur de politiques de sécurité & admission de grappe
│   ├── jambo-powerd/        # Gestion d'énergie ACPI et régulation thermique/C-states
│   ├── jambo-pqc/           # Cryptographie post-quantique (ML-KEM, ML-DSA) & transition souveraine
│   ├── jambo-profilerd/     # Échantillonnage PMC/PEBS, profils de flammes & analyse de latence
│   ├── jambo-raft/          # Moteur de consensus distribué Raft et réplication d'état
│   ├── jambo-rpc/           # Bus RPC distribué et capacités de cluster
│   ├── jambo-sandd/         # Confinement de processus et micro-bacs à sable Zero-Ambient
│   ├── jambo-schedd/        # Ordonnanceur distribué de charges de travail et micro-VMs
│   ├── jambo-secboot/       # Démarrage sécurisé (Secure Boot), mesure TPM 2.0 PCR & scellement
│   ├── jambo-secpolicyd/    # Démon d'attestation matérielle TPM 2.0 et confinement de grappe
│   ├── jambo-serviced/      # Registre de découverte de services & résolution de noms
│   ├── jambo-sh/            # Shell interactif orienté objets
│   ├── jambo-tee/           # Environnements d'Exécution de Confiance (TEE), enclaves et mémoire chiffrée
│   ├── jambo-timed/         # Synchronisation horlogère distribuée PTP/NTP haute précision
│   ├── jambo-traced/        # Moteur de traçage distribué & propagation de contexte
│   ├── jambo-vaultd/        # Coffre-fort de secrets distribué & quorum de déverrouillage
│   ├── jambo-vhostd/        # Virtualisation de périphériques vhost-user VirtIO Ring 3
│   ├── jambo-vmm/           # Moniteur de micro-VMs et isolation matérielle Type-2
│   ├── jambo-vpn/           # Passerelle VPN WireGuard post-quantique (ML-KEM + Curve25519) & transport chiffré
│   ├── jambo-waf/           # Pare-feu applicatif L7 (WAF) sandboxed, filtrage d'injections & WafCap
│   ├── jambo-walld/         # Pare-feu distribué dynamique & synchronisation conntrack
│   ├── jambo-wasm/          # Runtime WebAssembly / WASI Snapshot Preview 1
│   ├── jambo-wasm2/         # Wasm Component Model, interfaces WIT, Canonical ABI & bac à sable
│   ├── jambo-watchdogd/     # Surveillance de vivacité matérielle/logicielle & chien de garde
│   ├── jambo-zksnark/       # Preuves à divulgation nulle de connaissance (zk-SNARKs) & contraintes R1CS
│   ├── jambo-ztna/          # Architecture Zero Trust (ZTNA), micro-périmètres & ré-évaluation de posture
│   ├── jambo-casb/          # Courtier d'accès cloud/grappe (CASB), conformité multi-tenant & DLP
│   ├── jambo-cspm/          # Gestion de posture cloud/grappe (CSPM), dérive & remédiation autonome
│   └── pcie-bus-mgr/        # Gestionnaire de bus PCIe, MSI-X et isolation IOMMU
└── xtask/                   # Outil de compilation, création d'ISO et test QEMU
```

---

## **4. Instructions de compilation et d'exécution**

### **Prérequis**
- Rust `nightly` avec la cible `x86_64-unknown-none` (`rustup target add x86_64-unknown-none`)
- Composants : `rust-src`, `llvm-tools-preview`, `clippy`, `rustfmt`
- Outils système : `qemu-system-x86_64`, `xorriso`, `ovmf`

### **Commandes principales via `xtask`**

```bash
# 1. Compiler le noyau JamboKernel en mode release
cargo xtask build --release

# 2. Générer l'image ISO amorçable hybride UEFI / BIOS (jamboos-x86_64.iso)
cargo xtask iso --release

# 3. Lancer la machine virtuelle sous QEMU (4 cœurs SMP, 2 Go de RAM, OVMF UEFI)
cargo xtask qemu --release

# 4. Exécuter la suite complète de validation automatisée CI
cargo xtask test --release
```

---

## **5. Licence**

Le projet **JamboOS** est distribué sous double licence [MIT](LICENSE) ou [Apache-2.0](LICENSE), au choix de l'utilisateur.
