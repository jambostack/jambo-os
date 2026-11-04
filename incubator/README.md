# Incubateur R&D JamboOS (`incubator/`)

> **Statut de l'Incubateur** : Espace Autonome de Recherche & Prototypage Avancé  
> **Workspace Dédié** : Indépendant du micro-noyau officiel (zéro impact sur le cycle de compilation du Ring 0)

---

## 1. Raison d'Être & Rôle de l'Incubateur

L'espace `incubator/` héberge les briques prospectives, protocoles de recherche avancée, prototypes d'interface et machines à états en cours de modélisation pour JamboOS.

Le projet opère une séparation hermétique entre :
1. **Le Socle Opérationnel Officiel** (workspace racine) : Le micro-noyau Iron Core (`kernel/`), l'ABI système (`abi/`), la bibliothèque d'exécution (`libs/libjambo/`), le pilote VirtIO (`drivers/virtio/`) et les **38 microservices Ring 3 certifiés** (`services/`) compilés dans `initrd.tar`.
2. **L'Incubateur R&D (`incubator/`)** : Les modules prospectifs (cryptographie homomorphe, preuves à divulgation nulle de connaissance, intelligence artificielle souveraine, consensus distribué Raft) et les pilotes en attente de banc d'essai physique (NVMe, xHCI).

```
incubator/
├── Cargo.toml          # Workspace autonome d'incubation
├── README.md           # Charte, statuts et suivi de graduation
├── drivers/            # Pilotes en attente de banc d'essai physique
│   ├── nvme/           # Pilote NVMe 1.4 MMIO
│   └── xhci/           # Contrôleur hôte USB 3.0 xHCI
├── libs/               # Bibliothèques prospectives
│   ├── jambo-sdk/      # SDK utilisateur unifié (façade haut niveau)
│   └── jambo-ui/       # Toolkit d'interface graphique et rendu raster
└── services/           # Prototypes prospectifs & Algorithmes en mémoire
    ├── jambo-ai-*      # Sécurité et télémétrie IA souveraine
    ├── jambo-fhe/      # Chiffrement homomorphe complet (TFHE)
    ├── jambo-zksnark/  # Preuves à divulgation nulle de connaissance (Groth16/Plonk)
    ├── jambo-mpc/      # Calcul multipartite sécurisé
    ├── jambo-mixnet/   # Routage anonyme en oignon
    ├── jambo-raft/     # Consensus distribué d'état tolérant aux pannes
    └── ...             # Algorithmes de recherche fondamentale
```

---

## 2. Statuts de Maturité des Composants

Tous les modules résidant dans l'incubateur relèvent des niveaux **`[SPEC]`** ou **`[SIM]`** :

| Statut | Sigle | Définition & Critères d'Appartenance |
| :---: | :---: | :--- |
| **Spécification** | ⚪ `[SPEC]` | Définition d'interfaces IPC, structures de données ABI, validation d'architecture théorique. Sans couplage système actif. |
| **Simulation / Modèle** | 🔵 `[SIM]` | Algorithmes fonctionnels en environnement mémoire pur ou tests unitaires isolés, en attente de couplage Ring 3. |

*Rappel : Les statuts **`[RING3-HW]`** (38 microservices actifs dans `services/`) et **`[PROD]`** (micro-noyau, ABI, chaîne `xtask`) sont strictement réservés aux composants du socle officiel.*

---

## 3. Registre des Microservices Gradués vers le Socle Officiel (`services/`)

À l'issue des Paliers 2, 3 et 4, les **38 microservices** suivants ont satisfait à l'intégralité des critères de graduation et ont été promus dans l'arborescence officielle du système :

| PID | Service Officiel | Statut | Rôle dans l'Architecture JamboOS |
| :---: | :--- | :---: | :--- |
| **1** | `jambo-init` | 🟡 `[RING3-HW]` | Superviseur racine de démarrage et gestionnaire de cycle de vie Ring 3 |
| **2** | `jambo-sh` | 🟡 `[RING3-HW]` | Shell interactif connecté à la console série UART COM1 (115200 baud) |
| **3** | `jambo-blockd` | 🟡 `[RING3-HW]` | Pilote de stockage VirtIO-Block Modern 1.2 avec queues DMA et arène VMO |
| **4** | `jambo-fs` | 🟡 `[RING3-HW]` | Serveur de fichiers transactionnel JamboFS (Uberblock LBA 0, Inodes) |
| **5** | `jambo-netd` | 🟡 `[RING3-HW]` | Pilote réseau VirtIO-Net Modern 1.2, résolutions ARP et ping ICMP |
| **6** | `jambo-fdr` | 🟡 `[RING3-HW]` | Résilience matérielle, surveillance firmware et racine de confiance TPM 2.0 |
| **7** | `jambo-wasmd` | 🟡 `[RING3-HW]` | Runtime WebAssembly WASI `#![no_std]` ultra-léger pour micro-services |
| **8** | `jambo-pqc` | 🟡 `[RING3-HW]` | Cryptographie post-quantique en Ring 3 (ML-KEM, Falcon) |
| **9** | `jambo-kdir` | 🟡 `[RING3-HW]` | Surveillance d'intégrité du noyau et des tables de sauts |
| **10** | `jambo-forensics` | 🟡 `[RING3-HW]` | Confinement mémoire et capture forensique volatile |
| **11** | `jambo-powerd` | 🟡 `[RING3-HW]` | Gestion de l'énergie, états C-States et régulation thermique CPU |
| **12** | `jambo-metricsd` | 🟡 `[RING3-HW]` | Métrologie haute précision et télémétrie de latence IPC |
| **13** | `jambo-bpfd` | 🟡 `[RING3-HW]` | Bac à sable d'exécution eBPF et filtrage réseau XDP |
| **14** | `jambo-vpn` | 🟡 `[RING3-HW]` | Passerelle VPN post-quantique WireGuard souveraine |
| **15** | `jambo-authd` | 🟡 `[RING3-HW]` | Identité cryptographique, jetons de session et isolation des privilèges |
| **16** | `jambo-dnsd` | 🟡 `[RING3-HW]` | Résolution de noms DNS de grappe et découverte de microservices |
| **17** | `jambo-timed` | 🟡 `[RING3-HW]` | Synchronisation horlogère PTP/NTP et garantie de temps monotone |
| **18** | `jambo-auditd` | 🟡 `[RING3-HW]` | Registre d'audit inaltérable chaîné par empreintes cryptographiques |
| **19** | `jambo-walld` | 🟡 `[RING3-HW]` | Pare-feu d'état L3/L4 et synchronisation de tables conntrack |
| **20** | `jambo-vaultd` | 🟡 `[RING3-HW]` | Coffre-fort de secrets distribué et déverrouillage à seuil |
| **21** | `jambo-watchdogd`| 🟡 `[RING3-HW]` | Chien de garde matériel/logiciel et détection de famine de threads |
| **22** | `jambo-cored` | 🟡 `[RING3-HW]` | Capture automatique des crash dumps ELF64 et analyse post-mortem |
| **23** | `jambo-pkgd` | 🟡 `[RING3-HW]` | Gestionnaire de paquets adressés par le contenu (CAS) et mises à jour A/B |
| **24** | `jambo-certd` | 🟡 `[RING3-HW]` | Infrastructure PKI éphémère et émission de certificats mTLS |
| **25** | `jambo-policyd` | 🟡 `[RING3-HW]` | Moteur de politiques déclaratives de sécurité et contrôle d'admission |
| **26** | `jambo-secboot` | 🟡 `[RING3-HW]` | Démarrage mesuré TPM 2.0 et chaîne de confiance cryptographique |
| **27** | `jambo-logd` | 🟡 `[RING3-HW]` | Journalisation structurée haute performance et agrégation de traces |
| **28** | `jambo-kms` | 🟡 `[RING3-HW]` | Gestionnaire de clés de chiffrement et dérivation HKDF |
| **29** | `jambo-attest` | 🟡 `[RING3-HW]` | Attestation cryptographique distante et preuves ZKP |
| **30** | `jambo-waf` | 🟡 `[RING3-HW]` | Pare-feu applicatif L7 et filtrage d'injections malveillantes |
| **31** | `jambo-siem` | 🟡 `[RING3-HW]` | Moteur de corrélation d'événements et détection d'intrusions |
| **32** | `jambo-edr` | 🟡 `[RING3-HW]` | Détection et réponse sur terminaux en temps réel |
| **33** | `jambo-ndr` | 🟡 `[RING3-HW]` | Analyse d'anomalies de trafic réseau et détection de flux suspects |
| **34** | `jambo-xdr` | 🟡 `[RING3-HW]` | Détection et réponse étendue unifiant réseau, mémoire et processus |
| **35** | `jambo-soar` | 🟡 `[RING3-HW]` | Orchestration et automatisation de la remédiation aux incidents |
| **36** | `jambo-ueba` | 🟡 `[RING3-HW]` | Analyse comportementale des processus et détection d'anomalies |
| **37** | `jambo-itdr` | 🟡 `[RING3-HW]` | Détection et remédiation des menaces sur l'identité et les accès |
| **38** | `jambo-dlp` | 🟡 `[RING3-HW]` | Prévention des fuites de données confidentielles |

---

## 4. Critères de Graduation pour les Modules Restants

Pour qu'un module prospectif restant dans `incubator/` soit promu vers l'arborescence officielle, il doit satisfaire aux 5 conditions impératives :
1. **Isolation Ring 3 Stricte** : Espace d'adressage virtuel PML4 dédié (CR3 propre) et pile System V ABI indépendante.
2. **Communication Exclusive IPC & VMO** : Zéro appel direct non documenté ; passage de messages via canaux CSpace et mémoire virtuelle partagée.
3. **Couplage Matériel Authentique** : Détection sur bus réel/émulé (PCI, IOMMU VT-d, TPM 2.0) sans aucun composant simulé.
4. **Conformité Qualité & Zéro Mock** : Code 100% Rust `#![no_std]`, `cargo clippy -D warnings`, et zéro panique.
5. **Intégration dans `xtask` & Test CI** : Démarrage vérifié dans `initrd.tar` avec passage des tests QEMU (code de sortie 33).
