# Incubateur JamboOS (`incubator/`)

## 1. Raison d'Être & Rôle de l'Incubateur

L'espace `incubator/` héberge les briques prospectives, protocoles de recherche avancée, prototypes d'interface et machines à états en cours de modélisation pour JamboOS.

À compter du **Jalon 2.3 (`v0.3.43`)**, JamboOS opère une distinction formelle entre :
1. **Le Socle Opérationnel Officiel** (workspace racine) : 9 crates bare-metal vérifiées, testées et exécutées en Ring 3 sur matériel réel/émulé (VirtIO QEMU, micro-noyau sans mocks).
2. **L'Incubateur de Recherche & Développement (`incubator/`)** : Briques prospectives, protocoles cryptographiques post-quantiques, serveurs d'infrastructure distribuée et pilotes de périphériques en attente de couplage matériel direct en Ring 3.

```
incubator/
├── Cargo.toml          # Workspace autonome d'incubation
├── README.md           # Présente charte et statut des modules
├── drivers/            # Pilotes de périphériques en attente de validation matérielle
│   ├── nvme/           # Pilote NVMe (spécification en cours de portage Ring 3)
│   └── xhci/           # Contrôleur hôte USB xHCI
├── libs/               # Bibliothèques prospectives
│   ├── jambo-sdk/      # SDK utilisateur unifié (façade haut niveau)
│   └── jambo-ui/       # Toolkit d'interface graphique et rendu raster
└── services/           # ~100 serveurs et démons prospectifs
    ├── jambo-ai-*      # Sécurité et télémétrie IA souveraine
    ├── jambo-pqc/      # Cryptographie post-quantique (ML-KEM, Falcon)
    ├── jambo-wasm/     # Moteur d'isolation WebAssembly / Wasmtime
    ├── jambo-vpn/      # Pile réseau VPN souveraine
    └── ...             # Démons d'administration, audit et zéro-trust
```

---

## 2. Statuts de Maturité des Composants

Tous les modules de l'incubateur relèvent des niveaux **`[SPEC]`** ou **`[SIM]`** selon la matrice de maturité de JamboOS :

| Statut | Définition | Critères d'appartenance |
|:---:|---|---|
| **`[SPEC]`** | **Spécification / Prototype** | Définition d'interfaces IPC, structures de données, validation d'architecture théorique. Sans couplage système actif. |
| **`[SIM]`** | **Machine à États Simulée** | Algorithmes fonctionnels en environnement mémoire pur ou tests unitaires isolés, en attente de ressources Ring 3 (I/O ports, MMIO, DMA, IRQ). |

*Note : Les statuts **`[RING3-HW]`** (pilote ou démon couplé au matériel en Ring 3) et **`[PROD]`** (production bare-metal stabilisée) sont exclusivement réservés aux membres du workspace racine (`services/`, `drivers/`, `kernel`, `abi/`, `libs/libjambo`).*

---

## 3. Critères d'Éligibilité pour l'Intégration au Workspace Racine (Graduation)

Pour qu'un module quitte l'incubateur et intègre l'arborescence officielle (`services/`, `drivers/`, ou `libs/`), il doit satisfaire aux 5 jalons de graduation :

1. **Isolation Ring 3 Stricte** : Démon s'exécutant dans son propre espace d'adressage virtuel (Page Table isolée) sans accès direct privilégié Ring 0.
2. **Couplage IPC Authentique** : Communication exclusive via les canaux IPC de JamboKernel (`ChannelCreate`, `ChannelSend`, `ChannelRecv`, `ChannelCall`) et VMO zéro-copie (`VmoCreate`, `VmoMap`).
3. **Couplage Matériel Prouvé** : Pour les pilotes, validation sur bus PCI/PCIe réel ou émulé sous QEMU (ex. VirtIO, NVMe, AHCI) avec gestion des interruptions IRQ via IPC kernel.
4. **Zéro Mock & Zéro Empreinte Fantôme** : Le code source ne doit dépendre d'aucune simulation logicielle et doit compiler en `x86_64-unknown-none --release` sans aucun avertissement.
5. **Intégration dans `xtask` & QEMU CI** : Démarrage automatisé dans `initrd.tar`, validation par le démon d'initialisation `jambo-init`, et sortie propre avec code de succès CI.

---

## 4. Compilation & Développement

Le workspace d'incubation dispose de son propre fichier `Cargo.toml`. Il peut être vérifié et développé de manière indépendante sans polluer ni ralentir le cycle de compilation du micro-noyau officiel.
