# Spécification Technique — Jalon 3.5 : Confinement Mémoire & Forensics Volatile en Ring 3 (PID 10), Démon `jambo-forensics` & Commandes `forensics` (v0.3.49)

**Auteur :** Lead Architect & Superpowers System Designer  
**Date :** 1er Novembre 2026  
**Cible :** `v0.3.49`  
**Statut :** PROPOSÉ  

---

## 1. Contexte & Positionnement Stratégique

Après les jalons 3.1 (`v0.3.45` - Résilience Matérielle FDR & TPM 2.0), 3.2 (`v0.3.46` - Runtime WebAssembly/WASI), 3.3 (`v0.3.47` - Cryptographie Post-Quantique ML-KEM/ML-DSA) et 3.4 (`v0.3.48` - Surveillance d'Intégrité Noyau KDIR), JamboOS franchit la cinquième étape majeure du **Palier 3 (« Robustesse Système & Différenciateurs Souverains »)** : **le Confinement Mémoire & Forensics Volatile Post-Incident (`jambo-forensics` PID 10)**.

Les rapports d'experts soulignent :
> *Face à une compromission avancée ou une injection en mémoire, un système moderne ne doit ni paniquer aveuglément (kernel panic qui détruit les preuves volatiles) ni laisser le composant attaqué contaminer le reste du système. Il doit être capable de figer l'état volatile, capturer un snapshot médico-légal scellé cryptographiquement et confiner/mettre en quarantaine le processus en temps constant sans perturber le micro-noyau.*

L'objectif du **Jalon 3.5 (`v0.3.49`)** est d'établir le démon **`jambo-forensics` en Ring 3 (PID 10)** :
1. Capture et analyse médico-légale de la mémoire volatile des processus sans panique noyau.
2. Détection de résidus critiques : clés privées, tokens fuités, fragments de shellcode, chaînes ROP et estimation d'entropie Shannon en virgule fixe.
3. Scellement cryptographique inviolable d'éléments de preuve (`EvidenceSeal`) combinant BLAKE3, SHA-256 et signature asymétrique Ed25519 en `#![no_std]` (zero heap).
4. Registre inaltérable de chaîne de garde (*Chain of Custody*) chaîné par empreintes SHA-256.
5. Extraction d'artefacts temporels (*Timeline Extraction*) et calcul d'indice de menace cumulé.
6. Procédure de mise en quarantaine atomique (`quarantine`) isolant un processus compromis.
7. Commandes interactives dans le shell `jsh` : `forensics status`, `forensics dump <pid>`, `forensics timeline`, `forensics quarantine <pid>`.
8. Listing complet des **10 processus Ring 3** actifs dans la commande `ps`.
9. Intégration dans le micro-noyau `kernel` (PID 10, alignement 16 octets System V ABI, ordonnancement EEVDF) et validation QEMU UEFI avec code de sortie 33.

---

## 2. Architecture & Fonctionnalités de `jambo-forensics`

```
┌────────────────────────────────────────────────────────────────────────┐
│                        ESPACE UTILISATEUR (Ring 3)                     │
│                                                                        │
│  ┌──────────────┐   IPC Channels    ┌───────────────────────────────┐  │
│  │     jsh      │ ◄───────────────► │    jambo-forensics (PID 10)   │  │
│  │  (forensics  │                   │ • Capture Mémoire Volatile    │  │
│  │   status,    │                   │ • Scellement BLAKE3/SHA/Ed    │  │
│  │   dump,      │                   │ • Détection ROP / Shellcode   │  │
│  │   timeline,  │                   │ • Quarantaine de Processus    │  │
│  │  quarantine) │                   │ • Registre Chaîne de Garde    │  │
│  └──────────────┘                   │ • Capabilités ForensicsCap    │  │
│                                     └───────────────┬───────────────┘  │
└─────────────────────────────────────────────────────┼──────────────────┘
                                                      │ Syscalls x86_64
┌─────────────────────────────────────────────────────┼──────────────────┘
│                        MICRO-NOYAU (Ring 0)         ▼                  │
│               Ordonnanceur Multicœur EEVDF (PID 1 à 10)                 │
└────────────────────────────────────────────────────────────────────────┘
```

### 2.1 Moteur Forensics Souverain (`#![no_std]`, Zéro Tas)
1. **Contrôle d'Accès par Capabilités (`ForensicsCap`)** :
   - Zéro autorité ambiante, atténuation monotone stricte.
   - Droits : `CAPTURE_MEMORY`, `EXTRACT_ARTIFACTS`, `ACQUIRE_PROCESS`, `BUILD_TIMELINE`, `SIGN_EVIDENCE`, `VERIFY_SEAL`, `AUDIT_INSPECT`, `TRIAGE_INCIDENT`, `ADMIN`.
2. **Cryptographie Haute Performance & Non-Répudiation** :
   - Hachage BLAKE3 no_std (256 bits).
   - Hachage SHA-256 FIPS 180-4 no_std (256 bits).
   - Signatures numériques Ed25519 compactes pour sceller les preuves.
3. **Capture et Inspection Mémoire Volatile** :
   - `ProcessForensicImage` et `VmoSnapshot` : cartographie des régions mémoire, permissions W+X suspectes.
   - `MemoryResidueAnalyzer` : détection d'entropie élevée (chiffrement/payload), signatures shellcode (`0x90` NOP sleds, `0xcc` INT3, `0x0f 0x05` syscalls), gadgets ROP (`0xc3` RET).
4. **Chronologie d'Incident & Chaîne de Garde** :
   - Journal borné d'artefacts d'attaques (`ForensicArtifact`).
   - Journal de chaîne de garde (`CustodyEntry`) scellé par chaînage SHA-256 inviolable.
5. **Protocole IPC Déterministe (64 octets)** :
   - Opcodes : `GetStatus`, `DumpProcess`, `GetTimeline`, `QuarantineProcess`.
   - Structures `ForensicsRequest` et `ForensicsResponse` de 64 octets exactement.

---

## 3. Commandes Shell `jsh` (PID 2)

- `forensics status` : Affiche l'état du démon, les preuves scellées, le nombre d'entrées dans la chaîne de garde, le statut d'intégrité et le score de risque global.
- `forensics dump <pid>` : Déclenche l'acquisition d'image mémoire volatile du processus spécifié, calcule l'entropie, détecte les résidus malveillants et scelle le dump.
- `forensics timeline` : Affiche les artefacts d'incident chronologiques enregistrés.
- `forensics quarantine <pid>` : Place le processus cible en état de confinement/quarantaine, empêche ses transmissions IPC et scelle l'incident dans la chaîne de garde.
- `ps` : Liste complète des **10 processus Ring 3** :
  `init`, `jsh`, `blockd`, `fs`, `netd`, `fdr`, `wasmd`, `pqc`, `kdir`, `forensics`.

---

## 4. Intégration Micro-Noyau (`kernel`) & `xtask`

- `kernel/Cargo.toml` : version `0.3.49`.
- Extraction de `/bin/forensics` de l'Initrd USTAR.
- Allocation de pile Ring 3 avec validation de l'alignement System V ABI : `assert_eq!(forensics_sp % 16, 0)`.
- Ordonnancement du PID 10 dans l'ordonnanceur EEVDF.
- Journal UART : `[PASS] Confinement Memoire & Forensics Volatile (jambo-forensics PID 10) validee sous QEMU.`
- `xtask` : Compilation de `jambo-forensics` avec `libs/user-x86_64.ld` à `0x00400000`, empaquetage dans `target/initrd.tar`, bannière de disque `"Bienvenue sur JamboOS v0.3.49\n"`.
- Test QEMU automatisé avec code de sortie 33 (`isa-debug-exit`).

