# Spécification Technique — Jalon 3.3 : Cryptographie Post-Quantique Souveraine en Ring 3 (PID 8), Démon `jambo-pqc` & Commandes `pqc` (v0.3.47)

**Auteur :** Lead Architect & Superpowers System Designer  
**Date :** 31 Octobre 2026  
**Cible :** `v0.3.47`  
**Statut :** PROPOSÉ  

---

## 1. Contexte & Positionnement Stratégique

À la suite de la clôture des Jalons 3.1 (`v0.3.45` - Résilience Matérielle FDR & TPM 2.0) et 3.2 (`v0.3.46` - Exécution Microservices WebAssembly / WASI sans Linux), JamboOS aborde le troisième pilier stratégique du **Palier 3 (« Robustesse Système & Différenciateurs Souverains »)** : **la Cryptographie Post-Quantique (PQC) Native**.

Les 4 revues d'experts et les rapports d'architecture ont mis en exergue l'importance critique de la résistance aux menaces quantiques (algorithme de Shor) :
> *Plutôt que d'attendre une transition tardive, JamboOS se distingue en intégrant dès son espace utilisateur souverain les primitives post-quantiques normalisées FIPS 203 (ML-KEM) et FIPS 204 (ML-DSA), ainsi qu'un modèle d'échange hybride Dual-Defense.*

L'objectif du **Jalon 3.3 (`v0.3.47`)** est d'établir le démon cryptographique **`jambo-pqc` en Ring 3 (PID 8)** :
- Arithmétique polynomiale négacyclique exacte en anneau quotient $R_q = \mathbb{Z}_q[X]/(X^N + 1)$ en `#![no_std]`, zéro allocation dynamique.
- Mécanisme d'encapsulation de clés **ML-KEM** (inspiré de Kyber-768) et algorithme de signature numérique **ML-DSA** (inspiré de Dilithium-65).
- Échange de clés hybride Dual-Defense combinant ML-KEM et échange classique via HKDF-SHA256.
- Registre d'audit cryptographique scellé par chaîne SHA-256 continue (`audit_chain`).
- Commandes shell interactives `pqc status`, `pqc kex`, `pqc sign`, `pqc audit` dans `jsh`.
- Intégration dans le micro-noyau (PID 8 dans l'ordonnanceur multicœur EEVDF) et validation QEMU UEFI avec le code de sortie 33.

---

## 2. Architecture & Fonctionnalités de `jambo-pqc`

```
┌────────────────────────────────────────────────────────────────────────┐
│                        ESPACE UTILISATEUR (Ring 3)                     │
│                                                                        │
│  ┌──────────────┐   IPC Channels    ┌───────────────────────────────┐  │
│  │     jsh      │ ◄───────────────► │       jambo-pqc (PID 8)       │  │
│  │ (pqc status, │                   │ • ML-KEM (Kyber-768 FIPS 203) │  │
│  │  pqc kex,    │                   │ • ML-DSA (Dilithium FIPS 204) │  │
│  │  pqc sign,   │                   │ • Échange Hybride Dual-Defense│  │
│  │  pqc audit)  │                   │ • Registre d'Audit SHA-256    │  │
│  └──────────────┘                   │ • Capabilités PqcCap          │  │
│                                     └───────────────┬───────────────┘  │
└─────────────────────────────────────────────────────┼──────────────────┘
                                                      │ Syscalls x86_64
┌─────────────────────────────────────────────────────┼──────────────────┘
│                        MICRO-NOYAU (Ring 0)         ▼                  │
│               Ordonnanceur Multicœur EEVDF (PID 1 à 8)                  │
└────────────────────────────────────────────────────────────────────────┘
```

### 2.1 Moteur Cryptographique PQC (`#![no_std]`, Zéro Tas)
1. **ML-KEM (Module-LWE Key Encapsulation Mechanism)** :
   - Anneau quotient $R_q$ ($N=128$, $q=3329$, dimension matricielle $k=2$).
   - Échantillonnage à distribution binomiale centrée (CBD).
   - Génération de paires de clés (`keygen`), encapsulation (`encapsulate`), décapsulation (`decapsulate`).
2. **ML-DSA (Module-LWE Digital Signature Algorithm)** :
   - Modulus $q=8380417$, dimension $k=2$, paramètres $\gamma_1=32768, \gamma_2=8192$.
   - Échantillonnage par rejet Fiat-Shamir with Aborts.
   - Génération de signatures et vérification sans fuite de clé secrète.
3. **Échange Hybride Dual-Defense** :
   - Combinaison du secret partagé ML-KEM et d'un secret classique via HKDF-SHA256.
4. **Machine d'États de Transition Quantique (`PqcTransitionState`)** :
   - `ClassicalOnly` : Mode hérité déprécié.
   - `HybridPqcClassical` : Standard de production actif (Dual-Defense).
   - `PurePqcEnforced` : Confinement quantique strict sans primitive classique.
5. **Chaîne d'Audit Cryptographique Inviolable** :
   - Chaînage récursif SHA-256 pour chaque opération cryptographique (`record_audit`).
6. **Protocole IPC (`PqcRequest` / `PqcResponse`)** :
   - `PqcOpcode::GetStatus = 1` : état de la transition, algorithmes actifs, nombre de clés, opérations effectuées, empreinte d'audit.
   - `PqcOpcode::KeyExchange = 2` : exécution d'un échange KEM de référence et dérivation du secret partagé (32 octets).
   - `PqcOpcode::SignVerify = 3` : signature d'un message souverain avec ML-DSA et vérification d'authenticité.
   - `PqcOpcode::GetAudit = 4` : exportation du digest de tête du registre d'audit SHA-256.

---

## 3. Commandes Shell `jsh` (PID 2)

Dans `services/jambo-sh` :
1. **`pqc status`** :
   ```text
   Post-Quantum Cryptography (PQC) Status:
     Transition State  : HYBRID_PQC_CLASSICAL (Dual-Defense Active)
     Active Algorithms : ML-KEM-768 (FIPS 203), ML-DSA-65 (FIPS 204)
     Registered Keys   : 2 (1 KEM, 1 DSA)
     Operations Count  : KEM Encaps: 1 | Decaps: 1 | DSA Signs: 1 | Verifies: 1
     Audit Chain Head  : [SHA-256 Hex Digest]
     Memory Protection : Volatile Zeroize Ready
   ```
2. **`pqc kex`** :
   ```text
   [PQC] Executing ML-KEM-768 Key Encapsulation Mechanism...
     Key ID            : 1 (SovereignCluster-KEM)
     Ciphertext Size   : 768 bytes
     Shared Secret (SS): [32 bytes Hex]
     Dual-Defense KEX  : OK (HKDF-SHA256 Hybrid Secret Derived)
     Status            : SECURED (Quantum-Resistant Session Key Established)
   ```
3. **`pqc sign [message]`** :
   ```text
   [PQC] Signing message with ML-DSA-65 (FIPS 204)...
     Message           : "SOVEREIGN_SYSTEM_BEACON"
     Signature Size    : 544 bytes
     Verification      : VALID (100% Authentic, Non-Repudiable)
   ```
4. **`pqc audit`** :
   Affiche l'empreinte cryptographique de la chaîne d'audit PQC.
5. **`ps`** :
   Affichage actualisé des **8 processus Ring 3** :
   - PID 1 : `init`
   - PID 2 : `jsh`
   - PID 3 : `blockd`
   - PID 4 : `fs`
   - PID 5 : `netd`
   - PID 6 : `fdr`
   - PID 7 : `wasmd`
   - PID 8 : `pqc`

---

## 4. Intégration Micro-Noyau (`kernel`) & Outillage (`xtask`)

1. **Micro-Noyau (`kernel/src/main.rs`)** :
   - Extraction de `/bin/pqc` depuis `initrd.tar`.
   - Création et ordonnancement de PID 8 avec pile System V ABI (alignement 16 octets `RSP % 16 == 0`).
   - En mode test CI sous QEMU : validation de l'initialisation des 8 démons et affichage de :
     `[PASS] Cryptographie Post-Quantique Ring 3 (jambo-pqc PID 8) validée sous QEMU.`
2. **Build & Initrd (`xtask/src/main.rs`)** :
   - Fonction `build_pqc()` compilant `services/jambo-pqc` avec `libs/user-x86_64.ld`.
   - Packaging de `target/initrd.tar` avec les 8 exécutables : `init`, `jsh`, `blockd`, `fs`, `netd`, `fdr`, `wasmd`, `pqc`.
   - Mise à jour de la bannière disque vers `v0.3.47`.

---

## 5. Critères d'Acceptation & Validation

1. **Contrôles Qualité** :
   - `cargo fmt --all -- --check` réussi (0 écart).
   - `cargo clippy --package jambo-abi -- -D warnings` réussi (0 warning).
   - Compilation bare-metal des 9 binaires release (`kernel` + 8 démons utilisateur) avec 0 avertissement.
2. **Validation QEMU UEFI** :
   - Exécution sous QEMU UEFI avec OVMF EDK2 et isa-debug-exit.
   - Code de retour 33 attestant du succès total.
   - Traces de boot confirmant l'initialisation et l'ordonnancement de PID 1 à 8.
3. **Revue Complète & Tag Git** :
   - Whole-Branch Review validée (APPROVED).
   - Tag Git annoté officiel : `v0.3.47`.
