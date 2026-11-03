# Design Specification — Jalon 3.32 : Détection et Réponse aux Menaces sur les Identités ITDR (`jambo-itdr`, Ring 3, PID 37)

**Auteur** : Assistant JamboOS  
**Date** : 3 novembre 2026  
**Version cible** : `v0.3.76`  
**Statut** : Brouillon pour revue & approbation

---

## 1. Contexte & Objectifs

Le Jalon 3.32 de la feuille de route opérationnelle (Palier 3 — Sécurité Avancée et Observabilité Ring 3) a pour objectif d'élever le composant incubé `incubator/services/jambo-itdr` en démon de production Ring 3 : `services/jambo-itdr` (PID 37, `/bin/itdr`).

`jambo-itdr` opère en tant qu'autorité de surveillance de la posture des identités, jetons de session et capabilités émises notamment par `jambo-authd` (PID 15). Il détecte les compromissions d'identités, attaques par rejeu de session, vols et élévations de capabilités (*Pass-The-Capability*), mouvements latéraux de privilèges, dérives géotopologiques et attaques par bourrage d'identifiants, puis applique des remédiations déterministes autonomes à temps constant (révocation immédiate, quarantaine, abaissement de capabilités).

---

## 2. Contraintes Architecturales Fondamentales

1. **Strict `#![no_std]` et `#![no_main]`** :
   - Zéro allocation dynamique sur le tas (`alloc`, `Vec`, `Box`, `String` strictement interdits).
   - Tableaux statiques fixes pour les identités (`MAX_ITDR_IDENTITIES = 16`), les menaces (`MAX_ITDR_THREATS = 32`), les actions de réponse (`MAX_ITDR_ACTIONS = 32`) et le grand livre d'audit (`MAX_ITDR_LEDGER = 64`).
2. **Contrôle d'accès par capacités (ZAA - Zero Ambient Authority)** :
   - Structure `ItdrCap` à atténuation bitwise monotone (`itdr_rights`).
3. **Protocole IPC Déterministe à 64 octets** :
   - Messages synchrones `ItdrRequest` et `ItdrResponse` de taille fixe exactement égale à 64 octets.
   - Assertions statiques de compilation :
     ```rust
     const _: () = assert!(core::mem::size_of::<ItdrRequest>() == 64);
     const _: () = assert!(core::mem::size_of::<ItdrResponse>() == 64);
     ```
4. **Alignement Système V ABI** :
   - Alignement 16 octets du registre de pile utilisateur (`user_rsp % 16 == 0`).
   - Priorité EEVDF deadline 1000 pour le thread PID 37.
5. **Chaîne de confiance d'audit** :
   - Registre d'audit inaltérable scellé par chaînage SHA-256 (`record_audit`, `verify_audit_integrity`).

---

## 3. Protocole IPC Déterministe 64 octets

### 3.1 `ItdrRequest` (Taille exacte : 64 octets)
- `magic: u32` (4 octets, `0x49544452` = "ITDR")
- `opcode: u32` (4 octets) :
  - `0x01` : `GetStatus`
  - `0x02` : `RegisterIdentity`
  - `0x03` : `IngestThreat`
  - `0x04` : `AnalyzeThreats`
  - `0x05` : `RevokeIdentity`
  - `0x06` : `IsolateIdentity`
  - `0x07` : `RemediateAll`
  - `0x08` : `VerifyAudit`
- `handle_id: u32` (4 octets)
- `rights: u32` (4 octets)
- `identity_id: u32` (4 octets)
- `threat_type: u8` (1 octet)
- `severity: u8` (1 octet)
- `action_type: u8` (1 octet)
- `_reserved1: u8` (1 octet)
- `epoch: u64` (8 octets)
- `target_name: [u8; 32]` (32 octets)
*Total : 4 + 4 + 4 + 4 + 4 + 1 + 1 + 1 + 1 + 8 + 32 = 64 octets.*

### 3.2 `ItdrResponse` (Taille exacte : 64 octets)
- `magic: u32` (4 octets, `0x49544453` = "ITDS")
- `status: u32` (4 octets : 0 = OK, >0 = code d'erreur)
- `total_identities: u32` (4 octets)
- `quarantined_identities: u32` (4 octets)
- `total_threats: u32` (4 octets)
- `active_threats: u32` (4 octets)
- `avg_trust_score: u8` (1 octet)
- `global_identity_risk: u8` (1 octet)
- `identity_state: u8` (1 octet)
- `_reserved1: u8` (1 octet)
- `target_id: u32` (4 octets)
- `audit_hash: [u8; 16]` (16 octets : préfixe de hachage)
- `status_str: [u8; 16]` (16 octets : description ASCII sobre)
*Total : 4 + 4 + 4 + 4 + 4 + 4 + 1 + 1 + 1 + 1 + 4 + 16 + 16 = 64 octets.*

---

## 4. Intégration Système

1. **Crate `services/jambo-itdr`** :
   - Binaire `src/main.rs` : Point d'entrée `_start()`, auto-tests de démarrage, enregistrement endpoint 37 et boucle IPC coopérative.
   - Bibliothèque `src/lib.rs` : Logique ITDR, modèle de données, hacheur SHA-256 avec `Default`, sérialiseurs IPC, `ItdrClient`, tests unitaires.
2. **Shell `services/jambo-sh`** :
   - Ajout de `pub itdr_daemon: JamboItdrDaemon` dans `JamboShell`.
   - Dispatch `itdr` : `status`, `identities`, `threats`, `revoke <id>`, `isolate <id>`, `remediate`, `audit`.
   - Affichage de 37 processus actifs dans `cmd_ps`.
3. **Noyau & Build (`kernel/src/main.rs`, `xtask/src/main.rs`)** :
   - Version bump `v0.3.76`.
   - Extraction de `/bin/itdr` et démarrage PID 37 avec alignement 16 octets.
   - Validation QEMU avec ligne : `[PASS] Detection & Reponse Menaces Identites ITDR (jambo-itdr PID 37) validee sous QEMU.`.

