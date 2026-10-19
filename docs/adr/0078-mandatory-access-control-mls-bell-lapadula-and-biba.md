# ADR 0078: Mandat d'Accès Contrôlé (MAC) Multi-Niveaux (MLS), Modèles Bell-LaPadula & Biba (`jambo-mac`)

## Statut
Accepté (Phase 89 - Jalon v0.2.87)

## Contexte
Dans l'architecture du micro-noyau souverain JamboOS (`#![no_std]`), le contrôle d'accès discrétionnaire (DAC) et les capacités pures nécessitent une couche de politique de sécurité obligatoire (*Mandatory Access Control* / MAC) multi-niveaux (*Multi-Level Security* / MLS) pour prévenir toute exfiltration ou corruption de données sensibles :
1. **Hiérarchie de Classification de Confidentialité (Bell-LaPadula)** :
   - Niveaux : `Unclassified` (0), `Confidential` (1), `Secret` (2), `TopSecret` (3).
   - *Simple Security Property* (*No Read Up* / NRU) : Un sujet ne peut lire un objet que si son niveau d'habilitation domine celui de l'objet ($S.level \ge O.level$) et s'il possède tous les compartiments requis.
   - *$\star$-Property* (*No Write Down* / NWD) : Un sujet ne peut écrire dans un objet que si le niveau de l'objet domine celui du sujet ($O.level \ge S.level$) et si l'objet contient tous les compartiments du sujet, empêchant toute fuite d'information confidentielle vers un niveau inférieur.
2. **Hiérarchie d'Intégrité Biba** :
   - Niveaux : `Untrusted` (0), `User` (1), `System` (2), `Trusted` (3).
   - *Simple Integrity Property* (*No Read Down* / NRD) : Un sujet ne peut lire de données d'un objet d'intégrité inférieure ($O.integrity \ge S.integrity$), prévenant la contamination des sujets de confiance.
   - *$\star$-Integrity Property* (*No Write Up* / NWU) : Un sujet ne peut modifier ou écrire dans un objet d'intégrité supérieure ($S.integrity \ge O.integrity$), interdisant la corruption des composants système.
3. **Treillis de Compartiments / Catégories Non-Hiérarchiques** :
   - Masque de bits de catégories (Crypto, Network, Storage, Admin, Financial, Intelligence, Defense, Audit, User, Kernel).
   - Relation d'ordre partiel et domination stricte en treillis : $S$ domine $O$ ssi $(O.categories \setminus S.categories) = \emptyset$.
4. **Déclassification et Abaissement Contrôlés (`MAC_DOWNGRADE`)** :
   - Toute modification réduisant la classification d'un objet ou le confinement d'un sujet requiert formellement la capacité `MacCap` avec le droit `MAC_DOWNGRADE`.
5. **Chaîne d'Audit Cryptographique Inviolable SHA-256** :
   - Enregistrement séquentiel chaîné par hachage SHA-256 de chaque évaluation d'accès, modification d'étiquette et violation de politique.
6. **Contrôle d'Accès Capabilaire sans Autorité Ambiante (`MacCap`)** :
   - Droits granulaires : `MAC_READ`, `MAC_CHECK`, `MAC_LABEL`, `MAC_ENFORCE`, `MAC_DOWNGRADE`, `MAC_AUDIT`, `MAC_ADMIN`.
   - Atténuation capabilaire sans amplification possible.

## Décision
1. Implémentation du micro-service `services/jambo-mac` (`MacCap`, `MacLabel`, `ClassificationLevel`, `IntegrityLevel`, `compartments`, `JamboMacDaemon`).
2. Intégration de la commande `mac` dans le shell interactif `services/jambo-sh` (`status`, `subjects`, `objects`, `check`, `audit`).
3. Écriture du module de test noyau `kernel/src/sched/mac_test.rs` et inclusion dans `kernel/src/main.rs`.
4. Incrémentation de version vers `v0.2.87` pour l'ensemble des modules du workspace.

## Conséquences
- Confinement absolu de la confidentialité (BLP) et de l'intégrité (Biba) au niveau micro-noyau.
- Élimination des fuites d'informations latérales et de la corruption de données d'intégrité critique.
- Traçabilité cryptographique SHA-256 complète pour l'audit et la certification de sécurité.
