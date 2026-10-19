# ADR 0058: Moteur Déclaratif de Politiques de Sécurité & Contrôle d'Admission (`jambo-policyd`)

## Statut
Accepté (Phase 69 - Jalon v0.2.67)

## Contexte
Dans une architecture de grappe distribuée sous micro-noyau souverain orienté capacités, la régulation des actions inter-services (création de charges utiles, accès aux secrets, montage de stockage distribué, routage réseau) requiert un moteur déclaratif déterministe en espace utilisateur `#![no_std]`. Avec `services/jambo-policyd`, JamboOS implémente un moteur d'admission control et d'évaluation de politiques :
1. **Confinement Capabilaire de Gouvernance (`PolicyCap`)** :
   - L'accès aux opérations du moteur est régi par des jetons capabilitaires `PolicyCap`.
   - Droits granulaires (`POLICY_EVALUATE`, `POLICY_RULE_ADD`, `POLICY_RULE_DEL`, `POLICY_AUDIT`, `POLICY_ADMIN`), interdisant toute modification clandestine des règles d'admission.
2. **Principes Fondamentaux : Déni par Défaut & Préséance du Refus Explicite** :
   - Tout accès non explicitement couvert par une règle `Allow` est rejeté (*Deny-by-default*).
   - En présence de règles contradictoires ciblant une même ressource, le refus explicite (`PolicyEffect::Deny`) prévaut impérativement sur l'autorisation.
3. **Gestion Déterministe des Baux Temporels de Politiques** :
   - Chaque règle peut comporter une date limite d'expiration (`expires_at`).
   - Éviction automatique dès franchissement de la date de validité et purge prédictive sans fuite mémoire (`purge_expired`).
4. **Démon Orchestrateur Ring 3 (`JamboPolicyDaemon`) & Commandes `jsh`** :
   - Démon orchestrateur pré-configurant les règles d'amorçage pour les rôles `ROLE_SYSTEM` et `ROLE_OPERATOR`.
   - Commandes interactives dans `jsh` :
     - `policy status` : nombre de règles, compteur d'évaluations (autorisations, dénis) et confinement capabilaire.
     - `policy eval <role> <resource>` : évaluation temps réel d'une requête d'admission avec retour de décision (AUTORISÉ / REJETÉ).
     - `policy add <id> <resource>` : ajout dynamique d'une règle déclarative d'admission.
5. **Harnais de Validation Noyau (`kernel/src/sched/policyd_test.rs`)** :
   - Validation bout-en-bout sous QEMU (Phase 69) du contrôle capabilaire `PolicyCap`, du déni par défaut, de la préséance du Deny, de l'expiration temporelle, de l'audit et des commandes du shell.

## Décision
1. Implémentation du démon `JamboPolicyDaemon` et de ses tests unitaires dans `services/jambo-policyd/src/lib.rs`.
2. Intégration de `jambo-policyd` dans `services/jambo-sh` avec l'implémentation de la commande interactive `policy`.
3. Ajout de la dépendance dans `kernel/Cargo.toml` et création du module de validation `kernel/src/sched/policyd_test.rs`.
4. Intégration dans `kernel/src/main.rs`, validation complète sous QEMU (Phase 69) et publication de la version `v0.2.67`.

## Conséquences
- Admission control déterministe garantissant le moindre privilège à l'échelle de toute la grappe.
- Socle pour le traçage distribué et la propagation de contexte de sécurité (`jambo-traced`, Phase 70).
