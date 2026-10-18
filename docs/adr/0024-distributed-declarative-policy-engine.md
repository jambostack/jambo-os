# ADR 0024: Moteur de Politiques de Sécurité Déclaratives & Contrôle d'Admission de Grappe (`jambo-policyd`)

## Statut
Accepté (Phase 35 - Jalon v0.2.33)

## Contexte
Au sein de la grappe distribuée JamboOS, de multiples démons coopèrent pour gérer les charges de travail (`jambo-schedd`), le stockage distribué (`jambo-dfsd`), les secrets d'infrastructure (`jambo-vaultd`), le maillage réseau (`jambo-meshd`) et la découverte de services (`jambo-serviced`).

Si le micro-noyau garantit la séparation stricte des domaines mémoire et la non-forgeabilité des descripteurs de capacités (CSpace), l'admission de requêtes applicatives de haut niveau requiert un moteur de gouvernance déclarative :
1. **Contrôle d'admission Zero-Trust** : validation explicite avant toute action sensible (ex: instanciation de micro-VMs, enregistrement de routes d'entrée, accès aux clés de chiffrement de stockage).
2. **Politiques déclaratives fondées sur les attributs (ABAC)** : règles associant un sujet (rôle, ID d'entité), une action cible, une ressource protégée et des conditions contextuelles.
3. **Principe de fermeture et de déni par défaut (*Deny-by-default*)** : toute requête ne disposant pas d'une règle d'autorisation explicite (`Allow`) valide est systématiquement rejetée. Les règles de refus explicite (`Deny`) priment sur toute autorisation.
4. **Atténuation de capacités de gouvernance (`PolicyCap`)** : seules les entités disposant du droit d'évaluation ou d'administration peuvent interagir avec le moteur.
5. **Déterminisme mémoire strict `#![no_std]`** : évaluation en temps constant sans allocation dynamique non bornée.

## Décision
Nous implémentons le démon d'espace utilisateur `jambo-policyd` (`services/jambo-policyd`) intégrant :
1. **Règle de politique déclarative (`PolicyRule`)** :
   - Identifiant unique `rule_id: u32`.
   - Sujet concerné `subject_role: u16` (ex: `ROLE_SYSTEM`, `ROLE_OPERATOR`, `ROLE_WORKLOAD`, `ROLE_GUEST`).
   - Action ciblée `action_mask: u32` (ex: `ACTION_SPAWN_WORKLOAD`, `ACTION_ACCESS_SECRET`, `ACTION_REGISTER_SERVICE`, `ACTION_ROUTE_TRAFFIC`, `ACTION_ADMIN`).
   - Préfixe de ressource protégée (`[u8; 32]`).
   - Décision : `PolicyEffect::Allow` ou `PolicyEffect::Deny`.
   - Priorité relative `priority: u8` et horodatage d'expiration optionnel.
2. **Requête d'admission (`AdmissionRequest`)** :
   - Sujet émetteur `subject_id: u32`, rôle `role: u16`.
   - Action sollicitée `action: u32`.
   - Ressource ciblée `resource: [u8; 32]`.
   - Horodatage courant `timestamp: u64`.
3. **Moteur d'évaluation (`PolicyEngine`)** :
   - Capacité bornée (`MAX_RULES = 32`).
   - Mécanisme de filtrage : vérification des règles actives par ordre de priorité décroissante avec préséance du `Deny`.
   - Compteurs d'audit déterministes (requêtes évaluées, acceptées, rejetées).
4. **Contrôle d'accès par capacités (`PolicyCap`)** :
   - Droits explicites : `POLICY_EVALUATE` (0x01), `POLICY_RULE_ADD` (0x02), `POLICY_RULE_DEL` (0x04), `POLICY_AUDIT` (0x08), `POLICY_ADMIN` (0x80).

## Conséquences
- **Positives** :
  - Harmonisation et centralisation de la conformité de sécurité sur l'ensemble des sous-systèmes distribués de JamboOS.
  - Prévention native des élévations de privilèges et des dérives de configuration.
  - Auditabilité cryptographique complète des décisions d'admission.
- **Négatives / Arbitrages** :
  - Nombre maximum de règles de politique fixé statiquement en mémoire `#![no_std]`.
