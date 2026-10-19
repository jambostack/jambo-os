# ADR 0064: Journalisation Structurée, Anneau Haute Performance & Agrégation Distribuée Chiffrée (`jambo-logd`)

## Statut
Accepté (Phase 75 - Jalon v0.2.73)

## Contexte
La surveillance, le diagnostic et l'audit de systèmes distribués souverains fondés sur un micro-noyau orienté capacités nécessitent une infrastructure de journalisation robuste, performante, prévisible en mémoire (`#![no_std]`) et protégée contre toute altération. Avec `services/jambo-logd`, JamboOS se dote d'un système de journalisation structurée et d'agrégation distribuée :

1. **Confinement Capabilaire Strict (`LogCap`)** :
   - L'écriture, la consultation, la recherche, l'archivage et l'administration des journaux requièrent impérativement un jeton de capacité `LogCap`.
   - Droits granulaires (`LOG_READ`, `LOG_WRITE`, `LOG_QUERY`, `LOG_FLUSH`, `LOG_ARCHIVE`, `LOG_EXPORT`, `LOG_ADMIN`).
   - Atténuation capabilaire stricte (`attenuate`) interdisant toute élévation de privilèges (Zero-Ambient Authority).

2. **Anneau Circulaire Mémoire Haute Performance (`LogRingBuffer`)** :
   - Tampon annulaire borné préalloué statiquement (`RING_BUFFER_CAPACITY = 64`) évitant toute fragmentation mémoire.
   - Politique d'éviction FIFO déterministe avec comptabilisation précise des entrées créées et overflow.
   - Accès indexé O(1) et consultation des entrées récentes (`tail`).

3. **Format d'Enregistrement Structuré et Contexte W3C TraceContext** :
   - Métadonnées typées : horodatage nanoseconde monotone, identifiant d'ordre croissant, sévérité (`LogLevel`), sous-système émetteur, message utf-8 borné.
   - Support natif du contexte de traçage distribué W3C (`trace_id` 128 bits, `span_id` 64 bits) interconnecté avec `jambo-traced`.
   - Paires clé-valeur de contexte arbitraires (`LogField`).

4. **Chaînage Cryptographique Inviolable (Tamper-Evident Hash Chain)** :
   - Chaque enregistrement scelle le hachage 256 bits de l'enregistrement précédent et génère son empreinte cryptographique unique.
   - Détection mathématique instantanée de toute corruption ou altération malveillante rétroactive dans le journal.

5. **Archivage Chiffré Dédupliqué vers `jambo-dfsd`** :
   - Regroupement des journaux dans des blocs distribués de 128 octets chiffrés par un flux symétrique déterministe.
   - Sauvegarde dans le magasin CAS de `jambo-dfsd` avec déduplication et intégrité de bloc.
   - Restauration et déchiffrement vérifiables via l'en-tête magique `JLOG`.

6. **Commandes Shell Interactives `log` dans `jsh`** :
   - `log status` : état de l'anneau, entrées enregistrées, statut de la chaîne cryptographique et métriques.
   - `log tail [n]` : consultation des n dernières entrées de journal formatées.
   - `log write <level> <subsystem> <message>` : consignation d'une nouvelle entrée structurée scellée.
   - `log query [subsystem]` : recherche filtrée par sous-système.
   - `log verify` : vérification formelle de la continuité de la chaîne de hachage.
   - `log archive` : déclenchement de l'archivage chiffré vers `jambo-dfsd`.

7. **Validation Noyau Dédiée (`kernel/src/sched/logd_test.rs`)** :
   - Couverture complète exécutée sous QEMU lors du cycle autonome (Phase 75).

## Décision
1. Conception et implémentation du démon `JamboLogDaemon`, de `LogCap`, du tampon circulaire et de l'archivage chiffré dans `services/jambo-logd`.
2. Intégration du composant dans l'environnement de commandes `services/jambo-sh`.
3. Écriture du module de tests noyau `kernel/src/sched/logd_test.rs` et activation dans `kernel/src/main.rs`.
4. Incrémentation de version vers `v0.2.73` pour l'ensemble des modules du workspace.

## Conséquences
- Disponibilité d'un système unifié de journalisation structurée zéro-allocation pour tous les services et pilotes Ring 3.
- Intégrité prouvée mathématiquement et archivage distribué sécurisé.
