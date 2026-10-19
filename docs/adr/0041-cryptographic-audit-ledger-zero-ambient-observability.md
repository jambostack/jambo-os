# ADR 0041: Grand Livre d'Audit Cryptographique Immuable, Preuves Merkle & Observabilité Zéro-Autorité (`jambo-auditd`)

## Statut
Accepté (Phase 52 - Jalon v0.2.50)

## Contexte
Après la distribution RPC sécurisée et la résilience cluster de la Phase 51 (ADR 0040, v0.2.49), JamboOS consolide son architecture de sécurité micro-noyau avec `services/jambo-auditd`, fournissant un registre d'audit inviolable (tamper-evident ledger) et une observabilité en temps réel respectant rigoureusement le paradigme Zéro-Autorité Ambiante :
1. **Règle Fondamentale d'Audit Zéro-Autorité** :
   - Préservation stricte du principe du moindre privilège : aucun accès de lecture ou d'écriture n'est implicite.
   - Toute interaction avec le registre d'audit requiert la détention explicite d'une capacité `AuditCap` confinée aux catégories autorisées (`CSpace`, `MemoryMMU`, `IommuDma`, `NetworkIpc`, `DistributedRpc`, `Authentication`) et au niveau de sévérité requis.
2. **Grand Livre Cryptographique Inviolable (`AuditLedger`)** :
   - Tamper-evident ledger à structure séquentielle déterministe avec tampon statique circulaire sans allocation dynamique.
   - Chaque entrée (`AuditEntry`) est scellée par hachage cryptographique combinant son numéro de séquence, timestamp, PID source, catégorie, sévérité, code d'événement, charge utile et le hachage du bloc précédent (`prev_hash`).
   - Algorithme de vérification mathématique d'intégrité de chaîne (`verify_chain_integrity`) garantissant la détection immédiate de toute falsification ou corruption de mémoire (bit-flip).
3. **Moteur Heuristique de Détection d'Anomalies (`AnomalyDetector`)** :
   - Analyse dynamique des événements récents du journal d'audit.
   - Détection en temps réel d'attaques répétées : échecs de capacités itératifs, violations d'accès mémoire et attaques par rejeu RPC.
   - Émission d'alertes de sécurité précises (`SecurityAlert`) ciblant le PID suspect et le type d'incident.
4. **Commandes Interactives dans le Shell `jsh`** :
   - `audit status` : état du grand livre, nombre d'événements scellés, validité cryptographique et statut du moteur d'anomalies.
   - `audit log <msg>` : enregistrement explicite d'un événement d'audit scellé via capacité Ring 3.
   - `audit verify` : vérification mathématique complète de la chaîne cryptographique d'audit.
   - `audit alert` : analyse heuristique et détection d'anomalies suspectes récentes.
   - `audit dump` : inspection des derniers événements scellés dans le registre.
5. **Harnais de Validation Automatisée** (`kernel/src/sched/audit_test.rs`) :
   - Validation bout-en-bout du scellement cryptographique, de la détection de falsification, du confinement `AuditCap`, du détecteur d'anomalies et des commandes shell sous QEMU (Phase 52).

## Décision
1. Implémentation du démon `JamboAuditDaemon` dans `services/jambo-auditd/src/lib.rs`.
2. Intégration de `jambo-auditd` dans `services/jambo-sh` avec l'implémentation de la commande `audit`.
3. Ajout de la dépendance dans `kernel/Cargo.toml` et création de `kernel/src/sched/audit_test.rs`.
4. Validation complète sous QEMU (Phase 52) et publication de la version `v0.2.50`.

## Conséquences
- Traçabilité et auditabilité cryptographique absolue de toutes les opérations de sécurité du micro-noyau.
- Observabilité zéro-autorité garantissant l'impossibilité de modifier ou falsifier les journaux sans détection immédiate.
