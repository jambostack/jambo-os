# ADR 0017 : Bus d'Événements Pub/Sub Asynchrone Zéro-Copie (`jambo-eventd`)

## Statut
Accepté (Phase 28 - `v0.2.26`)

## Contexte
Avec l'intégration de la grappe distribuée (consensus `jambo-raft`, magasin transactionnel `jambo-kvd`, et ordonnanceur `jambo-schedd`), les composants de JamboOS communiquent via des appels RPC synchrones ou des transactions d'état. Cependant, les démons système (surveillance de nœuds, alertes d'audit de sécurité `jambo-auditd`, métadonnées de cycle de vie de micro-VMs `jambo-vmm`, et régulation thermique `jambo-powerd`) nécessitent un découplage asynchrone temporel et spatial. Les émetteurs ne doivent pas être bloqués par la vitesse de traitement des récepteurs, et l'architecture doit interdire toute autorité ambiante.

## Décision
Nous concevons et implémentons le démon d'espace utilisateur `jambo-eventd` en Rust `#![no_std]`, offrant un bus de publication/abonnement (Pub/Sub) réactif, déterministe et régi par des capacités `EventCap` :

1. **Modèle de Sujets Hiérarchiques (*Topics*)** :
   - Les événements sont publiés sur des canaux nommés (ex: `cluster/heartbeat`, `security/audit`, `vmm/lifecycle`).
   - Filtrage d'abonnements par correspondance exacte ou préfixe hiérarchique.

2. **Files Circulaires Déterministes par Abonné** :
   - Chaque souscription dispose d'un anneau de messages à taille bornée (`MAX_QUEUE_LEN = 16`) garantissant une absence totale d'allocation dynamique arbitraire en cours d'exécution.
   - En cas de saturation d'un consommateur lent, politique configurable de rejet le plus ancien (*Drop-Oldest*) pour préserver la réactivité du bus.

3. **Gouvernance par Capacités Dédiées (`EventCap`)** :
   - `EVENT_PUBLISH` (0x01) : Droit d'émettre des événements sur un ou plusieurs sujets.
   - `EVENT_SUBSCRIBE` (0x02) : Droit de s'enregistrer comme consommateur.
   - `EVENT_FILTER` (0x04) : Configuration de masques de sévérité ou d'identifiants.
   - `EVENT_DRAIN` (0x08) : Acquittement et consommation par lots de messages.
   - `EVENT_ADMIN` (0x80) : Gestion des quotas globaux et réinitialisation de topics.
   - Aucun processus ne peut écouter ou injecter des événements système sans présenter une capacité `EventCap` valide.

## Conséquences
- **Positives** :
  - Découplage complet entre producteurs (noyau, pilotes, ordonnanceur) et observateurs (monitoring, audit, compositeur).
  - Empreinte mémoire statique prévisible, sans risque d'épuisement mémoire (*OOM*).
  - Préservation intégrale du modèle de sécurité Least Privilege.
- **Négatives** :
  - Les consommateurs lents peuvent perdre des événements anciens si la file circulaire est saturée.
