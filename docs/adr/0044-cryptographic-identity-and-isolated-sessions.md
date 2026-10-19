# ADR 0044: Identité Cryptographique Asymétrique & Gestionnaire de Sessions Isolées (`jambo-authd`)

## Statut
Accepté (Phase 55 - Jalon v0.2.53)

## Contexte
Après la sécurisation du stockage par chiffrement transparent et scellement TPM 2.0 de la Phase 54 (ADR 0043, v0.2.52), JamboOS franchit une étape fondamentale dans son modèle de sécurité avec `services/jambo-authd`, en éliminant définitivement le concept d'utilisateur monolithique omnipotent (`root`) et les identifiants POSIX traditionnels (UID/GID) au profit d'identités cryptographiques asymétriques et de sessions capabilitaires isolées :
1. **Règle Fondamentale de Sécurité Zéro-Root** :
   - Aucun compte super-utilisateur `root` n'existe dans JamboOS. Le noyau ne reconnaît aucune autorité ambiante héritée.
   - Les privilèges sont strictement définis par des masques de droits granulaires associés à des identités cryptographiques asymétriques (`UserIdentity`) et des rôles fonctionnels typés (`Guest`, `StandardUser`, `SystemOperator`, `SecurityAuditor`).
2. **Authentification Défi-Réponse sans Mot de Passe en Clair (`CryptoAuthEngine`)** :
   - Aucun condensat de mot de passe n'est stocké en mémoire ou sur disque (suppression des fichiers de hachage de type `/etc/shadow`).
   - L'authentification repose sur un protocole défi-réponse : le démon émet un défi pseudo-aléatoire imprévisible de 32 octets (`generate_challenge`), que le client doit signer à l'aide de sa clé privée asymétrique (`sign_challenge`). La vérification est assurée par la clé publique correspondante (`verify_signature`).
3. **Jetons de Session Capabilitaires & Révocation Atomique Zero-Remanence (`SessionTokenCap`)** :
   - L'authentification réussie produit un jeton de session capabiliaire (`SessionTokenCap`) doté d'un `root_handle` spécifique, d'une durée de vie définie (`expires_at_ns`) et de droits d'accès circonscrits.
   - Le gestionnaire de sessions (`SessionManager`) assure l'invalidation temporelle automatique et la révocation atomique en cascade (`terminate_session`), purgeant intégralement la mémoire de session associée (Zero-Remanence) pour empêcher toute réutilisation post-déconnexion.
4. **Commandes Interactives dans le Shell `jsh`** :
   - `auth status` : état de la session active, rôle de l'utilisateur courant, sessions actives et annuaire des identités.
   - `auth login <user>` : authentification interactive par défi-réponse et obtention d'un jeton de session.
   - `auth logout` : déconnexion immédiate, révocation du jeton et purge sans rémanence de la mémoire de session.
   - `auth verify` : validation de la légitimité et de la durée de vie du jeton de session actif.
5. **Harnais de Validation Noyau (`kernel/src/sched/auth_test.rs`)** :
   - Validation bout-en-bout sous QEMU (Phase 55) du protocole défi-réponse, du rejet des signatures falsifiées, de l'expiration TTL et de la purge atomique des sessions.

## Décision
1. Ajout de `JamboAuthDaemon` dans `services/jambo-authd/src/lib.rs`.
2. Intégration de `jambo-authd` dans `services/jambo-sh` avec l'implémentation de la commande `auth`.
3. Ajout de la dépendance dans `kernel/Cargo.toml` et création de `kernel/src/sched/auth_test.rs`.
4. Validation complète sous QEMU (Phase 55) et publication de la version `v0.2.53`.

## Conséquences
- Élimination complète de la surface d'attaque liée au compte `root` et aux élévations de privilèges classiques (setuid/sudo).
- Traçabilité et isolation cryptographique de chaque session utilisateur sous l'autorité exclusive de capacités.
