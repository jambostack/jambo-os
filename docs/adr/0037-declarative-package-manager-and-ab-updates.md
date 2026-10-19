# ADR 0037: Gestionnaire de Paquets Déclaratifs (`jambo-pkgd`), Mises à Jour Atomiques A/B & JamboSDK

## Statut
Accepté (Phase 48 - Jalon v0.2.46)

## Contexte
Après l'introduction de la couche de compatibilité Linux POSIX et du runtime WASI sandboxed (ADR 0036, v0.2.45), JamboOS intègre la distribution logicielle et le cycle de vie du système d'exploitation par le biais de paquets immuables déclaratifs et de bascules de partitions dual-slot atomiques :
1. **Démon de Gestion de Paquets Déclaratif (`services/jambo-pkgd`)** :
   - Format de paquet immuable `JpkgManifest` associant un identifiant, une version sémantique, une empreinte cryptographique BLAKE3 et une signature Ed25519 garantissant l'absence de falsification.
   - Magasin de stockage adressé par le contenu (Content-Addressed Storage - CAS) vérifié formellement (rejet strict de paquets falsifiés ou avec empreinte nulle).
   - Partitionnement transactionnel A/B (`AbSlot::SlotA` / `AbSlot::SlotB`) : préparation de mises à jour dans la fente inactive (`stage_update`), bascule atomique en O(1) (`commit_update`), et annulation immédiate (`rollback`).
   - Tolérance aux pannes et watchdog de démarrage : après 3 échecs consécutifs d'amorçage sur une nouvelle fente non validée, déclenchement autonome d'un retour arrière instantané vers la fente stable.
2. **Kit de Développement Logiciel Natif (`libs/jambo-sdk`)** :
   - Trait de cycle de vie d'application `JamboApp` (`init`, `run_step`, `shutdown`) orchestré par `run_app`.
   - Contexte sécurisé `AppContext` confiné avec poignées de canaux IPC et mémoire partagée VMO.
   - Échange de messages structurés typés JamboIDL sans autorité ambiante.
3. **Commandes Interactives dans le Shell `jsh`** :
   - `jpkg slot` : affichage de la génération active et du slot courant (A/B).
   - `jpkg install <pkg>` : installation transactionnelle dans le magasin CAS.
   - `jpkg stage` : préparation de mise à jour dans le slot alternatif.
   - `jpkg commit` : validation atomique et bascule O(1).
   - `jpkg rollback` : annulation immédiate vers l'état stable précédent.
   - `sdk status` : vérification de l'état du framework applicatif JamboSDK.
   - `sdk run <app>` : lancement confiné d'une application native via le SDK.
4. **Harnais de Validation Automatisée** (`kernel/src/sched/pkg_test.rs`) :
   - Validation de l'isolation du magasin CAS et rejet des paquets frauduleux.
   - Validation du staging A/B, du commit O(1) et du fallback automatique après échecs de boot.
   - Validation du cycle de vie complet de l'application modèle via JamboSDK.
   - Validation des commandes interactives `jpkg` et `sdk`.

## Décision
1. Intégration de `jambo-pkgd` et `jambo-sdk` dans `jambo-sh` avec l'enrichissement de `jpkg` et l'ajout de `sdk`.
2. Ajout des dépendances dans `kernel/Cargo.toml` et création de `kernel/src/sched/pkg_test.rs`.
3. Validation complète sous QEMU (Phase 48) et publication de la version `v0.2.46`.

## Conséquences
- Déploiement et mises à jour système 100% atomiques, éliminant tout état de système corrompu ou d'incohérence logicielle intermédiaire.
- Intégrité cryptographique absolue de la chaîne d'approvisionnement logicielle via BLAKE3 et signatures Ed25519.
- Écosystème applicatif prêt pour le développement de logiciels natifs sécurisés par capacités.
