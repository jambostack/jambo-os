# Plan de Mise en Œuvre — Jalon 3.10 : Authentification Cryptographique & Jetons de Session Capabilitaires (`jambo-authd` PID 15) (v0.3.54)

Ce plan découpe la mise en œuvre du **Jalon 3.10 (`v0.3.54`)** en 4 tâches séquentielles exécutées selon la méthodologie Subagent-Driven Development (SDD) avec des sous-agents Implementer et Reviewer indépendants.

---

## Tâche 1 : Promotion de `jambo-authd` & Démon Ring 3 (`authd`, PID 15)

### Objectifs
1. Déplacer `incubator/services/jambo-authd` vers `services/jambo-authd`.
2. Mettre à jour `services/jambo-authd/Cargo.toml` (version `0.3.54`, chemin `libjambo = { path = "../../libs/libjambo" }`, target bin `authd`).
3. Ajouter `services/jambo-authd` aux membres du workspace racine `Cargo.toml`.
4. Définir le protocole IPC déterministe (`AuthOpcode`, `AuthRequest`, `AuthResponse`) avec assertions statiques de taille (`size_of == 64`).
5. Implémenter le client IPC ergonomique (`AuthClient`) pour simplifier les appels inter-services.
6. Créer le point d'entrée exécutable `services/jambo-authd/src/main.rs` :
   - `#![no_std]`, `#![no_main]`.
   - Point d'entrée `#[no_mangle] pub extern "C" fn _start() -> !`.
   - Initialisation de `JamboAuthDaemon::new()` et `init_defaults()`.
   - Auto-test au démarrage : validation de la session opérateur, authentification par défi-réponse d'un utilisateur secondaire (`auditor`), validation du jeton de session, test de révocation atomique zero-remanence.
   - Enregistrement du canal IPC (serveur IPC avec `libjambo::syscall6` / `ChannelCreate`).
   - Boucle coopérative avec `syscall_thread_yield()`.
7. Vérifier que `cargo test --package jambo-authd` réussit à 100%.
8. Vérifier la compilation bare-metal pour `x86_64-unknown-none`.

---

## Tâche 2 : Commandes `auth` dans le Shell `jsh` (PID 2) & Listing 15 Processus

### Objectifs
1. Mettre à jour `services/jambo-sh/Cargo.toml` pour ajouter `jambo-authd = { path = "../jambo-authd" }` et versionner à `0.3.54`.
2. Intégrer les commandes `auth` dans `services/jambo-sh/src/lib.rs` :
   - `auth status` : Affiche l'état du sous-système d'identité (utilisateurs enregistrés, sessions actives, ID de session active).
   - `auth login <username>` : Authentifie l'utilisateur par défi-réponse sans mot de passe en clair.
   - `auth token` : Affiche les détails du jeton de session capabilaire actif (ID session, rôle, handle, expiration).
   - `auth revoke <session_id>` : Révoque atomiquement la session spécifiée et purge la mémoire associée.
3. Mettre à jour l'aide `help` pour inclure la commande `auth`.
4. Mettre à jour la commande `ps` pour lister exhaustivement les 15 processus Ring 3 :
   - PID 1 à 14 existants
   - PID 15 : `/bin/authd (Demon Identite & Jetons de Session Capabilitaires Ring 3)`
5. Mettre à jour la bannière `jsh` pour `v0.3.54`.
6. Écrire des tests unitaires exhaustifs pour les commandes `auth` dans `services/jambo-sh/src/lib.rs` et vérifier que 100% des tests shell passent.

---

## Tâche 3 : Micro-Noyau `kernel` & Outillage `xtask`

### Objectifs
1. Mettre à jour `kernel/Cargo.toml` à la version `0.3.54`.
2. Modifier `kernel/src/main.rs` :
   - Extraire `/bin/authd` (ou `/bin/jambo-authd`) depuis l'initrd TAR.
   - Créer le processus Ring 3 PID 15 (`"authd"`).
   - Vérifier l'alignement de pile System V ABI (`assert_eq!(authd_sp % 16, 0)`).
   - Définir `authd_thread.lock().deadline = 1000` et enfiler dans l'ordonnanceur EEVDF.
   - Journaliser :
     `[PROCESS] Démon Identité & Jetons de Session authd (PID 15) initialisé avec pile System V ABI (RSP: {:#018x}) et enfilé`
   - Émettre le message UART officiel dans le bloc de test QEMU :
     `kprintln!("\x1b[1;32m[PASS] Identite Cryptographique & Jetons de Session (jambo-authd PID 15) validee sous QEMU.\x1b[0m");`
3. Modifier `xtask/src/main.rs` :
   - Ajouter `build_authd(release: bool) -> anyhow::Result<PathBuf>` utilisant `libs/user-x86_64.ld`.
   - Mettre à jour `build_userland` pour compiler et retourner les 15 binaires.
   - Copier `authd` dans `target/initrd_stage/bin/authd` et l'empaqueter dans `target/initrd.tar`.
   - Mettre à jour la bannière disque : `"Bienvenue sur JamboOS v0.3.54\n"`.
   - Ajouter la détection du message de réussite `[PASS] Identite Cryptographique & Jetons de Session (jambo-authd PID 15) validee` dans la validation QEMU de `xtask`.

---

## Tâche 4 : Validation Globale, End-to-End QEMU UEFI & Tag `v0.3.54`

### Objectifs
1. Vérifier le formatage global (`cargo fmt --all -- --check`).
2. Vérifier `cargo clippy` (`-D warnings`) sur `services/jambo-authd`, `services/jambo-sh`, `kernel`, `xtask`.
3. Lancer la compilation complète en mode release bare-metal : `cargo xtask build --release`.
4. Lancer le test QEMU UEFI de bout en bout : `cargo xtask test-qemu`.
5. Confirmer la présence des 15 processus dans `target/qemu_output.log` et le code de sortie `33` (`QemuExitCode::Success`).
6. Réaliser la Whole-Branch Review complète (`35e897f..HEAD`).
7. Créer le tag git annoté `v0.3.54` et pousser vers `origin/main` avec les tags.
8. Mettre à jour l'artefact de feuille de route `synthese_avis_et_feuille_de_route_jamboos.md`.

