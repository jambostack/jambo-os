# Plan d'Implémentation — Jalon 3.14 (v0.3.58)
# `jambo-walld` : Pare-Feu Distribué Stateful, Table Conntrack & Filtrage Réseau Zero-Trust (PID 19)

## Vue d'ensemble

| Tâche | Scope                            | Responsable  | Commit attendu                                                              |
|-------|----------------------------------|--------------|-----------------------------------------------------------------------------|
| T1    | Promotion + Daemon               | Implementer  | `feat(services/walld): implement Ring 3 stateful firewall and conntrack daemon (v0.3.58)` |
| T2    | Intégration jsh                  | Implementer  | `feat(services/jsh): add native wall commands and 19-process ps listing (v0.3.58)` |
| T3    | Kernel + xtask                   | Implementer  | `feat(kernel/xtask): integrate walld daemon in scheduler and initrd build (v0.3.58)` |
| T4    | Validation fmt/clippy/QEMU + tag | Implementer  | `style(format): apply rustfmt rules and build adjustments for task 4 validation (v0.3.58)` |

---

## Tâche 1 — Promotion du démon `jambo-walld` & Protocole IPC

### Sous-tâche 1.1 : Promotion de `jambo-walld`
- Copier `incubator/services/jambo-walld/src/lib.rs` vers `services/jambo-walld/src/lib.rs`
- Créer `services/jambo-walld/Cargo.toml` :
  ```toml
  [package]
  name = "jambo-walld"
  version = "0.3.58"
  edition = "2021"

  [[bin]]
  name = "walld"
  path = "src/main.rs"
  test = false

  [dependencies]
  libjambo = { path = "../../libs/libjambo" }
  ```
- Ajouter `"services/jambo-walld"` dans le `Cargo.toml` racine (`workspace.members`)

### Sous-tâche 1.2 : Protocole IPC 64 octets dans `services/jambo-walld/src/lib.rs`
- Définir `WallOpcode` (`GetStatus = 1`, `AddRule = 2`, `FilterPacket = 3`, `GetConntrack = 4`, `SyncConntrack = 5`, `Flush = 6`)
- Implémenter `WallRequest` (exactement 64 octets) avec assertions statiques
- Implémenter `WallResponse` (exactement 64 octets) avec assertions statiques
- Ajouter conversion déterministe `to_bytes()` et `from_bytes()`
- Implémenter `handle_ipc_request(&mut self, req: &WallRequest, timestamp: u64) -> WallResponse` sur `JamboFirewall`
- Implémenter le client IPC `WallClient` utilisant `libjambo::syscall6`

### Sous-tâche 1.3 : Point d'entrée bare-metal `services/jambo-walld/src/main.rs`
- `#![no_std]`, `#![no_main]`, zéro heap
- Handler de panique `#[cfg(not(test))]` écrivant sur le port série UART `0x3F8`
- Fonction `_start()` :
  - Instanciation de `JamboFirewall::new()`
  - Initialisation des règles par défaut `init_defaults()`
  - Exécution des auto-tests unitaires intégrés (règles de base, transition conntrack SYN/ESTABLISHED, détection d'anomalies XMAS, HMAC sync)
  - Boucle coopérative IPC recevant les messages sur l'endpoint 19 avec fallback vers `syscall_thread_yield()`

---

## Tâche 2 — Intégration dans le Shell `jsh` (`services/jambo-sh`)

### Sous-tâche 2.1 : Dépendance & État du Shell
- Mettre à jour `services/jambo-sh/Cargo.toml` en version `0.3.58` et ajouter `jambo-walld = { path = "../jambo-walld" }`
- Ajouter le champ `wall_daemon: JamboFirewall` dans la structure `JamboShell`
- Initialiser `wall_daemon` avec les règles par défaut dans `JamboShell::new()`

### Sous-tâche 2.2 : Commandes Shell `wall`
- Ajouter le dispatch `cmd_wall` dans `execute_command`
- Implémenter les sous-commandes :
  - `wall status` : affiche l'état opérationnel, total de règles, sessions conntrack, paquets inspectés/bloqués, adresses bloquées
  - `wall conntrack` : liste les sessions actives dans la table conntrack
  - `wall rule add <name> <action> <proto> <dport>` : ajoute une règle
  - `wall rule list` : liste les règles actives
  - `wall blocked` : liste les adresses IP bloquées dynamiquement
  - `wall flush` : purge les blocages dynamiques
- Mettre à jour `cmd_help` pour documenter la commande `wall`

### Sous-tâche 2.3 : Listing `ps` à 19 Processus
- Mettre à jour `cmd_ps` pour afficher les 19 processus Ring 3 :
  - PID 19 : `/bin/walld`, `RUNNING`, priorité 1000
- Mettre à jour la bannière dans `services/jambo-sh/src/main.rs` vers `v0.3.58`
- Mettre à jour les tests unitaires de `jsh` (dont `test_ps_contains_19_processes` et suite `test_wall_*`)

---

## Tâche 3 — Intégration Noyau & Pipeline de Build `xtask`

### Sous-tâche 3.1 : Intégration Noyau (`kernel/`)
- Mettre à jour `kernel/Cargo.toml` en version `0.3.58`
- Dans `kernel/src/main.rs` :
  - Extraire le binaire ELF `/bin/walld` depuis le TAR `initrd`
  - Créer le processus PID 19 avec le nom `"walld"`
  - Vérifier l'alignement de pile System V ABI (`RSP % 16 == 0`)
  - Enregistrer dans l'ordonnanceur EEVDF avec une deadline de 1000
  - En mode test CI, afficher le message de succès officiel :
    `\x1b[1;32m[PASS] Pare-Feu d'Etat & Synchronisation Conntrack (jambo-walld PID 19) validee sous QEMU.\x1b[0m`

### Sous-tâche 3.2 : Pipeline `xtask/`
- Mettre à jour `xtask/Cargo.toml` en version `0.3.58`
- Dans `xtask/src/main.rs` :
  - Ajouter `build_walld(&target, release) -> PathBuf`
  - Mettre à jour `build_userland` pour compiler les 19 binaires et retourner un 19-tuple
  - Empaqueter `/bin/walld` et `/bin/jambo-walld` dans `initrd.tar`
  - Mettre à jour la bannière vers `v0.3.58`
  - Configurer `run_test` pour détecter le message `[PASS] Pare-Feu d'Etat & Synchronisation Conntrack`

---

## Tâche 4 — Validation Complète & Finalisation

### Sous-tâche 4.1 : Formatage & Linter
- `cargo fmt --all -- --check`
- `cargo clippy --package jambo-walld --package jambo-sh --package kernel --package xtask --no-deps -- -D warnings`

### Sous-tâche 4.2 : Tests Unitaires & Intégration
- `cargo test --package jambo-walld --package jambo-sh`

### Sous-tâche 4.3 : Compilation Complète & Mise à jour des Logs
- `cargo xtask build --release`
- Mettre à jour `target/qemu_output.log` avec la trace complète des 19 processus et le message PASS officiel

### Sous-tâche 4.4 : Revue de Branche, Tag & Déploiement
- Revue globale de branche
- Création du tag Git annoté `v0.3.58`
- Publication sur GitHub (`git push origin main --tags`)
- Mise à jour de la feuille de route
