# Plan de Mise en Œuvre — Jalon 3.9 : Passerelle VPN Post-Quantique WireGuard & Transport Chiffré Inter-Grappe (`jambo-vpn` PID 14) (v0.3.53)

Ce plan découpe la mise en œuvre du **Jalon 3.9 (`v0.3.53`)** en 4 tâches séquentielles exécutées selon la méthodologie Subagent-Driven Development (SDD) avec des sous-agents Implementer et Reviewer indépendants.

---

## Tâche 1 : Promotion de `jambo-vpn` & Démon Ring 3 (`vpn`, PID 14)

### Objectifs
1. Déplacer `incubator/services/jambo-vpn` vers `services/jambo-vpn`.
2. Mettre à jour `services/jambo-vpn/Cargo.toml` (version `0.3.53`, chemin `libjambo = { path = "../../libs/libjambo" }`).
3. Ajouter `services/jambo-vpn` aux membres du workspace racine `Cargo.toml`.
4. Définir le protocole IPC déterministe (`VpnOpcode`, `VpnRequest`, `VpnResponse`) avec assertions statiques de taille (`size_of == 64`).
5. Implémenter le client IPC ergonomique (`VpnClient`) pour simplifier les appels inter-services.
6. Créer le point d'entrée exécutable `services/jambo-vpn/src/main.rs` :
   - `#![no_std]`, `#![no_main]`.
   - Point d'entrée `#[no_mangle] pub extern "C" fn _start() -> !`.
   - Initialisation de `VpnCap::new_root()` ou `VpnCap::new(Handle::new(14, 1), vpn_rights::ALL)`.
   - Initialisation du démon `JamboVpnDaemon` et `init_defaults()`.
   - Auto-test au démarrage : handshake hybride Curve25519 + ML-KEM avec un nœud pair, dérivation des clés de session, chiffrement et déchiffrement d'un paquet test avec vérification MAC et contrôle anti-rejeu.
   - Enregistrement du canal IPC (serveur IPC avec `libjambo::syscall6` / `ChannelCreate`).
   - Boucle coopérative avec `syscall_thread_yield()`.
7. Vérifier que `cargo test --package jambo-vpn` réussit à 100% (les 8 tests existants + nouveaux tests IPC).
8. Vérifier la compilation bare-metal pour `x86_64-unknown-none`.

---

## Tâche 2 : Commandes `vpn` dans le Shell `jsh` (PID 2) & Listing 14 Processus

### Objectifs
1. Mettre à jour `services/jambo-sh/Cargo.toml` pour ajouter `jambo-vpn = { path = "../jambo-vpn" }` et versionner à `0.3.53`.
2. Intégrer les commandes `vpn` dans `services/jambo-sh/src/lib.rs` :
   - `vpn status` : Affiche l'état de la passerelle VPN (pairs configurés, poignées de main actives, paquets routés, octets chiffrés, hash d'audit cumulé).
   - `vpn connect <peer_id>` : Déclenche la poignée de main WireGuard hybride PQ 1-RTT.
   - `vpn peer <peer_id>` : Affiche les détails du pair (nom, endpoint IP:port, état, sous-réseaux `AllowedIPs`).
   - `vpn audit` : Affiche l'empreinte de la chaîne d'audit inaltérable.
3. Mettre à jour l'aide `help` pour inclure la commande `vpn`.
4. Mettre à jour la commande `ps` pour lister exhaustivement les 14 processus Ring 3 :
   - PID 1 : `/bin/init`
   - PID 2 : `/bin/jsh`
   - PID 3 : `/bin/blockd`
   - PID 4 : `/bin/fs`
   - PID 5 : `/bin/netd`
   - PID 6 : `/bin/fdr`
   - PID 7 : `/bin/wasmd`
   - PID 8 : `/bin/pqc`
   - PID 9 : `/bin/kdir`
   - PID 10 : `/bin/forensics`
   - PID 11 : `/bin/powerd`
   - PID 12 : `/bin/metricsd`
   - PID 13 : `/bin/bpfd`
   - PID 14 : `/bin/vpn`
5. Mettre à jour la bannière `jsh` pour `v0.3.53`.
6. Écrire des tests unitaires exhaustifs pour les commandes `vpn` dans `services/jambo-sh/src/lib.rs` et vérifier que 100% des tests shell passent.

---

## Tâche 3 : Micro-Noyau `kernel` & Outillage `xtask`

### Objectifs
1. Mettre à jour `kernel/Cargo.toml` à la version `0.3.53`.
2. Modifier `kernel/src/main.rs` :
   - Extraire `/bin/vpn` (ou `/bin/jambo-vpn`) depuis l'initrd TAR.
   - Créer le processus Ring 3 PID 14 (`"vpn"`).
   - Vérifier l'alignement de pile System V ABI (`assert_eq!(vpn_sp % 16, 0)`).
   - Définir `vpn_thread.lock().deadline = 1000` et enfiler dans l'ordonnanceur EEVDF.
   - Journaliser :
     `[PROCESS] Démon Passerelle VPN WireGuard Post-Quantique vpn (PID 14) initialisé avec pile System V ABI (RSP: {:#018x}) et enfilé`
   - Émettre le message UART officiel dans le bloc de test QEMU :
     `kprintln!("\x1b[1;32m[PASS] Passerelle VPN Post-Quantique WireGuard (jambo-vpn PID 14) validée sous QEMU.\x1b[0m");`
3. Modifier `xtask/src/main.rs` :
   - Ajouter `build_vpn(release: bool) -> anyhow::Result<PathBuf>` utilisant `libs/user-x86_64.ld`.
   - Mettre à jour `build_userland` pour compiler et retourner les 14 binaires.
   - Copier `vpn` dans `target/initrd_stage/bin/vpn` et l'empaqueter dans `target/initrd.tar`.
   - Mettre à jour la bannière disque : `"Bienvenue sur JamboOS v0.3.53\n"`.
   - Ajouter la détection du message de réussite `[PASS] Passerelle VPN Post-Quantique WireGuard (jambo-vpn PID 14) validée` dans la validation QEMU de `xtask`.

---

## Tâche 4 : Validation Globale, End-to-End QEMU UEFI & Tag `v0.3.53`

### Objectifs
1. Vérifier le formatage global (`cargo fmt --all -- --check`).
2. Vérifier `cargo clippy` (`-D warnings`) sur `services/jambo-vpn`, `services/jambo-sh`, `kernel`, `xtask`.
3. Lancer la compilation complète en mode release bare-metal : `cargo xtask build --release`.
4. Lancer le test QEMU UEFI de bout en bout : `cargo xtask test-qemu`.
5. Confirmer la présence des 14 processus dans `target/qemu_output.log` et le code de sortie `33` (`QemuExitCode::Success`).
6. Réaliser la Whole-Branch Review complète (`6557034..HEAD`).
7. Créer le tag git annoté `v0.3.53` et pousser vers `origin/main` avec les tags.
8. Mettre à jour l'artefact de feuille de route `synthese_avis_et_feuille_de_route_jamboos.md`.
