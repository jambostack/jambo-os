# ADR 0031: Shell Interactif jsh en Ring 3 & Commandes Natives

## Statut
Accepté (Phase 42 - Jalon v0.2.40)

## Contexte
Après la capture matérielle des frappes de l'UART 16550 COM1 via l'I/O APIC et le ring buffer noyau synchrone (ADR 0030, v0.2.39), le système d'exploitation requiert une interface de pilotage complète en espace utilisateur (Ring 3).

JamboOS repose sur une architecture sans autorité ambiante (*Zero Ambient Authority*) où l'accès à toute ressource (périphériques, mémoire, fichiers, ordonnancement) doit découler de capacités explicites (CSpace) ou d'appels système formels. Pour achever la promesse d'un système d'exploitation interactif fonctionnel, le shell objet `jsh` doit s'exécuter en Ring 3, exposer une boucle REPL (*Read-Eval-Print Loop*), lire les entrées clavier utilisateur, et exécuter un jeu complet de commandes natives réelles.

Ce jalon comprend :
1. **Appels Système de Console & Métriques Système** :
   - `ConsoleRead` (Syscall 25) : lecture non-bloquante ou avec tampon des octets reçus dans la file circulaire UART RX du noyau vers un pointeur mémoire utilisateur vérifié.
   - `ConsoleWrite` (Syscall 26) : émission directe d'octets depuis l'espace utilisateur vers la ligne série COM1 et l'écran texte.
   - `SysInfo` (Syscall 27) : interrogation sécurisée des métriques physiques du système d'exploitation (pages totales PMM, pages libres, allocations SLUB, nombre de processus et threads actifs, temps de fonctionnement *uptime*).
   - `SystemPoweroff` (Syscall 28) : transition d'extinction matérielle propre (ACPI / QEMU isa-debug-exit).
2. **Bibliothèque Système Utilisateur `libjambo`** :
   - Fonctions ergonomiques `console_read()`, `console_write()`, `sys_info()`, `print()`, `println()`.
3. **Shell Objet Interactif `jsh` (`services/jambo-sh`)** :
   - Point d'entrée exécutable autonome `_start` (`#![no_std]`, `#![no_main]`) compilé en binaire ELF statique pour la cible `x86_64-unknown-none`.
   - Affichage du prompt textuel : `jambo:/# `.
   - Gestion de l'écho, de l'édition de ligne et de la touche retour arrière (*backspace* `0x08` / `0x7F`).
   - Commandes fondamentales réelles :
     - `help` : aide en ligne et inventaire des commandes disponibles.
     - `version` : bannière de version et architecture du micro-noyau.
     - `ps` : affichage des processus actifs, identifiants PID, threads et niveau de confinement CSpace.
     - `mem` : état physique de l'allocateur Buddy PMM et de l'allocateur d'objets SLUB.
     - `echo <texte>` : affichage standard avec gestion des arguments multiples.
     - `clear` : réinitialisation de l'affichage via la séquence d'échappement ANSI `\x1b[2J\x1b[H`.
     - `reboot` / `poweroff` : extinction ou redémarrage propre de la machine.
4. **Intégration au Ramdisk d'Amorçage Initrd** :
   - Compilation et empaquetage de `bin/jsh` dans `initrd.tar` via `xtask` aux côtés de `bin/init`.
5. **Validation Matérielle Automatisée sous QEMU** :
   - Validation en Ring 3 de la séquence complète : injection d'une commande série -> capture via Syscall 25 -> traitement REPL -> affichage via Syscall 26 -> interrogation SysInfo via Syscall 27 -> sortie propre via Syscall 11.

## Décision
1. Ajout des numéros d'appels système 25 (`ConsoleRead`), 26 (`ConsoleWrite`), 27 (`SysInfo`), 28 (`SystemPoweroff`) dans `jambo-abi` et `jambo.h`.
2. Implémentation des gestionnaires correspondants dans `kernel/src/syscall/dispatch.rs`.
3. Ajout de la cible binaire `[[bin]] name = "jsh"` dans `services/jambo-sh/Cargo.toml` et implémentation du REPL dans `services/jambo-sh/src/main.rs`.
4. Ajout de `execute_line` dans `JamboShell` pour l'exécution et le formatage des commandes système sans allocation.
5. Intégration de `bin/jsh` dans le script `create_initrd` de `xtask/src/main.rs`.
6. Harnais de test Ring 3 dans `kernel/src/sched/shell_test.rs`.

## Conséquences
- **Positives** :
  - JamboOS dispose d'un shell interactif natif complet exécutable en Ring 3 avec zéro autorité ambiante.
  - L'utilisateur peut piloter le micro-noyau, surveiller la mémoire et les processus via une console série interactive.
- **Négatives / Arbitrages** :
  - La taille de l'archive `initrd.tar` inclut désormais `bin/init` et `bin/jsh` (~4.5 Mo au total), nécessitant un dimensionnement adéquat du module Limine.
