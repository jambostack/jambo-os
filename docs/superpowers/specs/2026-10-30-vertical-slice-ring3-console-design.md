# Spécification d'Architecture : Jalon 2.1 — Console & Shell Interactif Réel (v0.3.41)

- **Date :** 2026-10-30
- **Version cible :** `v0.3.41` (Lignée `0.3.x` — Consolidation de la stabilité avant v0.4.0)
- **Auteur :** ASSOGBA Prudence Dieudonné & Antigravity
- **Statut :** Validé / En cours de planification

---

## 1. Contexte & Motivation

À l'issue du **Palier 1 (« Iron Core »)**, le micro-noyau JamboKernel a été entièrement découplé et validé sous QEMU UEFI :
* Plus de 23 000 lignes de simulations in-memory et 104 faux fichiers de tests ont été supprimés.
* Le micro-noyau Ring 0 est pur, compile en ~0,5 seconde sous `x86_64-unknown-none` et `aarch64-unknown-none`, et assure la transition matérielle sécurisée vers Ring 3 (`enter_user_mode` via `IRETQ`).

Cependant, l'espace utilisateur (`services/jambo-init` et `services/jambo-sh`) souffre de la même dette technique initiale :
1. `services/jambo-init` dépend encore de **37 crates de simulation** (`jambo-aid`, `jambo-vmm`, `jambo-authd`, etc.) et son `main.rs` comprend 1 849 lignes d'assertions in-memory.
2. `services/jambo-sh` comprend **23 107 lignes de code** car sa structure `JamboShell` intègre artificiellement 40 démons fictifs sous forme de champs structurés.

L'objectif du **Jalon 2.1** est de réaliser la première moitié de la tranche verticale Ring 3 en établissant une session console et un shell interactif authentiques, tout en éliminant cette dette dans l'espace utilisateur.

---

## 2. Objectifs & Non-Objectifs

### Objectifs (In-Scope)
* **Assainissement de l'espace utilisateur** : Découpler totalement `jambo-init` et `jambo-sh` de toutes les crates `services/*` fictives. Leurs `Cargo.toml` ne doivent dépendre que de `libjambo`.
* **Hiérarchie de processus Ring 3** :
  * PID 1 (`jambo-init`) : Superviseur système racine non privilégié, responsable de l'initialisation de l'environnement et du lancement de `jsh`.
  * PID 2 (`jsh`) : Shell interactif tournant dans son propre espace d'adressage et fil d'exécution.
* **E/S Console UART bidirectionnelles réelles** :
  * Lecture non bloquante sur le port série COM1 (Syscall 25 `ConsoleRead`) avec retour d'interruption UART IRQ 4.
  * Écriture directe sur COM1 (Syscall 26 `ConsoleWrite`).
  * Utilisation coopérative de Syscall 12 `ThreadYield` pour éviter les boucles actives à 100 % CPU.
* **Commandes natives du shell `jsh`** :
  * `help` : Liste des commandes disponibles et syntaxe.
  * `sysinfo` : Métriques réelles du noyau (pages totales, allouées, libres, uptime).
  * `ps` : Liste des processus et états.
  * `echo <texte>` : Affichage de texte sur stdout.
  * `clear` : Nettoyage d'écran par séquence ANSI.
  * `reboot` : Arrêt ou redémarrage de la machine via Syscall 28 `SystemPoweroff`.
* **Double validation sous QEMU** :
  * Mode interactif manuel via `cargo xtask run --release`.
  * Mode test automatisé CI sans régression via `cargo xtask test --release`.

### Non-Objectifs (Hors périmètre pour le Jalon 2.1)
* Le pilote de stockage `virtio-blk` et le système de fichiers `jambo-fs` font l'objet du **Jalon 2.2** (`v0.3.42`).
* Aucun passage immédiat en `v0.4.0` : nous restons sur la branche `0.3.x` pour consolider la stabilité étape par étape.
* Pas de support d'interpréteur de script complexe (bash/sh piping avancé, redirections de fichiers) : `jsh` est un Object Shell minimaliste orienté commandes et capacités.

---

## 3. Architecture Détaillée

```
┌─────────────────────────────────────────────────────────────────────────┐
│                          ESPACE UTILISATEUR (RING 3)                    │
│                                                                         │
│  ┌───────────────────────────┐         ┌─────────────────────────────┐  │
│  │   jambo-init (PID 1)      │         │         jsh (PID 2)         │  │
│  │  - Superviseur racine     │         │  - Shell interactif UART    │  │
│  │  - Monte les capacités    │ (Spawn) │  - Boucle d'événements RX   │  │
│  │  - Spawne jsh via syscall │────────>│  - Commandes : help, ps,    │  │
│  │  - Surveille son statut   │         │    sysinfo, caps, echo      │  │
│  └─────────────┬─────────────┘         └──────────────┬──────────────┘  │
│                │ (Syscalls: ProcessCreate,            │ (Syscalls:      │
│                │  ThreadCreate, ThreadStart)          │  ConsoleRead,   │
│                │                                      │  ConsoleWrite,  │
│                │                                      │  SysInfo, Yield)│
├────────────────┼──────────────────────────────────────┼─────────────────┤
│                ▼                                      ▼                 │
│  ┌───────────────────────────────────────────────────────────────────┐  │
│  │                    JAMBOKERNEL IRON CORE (RING 0)                 │  │
│  │  - Ordonnanceur EEVDF (threads ordonnancés en Ring 3)             │  │
│  │  - Tables CSpace (isolation stricte des capacités par PID)        │  │
│  │  - Tampon circulaire UART COM1 (interception matérielle IRQ 4)    │  │
│  └───────────────────────────────────────────────────────────────────┘  │
└─────────────────────────────────────────────────────────────────────────┘
```

### 3.1. Séquence d'Amorçage et Superviseur PID 1 (`services/jambo-init`)

1. **Entrée en Ring 3** : Le micro-noyau extrait `/bin/init` depuis l'archive `initrd.tar`, mappe son espace d'adressage virtuel ELF64, prépare la pile System V ABI et effectue la transition vers le point d'entrée utilisateur.
2. **Initialisation de `jambo-init`** :
   * Ne dépend que de `libjambo`.
   * Récupère la capacité vers le binaire `/bin/jsh` (fourni via l'archive Initrd ou pré-mappé).
   * Appelle `libjambo::syscall6(SyscallNumber::ProcessCreate, ...)` pour initialiser le descripteur de PID 2.
   * Appelle `libjambo::syscall6(SyscallNumber::ThreadCreate, ...)` et `ThreadStart` pour démarrer le fil d'exécution de `jsh`.
3. **Boucle de surveillance** :
   * `jambo-init` n'exécute pas de calcul intensif ; il entre dans une boucle d'attente passive (`ThreadYield`), prêt à intercepter tout signal ou crash de sous-processus.

### 3.2. Le Shell Interactif (`services/jambo-sh`)

1. **Architecture de `jsh`** :
   * `services/jambo-sh/Cargo.toml` nettoyé pour ne dépendre que de `libjambo`.
   * `src/lib.rs` réécrit en une bibliothèque légère (~250 lignes) contenant la structure `JamboShell` sans aucun démon externe.
2. **Gestion de la Ligne de Commande** :
   * Tampon fixe statique de 256 octets (`[u8; 256]`).
   * Pas d'allocateur dynamique nécessaire (`#![no_std]`).
   * Découpage des arguments par espaces dans un tableau fixe `[&str; 8]`.
3. **Commandes Implémentées** :
   * `help` : Affiche la bannière d'aide et les commandes reconnues.
   * `sysinfo` : Invoque `libjambo::sys_info()` (`Syscall 27`) et affiche la mémoire physique totale, la mémoire libre et l'uptime en secondes.
   * `ps` : Affiche la liste des tâches actives (PID 1 `jambo-init`, PID 2 `jsh`).
   * `echo [texte...]` : Concatène et renvoie les arguments passés sur la sortie standard.
   * `clear` : Envoie la séquence ANSI de réinitialisation d'écran `\x1b[2J\x1b[H`.
   * `reboot` : Invoque l'appel système `SystemPoweroff` (`Syscall 28`) avec le code de redémarrage.

### 3.3. Chaîne d'E/S Matérielles UART COM1

* **Interruption Réception (RX)** :
  * La frappe au clavier déclenche l'interruption matérielle COM1 UART.
  * Le contrôleur IOAPIC achemine l'IRQ 4 vers le vecteur IDT 36.
  * Le gestionnaire d'interruption Ring 0 écrit l'octet dans la file circulaire protégée `SERIAL_RX_QUEUE`.
* **Lecture Utilisateur (Syscall 25 `ConsoleRead`)** :
  * `jsh` appelle `libjambo::console_read(&mut rx_byte)`.
  * Le noyau dépile les octets reçus. Si aucun octet n'est prêt, `console_read` retourne 0 et `jsh` cède le tour processeur via `ThreadYield`.
* **Écriture Utilisateur (Syscall 26 `ConsoleWrite`)** :
  * `jsh` appelle `libjambo::console_write(buffer)`.
  * Le micro-noyau écrit directement dans le registre de transmission COM1 (`0x3F8`).

---

## 4. Gestion des Erreurs & Robustesse

1. **Débordement de tampon de saisie** : Si l'utilisateur saisit plus de 255 caractères sans valider avec Entrée, les caractères excédentaires sont ignorés sans écrasement de pile ni panique.
2. **Caractères d'échappement & Backspace** : Prise en charge explicite de `0x08` (BS) et `0x7F` (DEL) avec émission de la séquence d'effacement `\x08 \x08`.
3. **Commande Inconnue** : Si la commande saisie n'existe pas, `jsh` affiche un message explicite `jsh: command not found: <nom>` et réaffiche immédiatement le prompt.
4. **Crash ou Terminaison de `jsh`** : Si le thread de `jsh` effectue une faute fatale ou appelle `ThreadExit`, `jambo-init` (PID 1) reste actif en Ring 3 et peut relancer le shell.

---

## 5. Stratégie de Validation & CI

### 5.1. Validation Interactive Manuelle
Exécution via l'outillage standard :
```bash
cargo xtask run --release
```
Attendu :
* Lancement de QEMU connecté à la console courante (`-serial stdio`).
* Affichage de la bannière Limine, initialisation du micro-noyau Iron Core.
* Transition en Ring 3, démarrage de `init`, puis apparition de la bannière :
  ```text
  ========================================
    JamboOS Object Shell (jsh) v0.3.41    
  ========================================
  jambo:/# 
  ```
* Capacité pour l'utilisateur de taper des commandes (`help`, `sysinfo`, `echo Test`, `reboot`) et d'obtenir des réponses instantanées.

### 5.2. Validation Automatisée Headless (CI)
Exécution via la suite de tests :
```bash
cargo xtask test --release
```
* Détection automatique de `cmdline: test`.
* Le noyau injecte une suite de commandes de test dans le tampon UART (`help\n`, `sysinfo\n`, `echo ci-pass\n`, `reboot\n`).
* Vérification que la réponse `ci-pass` est émise par `jsh`.
* Sortie automatique avec le code de succès 33 via `isa-debug-exit`.
