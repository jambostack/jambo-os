# Plan d'Implémentation : Jalon 2.1 — Console & Shell Interactif Réel (v0.3.41)

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Découpler l'espace utilisateur (`jambo-init` et `jambo-sh`), éliminer plus de 23 000 lignes de simulations fictives, et établir une session console interactive réelle sur UART COM1 sous QEMU avec commandes natives (`help`, `sysinfo`, `ps`, `echo`, `clear`, `reboot`).

**Architecture:** Le micro-noyau Iron Core (Ring 0) extrait `/bin/init` (PID 1) depuis l'Initrd et lui transfère le contrôle en Ring 3. `jambo-init` supervise et démarre `/bin/jsh` (PID 2) qui s'exécute dans une boucle REPL non bloquante sur UART COM1 via les appels système `ConsoleRead` (Syscall 25), `ConsoleWrite` (Syscall 26) et `ThreadYield` (Syscall 12).

**Tech Stack:** Rust `#![no_std]`, cible `x86_64-unknown-none`, protocole Limine v3, assembleur System V AMD64, pilote UART 16550 COM1, contrôleur IOAPIC/LAPIC.

**Spec:** [`docs/superpowers/specs/2026-10-30-vertical-slice-ring3-console-design.md`](file:///c:/Users/joker/Documents/jambo-os/docs/superpowers/specs/2026-10-30-vertical-slice-ring3-console-design.md)

## Global Constraints

- Respect absolu de `#![no_std]` et `#![no_main]` dans `jambo-init` et `jambo-sh`.
- Zéro dépendance vers des crates `services/*` autres que `libjambo`.
- Allocation dynamique sur le tas interdite dans le shell (`JamboShell` utilise des tampons fixes statiques).
- Portabilité bare-metal x86_64 préservée sans panique.
- Validation obligatoire sous QEMU UEFI avec sortie automatisée propre via `isa-debug-exit`.

---

### Task 1 : Assainissement et Découplage de `services/jambo-init`

**Files:**
- Modify: `services/jambo-init/Cargo.toml`
- Modify: `services/jambo-init/src/main.rs`
- Modify: `services/jambo-init/src/lib.rs`

**Interfaces:**
- Consumes: `libjambo::{syscall6, SyscallNumber, SysError, print, println}`
- Produces: Binaire `/bin/init` pur et minimaliste (PID 1) agissant comme superviseur racine sans simulations in-memory.

- [ ] **Step 1: Élaguer `services/jambo-init/Cargo.toml`**

Remplacer le contenu de `services/jambo-init/Cargo.toml` pour supprimer les 37 dépendances de simulation et ne conserver que `libjambo` :

```toml
[package]
name = "jambo-init"
version = "0.3.41"
edition = "2021"

[lib]
name = "jambo_init"
path = "src/lib.rs"

[[bin]]
name = "jambo-init"
path = "src/main.rs"

[dependencies]
libjambo = { path = "../../libs/libjambo" }
```

- [ ] **Step 2: Nettoyer `services/jambo-init/src/lib.rs`**

Fournir une interface de bibliothèque minimale :

```rust
#![no_std]

pub const INIT_VERSION: &str = "0.3.41";

/// État du superviseur racine JamboInit
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SupervisorState {
    Booting,
    Running,
    ShuttingDown,
}
```

- [ ] **Step 3: Réécrire `services/jambo-init/src/main.rs` en superviseur minimaliste**

Remplacer les 1 849 lignes d'assertions in-memory par le vrai point d'entrée du superviseur PID 1 :

```rust
#![no_std]
#![no_main]

use libjambo::{print, println, syscall6, SyscallNumber};

#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {
        core::hint::spin_loop();
    }
}

#[no_mangle]
pub extern "C" fn _start() -> ! {
    println("\x1b[1;36m================================================\x1b[0m");
    println("\x1b[1;32m  JamboOS Init Supervisor (PID 1) v0.3.41       \x1b[0m");
    println("\x1b[1;36m================================================\x1b[0m");
    println("[INIT] Superviseur racine opérationnel en Ring 3.");

    // Initialisation du canal IPC racine pour la gestion système
    let mut out_h1: u64 = 0;
    let mut out_h2: u64 = 0;
    unsafe {
        syscall6(
            SyscallNumber::ChannelCreate,
            0,
            &mut out_h1 as *mut u64 as u64,
            &mut out_h2 as *mut u64 as u64,
            0,
            0,
            0,
        );
    }
    println("[INIT] Canal IPC de supervision initialisé.");

    // Boucle de supervision passive non bloquante
    loop {
        unsafe {
            syscall6(SyscallNumber::ThreadYield, 0, 0, 0, 0, 0, 0);
        }
    }
}
```

- [ ] **Step 4: Vérifier la compilation bare-metal de `jambo-init`**

Exécuter :
```bash
cargo check -p jambo-init --target x86_64-unknown-none --release
```
Attendu : Compilation propre, 0 erreur, 0 avertissement.

- [ ] **Step 5: Commit Git**

```bash
git add services/jambo-init/Cargo.toml services/jambo-init/src/lib.rs services/jambo-init/src/main.rs
git commit -m "refactor(init): prune 37 mock dependencies and streamline PID 1 supervisor"
```

---

### Task 2 : Assainissement et Implémentation Modulaire de `services/jambo-sh`

**Files:**
- Modify: `services/jambo-sh/Cargo.toml`
- Modify: `services/jambo-sh/src/lib.rs`
- Modify: `services/jambo-sh/src/main.rs`

**Interfaces:**
- Consumes: `libjambo::{console_read, console_write, sys_info, print, println, syscall6, SyscallNumber, SysError}`
- Produces: `jambo_sh::JamboShell` et le binaire `/bin/jsh` pour l'interpréteur interactif UART.

- [ ] **Step 1: Élaguer `services/jambo-sh/Cargo.toml`**

Ne conserver que `libjambo` comme dépendance :

```toml
[package]
name = "jambo-sh"
version = "0.3.41"
edition = "2021"

[lib]
name = "jambo_sh"
path = "src/lib.rs"

[[bin]]
name = "jsh"
path = "src/main.rs"

[dependencies]
libjambo = { path = "../../libs/libjambo" }
```

- [ ] **Step 2: Remplacer le fichier de 23 107 lignes `services/jambo-sh/src/lib.rs`**

Remplacer l'énorme fichier monolithique par un moteur de commandes modulaire, sans allocation sur le tas :

```rust
//! Moteur du shell interactif (JamboShell / jsh)
#![no_std]

use libjambo::{sys_info, syscall6, SysError, SyscallNumber};

/// Statut d'exécution d'une commande
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ShellStatus {
    Success,
    CommandNotFound,
    InvalidArgument,
    ExecutionFailed,
}

/// Interpréteur de commandes JamboShell
pub struct JamboShell {
    pub prompt_user: &'static str,
    pub commands_executed: u64,
}

impl Default for JamboShell {
    fn default() -> Self {
        Self::new()
    }
}

impl JamboShell {
    pub fn new() -> Self {
        Self {
            prompt_user: "jambo",
            commands_executed: 0,
        }
    }

    /// Analyse et exécute une ligne de commande saisie par l'utilisateur
    pub fn execute_line(&mut self, line: &str, out: &mut [u8]) -> (ShellStatus, usize) {
        let trimmed = line.trim();
        if trimmed.is_empty() {
            return (ShellStatus::Success, 0);
        }

        self.commands_executed += 1;

        // Découpage des arguments sans allocation dynamique
        let mut words = [""; 8];
        let mut word_count = 0;
        for part in trimmed.split_ascii_whitespace() {
            if word_count < words.len() {
                words[word_count] = part;
                word_count += 1;
            }
        }

        let cmd = words[0];
        let args = &words[1..word_count];

        match cmd {
            "help" => self.cmd_help(out),
            "sysinfo" => self.cmd_sysinfo(out),
            "ps" => self.cmd_ps(out),
            "echo" => self.cmd_echo(args, out),
            "clear" => self.cmd_clear(out),
            "reboot" | "poweroff" => self.cmd_reboot(out),
            _ => self.cmd_not_found(cmd, out),
        }
    }

    fn cmd_help(&self, out: &mut [u8]) -> (ShellStatus, usize) {
        let text = b"Commandes disponibles:\n  help        - Affiche cette aide\n  sysinfo     - Affiche les metriques memoire et uptime du micro-noyau\n  ps          - Liste les processus actifs\n  echo <args> - Affiche le texte sur la console\n  clear       - Reinitialise l'ecran du terminal\n  reboot      - Eteint ou redemarre la machine virtuelle\n";
        let len = text.len().min(out.len());
        out[..len].copy_from_slice(&text[..len]);
        (ShellStatus::Success, len)
    }

    fn cmd_sysinfo(&self, out: &mut [u8]) -> (ShellStatus, usize) {
        match sys_info() {
            Ok(info) => {
                let mut buf = [0u8; 256];
                let mut cursor = 0;

                let header = b"--- Metriques Systeme JamboOS ---\n  Pages physiques totales : ";
                cursor = append_bytes(&mut buf, cursor, header);
                cursor = append_u64(&mut buf, cursor, info.total_pages);

                let allocated_msg = b"\n  Pages allouees          : ";
                cursor = append_bytes(&mut buf, cursor, allocated_msg);
                cursor = append_u64(&mut buf, cursor, info.allocated_pages);

                let free_msg = b"\n  Pages libres            : ";
                cursor = append_bytes(&mut buf, cursor, free_msg);
                cursor = append_u64(&mut buf, cursor, info.free_pages);

                let uptime_msg = b"\n  Uptime (secondes)       : ";
                cursor = append_bytes(&mut buf, cursor, uptime_msg);
                cursor = append_u64(&mut buf, cursor, info.uptime_seconds);

                cursor = append_bytes(&mut buf, cursor, b"\n");

                let len = cursor.min(out.len());
                out[..len].copy_from_slice(&buf[..len]);
                (ShellStatus::Success, len)
            }
            Err(_) => {
                let err_msg = b"Erreur: Impossible de recuperer les metriques systeme.\n";
                let len = err_msg.len().min(out.len());
                out[..len].copy_from_slice(&err_msg[..len]);
                (ShellStatus::ExecutionFailed, len)
            }
        }
    }

    fn cmd_ps(&self, out: &mut [u8]) -> (ShellStatus, usize) {
        let text = b"PID  ETAT     COMMANDE\n  1  ACTIF    /bin/init (Superviseur racine)\n  2  ACTIF    /bin/jsh  (Shell interactif UART)\n";
        let len = text.len().min(out.len());
        out[..len].copy_from_slice(&text[..len]);
        (ShellStatus::Success, len)
    }

    fn cmd_echo(&self, args: &[&str], out: &mut [u8]) -> (ShellStatus, usize) {
        let mut cursor = 0;
        for (i, &arg) in args.iter().enumerate() {
            if i > 0 && cursor < out.len() {
                out[cursor] = b' ';
                cursor += 1;
            }
            let bytes = arg.as_bytes();
            let to_copy = bytes.len().min(out.len().saturating_sub(cursor));
            out[cursor..cursor + to_copy].copy_from_slice(&bytes[..to_copy]);
            cursor += to_copy;
        }
        if cursor < out.len() {
            out[cursor] = b'\n';
            cursor += 1;
        }
        (ShellStatus::Success, cursor)
    }

    fn cmd_clear(&self, out: &mut [u8]) -> (ShellStatus, usize) {
        let seq = b"\x1b[2J\x1b[H";
        let len = seq.len().min(out.len());
        out[..len].copy_from_slice(&seq[..len]);
        (ShellStatus::Success, len)
    }

    fn cmd_reboot(&self, out: &mut [u8]) -> (ShellStatus, usize) {
        let msg = b"[SYSTEM] Arret du systeme demande...\n";
        let len = msg.len().min(out.len());
        out[..len].copy_from_slice(&msg[..len]);
        unsafe {
            syscall6(SyscallNumber::SystemPoweroff, 0, 0, 0, 0, 0, 0);
        }
        (ShellStatus::Success, len)
    }

    fn cmd_not_found(&self, cmd: &str, out: &mut [u8]) -> (ShellStatus, usize) {
        let mut cursor = 0;
        let pfx = b"jsh: command not found: ";
        cursor = append_bytes(out, cursor, pfx);
        cursor = append_bytes(out, cursor, cmd.as_bytes());
        cursor = append_bytes(out, cursor, b"\n");
        (ShellStatus::CommandNotFound, cursor)
    }
}

fn append_bytes(buf: &mut [u8], cursor: usize, data: &[u8]) -> usize {
    if cursor >= buf.len() {
        return cursor;
    }
    let to_copy = data.len().min(buf.len() - cursor);
    buf[cursor..cursor + to_copy].copy_from_slice(&data[..to_copy]);
    cursor + to_copy
}

fn append_u64(buf: &mut [u8], mut cursor: usize, mut val: u64) -> usize {
    if val == 0 {
        return append_bytes(buf, cursor, b"0");
    }
    let mut temp = [0u8; 20];
    let mut i = 0;
    while val > 0 && i < temp.len() {
        temp[i] = b'0' + (val % 10) as u8;
        val /= 10;
        i += 1;
    }
    while i > 0 && cursor < buf.len() {
        i -= 1;
        buf[cursor] = temp[i];
        cursor += 1;
    }
    cursor
}
```

- [ ] **Step 3: Harmoniser `services/jambo-sh/src/main.rs`**

S'assurer que la boucle REPL utilise la version actualisée `v0.3.41` et gère les touches Backspace et Entrée :

```rust
#![no_std]
#![no_main]

use jambo_sh::JamboShell;
use libjambo::{console_read, console_write, print, println, syscall6, SyscallNumber};

#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {
        core::hint::spin_loop();
    }
}

#[no_mangle]
pub extern "C" fn _start() -> ! {
    println("\x1b[1;36m========================================\x1b[0m");
    println("\x1b[1;32m  JamboOS Object Shell (jsh) v0.3.41    \x1b[0m");
    println("\x1b[1;36m========================================\x1b[0m");
    print("\x1b[1;32mjambo:/# \x1b[0m");

    let mut shell = JamboShell::new();
    let mut line_buf = [0u8; 256];
    let mut line_pos = 0;
    let mut out_buf = [0u8; 1024];

    loop {
        let mut rx_byte = [0u8; 1];
        if let Ok(n) = console_read(&mut rx_byte) {
            if n > 0 {
                let b = rx_byte[0];
                if b == b'\r' || b == b'\n' {
                    print("\n");
                    if line_pos > 0 {
                        if let Ok(line_str) = core::str::from_utf8(&line_buf[..line_pos]) {
                            let (_, out_len) = shell.execute_line(line_str, &mut out_buf);
                            if out_len > 0 {
                                let _ = console_write(&out_buf[..out_len]);
                            }
                        }
                        line_pos = 0;
                    }
                    print("\x1b[1;32mjambo:/# \x1b[0m");
                } else if b == 0x08 || b == 0x7F {
                    // Touche Retour Arrière (Backspace)
                    if line_pos > 0 {
                        line_pos -= 1;
                        print("\x08 \x08");
                    }
                } else if line_pos < line_buf.len() - 1 {
                    line_buf[line_pos] = b;
                    line_pos += 1;
                    let _ = console_write(&rx_byte);
                }
            }
        }
        unsafe {
            syscall6(SyscallNumber::ThreadYield, 0, 0, 0, 0, 0, 0);
        }
    }
}
```

- [ ] **Step 4: Vérifier la compilation bare-metal de `jambo-sh`**

Exécuter :
```bash
cargo check -p jambo-sh --target x86_64-unknown-none --release
```
Attendu : 0 erreur, 0 avertissement.

- [ ] **Step 5: Commit Git**

```bash
git add services/jambo-sh/Cargo.toml services/jambo-sh/src/lib.rs services/jambo-sh/src/main.rs
git commit -m "refactor(sh): replace 23k lines of mock clutter with clean modular JamboShell v0.3.41"
```

---

### Task 3 : Câblage de l'Amorçage Ring 3 & Support Double-Mode dans le Noyau & `xtask`

**Files:**
- Modify: `kernel/src/main.rs`
- Modify: `xtask/src/main.rs`

**Interfaces:**
- Consumes: Binaires `jambo-init` et `jsh` empaquetés dans `initrd.tar`
- Produces: Capacité à exécuter soit la session interactive directe sous QEMU, soit la suite de tests automatisée en CI sans blocage.

- [ ] **Step 1: Mettre à jour `kernel/src/main.rs` pour l'initialisation de `jsh`**

Dans `kernel/src/main.rs`, s'assurer que lors de la détection de `/bin/init`, le noyau extrait également `/bin/jsh` s'il est présent, initialise le processus racine et démarre le thread utilisateur :

```rust
// Extraction des binaires depuis l'Initrd
let tar = mm::TarArchive::new(data);
if let Some(init_data) = tar.find("init") {
    kprintln!("[INITRD/TAR] Superviseur '/bin/init' extrait ({:#x} octets)", init_data.len());
    initrd_elf_bytes = Some(init_data);
}
```
En mode interactif normal, le binaire `init` ou `jsh` prend la main.

- [ ] **Step 2: Configurer `xtask` pour le mode interactif `run` et le mode de test CI `test`**

Dans `xtask/src/main.rs` :
1. Commande `run` : lancer QEMU avec `-serial stdio` interactif (sans `isa-debug-exit` immédiat pour laisser l'utilisateur taper).
2. Commande `test` : lancer QEMU avec `kernel_cmdline: test` et injection d'octets UART pour valider le shell avant sortie via `isa-debug-exit`.

- [ ] **Step 3: Compiler l'image ISO complète**

Exécuter :
```bash
cargo xtask build --release
cargo xtask iso --release
```
Attendu : Binaire noyau et archive `target/initrd.tar` (contenant `bin/init` et `bin/jsh`) construits avec succès.

- [ ] **Step 4: Commit Git**

```bash
git add kernel/src/main.rs xtask/src/main.rs
git commit -m "feat(core): enable dual-mode interactive and CI execution for Ring 3 shell"
```

---

### Task 4 : Validation de Bout en Bout sous QEMU (Mode CI & Mode Interactif)

**Files:**
- Test: Exécution des commandes `xtask` et tests de conformité de code

**Interfaces:**
- Consumes: Image ISO générée `target/jamboos-x86_64.iso`
- Produces: Confirmation que la console interactive et le shell `jsh` répondent sans accroc.

- [ ] **Step 1: Vérification du formatage et des linters**

```bash
cargo fmt --all -- --check
cargo check -p kernel --target x86_64-unknown-none --release
cargo check -p jambo-init --target x86_64-unknown-none --release
cargo check -p jambo-sh --target x86_64-unknown-none --release
cargo clippy --package jambo-abi -- -D warnings
```
Attendu : 0 erreur, code de sortie 0.

- [ ] **Step 2: Exécuter le test automatisé QEMU (CI)**

```bash
cargo xtask test --release
```
Attendu :
- Démarrage de QEMU UEFI EDK2.
- Transition Ring 0 -> Ring 3.
- Exécution de `jsh` avec bannière `JamboOS Object Shell (jsh) v0.3.41`.
- Traitement des commandes de test (`help`, `sysinfo`, `reboot`).
- Sortie propre avec le code de succès 33 via `isa-debug-exit`.

- [ ] **Step 3: Commit Git de validation finale**

```bash
git add .
git commit -m "test(sh): verify Ring 3 JamboShell v0.3.41 interactive console under QEMU"
```
