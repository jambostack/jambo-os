# Spécification Technique — Jalon 6.4 (v0.3.91) : Utilitaires Coreutils Autonomes en Ring 3 & Exécution Capabilaire depuis jsh

> **Date** : 7 novembre 2026  
> **Composants cibles** : `libs/libjambo`, `services/jambo-coreutils`, `services/jambo-sh`, `kernel`, `xtask`  
> **Version cible** : `v0.3.91` (Pre-Alpha / Prototype Expérimental de Recherche)  
> **Statut** : Approuvé

---

## 1. Objectifs & Portée

L'objectif du **Jalon 6.4** est de doter JamboOS d'une suite d'utilitaires Coreutils autonomes en espace utilisateur (Ring 3) :
- `bin/echo`
- `bin/cat`
- `bin/wc`
- `bin/true`
- `bin/false`
- `bin/ls`

Ces utilitaires s'appuient exclusivement sur la bibliothèque utilisateur `#![no_std]` [`libs/libjambo`](file:///c:/Users/joker/Documents/jambo-os/libs/libjambo) (couches `vfs` et `posix`), sans allocation dynamique obligatoire, dans le respect strict du principe de moindre privilège et de l'isolation mémoire micro-noyau.

### Exigences Fondamentales
1. **Binaires Autonomes Ring 3** :
   - Chaque utilitaire dispose d'un point d'entrée exécutable autonome `_start` conforme à la System V AMD64 ABI.
   - Le parsing des arguments `argc` et `argv` s'effectue directement sur le cadre de pile configuré par le micro-noyau (`[argc][argv0][argv1]...[NULL]`).
   - La terminaison s'effectue par l'appel système `SyscallNumber::ThreadExit` (Syscall 11) propageant le code de retour POSIX ($0$ pour succès, $> 0$ pour erreur).
2. **Bibliothèque Réutilisable (`libjambo::coreutils`)** :
   - Un moteur centralisé dans `libs/libjambo/src/coreutils.rs` implémente les algorithmes de chaque outil.
   - Les flux d'entrée/sortie sont orientés descripteurs de fichiers POSIX (`stdin = 0`, `stdout = 1`, `stderr = 2`) ou buffers mémoires pour les tests unitaires.
3. **Spécification Fonctionnelle des Outils** :
   - `echo` :
     - Affiche les arguments séparés par des espaces.
     - Prend en charge le drapeau `-n` (suppression du saut de ligne final).
     - Retourne toujours $0$.
   - `cat` :
     - Concatène et affiche les fichiers passés en argument ou le flux standard si aucun argument ou `"-"`.
     - Émet un message d'erreur sur `stderr` en cas de fichier introuvable (`EBADF` / `ENOENT`).
     - Retourne $0$ si tous les fichiers ont été lus avec succès, $1$ sinon.
   - `wc` :
     - Compte les lignes (`\n`), les mots (séparateurs d'espaces/tabulations/retours) et les octets.
     - Prend en charge les drapeaux `-l` (lignes), `-w` (mots), `-c` (octets). Par défaut : `-l -w -c`.
     - Si plusieurs fichiers sont fournis, émet une ligne de récapitulation `total`.
   - `true` :
     - Termine immédiatement avec le code de sortie $0$.
   - `false` :
     - Termine immédiatement avec le code de sortie $1$.
   - `ls` :
     - Liste les entrées de répertoire disponibles dans le VFS ou chemins système enregistrés (`/bin`, `/dev`, `/etc`, `/tmp`).
     - Prend en charge les drapeaux `-l` (format long avec type `d`/`-`/`c` et taille) et `-a` (tous les fichiers).
4. **Intégration Shell `jsh`** :
   - Prise en charge des commandes autonomes avec ou sans préfixe `/bin/` (`cat`, `/bin/cat`, `echo`, `/bin/echo`, etc.).
   - Nouvelle commande introspective `coreutils` listant les 6 utilitaires, leur empreinte binaire, leurs permissions CSpace et leur statut de conformité POSIX.
5. **Intégration Initrd & Packaging `xtask`** :
   - Compilation croisée des 6 binaires vers `x86_64-unknown-none`.
   - Copie dans l'arbre initrd (`/bin/*` et racine `/*`) et inclusion dans `jambo-initrd.tar`.
   - Validation automatisée sous QEMU.

---

## 2. Architecture & Conception Détaillée

### 2.1 Moteur Coreutils (`libs/libjambo/src/coreutils.rs`)

```rust
pub struct WcResult {
    pub lines: usize,
    pub words: usize,
    pub bytes: usize,
}

pub fn run_echo(args: &[&str], out_fd: i32) -> i32;
pub fn run_cat(paths: &[&str], in_fd: i32, out_fd: i32, err_fd: i32) -> i32;
pub fn run_wc(args: &[&str], in_fd: i32, out_fd: i32, err_fd: i32) -> i32;
pub fn run_true() -> i32;
pub fn run_false() -> i32;
pub fn run_ls(args: &[&str], out_fd: i32, err_fd: i32) -> i32;
```

### 2.2 Point d'Entrée Exécutable (`services/jambo-coreutils/src/bin/*.rs`)

Chaque utilitaire autonome partage la convention System V AMD64 :
```rust
#[no_mangle]
pub unsafe extern "C" fn _start() -> ! {
    let sp: *const usize;
    core::arch::asm!("mov {}, rsp", out(reg) sp);
    let argc = *sp;
    let argv_ptr = sp.add(1) as *const *const u8;
    // ... Extraction des slices &str ...
    let exit_code = run_tool(&args);
    syscall6(SyscallNumber::ThreadExit, exit_code as u64, 0, 0, 0, 0, 0);
    loop { core::hint::spin_loop(); }
}
```

### 2.3 Sécurité & Isolation Mémoire
- Chaque binaire Ring 3 exécuté par le noyau dispose de son propre espace d'adressage virtuel `AddressSpace` (isolation par table de pages PML4 isolée).
- L'autorité ambiante est proscrite : seuls les descripteurs de fichiers ouverts et les capacités CSpace légitimes sont accessibles.

