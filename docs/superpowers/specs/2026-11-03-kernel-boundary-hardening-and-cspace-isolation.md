# Spécification de Conception — Jalon 4.1 (v0.3.78)
# Durcissement des Frontières Noyau & Isolation des Capacités par Processus

**Auteur :** Architecte Micro-Noyau JamboOS  
**Date :** 3 novembre 2026  
**Cible :** JamboKernel Iron Core `v0.3.78`  
**Contexte :** Traitement des vulnérabilités critiques **C-01** (Isolation des capacités par processus et amplification de privilèges) et **C-02** (Validation des pointeurs et déréférencements directs en Ring 0) issues du rapport d'audit `JAMBO_OS_TECHNICAL_AUDIT.md`.

---

## 1. Contexte & Problématique

L'audit technique approfondi (`JAMBO_OS_TECHNICAL_AUDIT.md`) a révélé deux failles architecturales majeures au niveau du micro-noyau :

1. **Absence d'isolation CSpace par processus (C-01)** :
   - `KERNEL_CSPACE` est actuellement une instance unique et globale déclarée dans `kernel/src/cap/cspace.rs`.
   - Tous les processus utilisateurs partagent la même table de handles. Un processus A peut référencer ou manipuler les objets d'un processus B sans barrière d'étanchéité.
   - De surcroît, le syscall `CapTransfer` réinsère l'objet avec `cap_rights::ALL`, provoquant une **amplification unilatérale de privilèges**.
2. **Déréférencement direct de pointeurs utilisateurs en Ring 0 (C-02)** :
   - Dans `kernel/src/syscall/dispatch.rs`, les registres contenant des adresses utilisateurs (`a2`, `a3`, etc.) sont directement transtypés en pointeurs Rust (`as *mut u64`, `as *const u8`) puis déréférencés en mode superviseur.
   - Si un utilisateur malveillant ou erroné passe une adresse non canonique, un pointeur nul, ou pire, une adresse appartenant à l'espace mémoire privilégié du noyau (HHDM à `0xffff800000000000`), le noyau provoque un crash ou effectue une lecture/écriture arbitraire en mémoire superviseur.

---

## 2. Objectifs Techniques du Jalon 4.1

1. **Isolation stricte du CSpace par Processus** :
   - Chaque instance de `Process` possède son propre `CSpace` protégé par son propre verrou (`Arc<Mutex<CSpace>>`).
   - Chaque `Thread` hérite de la référence vers le `CSpace` de son processus parent.
   - La résolution et la création de handles s'effectuent exclusivement dans le `CSpace` du processus appelant.
   - `CapTransfer` transfère une capacité vers le `CSpace` d'un processus cible spécifié, en appliquant obligatoirement un masque d'atténuation monotone (`new_rights = current_rights & rights_mask`). Toute promotion vers `ALL` est strictement bannie.
2. **Couche de Sécurité Mémoire `user_ptr` & Primitives `copy_from_user` / `copy_to_user`** :
   - Création du module `kernel/src/syscall/user_ptr.rs`.
   - Validation stricte de chaque adresse virtuelle utilisateur :
     - Adresse non nulle.
     - Pas de débordement arithmétique (`vaddr.checked_add(len)`).
     - Adresse strictement bornée dans l'espace utilisateur canonique (`vaddr + len <= USER_ADDR_LIMIT` où `USER_ADDR_LIMIT = 0x0000_7fff_ffff_0000`).
     - Vérification de l'existence du mapping dans `AddressSpace` et vérification des droits matériels (`READ` pour lecture, `WRITE` pour écriture).
   - Remplacement systématique de tous les accès directs mémoire dans `dispatch_syscall` par ces primitives sécurisées, renvoyant `SysError::BadAddress` sans aucun crash noyau.
3. **Tests Adversariaux & Vérification Formelle** :
   - Suite de tests unitaires adversariaux simulant des pointeurs nuls, des adresses noyau HHDM, des dépassements de buffer et des tentatives d'usurpation de handle entre deux processus distincts.

---

## 3. Architecture & Interfaces

### 3.1. Structure du CSpace par Processus

Dans `kernel/src/sched/process.rs` :
```rust
pub struct Process {
    pub id: u64,
    pub name: String,
    pub aspace: Arc<AddressSpace>,
    pub cspace: Arc<Mutex<CSpace>>, // CSpace isolé par processus
    pub threads: Mutex<Vec<Arc<Mutex<Thread>>>>,
    pub state: Mutex<ProcessState>,
    pub entry_point: u64,
    pub user_stack_top: u64,
}
```

Dans `kernel/src/sched/thread.rs` :
```rust
pub struct Thread {
    pub id: u64,
    pub process_id: u64,
    pub state: ThreadState,
    pub rsp: u64,
    pub stack_base: usize,
    pub stack_top: usize,
    pub vruntime: u64,
    pub deadline: u64,
    pub weight: u32,
    pub is_user: bool,
    pub user_entry: u64,
    pub user_rsp: u64,
    pub aspace: Option<Arc<AddressSpace>>,
    pub cspace: Option<Arc<Mutex<CSpace>>>, // Référence CSpace du thread
}
```

### 3.2. Primitives de Copie Mémoire Sécurisée (`user_ptr.rs`)

```rust
pub const USER_ADDR_LIMIT: u64 = 0x0000_7fff_ffff_0000;

pub fn validate_user_range(
    aspace: &AddressSpace,
    vaddr: u64,
    len: usize,
    write: bool,
) -> Result<(), SysError>;

pub fn copy_from_user<T: Copy>(
    aspace: &AddressSpace,
    src_vaddr: u64,
) -> Result<T, SysError>;

pub fn copy_to_user<T: Copy>(
    aspace: &AddressSpace,
    dst_vaddr: u64,
    val: &T,
) -> Result<(), SysError>;

pub fn copy_from_user_slice(
    aspace: &AddressSpace,
    src_vaddr: u64,
    dst: &mut [u8],
) -> Result<(), SysError>;

pub fn copy_to_user_slice(
    aspace: &AddressSpace,
    dst_vaddr: u64,
    src: &[u8],
) -> Result<(), SysError>;
```

### 3.3. Nouveau Protocole `CapTransfer` Non-Amplifiable

Signature du syscall `CapTransfer` :
- `a1` : `handle` source dans le CSpace du processus appelant.
- `a2` : `target_proc_h` handle du processus récepteur (ou `0` pour processus courant).
- `a3` : `rights_mask` masque d'atténuation.
- `a4` : `out_handle_ptr` pointeur utilisateur où écrire le nouveau handle.

Règle d'atténuation stricte :
```rust
let new_rights = current_rights & rights_mask;
target_cspace.insert(object, new_rights);
```
Il est impossible pour le récepteur d'obtenir plus de droits que l'émetteur.

---

## 4. Matrice de Sécurité & Critères d'Acceptation

1. **Aucun Déréférencement Direct** : `grep -n "as \*mut" kernel/src/syscall/dispatch.rs` et `grep -n "as \*const" kernel/src/syscall/dispatch.rs` doivent être entièrement nettoyés au profit des primitives de `user_ptr`.
2. **Étanchéité Multi-Processus** : Le processus A tentant de faire `CapDrop` ou `CapDup` sur un `Handle` de B doit recevoir `SysError::InvalidHandle`.
3. **Résilience Adversariale** : Tout appel système passant `0x0`, `0x1`, `0xffff_8000_0000_0000` (adresse noyau) ou `u64::MAX` doit renvoyer proprement `SysError::BadAddress` sans panique ni crash du micro-noyau.
4. **Boot QEMU & CI** : Les 38 processus démarrent normalement avec leurs CSpaces isolés et les tests unitaires du noyau passent à 100 %.
