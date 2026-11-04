# Jalon 4.5 : Broker de Configuration Matérielle/PCI, Entropie Cryptographique AT_RANDOM & Audit Unsafe du Noyau (Spécification Technique)

## 1. Contexte & Objectifs

Cette spécification résout les vulnérabilités et non-conformités critiques identifiées lors de l'audit externe technique (**C-03**, **S-02**, **S-01**) et réalise le durcissement formel de la surface de confiance (*Trusted Computing Base* - TCB) :

1. **C-03 (Critique) : Le pilote Ring 3 exécute des instructions d'E/S privilégiées**
   - *Constat d'audit* : `services/jambo-blockd/src/main.rs` et `services/jambo-netd/src/main.rs` réalisent la découverte PCI via des instructions assembleur privilégiées `out dx, eax` et `in eax, dx` sur les ports `0xCF8` et `0xCFC`. Or, en Ring 3 standard (`RFLAGS = 0x202` et `iopb_offset` pointant après le TSS sans bitmap I/O), ces instructions déclenchent une exception de protection générale (#GP).
   - *Correction exigée* : Établir un broker noyau sécurisé pour les accès de configuration matérielle/PCI (Syscall 29 `DeviceIo`), interdire l'élévation globale `IOPL=3`, exiger la validation des privilèges de pilote, et éliminer tout accès direct par ports dans l'espace utilisateur Ring 3.
   - *Critère d'acceptation* : Un pilote Ring 3 découvre et configure son matériel via le broker noyau sans exécuter d'instruction privilégiée directe, et un processus utilisateur non autorisé se voit refuser l'accès avec `SysError::PermissionDenied`.

2. **S-02 (Sécurité) : Valeur `AT_RANDOM` constante**
   - *Constat d'audit* : `kernel/src/sched/process.rs`, dans `setup_user_stack()`, inscrivait une séquence statique codée en dur de 16 octets (`[0x42, 0x13, 0x37, ...]`). Cette valeur prévisible ne pouvait servir de source d'entropie pour les runtimes ou bibliothèques cryptographiques.
   - *Correction exigée* : Générer 16 octets d'aléa cryptographique réel à chaque création de processus via `rdrand` (x86_64) / `cntvct_el0` (ARM64) couplé à un générateur à état d'entropie (SplitMix64 / jitter TSC).

3. **S-01 (Sécurité) : Élimination des handles magiques et valeurs de secours**
   - *Constat d'audit* : Remplacement de handles retournés nuls par des entiers constants dans certains services.
   - *Correction exigée* : Tous les handles manipulés par l'espace utilisateur doivent provenir exclusivement d'allocations de capacités explicites par le noyau.

4. **Audit Exhaustif de la Surface `unsafe` du Noyau (Réduction du TCB)**
   - Examen systématique des 67 blocs `unsafe` du noyau.
   - Ajout systématique de clauses documentées `// SAFETY:` pour expliciter les préconditions, invariants de mémoire et post-conditions.
   - Élimination de tout bloc `unsafe` redondant ou contournable en Rust sûr.

---

## 2. Architecture & Principes Fondamentaux

### 2.1 Broker Matériel / PCI en Ring 0 (`SyscallNumber::DeviceIo = 29`)

Dans le micro-noyau JamboOS, les périphériques physiques sont confinés par l'IOMMU et les pilotes s'exécutent en Ring 3 sans privilèges d'E/S globales (`IOPL=0`).

Pour accéder à la configuration PCI :
```
[Userland Driver (Ring 3)]                 [Kernel Syscall Dispatch (Ring 0)]             [Hardware (PCI Bus)]
   libjambo::pci_read32(bdf, reg)  --->   Syscall 29 (DeviceIo)
                                           - Vérification des droits du processus
                                           - Validation des bornes (reg <= 0xFC, bdf valide)
                                           - Exécution privilégiée en Ring 0  --------->  out 0xCF8 / in 0xCFC
                                           - Écriture protégée du résultat vers userland <---------
```

Opérations supportées :
```rust
pub mod device_io_op {
    pub const PCI_READ32: u32 = 1;
    pub const PCI_WRITE32: u32 = 2;
    pub const PCI_READ16: u32 = 3;
    pub const PCI_WRITE16: u32 = 4;
    pub const PCI_READ8: u32 = 5;
    pub const PCI_WRITE8: u32 = 6;
}
```

Contrôle d'accès :
- Le noyau vérifie que le thread émetteur appartient à un processus autorisé (ex: PID de pilote système ou processus détenant une capacité matérielle/IOMMU).
- Tout appelant non autorisé reçoit `SysError::PermissionDenied`.

### 2.2 Entropie Cryptographique Authentique pour `AT_RANDOM`

Le noyau fournit une fonction d'entropie matérielle `get_random_u64()` :
- Sur x86_64 : instruction matérielle `rdrand` vérifiée avec drapeau Carry (`setc`). En cas d'indisponibilité, mixage cryptographique de haute fréquence du compteur de cycles d'horloge (TSC) via l'algorithme SplitMix64.
- Sur AArch64 : registre de compteur virtuel `cntvct_el0` couplé au mixeur SplitMix64.
- Dans `Process::setup_user_stack()` : génération de 16 octets uniques et non déterministes par processus.

---

## 3. Critères d'Acceptation & Validation

1. **Zéro Instruction Privilégiée en Ring 3** :
   - `jambo-blockd` et `jambo-netd` n'exécutent plus aucune instruction `in` ou `out` en assembleur direct. Tous les accès passent par l'appel système `DeviceIo`.
2. **Entropie `AT_RANDOM` Démontrée** :
   - Deux processus distincts créés consécutivement reçoivent des valeurs `AT_RANDOM` strictement différentes et non nulles.
3. **Contrôle d'Accès Matériel Étanche** :
   - Un processus non privilégié tentant d'exécuter `DeviceIo` est rejeté avec `SysError::PermissionDenied`.
4. **Surface Unsafe Conforme & Documentée** :
   - 100 % des blocs `unsafe` du noyau sont munis d'un invariant `// SAFETY:`.
5. **Compilation & QEMU** :
   - Compilation complète du noyau et des 38 microservices en mode debug et release sans erreur.
   - Validation sous QEMU confirmant le succès de la suite de tests.

