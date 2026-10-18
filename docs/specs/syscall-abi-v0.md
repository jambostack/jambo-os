# Spécification de l'ABI des 24 Appels Système JamboOS (v0.1)

## 1. Convention d'Appel (x86-64 & aarch64)

### x86-64
- **Instruction d'entrée** : `SYSCALL`
- **Instruction de sortie** : `SYSRETQ`
- **Numéro d'appel système** : `RAX`
- **Arguments (jusqu'à 6)** : `RDI`, `RSI`, `RDX`, `R10`, `R8`, `R9` (Note : `RCX` est écrasé par `RIP` et `R11` par `RFLAGS`)
- **Valeur de retour** : `RAX` (0 pour succès, code négatif pour erreur `SysError`) + `RDX` pour retour secondaire éventuel.

### aarch64
- **Instruction d'entrée** : `SVC #0`
- **Instruction de sortie** : `ERET`
- **Numéro d'appel système** : `X8`
- **Arguments (jusqu'à 6)** : `X0` à `X5`
- **Valeur de retour** : `X0`

---

## 2. Table des 24 Appels Système Orthogonaux

### Famille 1 : Gestion des Capacités (CSpace)
| Numéro | Nom | Arguments | Description |
|---|---|---|---|
| 1 | `cap_dup` | `(src_handle: u64, rights_mask: u32, out_handle: *mut u64)` | Duplique une capacité en réduisant optionnellement ses droits |
| 2 | `cap_drop` | `(handle: u64)` | Libère et révoque un Handle dans le CSpace du processus appelant |
| 3 | `cap_transfer` | `(dest_proc: u64, handle: u64, rights_mask: u32, out_handle: *mut u64)` | Transfère une capacité vers un CSpace cible autorisé |

### Famille 2 : Gestion de la Mémoire Virtuelle (VMM & VMO)
| Numéro | Nom | Arguments | Description |
|---|---|---|---|
| 4 | `vmo_create` | `(size: u64, flags: u32, out_handle: *mut u64)` | Alloue un Virtual Memory Object (VMO) |
| 5 | `vmo_map` | `(vmo_handle: u64, offset: u64, size: u64, vaddr: u64, prot: u32, out_vaddr: *mut u64)` | Mappe un segment de VMO dans l'espace d'adressage |
| 6 | `vmo_unmap` | `(vaddr: u64, size: u64)` | Démappe une plage virtuelle |
| 7 | `vmo_protect` | `(vaddr: u64, size: u64, prot: u32)` | Modifie les permissions de projection (W^X) |

### Famille 3 : Processus et Ordonnancement
| Numéro | Nom | Arguments | Description |
|---|---|---|---|
| 8 | `process_create` | `(aspace_handle: u64, flags: u32, out_handle: *mut u64)` | Crée un nouveau processus isolé (sans autorité ambiante) |
| 9 | `thread_create` | `(proc_handle: u64, entry_point: u64, stack_top: u64, out_handle: *mut u64)` | Crée un thread rattaché à un processus |
| 10 | `thread_start` | `(thread_handle: u64, arg: u64)` | Démarre l'exécution du thread dans l'ordonnanceur EEVDF |
| 11 | `thread_exit` | `(exit_code: i32) -> !` | Termine le thread appelant |
| 12 | `thread_yield` | `()` | Cède volontairement le processeur |

### Famille 4 : IPC et Synchronisation
| Numéro | Nom | Arguments | Description |
|---|---|---|---|
| 13 | `channel_create` | `(flags: u32, out_h1: *mut u64, out_h2: *mut u64)` | Crée une paire d'embouts de canal bidirectionnel |
| 14 | `channel_call` | `(chan_handle: u64, send_buf: *const u8, send_len: u32, recv_buf: *mut u8, recv_len: *mut u32)` | Fastpath IPC synchrone par registres |
| 15 | `port_create` | `(flags: u32, out_handle: *mut u64)` | Crée un port d'attente d'événements asynchrones |
| 16 | `port_wait` | `(port_handle: u64, timeout_ns: u64, out_event: *mut JamboEvent)` | Bloque en attente d'un signal ou paquet d'événement |
| 17 | `ring_setup` | `(vmo_handle: u64, ring_desc: *const RingDesc, out_handle: *mut u64)` | Configure un anneau partagé zéro-copie |
| 18 | `ring_enter` | `(ring_handle: u64, to_submit: u32, min_complete: u32, timeout_ns: u64)` | Notifie le noyau d'entrées d'anneau à traiter |
| 19 | `futex_wait` | `(uaddr: *const u32, val: u32, timeout_ns: u64)` | Mise en veille conditionnelle sur adresse mémoire |
| 20 | `futex_wake` | `(uaddr: *const u32, count: u32)` | Réveille les threads bloqués sur le futex |

### Famille 5 : Matériel, Interruptions et Temps
| Numéro | Nom | Arguments | Description |
|---|---|---|---|
| 21 | `irq_bind` | `(vector: u32, port_handle: u64, out_handle: *mut u64)` | Lie une interruption matérielle (MSI-X) à un port |
| 22 | `irq_ack` | `(irq_handle: u64)` | Réarme la ligne d'interruption |
| 23 | `iommu_map` | `(domain_handle: u64, dma_vaddr: u64, paddr: u64, size: u64, prot: u32)` | Mappe une plage mémoire pour le DMA d'un périphérique |
| 24 | `clock_gettime` | `(clock_id: u32, out_timespec: *mut Timespec)` | Obtient le temps système haute résolution (TSC-Deadline) |

---

## 3. Codes d'Erreur Système (`SysError`)
- `0` : `SUCCESS`
- `-1` : `INVALID_HANDLE`
- `-2` : `PERMISSION_DENIED` (Capacité insuffisante)
- `-3` : `INVALID_ARGUMENT`
- `-4` : `OUT_OF_MEMORY`
- `-5` : `BUFFER_TOO_SMALL`
- `-6` : `TIMED_OUT`
- `-7` : `RESOURCE_BUSY`
- `-8` : `NOT_SUPPORTED`
- `-9` : `PEER_CLOSED`
- `-10` : `BAD_ADDRESS`
