# Spécification de Conception — Jalon 4.2 (v0.3.79)
# Sécurisation du PMM Buddy Allocator & Cycle de Vie Mémoire Physique

**Auteur :** Architecte Micro-Noyau JamboOS  
**Date :** 3 novembre 2026  
**Cible :** JamboKernel Iron Core `v0.3.79`  
**Contexte :** Traitement des vulnérabilités de gestion mémoire physique **S-05** (Cycle de vie, double-free et corruption des listes libres PMM) et **C-06** (Défauts du cycle de vie des VMO et persistance des mappings) issues du rapport d'audit `JAMBO_OS_TECHNICAL_AUDIT.md`.

---

## 1. Contexte & Problématique

L'audit technique (`JAMBO_OS_TECHNICAL_AUDIT.md`) a mis en exergue des fragilités substantielles dans l'allocateur de pages physiques (`kernel/src/mm/pmm.rs`) et l'objet de mémoire virtuelle (`kernel/src/mm/vmo.rs`) :

1. **Vulnérabilité Double-Free dans le PMM (`pmm.rs`)** :
   - `BuddyAllocator::free(paddr, order)` réinsère inconditionnellement le bloc dans `free_lists[order]` via `push_block(paddr, order)`.
   - Si une page ou un bloc est libéré deux fois (double-free), un cycle infini `A -> A` est injecté directement dans la liste chaînée intrusive. La prochaine allocation provoque une boucle infinie ou la réallocation simultanée de la même page à deux consommateurs distincts, brisant l'isolation spatiale du micro-noyau.
   - Aucun contrôle d'alignement matériel : une libération avec une adresse désalignée corrompt les pointeurs de la liste libre.
   - Aucun contrôle de bornes : la libération d'une adresse hors mémoire gérée corrompt l'espace mémoire physique.

2. **Absence de Fusion Buddy (Coalescing) & Fragmentation Critique** :
   - Lorsqu'un bloc d'ordre $k$ est libéré, l'allocateur ne vérifie pas si son bloc jumeau (*buddy* à `paddr ^ (PAGE_SIZE << k)`) est également libre.
   - Les blocs d'ordre supérieur scindés (notamment les piles noyau de 16 Kio / Ordre 2 ou les tampons VMO) ne sont jamais reconstitués, entraînant une fragmentation irréversible de la mémoire physique.

3. **Fuite d'Informations Résiduelles (Non-Scrubbing)** :
   - Les pages physiques nouvellement allouées ne sont pas systématiquement épurées (zeroed) au niveau du PMM, risquant de divulguer des fragments de clés cryptographiques, hashs d'intégrité ou jetons d'authentification entre différents processus utilisateurs successifs.

4. **Fragilité de la Destruction des VMO (`vmo.rs`)** :
   - Le `Drop` de `Vmo` libère brutalement les pages physiques sans référence partagée pérenne si `is_cow == false`, alors qu'un clone CoW peut encore pointer sur les mêmes adresses physiques, entraînant un Use-After-Free physique.

---

## 2. Objectifs Techniques du Jalon 4.2

1. **Protection Anti-Double-Free & Bitmap d'Attribution Physique** :
   - Intégration d'un bitmap d'état d'allocation statique `alloc_bitmap: [u64; BITMAP_WORDS]` dans `BuddyAllocator`, sans dépendance vers le tas (compatible `no_std` et bootloader précoce).
   - Couverture jusqu'à 4 Gio de mémoire vive physique (1 048 576 pages gérées).
   - Validation stricte lors de `free(paddr, order)` :
     - Vérification de l'alignement strict sur $2^{order} \times 4096$.
     - Vérification que toutes les pages du bloc sont actuellement marquées `ALLOCATED`.
     - Si une page est déjà libre : détection formelle de double-free, rejet immédiat de l'opération, journalisation d'alerte, zéro corruption de la liste libre.
2. **Fusion Bidirectionnelle des Buddies (Buddy Coalescing)** :
   - Implémentation de la fusion récursive des blocs contigus : pour tout bloc libéré d'ordre $k$, si son buddy `paddr ^ (PAGE_SIZE << k)` est libre et présent dans `free_lists[k]`, les deux blocs sont fusionnés en un bloc d'ordre $k+1$.
   - Reconstitution déterministe des grands blocs jusqu'à `MAX_ORDER - 1` (4 Mio).
3. **Épuration Mémoire Systématique (Zero-Scrubbing)** :
   - `allocate()` garantit que toute page remise à un sous-système ou processus est strictement initialisée à zéro (`write_bytes(0)`), interdisant toute fuite d'informations résiduelles inter-domaines.
4. **Sécurisation du Cycle de Vie des VMO (`Arc<VmoBacking>`)** :
   - Encapsulation des pages physiques dans une structure partagée ref-countée `VmoBacking`.
   - Libération des pages physiques uniquement lors de la destruction de la dernière référence vivante, garantissant l'immunité contre le Use-After-Free physique.
5. **Suite de Tests Adversariaux PMM & Validation Bare-Metal** :
   - Test A : Rejet d'adresse physique désalignée sans corruption.
   - Test B : Rejet d'adresse physique hors bornes.
   - Test C : Détection et neutralisation d'un double-free sans cycle dans la liste libre.
   - Test D : Validation de la fusion Buddy (coalescing Ordre 0 -> Ordre 1 -> Ordre 2).
   - Test E : Validation du zero-scrubbing.

---

## 3. Architecture & Implémentation Détaillée

### 3.1. Bitmap de Contrôle d'Attribution (`kernel/src/mm/pmm.rs`)

```rust
pub const MAX_TRACKED_PAGES: usize = 1024 * 1024; // 1 048 576 pages = 4 Gio de RAM
pub const BITMAP_WORDS: usize = MAX_TRACKED_PAGES / 64; // 16 384 mots u64 (128 Kio en .bss)

pub struct BuddyAllocator {
    free_lists: [*mut FreeBlock; MAX_ORDER],
    alloc_bitmap: [u64; BITMAP_WORDS],
    min_paddr: usize,
    max_paddr: usize,
    total_pages: usize,
    allocated_pages: usize,
}
```

Méthodes de gestion atomique de l'état :
- `is_page_allocated(pfn: usize) -> bool`
- `set_range_allocated(start_pfn: usize, order: usize)`
- `set_range_free(start_pfn: usize, order: usize)`
- `is_range_allocated(start_pfn: usize, order: usize) -> bool`
- `is_range_free(start_pfn: usize, order: usize) -> bool`

### 3.2. Algorithme de Fusion Buddy Sécurisé

```rust
pub fn free(&mut self, mut paddr: usize, mut order: usize) -> Result<(), PmmError> {
    // 1. Validation alignement
    let block_size = PAGE_SIZE << order;
    if (paddr & (block_size - 1)) != 0 {
        return Err(PmmError::Misaligned);
    }

    // 2. Validation bornes
    let pfn = paddr / PAGE_SIZE;
    if pfn + (1 << order) > MAX_TRACKED_PAGES {
        return Err(PmmError::OutOfBounds);
    }

    // 3. Détection formelle anti-double-free
    if !self.is_range_allocated(pfn, order) {
        return Err(PmmError::DoubleFree);
    }

    // 4. Marquer les pages comme libres dans le bitmap
    self.set_range_free(pfn, order);
    self.allocated_pages = self.allocated_pages.saturating_sub(1 << order);

    // 5. Fusion itérative avec les buddies
    while order < MAX_ORDER - 1 {
        let buddy_paddr = paddr ^ (PAGE_SIZE << order);
        let buddy_pfn = buddy_paddr / PAGE_SIZE;

        if buddy_pfn + (1 << order) <= MAX_TRACKED_PAGES 
            && self.is_range_free(buddy_pfn, order) 
            && unsafe { self.remove_free_block(buddy_paddr, order) }
        {
            paddr = paddr.min(buddy_paddr);
            order += 1;
        } else {
            break;
        }
    }

    // 6. Insérer le bloc fusionné dans la liste libre
    unsafe {
        self.push_block(paddr, order);
    }
    Ok(())
}
```

### 3.3. Cycle de Vie Sécurisé des VMO (`kernel/src/mm/vmo.rs`)

```rust
struct VmoBacking {
    pages: Mutex<Vec<Option<usize>>>,
    vmo_type: VmoType,
}

impl Drop for VmoBacking {
    fn drop(&mut self) {
        let mut pages = self.pages.lock();
        for page in pages.iter_mut() {
            if let Some(paddr) = page.take() {
                free_page(paddr);
            }
        }
    }
}

pub struct Vmo {
    size: usize,
    backing: Arc<VmoBacking>,
    is_cow: bool,
}
```

---

## 4. Critères d'Acceptation & Validation

1. **Immunité Anti-Double-Free** : Toute tentative de double libération sur `free_page(paddr)` ou `PMM.free(paddr, order)` renvoie `Err(PmmError::DoubleFree)` sans altérer la cohérence des listes libres.
2. **Reconstitution de Mémoire (Coalescing)** : Allouer 2 pages adjacentes d'Ordre 0, puis les libérer toutes les deux permet d'allouer immédiatement un bloc d'Ordre 1 (8 Kio) sans faute.
3. **Zéro-Leak Inter-Processus** : Toute page allouée est garantie contenir 4096 zéros binaires.
4. **Boot QEMU CI** : Les 38 démons démarrent avec succès sous QEMU, avec bannière `v0.3.79` et validation de la ligne exacte :
   `[PASS] Securisation PMM Buddy Allocator & Cycle de Vie VMO validee sous QEMU.`

